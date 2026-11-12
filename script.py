from __future__ import annotations

import argparse
import csv
import functools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from base64 import b64decode, b64encode
from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http import cookiejar
from pathlib import Path
from typing import Any, Literal

import requests

APP_SLUG = "veracode-workflow-app"
INTEGRATION_REPO_NAME = "veracode"
INTEGRATION_SOURCE_URL = "https://github.com/veracode/github-actions-integration.git"
API_VER = "2022-11-28"

_TEAMS_INJECT_RE = re.compile(
    r"([ \t]*(?:-[ \t]+)?uses:[ \t]+veracode/(?:veracode-)?uploadandscan-action@[^\n]+\n"
    r"(?:[ \t]+[^\n]+\n)*?"
    r"[ \t]+with:\n)"
    r"((?:[ \t]+[^\n]+\n)+)",
    re.MULTILINE,
)
_TEAMS_ALREADY_SET_RE = re.compile(r"^\s+teams\s*:", re.MULTILINE)
_TEAMS_VALUE_RE = re.compile(r'^(\s+teams\s*:\s*)["\']?([^"\'"\n]*)["\']?\s*$', re.MULTILINE)

_VERACODE_SECRET_NAMES: tuple[str, ...] = (
    "VERACODE_API_ID",
    "VERACODE_API_KEY",
    "VERACODE_AGENT_TOKEN",
)

# GitHub Actions the integration requires to be allowlisted when an org uses
# the "selected" actions policy. github.com-owned actions (actions/*) are
# covered by the github_owned_allowed flag and are not listed here.
_REQUIRED_ACTION_PATTERNS: tuple[str, ...] = (
    "actions/checkout@*",
    "actions/download-artifact@*",
    "actions/setup-java@*",
    "actions/upload-artifact@*",
    "android-actions/setup-android@*",
    "flutter-actions/setup-flutter@*",
    "octokit/request-action@*",
    "veracode/container_iac_secrets_scanning@*",
    "veracode/github-actions-integration-helper@*",
    "veracode/uploadandscan-action@*",
    "veracode/veracode-flaws-to-issues@*",
    "veracode/Veracode-pipeline-scan-action@*",
    "veracode/veracode-pipeline-scan-results-to-sarif@*",
    "veracode/veracode-sca@*",
)

# actions/* patterns are satisfied by github_owned_allowed=true, so they do not
# need to appear in patterns_allowed.
_GITHUB_OWNED_PREFIX = "actions/"

_print_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Global rate limiter (primary + secondary GitHub limits)
# ---------------------------------------------------------------------------
# See README "Rate Limits" for the full budget table and what is / is not
# modelled proactively.

# Safety margins:
_SAFE_FRACTION_HOURLY = 0.80          # 4,000/hour of 5,000
_SAFE_FRACTION_CONTENT_PER_MIN = 0.75 # 60/min of 80
_SAFE_FRACTION_CONTENT_PER_HOUR = 0.80  # 400/hour of 500
_SAFE_FRACTION_POINTS_PER_MIN = 0.80  # 720 points/min of 900

# Secondary-limit point costs (README: Rate Limits).
_POINTS_LIMIT_REST_PER_MIN = 900
_POINTS_LIMIT_GRAPHQL_PER_MIN = 2000
_POINT_COST_READ = 1
_POINT_COST_WRITE = 5

# Backstop against GitHub's 100 concurrent limit. --workers is not hard-capped.
_MAX_CONCURRENT_REQUESTS = 50

_MAX_BACKOFF_SLEEP_SECONDS = 300    # cap on any single backoff sleep
_MAX_RATE_LIMIT_TOTAL_WAIT = 3900   # cap on total wait for a window reset
_MAX_BRANCH_POLL_INTERVAL = 60      # ceiling for post-import branch poll backoff

_RATE_LIMIT_MAX_ATTEMPTS = 6        # rate-limit retries; 5xx/network use max_retries

# Veracode REST is 500/min per IP; we pace off 250 (README: Rate Limits).
_VERACODE_REST_LIMIT_PER_MIN = 500
_VERACODE_PACE_BASE_PER_MIN = 250
_VERACODE_SAFE_FRACTION_PER_MIN = 0.80  # 200/min
_VERACODE_MAX_CONCURRENT_REQUESTS = 4

_CONTENT_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class _SlidingWindow:
    """Thread-safe sliding window counter over `window_seconds`.

    Uses a deque so left-side pruning during long-running sessions is O(1)
    per removed item, rather than O(n) with list.pop(0).
    """
    __slots__ = ("window", "_events", "_lock")

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune_locked(self, cutoff: float) -> None:
        events = self._events
        while events and events[0] < cutoff:
            events.popleft()

    def add(self) -> None:
        now = time.time()
        with self._lock:
            self._events.append(now)
            self._prune_locked(now - self.window)

    def count(self) -> int:
        cutoff = time.time() - self.window
        with self._lock:
            self._prune_locked(cutoff)
            return len(self._events)

    def oldest_in_window(self) -> float | None:
        cutoff = time.time() - self.window
        with self._lock:
            self._prune_locked(cutoff)
            return self._events[0] if self._events else None


class _WeightedSlidingWindow:
    """Sliding window where each event carries a point cost; count() sums costs."""
    __slots__ = ("window", "_events", "_total", "_lock")

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._events: deque[tuple[float, int]] = deque()
        self._total = 0
        self._lock = threading.Lock()

    def _prune_locked(self, cutoff: float) -> None:
        events = self._events
        while events and events[0][0] < cutoff:
            self._total -= events.popleft()[1]

    def add(self, points: int) -> None:
        now = time.time()
        with self._lock:
            self._events.append((now, points))
            self._total += points
            self._prune_locked(now - self.window)

    def count(self) -> int:
        cutoff = time.time() - self.window
        with self._lock:
            self._prune_locked(cutoff)
            return self._total

    def oldest_in_window(self) -> float | None:
        cutoff = time.time() - self.window
        with self._lock:
            self._prune_locked(cutoff)
            return self._events[0][0] if self._events else None


class _RateLimiter:
    """
    Global rate limiter shared across worker threads.

    Tracks:
      - hourly request count vs primary 5,000/hour budget
      - content-creating writes per minute and per hour
      - in-flight concurrent request count
    """
    def __init__(self) -> None:
        self.hourly = _SlidingWindow(3600)
        self.content_minute = _SlidingWindow(60)
        self.content_hour = _SlidingWindow(3600)
        self.points_minute = _WeightedSlidingWindow(60)
        self.graphql_points_minute = _WeightedSlidingWindow(60)
        self.concurrent = threading.Semaphore(_MAX_CONCURRENT_REQUESTS)

        self.hourly_cap = int(5000 * _SAFE_FRACTION_HOURLY)
        self.content_min_cap = int(80 * _SAFE_FRACTION_CONTENT_PER_MIN)
        self.content_hour_cap = int(500 * _SAFE_FRACTION_CONTENT_PER_HOUR)
        self.points_min_cap = int(_POINTS_LIMIT_REST_PER_MIN * _SAFE_FRACTION_POINTS_PER_MIN)
        self.graphql_points_min_cap = int(
            _POINTS_LIMIT_GRAPHQL_PER_MIN * _SAFE_FRACTION_POINTS_PER_MIN
        )
        # Guards hourly_cap, which observe_limit re-derives from the token's
        # real limit once the first response header arrives.
        self._limit_lock = threading.Lock()

        self._warn_lock = threading.Lock()
        self._last_warn_ts: float = 0.0

    def _warn(self, msg: str) -> None:
        now = time.time()
        with self._warn_lock:
            if now - self._last_warn_ts < 10:
                return
            self._last_warn_ts = now
        tprint(msg)

    def acquire(self, method: str, graphql: bool = False) -> None:
        """Block until safe. `graphql` bills to the GraphQL bucket, not REST
        content-creation, even though it is an HTTP POST.

        Caps are checked then incremented without a lock across both steps, so
        N workers can overshoot by at most N-1. The 0.75-0.80 safety fractions
        absorb that.
        """
        is_content = (not graphql) and method.upper() in _CONTENT_METHODS
        points = _POINT_COST_WRITE if method.upper() in _CONTENT_METHODS else _POINT_COST_READ
        if graphql:
            # Non-mutating GraphQL queries cost 1 point. This tool issues only
            # queries over GraphQL; if a mutation is ever added, charge 5.
            points = _POINT_COST_READ
        points_window = self.graphql_points_minute if graphql else self.points_minute
        points_cap = self.graphql_points_min_cap if graphql else self.points_min_cap
        points_label = "GraphQL" if graphql else "REST"

        # Hourly primary budget
        while True:
            if self.hourly.count() < self.hourly_cap:
                break
            oldest = self.hourly.oldest_in_window()
            wait = max((oldest + 3600) - time.time(), 1.0) if oldest else 5.0
            self._warn(f"  [RATE LIMIT] Hourly safe budget reached ({self.hourly_cap} req/hour). "
                       f"Waiting {int(wait)}s.")
            time.sleep(min(wait, 30))

        if is_content:
            # Per-minute content creation budget (the binding constraint)
            while True:
                if self.content_minute.count() < self.content_min_cap:
                    break
                oldest = self.content_minute.oldest_in_window()
                wait = max((oldest + 60) - time.time(), 1.0) if oldest else 2.0
                self._warn(f"  [RATE LIMIT] Content-write minute budget reached "
                           f"({self.content_min_cap}/min). Pacing for {wait:.1f}s.")
                time.sleep(min(wait, 10))

            # Per-hour content creation budget
            while True:
                if self.content_hour.count() < self.content_hour_cap:
                    break
                oldest = self.content_hour.oldest_in_window()
                wait = max((oldest + 3600) - time.time(), 1.0) if oldest else 30.0
                self._warn(f"  [RATE LIMIT] Content-write hourly budget reached "
                           f"({self.content_hour_cap}/hour). Waiting {int(wait)}s.")
                time.sleep(min(wait, 60))

        # Per-minute secondary points budget (REST and GraphQL are separate
        # buckets; see _POINTS_LIMIT_* above).
        while True:
            if points_window.count() + points <= points_cap:
                break
            oldest = points_window.oldest_in_window()
            wait = max((oldest + 60) - time.time(), 1.0) if oldest else 2.0
            self._warn(f"  [RATE LIMIT] {points_label} points-per-minute budget reached "
                       f"({points_cap} points/min). Pacing for {wait:.1f}s.")
            time.sleep(min(wait, 10))

        self.concurrent.acquire()
        self.hourly.add()
        points_window.add(points)
        if is_content:
            self.content_minute.add()
            self.content_hour.add()

    def release(self) -> None:
        self.concurrent.release()

    def observe_limit(self, limit: int, resource: str | None) -> None:
        """
        Re-derive the hourly cap from x-ratelimit-limit. No-op for a PAT on
        github.com (5000*0.8 == the 4000 default); only moves on --api-base
        (GHES), where the site admin sets the limit. 'core' resource only.
        """
        if limit <= 0:
            return
        if resource is not None and resource != "core":
            return
        new_cap = int(limit * _SAFE_FRACTION_HOURLY)
        with self._limit_lock:
            if new_cap == self.hourly_cap:
                return
            old_cap = self.hourly_cap
            self.hourly_cap = new_cap
        tprint(f"  [INFO] Adjusting hourly budget to {new_cap} "
               f"(GitHub reports a limit of {limit} for this token; was {old_cap}).")

    def snapshot(self) -> dict[str, Any]:
        return {
            "requests_last_hour": self.hourly.count(),
            "hourly_cap": self.hourly_cap,
            "content_writes_last_minute": self.content_minute.count(),
            "content_min_cap": self.content_min_cap,
            "content_writes_last_hour": self.content_hour.count(),
            "content_hour_cap": self.content_hour_cap,
            "points_last_minute": self.points_minute.count(),
            "points_min_cap": self.points_min_cap,
            "graphql_points_last_minute": self.graphql_points_minute.count(),
            "graphql_points_min_cap": self.graphql_points_min_cap,
        }


class _VeracodeRateLimiter:
    """Proactive pacing for Veracode REST. Separate counters from GitHub's."""
    def __init__(self) -> None:
        self.minute = _SlidingWindow(60)
        self.minute_cap = int(_VERACODE_PACE_BASE_PER_MIN * _VERACODE_SAFE_FRACTION_PER_MIN)
        self.concurrent = threading.Semaphore(_VERACODE_MAX_CONCURRENT_REQUESTS)

        self._total_lock = threading.Lock()
        self._total = 0

        self._warn_lock = threading.Lock()
        self._last_warn_ts: float = 0.0

    def _warn(self, msg: str) -> None:
        now = time.time()
        with self._warn_lock:
            if now - self._last_warn_ts < 10:
                return
            self._last_warn_ts = now
        tprint(msg)

    def acquire(self) -> None:
        while True:
            if self.minute.count() < self.minute_cap:
                break
            oldest = self.minute.oldest_in_window()
            wait = max((oldest + 60) - time.time(), 1.0) if oldest else 2.0
            self._warn(f"  [RATE LIMIT] Veracode minute budget reached "
                       f"({self.minute_cap}/min). Pacing for {wait:.1f}s.")
            time.sleep(min(wait, 10))

        self.concurrent.acquire()
        self.minute.add()
        with self._total_lock:
            self._total += 1

    def release(self) -> None:
        self.concurrent.release()

    @property
    def total_requests(self) -> int:
        with self._total_lock:
            return self._total

    def snapshot(self) -> dict[str, Any]:
        return {
            "requests_last_minute": self.minute.count(),
            "minute_cap": self.minute_cap,
            "total_requests": self.total_requests,
            "documented_rest_limit_per_min": _VERACODE_REST_LIMIT_PER_MIN,
        }


_rate_limiter = _RateLimiter()
_veracode_rate_limiter = _VeracodeRateLimiter()


# ---------------------------------------------------------------------------
# Per-org output buffer
# ---------------------------------------------------------------------------

class OrgBuffer:
    def __init__(self, org: str, org_idx: int, total_orgs: int, flush_on_add: bool = False) -> None:
        self.org = org
        self.org_idx = org_idx
        self.total_orgs = total_orgs
        self.flush_on_add = flush_on_add
        self._lines: list[str] = []

    def add(self, msg: str) -> None:
        if self.flush_on_add:
            with _print_lock:
                print(msg, flush=True)
        else:
            self._lines.append(msg)

    def flush(self) -> None:
        if self.flush_on_add or not self._lines:
            return
        pct = (self.org_idx / self.total_orgs * 100) if self.total_orgs else 100.0
        header = f"\n[{self.org_idx}/{self.total_orgs} ({pct:.1f}%)] {self.org}"
        block = "\n".join([header] + self._lines)
        try:
            with _print_lock:
                print(block, flush=True)
        finally:
            self._lines.clear()

    def flush_then_clear(self, progress: "ProgressDisplay", slot_id: int) -> None:
        if self.flush_on_add:
            return
        pct = (self.org_idx / self.total_orgs * 100) if self.total_orgs else 100.0
        header = f"\n[{self.org_idx}/{self.total_orgs} ({pct:.1f}%)] {self.org}"
        block = "\n".join([header] + self._lines) if self._lines else header
        try:
            with _print_lock:
                print(block, flush=True)
        finally:
            self._lines.clear()
            progress.clear_slot(slot_id)


# ---------------------------------------------------------------------------
# Live progress display for parallel mode
# ---------------------------------------------------------------------------

class ProgressDisplay:
    def __init__(self, workers: int) -> None:
        self._active = workers > 1

    def start(self, org: str, idx: int, total: int) -> None:
        if not self._active:
            return
        pct = (idx / total * 100) if total else 100.0
        tprint(f"  --> [{idx}/{total} ({pct:.1f}%)] starting: {org}")

    def clear_slot(self, slot_id: int) -> None:
        pass

    def stop(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Typed stats container
# ---------------------------------------------------------------------------

@dataclass
class RunStats:
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    total_orgs: int = 0
    processed: int = 0
    repo_success: int = 0
    repo_fail: int = 0
    app_installed: int = 0
    app_missing: int = 0
    secrets_success: int = 0
    secrets_fail: int = 0
    secrets_checked: int = 0
    secrets_all_exist: int = 0
    secrets_partial: int = 0
    secrets_all_missing: int = 0
    secrets_no_permission: int = 0
    yml_updated: int = 0
    yml_skipped: int = 0
    yml_failed: int = 0
    teams_updated: int = 0
    teams_skipped: int = 0
    teams_failed: int = 0
    teams_created_on_platform: int = 0
    teams_already_exist_on_platform: int = 0
    teams_create_failed_on_platform: int = 0
    teams_linked_to_workspace: int = 0
    teams_link_already: int = 0
    teams_link_failed: int = 0
    default_branch_fixed: int = 0
    default_branch_ok: int = 0
    default_branch_failed: int = 0
    fix_repos_checked: int = 0
    fix_repos_remediated: int = 0
    fix_repos_skipped: int = 0
    reimports_done: int = 0
    reimports_failed: int = 0
    actions_allowed: int = 0
    actions_missing: int = 0
    actions_no_permission: int = 0


# ---------------------------------------------------------------------------
# Shared run context
# ---------------------------------------------------------------------------

@dataclass
class RunContext:
    api_base: str
    web_base: str
    token: str
    do_apply_repo: bool
    do_set_secrets: bool
    do_set_teams: bool
    do_update_yml: bool
    do_create_teams: bool
    do_fix_repos: bool
    do_link_teams: bool
    dry_run: bool
    teams_mode: Literal["auto", "file", "hybrid", "none"]
    yml_content: str | None
    onboarding_yml_content: str | None
    teams_map: dict[str, str]
    team_prefix: str
    veracode_api_id: str | None
    veracode_api_key: str | None
    veracode_sa_api_id: str | None
    veracode_sa_api_key: str | None
    total_orgs: int
    report_path: Path
    checkpoint_file: Path
    do_iac_rbac: bool = True
    stats: RunStats = field(default_factory=RunStats)
    stats_lock: threading.Lock = field(default_factory=threading.Lock)
    rows_lock: threading.Lock = field(default_factory=threading.Lock)
    report_lock: threading.Lock = field(default_factory=threading.Lock)
    checkpoint_lock: threading.Lock = field(default_factory=threading.Lock)
    missing_repo_rows: list[list[str]] = field(default_factory=list)
    missing_app_rows: list[list[str]] = field(default_factory=list)
    manual_links_rows: list[list[str]] = field(default_factory=list)
    actions_allowlist_rows: list[list[str]] = field(default_factory=list)
    completed_orgs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.do_set_secrets:
            if not self.veracode_api_id or not self.veracode_api_key:
                raise ValueError("do_set_secrets requires veracode_api_id and veracode_api_key")
            if not self.veracode_sa_api_id or not self.veracode_sa_api_key:
                raise ValueError("do_set_secrets requires veracode_sa_api_id and veracode_sa_api_key")
        if self.do_create_teams:
            if not self.veracode_api_id or not self.veracode_api_key:
                raise ValueError("do_create_teams requires veracode_api_id and veracode_api_key")
        if self.do_link_teams:
            if not self.veracode_api_id or not self.veracode_api_key:
                raise ValueError("do_link_teams requires veracode_api_id and veracode_api_key")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def tprint(*args: Any, **kwargs: Any) -> None:
    with _print_lock:
        print(*args, **kwargs)


def env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def gh_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": API_VER,
        "User-Agent": "veracode-workflow-rollout-helper",
    }


# ---------------------------------------------------------------------------
# Rate limit (shared across all threads)
# ---------------------------------------------------------------------------

def check_rate_limit(response: requests.Response) -> None:
    """
    Reactive check based on GitHub's response headers. The proactive
    _rate_limiter handles steady-state pacing; this catches edge cases where
    GitHub's reported remaining is lower than our local estimate (other tools
    sharing the token, or undisclosed secondary budgets).
    """
    remaining_hdr = response.headers.get("X-RateLimit-Remaining")
    reset_hdr = response.headers.get("X-RateLimit-Reset")

    limit_hdr = response.headers.get("X-RateLimit-Limit")
    if limit_hdr:
        try:
            _rate_limiter.observe_limit(
                int(limit_hdr), response.headers.get("X-RateLimit-Resource")
            )
        except ValueError:
            pass

    if not remaining_hdr or not reset_hdr:
        return

    try:
        remaining = int(remaining_hdr)
        reset_time = int(reset_hdr)
    except ValueError:
        return

    if remaining < 200 and remaining % 50 == 0:
        reset_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reset_time))
        tprint(f"  [INFO] Primary rate limit: {remaining} requests remaining (resets at {reset_dt})")

    # Backstop: loop and re-check against x-ratelimit-reset rather than
    # proceeding after one truncated sleep. Total wait is bounded so a bogus
    # reset header cannot wedge the process.
    if remaining < 50:
        deadline = time.time() + _MAX_RATE_LIMIT_TOTAL_WAIT
        while True:
            until_reset = reset_time - int(time.time())
            if until_reset <= 0:
                break
            if time.time() >= deadline:
                tprint(f"  [RATE LIMIT] x-ratelimit-reset is still {until_reset}s out after waiting "
                       f"{_MAX_RATE_LIMIT_TOTAL_WAIT}s; treating it as unreliable and continuing.")
                break
            wait_seconds = until_reset + 5
            tprint(f"  [RATE LIMIT] GitHub reports {remaining} remaining; sleeping {wait_seconds}s "
                   f"until window reset to be safe.")
            time.sleep(min(wait_seconds, _MAX_BACKOFF_SLEEP_SECONDS))


# ---------------------------------------------------------------------------
# Unified retry core
# ---------------------------------------------------------------------------

def parse_retry_after(headers: Any, default: int = 60) -> int:
    """Parse Retry-After as delay-seconds or HTTP-date. Falls back to `default`."""
    raw = None
    try:
        raw = headers.get("Retry-After")
        if raw is None:
            raw = headers.get("retry-after")
    except AttributeError:
        return default
    if raw is None:
        return default

    raw = str(raw).strip()
    if not raw:
        return default

    try:
        return max(int(raw), 0)
    except ValueError:
        pass

    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return default
    if when is None:
        return default
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(int((when - datetime.now(timezone.utc)).total_seconds()), 0)


def _is_primary_rate_limited(r: requests.Response) -> bool:
    """403/429 with x-ratelimit-remaining 0 is primary exhaustion, not a perms error."""
    if r.status_code not in (403, 429):
        return False
    remaining = r.headers.get("X-RateLimit-Remaining") or r.headers.get("x-ratelimit-remaining")
    if remaining is not None:
        try:
            if int(remaining) <= 0:
                return True
        except ValueError:
            pass
    return "api rate limit exceeded" in (r.text or "").lower()


def _rate_limit_wait(r: requests.Response, rl_attempt: int) -> float:
    """Wait before retrying a rate-limited response.

    Precedence per GitHub docs: Retry-After, then x-ratelimit-reset but only
    when remaining is 0, else a 60s floor. Escalates 2**attempt, capped, with
    upward-only jitter so the wait is never below what the server asked for.
    """
    base = float(parse_retry_after(r.headers, default=0))

    if base <= 0:
        remaining_hdr = (r.headers.get("X-RateLimit-Remaining")
                         or r.headers.get("x-ratelimit-remaining"))
        reset_hdr = r.headers.get("X-RateLimit-Reset") or r.headers.get("x-ratelimit-reset")
        exhausted = False
        if remaining_hdr is not None:
            try:
                exhausted = int(remaining_hdr) <= 0
            except ValueError:
                exhausted = False
        if exhausted and reset_hdr:
            try:
                base = (int(reset_hdr) - time.time()) + 5
            except ValueError:
                base = 0.0

    if base <= 0:
        base = 60.0

    escalated = min(base * (2 ** rl_attempt), float(_MAX_BACKOFF_SLEEP_SECONDS))
    return escalated + random.uniform(0, min(escalated * 0.25, 5.0))


def _fault_backoff(attempt: int) -> float:
    """Backoff for 5xx and network faults, with full upward jitter."""
    base = float((2 ** attempt) * 2)
    return base + random.uniform(0, base)


def _retry_request(
    make_request: Callable[[], requests.Response],
    label: str,
    max_retries: int = 3,
) -> requests.Response:
    if max_retries < 1:
        raise ValueError(f"max_retries must be >= 1, got {max_retries}")
    rate_limit_attempts = max(max_retries, _RATE_LIMIT_MAX_ATTEMPTS)
    attempt = 0
    rl_attempt = 0
    while True:
        try:
            r = make_request()

            is_secondary = (
                r.status_code in (403, 429)
                and "secondary rate limit" in (r.text or "").lower()
            )
            is_primary = (not is_secondary) and _is_primary_rate_limited(r)

            if r.status_code == 429 or is_secondary or is_primary:
                if rl_attempt < rate_limit_attempts - 1:
                    wait = _rate_limit_wait(r, rl_attempt)
                    if is_secondary:
                        kind = "secondary rate limit"
                    elif is_primary:
                        kind = "primary rate limit"
                    else:
                        kind = "429"
                    tprint(f"  [{label}] {kind}, waiting {wait:.0f}s "
                           f"(retry {rl_attempt + 1}/{rate_limit_attempts})...")
                    time.sleep(wait)
                    rl_attempt += 1
                    continue
                return r
            if r.status_code >= 500:
                if attempt < max_retries - 1:
                    wait = _fault_backoff(attempt)
                    tprint(f"  [{label}] {r.status_code}, waiting {wait:.0f}s (retry {attempt + 1}/{max_retries})...")
                    time.sleep(wait)
                    attempt += 1
                    continue
                return r
            return r
        except (requests.exceptions.Timeout, requests.exceptions.RequestException) as exc:
            if attempt < max_retries - 1:
                wait = _fault_backoff(attempt)
                label_exc = "timeout" if isinstance(exc, requests.exceptions.Timeout) else str(exc)[:50]
                tprint(f"  [{label}] {label_exc}, waiting {wait:.0f}s (retry {attempt + 1}/{max_retries})...")
                time.sleep(wait)
                attempt += 1
                continue
            raise


_thread_local = threading.local()


class _BlockAllCookies(cookiejar.DefaultCookiePolicy):
    """Accept and return no cookies (matches the old per-call session behaviour)."""
    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False

    def return_ok(self, cookie: Any, request: Any) -> bool:
        return False


def _session() -> requests.Session:
    """One Session per thread: pooled connections, no cross-thread sharing.
    Cookies blocked so behaviour matches the old per-call requests.request().
    """
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.cookies.set_policy(_BlockAllCookies())
        _thread_local.session = sess
    return sess


def request(
    method: str,
    url: str,
    token: str,
    max_retries: int = 3,
    *,
    graphql: bool = False,
    **kwargs: Any,
) -> requests.Response:
    """`graphql=True` bills to the GraphQL bucket, skips content-creation
    accounting, and skips check_rate_limit (its headers are GraphQL-bucket
    values, not REST primary).
    """
    headers = gh_headers(token)

    def make() -> requests.Response:
        _rate_limiter.acquire(method, graphql=graphql)
        try:
            r = _session().request(method, url, headers=headers, timeout=45, **kwargs)
        finally:
            _rate_limiter.release()
        if not graphql:
            check_rate_limit(r)
        return r
    return _retry_request(make, "GITHUB", max_retries)


def _veracode_auth(api_id: str, api_key: str) -> Any:
    """HMAC auth cached per credential pair per thread (not shared: the plugin
    signs each request and is not documented thread-safe). Import stays local so
    the "not installed" error still surfaces at first Veracode use.
    """
    cache = getattr(_thread_local, "veracode_auth", None)
    if cache is None:
        cache = {}
        _thread_local.veracode_auth = cache
    key = (api_id, api_key)
    auth = cache.get(key)
    if auth is None:
        from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
        auth = RequestsAuthPluginVeracodeHMAC(api_key_id=api_id, api_key_secret=api_key)
        cache[key] = auth
    return auth


def veracode_request(
    method: str,
    endpoint: str,
    api_id: str,
    api_key: str,
    max_retries: int = 3,
    **kwargs: Any,
) -> requests.Response:
    url = f"https://api.veracode.com{endpoint}"
    auth = _veracode_auth(api_id, api_key)

    def make() -> requests.Response:
        _veracode_rate_limiter.acquire()
        try:
            return _session().request(method, url, auth=auth, timeout=45, **kwargs)
        finally:
            _veracode_rate_limiter.release()
    return _retry_request(make, "VERACODE", max_retries)


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def parse_link_next(link_header: str) -> str | None:
    for part in (p.strip() for p in link_header.split(",")):
        if 'rel="next"' in part:
            left = part.split(";")[0].strip()
            if left.startswith("<") and left.endswith(">"):
                return left[1:-1]
    return None


def paginate_list(url: str, token: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    next_url: str | None = url
    while next_url:
        r = request("GET", next_url, token, params=params)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {next_url} failed: {r.status_code} {r.text}")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Expected list from {next_url}, got {type(data)}")
        yield from data
        link = r.headers.get("Link") or r.headers.get("link")
        next_url = parse_link_next(link) if link else None
        params = None


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(header)
        writer.writerows(rows)


def append_report_entry(report_path: Path, entry: dict[str, Any]) -> None:
    with report_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry) + "\n")


def finalize_report(report_path: Path) -> None:
    if not report_path.exists():
        return
    entries: list[Any] = []
    with report_path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    print(f"  [WARNING] Skipping corrupt report line {lineno}: {exc} - {line[:80]}", file=sys.stderr)
    tmp = report_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(entries, f, indent=2)
        f.write("\n")
    tmp.replace(report_path)


def write_teams_map_csv(path: Path, orgs: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["org", "teams"])
        writer.writerows([org, ""] for org in orgs)


def write_orgs_txt(path: Path, orgs: list[str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.writelines(org + "\n" for org in orgs)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

# Ceiling for a git clone or push; without it a stall blocks a worker forever.
_GIT_SUBPROCESS_TIMEOUT = 900


@functools.lru_cache(maxsize=1)
def check_git_available() -> bool:
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def git_clone_bare(source_url: str) -> tuple[bool, str, str | None]:
    temp_dir: str | None = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="veracode-clone-")
        bare_repo = os.path.join(temp_dir, "repo.git")
        result = subprocess.run(
            ["git", "clone", "--bare", source_url, bare_repo],
            capture_output=True, text=True, timeout=_GIT_SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0:
            return False, f"Clone failed: {result.stderr}", None
        out = temp_dir
        temp_dir = None
        return True, "Clone successful", out
    except subprocess.TimeoutExpired:
        return False, f"Clone timed out after {_GIT_SUBPROCESS_TIMEOUT}s", None
    except Exception as exc:
        return False, str(exc), None
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def git_mirror_import(
    source_url: str,
    target_org: str,
    target_repo: str,
    token: str,
    web_base: str = "https://github.com",
    cached_clone_dir: str | None = None,
) -> tuple[bool, str]:
    temp_dir: str | None = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="veracode-import-")
        bare_repo = os.path.join(temp_dir, "repo.git")

        if cached_clone_dir:
            shutil.copytree(os.path.join(cached_clone_dir, "repo.git"), bare_repo)
        else:
            clone_result = subprocess.run(
                ["git", "clone", "--bare", source_url, bare_repo],
                capture_output=True, text=True, timeout=_GIT_SUBPROCESS_TIMEOUT,
            )
            if clone_result.returncode != 0:
                return False, f"Clone failed: {clone_result.stderr}"

        host = web_base.rstrip("/").removeprefix("https://").removeprefix("http://")
        target_url = f"https://x-access-token:{token}@{host}/{target_org}/{target_repo}.git"

        push_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        push_result = subprocess.run(
            [
                "git", "-C", bare_repo,
                "-c", "credential.helper=",
                "-c", "credential.helper=cache",
                "-c", "http.https://github.com/.extraheader=",
                "push", "--mirror", target_url,
            ],
            capture_output=True, text=True, env=push_env,
            timeout=_GIT_SUBPROCESS_TIMEOUT,
        )
        if push_result.returncode != 0:
            safe_stderr = push_result.stderr.replace(token, "***")
            return False, f"Push failed: {safe_stderr}"

        return True, "Import successful"

    except subprocess.TimeoutExpired as exc:
        # exc echoes the command line, which carries the token in the push URL.
        stage = "Push" if "push" in (exc.cmd or []) else "Clone"
        return False, f"{stage} timed out after {_GIT_SUBPROCESS_TIMEOUT}s"
    except Exception as exc:
        return False, str(exc).replace(token, "***")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Veracode API helpers
# ---------------------------------------------------------------------------

def _find_workspace_by_name(
    org_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> str | None:
    page = 0
    while True:
        r = veracode_request(
            "GET", "/srcclr/v3/workspaces", api_id, api_key,
            params={"filter[workspace]": org_name, "size": 100, "page": page},
        )
        if r.status_code == 401:
            log("  [ERROR] Veracode authentication failed - check credentials")
            return None
        if r.status_code == 403:
            log("  [ERROR] Veracode permission denied - insufficient access")
            return None
        if r.status_code != 200:
            log(f"  [ERROR] Failed to list workspaces: {r.status_code} - {r.text[:200]}")
            return None

        body = r.json()
        for ws in body.get("_embedded", {}).get("workspaces", []):
            if ws.get("name") == org_name:
                ws_id = ws.get("id")
                if not ws_id:
                    log(f"  [WARNING] Workspace '{org_name}' matched but has no id in response - skipping")
                    continue
                return ws_id

        page_meta = body.get("page", {})
        total_pages = page_meta.get("total_pages", 1)
        if page >= total_pages - 1:
            break
        page += 1
    return None


def create_veracode_workspace(
    org_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> str | None:
    try:
        existing_id = _find_workspace_by_name(org_name, api_id, api_key, log)
        if existing_id:
            return existing_id

        r = veracode_request("POST", "/srcclr/v3/workspaces", api_id, api_key, json={"name": org_name})
        if r.status_code not in (200, 201):
            log(f"  [ERROR] Failed to create workspace: {r.status_code} - {r.text[:200]}")
            return None

        for _ in range(3):
            workspace_id = _find_workspace_by_name(org_name, api_id, api_key, log)
            if workspace_id:
                return workspace_id
            time.sleep(1)
        log(f"  [ERROR] Workspace created but not found after 3 lookup attempts for: {org_name}")
        return None
    except Exception as exc:
        log(f"  [ERROR] create_veracode_workspace: {exc}")
        return None


def list_veracode_agents(workspace_id: str, api_id: str, api_key: str) -> list[dict[str, Any]] | None:
    try:
        r = veracode_request("GET", f"/srcclr/v3/workspaces/{workspace_id}/agents", api_id, api_key)
        if r.status_code == 200:
            return r.json().get("_embedded", {}).get("agents", [])
        return None
    except Exception:
        return None


def create_veracode_agent_token(
    workspace_id: str,
    org_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> str | None:
    try:
        suffix = "-agt"
        max_org_len = 20 - len(suffix)
        truncated_org = org_name[:max_org_len]
        if not truncated_org or not truncated_org[0].isalpha():
            truncated_org = "gh" + truncated_org[:max_org_len - 2]
        agent_name = f"{truncated_org}{suffix}"

        existing_agents = list_veracode_agents(workspace_id, api_id, api_key)
        if existing_agents is None:
            log(f"  [ERROR] Could not list agents for workspace {workspace_id} - aborting token creation")
            return None

        for agent in existing_agents:
            if agent.get("name") == agent_name:
                agent_id = agent.get("id")
                regen = veracode_request(
                    "POST",
                    f"/srcclr/v3/workspaces/{workspace_id}/agents/{agent_id}/token:regenerate",
                    api_id, api_key,
                )
                if regen.status_code == 200:
                    access_token = regen.json().get("access_token")
                    if access_token:
                        return access_token
                    log("  [ERROR] token:regenerate succeeded but no access_token in response")
                    return None
                log(f"  [ERROR] token:regenerate failed: {regen.status_code} - {regen.text[:200]}")
                return None

        r = veracode_request(
            "POST",
            f"/srcclr/v3/workspaces/{workspace_id}/agents",
            api_id, api_key,
            json={"name": agent_name, "agent_type": "CLI"},
        )
        if r.status_code != 200:
            log(f"  [ERROR] Failed to create agent: {r.status_code} - {r.text[:200]}")
            return None
        if not r.content:
            log("  [ERROR] Agent POST returned empty body")
            return None
        try:
            agent_body = r.json()
        except json.JSONDecodeError:
            log("  [ERROR] Failed to parse agent POST response")
            return None

        access_token = agent_body.get("token", {}).get("access_token")
        if access_token:
            return access_token
        log(f"  [ERROR] Agent created but no token.access_token in response: {agent_body}")
        return None
    except Exception as exc:
        log(f"  [ERROR] create_veracode_agent_token: {exc}")
        return None


# ---------------------------------------------------------------------------
# Veracode Identity API - Team management
# ---------------------------------------------------------------------------

def _find_veracode_team_by_name(
    team_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> str | None:
    page = 0
    while True:
        r = veracode_request(
            "GET", "/api/authn/v2/teams", api_id, api_key,
            params={"all_for_org": "true", "size": 100, "page": page},
        )
        if r.status_code == 401:
            log("  [ERROR] Veracode authentication failed (Identity API) - check credentials")
            return None
        if r.status_code == 403:
            log("  [ERROR] Veracode permission denied (Identity API) - need Administrator role")
            return None
        if r.status_code != 200:
            log(f"  [ERROR] Failed to list teams: {r.status_code} - {r.text[:200]}")
            return None

        body = r.json()
        for team in body.get("_embedded", {}).get("teams", []):
            if team.get("team_name") == team_name:
                tid = team.get("team_id")
                if not tid:
                    log(f"  [WARNING] Team '{team_name}' matched but has no team_id - skipping")
                    continue
                return tid

        page_meta = body.get("page", {})
        total_pages = page_meta.get("total_pages", 1)
        if page >= total_pages - 1:
            break
        page += 1
    return None


def create_veracode_team(
    team_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> str | None:
    try:
        r = veracode_request(
            "POST", "/api/authn/v2/teams", api_id, api_key,
            json={"team_name": team_name},
        )
        if r.status_code in (200, 201):
            body = r.json()
            tid = body.get("team_id")
            if tid:
                return tid
            log(f"  [WARNING] Team POST succeeded but no team_id in response: {str(body)[:200]}")
        elif r.status_code == 409:
            log(f"  [INFO] Team '{team_name}' already exists (409 conflict)")
        else:
            log(f"  [ERROR] Failed to create team '{team_name}': {r.status_code} - {r.text[:200]}")
            return None

        for _ in range(3):
            tid = _find_veracode_team_by_name(team_name, api_id, api_key, log)
            if tid:
                return tid
            time.sleep(1)
        log(f"  [ERROR] Team created/exists but not found after lookup for: {team_name}")
        return None
    except Exception as exc:
        log(f"  [ERROR] create_veracode_team: {exc}")
        return None


def ensure_veracode_team(
    team_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> tuple[str | None, str]:
    existing_id = _find_veracode_team_by_name(team_name, api_id, api_key, log)
    if existing_id:
        return existing_id, "already_exists"

    new_id = create_veracode_team(team_name, api_id, api_key, log)
    if new_id:
        return new_id, "created"
    return None, "error"


# ---------------------------------------------------------------------------
# Veracode SCA API - Team <-> Workspace association
# ---------------------------------------------------------------------------

def add_team_to_workspace(
    workspace_id: str,
    team_id: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> tuple[bool, str]:
    """
    Associate a Veracode team with an SCA agent-based workspace so the team can
    see that workspace's scan results. Idempotent: PUT re-adds cleanly.

    Returns (success, action): 'linked' | 'already_linked' | 'error'.

    PUT /srcclr/v3/workspaces/{id}/teams/{teamId} (SCA Agent API spec, addTeam).
    team_id must be the SCA team id, not the Identity API team_id.
    """
    try:
        r = veracode_request(
            "PUT",
            f"/srcclr/v3/workspaces/{workspace_id}/teams/{team_id}",
            api_id, api_key,
        )
        if r.status_code in (200, 201, 204):
            return True, "linked"
        if r.status_code == 409:
            return True, "already_linked"
        log(f"  [ERROR] Link team {team_id} -> workspace {workspace_id}: "
            f"{r.status_code} - {r.text[:200]}")
        return False, "error"
    except Exception as exc:
        log(f"  [ERROR] add_team_to_workspace: {exc}")
        return False, "error"


def _sca_embedded_items(body: Any, key: str) -> list[dict[str, Any]]:
    """Items of a HAL list response (`_embedded.<key>`), tolerant of key naming."""
    embedded = body.get("_embedded", {}) if isinstance(body, dict) else {}
    items = embedded.get(key)
    if items is None:
        items = next((v for v in embedded.values() if isinstance(v, list)), [])
    return [i for i in items if isinstance(i, dict)]


def _find_sca_team_id(
    team_name: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
    attempts: int = 1,
    wait_seconds: int = 10,
) -> str | None:
    """Resolve the SCA Agent API team id (GET /srcclr/v3/teams?name=...).

    The SCA API uses its own team ids, not the Identity API team_id (UUID), so
    linking must use this id. A team created moments ago may take a short
    time to appear here, hence the optional retries.
    """
    for attempt in range(1, attempts + 1):
        page = 0
        while True:
            r = veracode_request(
                "GET", "/srcclr/v3/teams", api_id, api_key,
                params={"name": team_name, "size": 100, "page": page},
            )
            if r.status_code in (401, 403):
                log(f"  [ERROR] SCA teams lookup denied ({r.status_code}) - check Veracode credentials/roles")
                return None
            if r.status_code != 200:
                log(f"  [ERROR] SCA teams lookup failed: {r.status_code} - {r.text[:200]}")
                return None
            body = r.json()
            for team in _sca_embedded_items(body, "teams"):
                if team.get("name") == team_name and team.get("id") not in (None, ""):
                    return str(team["id"])
            page_meta = body.get("page", {}) if isinstance(body, dict) else {}
            if page >= page_meta.get("total_pages", 1) - 1:
                break
            page += 1
        if attempt < attempts:
            log(f"  [INFO] Team '{team_name}' not visible in SCA yet - retrying in {wait_seconds}s "
                f"({attempt}/{attempts - 1})")
            time.sleep(wait_seconds)
    return None


def _workspace_has_team(
    workspace_id: str,
    sca_team_id: str,
    api_id: str,
    api_key: str,
    log: Callable[[str], None] = tprint,
) -> bool | None:
    """True/False if the workspace already has the team; None if unknown."""
    r = veracode_request("GET", f"/srcclr/v3/workspaces/{workspace_id}/teams", api_id, api_key)
    if r.status_code != 200:
        log(f"  [WARNING] Could not read teams of workspace {workspace_id}: {r.status_code}")
        return None
    return any(str(t.get("id")) == sca_team_id for t in _sca_embedded_items(r.json(), "teams"))


def ensure_team_linked_to_workspace(
    org_name: str,
    team_name: str,
    api_id: str,
    api_key: str,
    workspace_id: str | None = None,
    team_id: str | None = None,
    log: Callable[[str], None] = tprint,
    wait_for_team: bool = False,
) -> tuple[bool, str]:
    """
    Link `team_name` to the SCA workspace named `org_name`. Resolves the
    workspace id by name if it was not captured this run. Creates neither the
    workspace nor the team.

    team_id, if given, must be an SCA Agent API team id. Identity API team ids
    (UUIDs from /api/authn/v2/teams) are rejected by the SCA API with 404, so
    by default the SCA id is resolved by name. wait_for_team retries that
    lookup for a team created moments ago.

    Returns (success, action): 'linked' | 'already_linked' | 'error' |
    'workspace_not_found' | 'team_not_found'.
    """
    if not workspace_id:
        workspace_id = _find_workspace_by_name(org_name, api_id, api_key, log)
        if not workspace_id:
            return False, "workspace_not_found"
    if not team_id:
        team_id = _find_sca_team_id(
            team_name, api_id, api_key, log,
            attempts=4 if wait_for_team else 1,
        )
        if not team_id:
            return False, "team_not_found"
    if _workspace_has_team(workspace_id, team_id, api_id, api_key, log):
        return True, "already_linked"
    return add_team_to_workspace(workspace_id, team_id, api_id, api_key, log)


# ---------------------------------------------------------------------------
# GitHub secrets helpers
# ---------------------------------------------------------------------------

def get_org_public_key(
    api_base: str,
    org: str,
    token: str,
    log: Callable[[str], None] = tprint,
) -> tuple[str, str] | None:
    try:
        r = request("GET", f"{api_base}/orgs/{org}/actions/secrets/public-key", token)
        if r.status_code != 200:
            log(f"  [{org}] Failed to get public key: HTTP {r.status_code}")
            return None
        data = r.json()
        key_id = str(data.get("key_id") or "")
        key = str(data.get("key") or "")
        if not key_id or not key:
            log(f"  [{org}] Public key response missing key_id or key: {data}")
            return None
        return key_id, key
    except Exception as exc:
        log(f"  [{org}] Exception fetching public key: {exc}")
        return None


def encrypt_secret(public_key: str, secret_value: str) -> str:
    from nacl import encoding, public as nacl_public
    pk = nacl_public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = nacl_public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def secret_exists(
    api_base: str,
    org: str,
    token: str,
    secret_name: str,
    log: Callable[[str], None] = tprint,
) -> bool:
    try:
        r = request("GET", f"{api_base}/orgs/{org}/actions/secrets/{secret_name}", token)
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
        if r.status_code == 403:
            log(f"  [{org}] Cannot check secret {secret_name}: token lacks admin:org scope")
            return False
        log(f"  [{org}] Unexpected response checking {secret_name}: {r.status_code}")
        return False
    except Exception as exc:
        log(f"  [{org}] Error checking secret {secret_name}: {exc}")
        return False


def check_veracode_secrets_status(api_base: str, org: str, github_token: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for secret_name in _VERACODE_SECRET_NAMES:
        try:
            r = request("GET", f"{api_base}/orgs/{org}/actions/secrets/{secret_name}", github_token)
            if r.status_code == 200:
                results[secret_name] = "exists"
            elif r.status_code == 403:
                results[secret_name] = "no_permission"
            elif r.status_code == 404:
                results[secret_name] = "missing"
            else:
                results[secret_name] = "error"
        except Exception:
            results[secret_name] = "error"
    return results


def set_veracode_secrets(
    api_base: str,
    org: str,
    github_token: str,
    veracode_sa_api_id: str,
    veracode_sa_api_key: str,
    veracode_agent_token: str,
    log: Callable[[str], None] = tprint,
) -> tuple[bool, dict[str, str]]:
    key_info = get_org_public_key(api_base, org, github_token, log)
    if not key_info:
        log(f"  [{org}] Could not fetch org public key - skipping secrets")
        return False, {s: "failed" for s in _VERACODE_SECRET_NAMES}
    key_id, public_key = key_info

    secrets_to_set = {
        "VERACODE_API_ID": veracode_sa_api_id,
        "VERACODE_API_KEY": veracode_sa_api_key,
        "VERACODE_AGENT_TOKEN": veracode_agent_token,
    }
    results: dict[str, str] = {}
    for secret_name, secret_value in secrets_to_set.items():
        try:
            payload = {
                "encrypted_value": encrypt_secret(public_key, secret_value),
                "key_id": key_id,
                "visibility": "all",
            }
            r = request("PUT", f"{api_base}/orgs/{org}/actions/secrets/{secret_name}", github_token, json=payload)
            ok = r.status_code in (201, 204)
            if not ok:
                log(f"    [ERROR] Secret {secret_name} PUT failed: {r.status_code}")
        except Exception as exc:
            log(f"    [ERROR] Exception setting secret {secret_name}: {exc}")
            ok = False

        if ok:
            time.sleep(0.5)
            verified = secret_exists(api_base, org, github_token, secret_name, log)
            results[secret_name] = "set" if verified else "set_unverified"
        else:
            results[secret_name] = "failed"

    all_ok = all(v.startswith("set") for v in results.values())
    return all_ok, results


# ---------------------------------------------------------------------------
# Default branch helpers
# ---------------------------------------------------------------------------

def get_repo_default_branch(api_base: str, org: str, repo: str, token: str) -> str | None:
    """Return the current default branch name, or None on error."""
    try:
        r = request("GET", f"{api_base}/repos/{org}/{repo}", token)
        if r.status_code == 200:
            return r.json().get("default_branch")
        return None
    except Exception:
        return None


def set_default_branch(
    api_base: str,
    org: str,
    repo: str,
    token: str,
    branch: str = "main",
    log: Callable[[str], None] = tprint,
    current_branch: str | None = None,
) -> tuple[bool, str]:
    """
    Set the default branch for a repo.
    Returns (success, action) where action is one of:
    'already_main', 'set_to_main', 'branch_not_found' (caller should re-import),
    'failed'.
    `current_branch`: pass a already-read default_branch to skip a duplicate GET.
    """
    current = current_branch if current_branch is not None else get_repo_default_branch(api_base, org, repo, token)
    if current is None:
        log(f"  [{org}] Could not read default_branch for {repo}")
        return False, "failed"

    if current == branch:
        return True, "already_main"

    target_exists_r = request("GET", f"{api_base}/repos/{org}/{repo}/branches/{branch}", token)
    if target_exists_r.status_code != 200:
        log(f"  [{org}] Branch '{branch}' does not exist in {repo} - repo needs re-import from upstream")
        return False, "branch_not_found"

    r = request("PATCH", f"{api_base}/repos/{org}/{repo}", token, json={"default_branch": branch})
    if r.status_code == 200:
        log(f"  [{org}] Default branch changed: {current!r} -> {branch!r}")
        return True, "set_to_main"

    if r.status_code == 422:
        body = r.json()
        msg = str(body).lower()
        if "does not exist" in msg or "not found" in msg or "invalid" in msg:
            log(f"  [{org}] Branch '{branch}' does not exist in {repo} - repo needs re-import from upstream")
            return False, "branch_not_found"

    log(f"  [{org}] PATCH default_branch failed: {r.status_code} - {r.text[:200]}")
    return False, "failed"


def check_and_fix_default_branch(
    api_base: str,
    org: str,
    repo: str,
    token: str,
    dry_run: bool = False,
    log: Callable[[str], None] = tprint,
) -> tuple[bool, str]:
    """
    Check if default branch is 'main'; fix it if not (unless dry_run).
    Returns (is_main, action).
    """
    current = get_repo_default_branch(api_base, org, repo, token)
    if current is None:
        return False, "read_failed"
    if current == "main":
        return True, "already_main"
    if dry_run:
        main_r = request("GET", f"{api_base}/repos/{org}/{repo}/branches/main", token)
        if main_r.status_code != 200:
            log(f"  [{org}] Default branch is '{current}' and 'main' does not exist - would re-import in apply mode")
            return False, "branch_not_found"
        log(f"  [{org}] Default branch is '{current}' (not 'main') - would fix in apply mode")
        return False, f"needs_fix:{current}"
    return set_default_branch(api_base, org, repo, token, "main", log, current_branch=current)


# ---------------------------------------------------------------------------
# Repo health check for --fix-repos
# ---------------------------------------------------------------------------

@dataclass
class RepoHealthResult:
    org: str
    repo_exists: bool = False
    repo_empty: bool = False
    default_branch: str | None = None
    default_branch_ok: bool = False
    default_branch_action: str = "not_checked"
    veracode_yml_present: bool = False
    veracode_yml_action: str = "not_checked"
    teams_action: str = "not_checked"
    reimport_action: str = "not_needed"
    needs_remediation: bool = False


def check_repo_health(
    api_base: str,
    org: str,
    repo: str,
    token: str,
    yml_content: str | None,
    teams_value: str | None,
    onboarding_yml_content: str | None,
    dry_run: bool,
    web_base: str = "https://github.com",
    cached_clone_dir: str | None = None,
    log: Callable[[str], None] = tprint,
    include_iac_rbac: bool = False,
) -> RepoHealthResult:
    result = RepoHealthResult(org=org)

    if not repo_exists(api_base, org, repo, token):
        log(f"  [{org}] Repo '{repo}' does not exist - skipping health check")
        return result

    result.repo_exists = True

    if repo_is_empty(api_base, org, repo, token):
        result.repo_empty = True
        log(f"  [{org}] Repo '{repo}' exists but is empty - skipping health checks")
        return result

    # --- Default branch -------------------------------------------------------
    db_ok, db_action = check_and_fix_default_branch(api_base, org, repo, token, dry_run, log)
    # Only re-read when the outcome leaves the branch genuinely unknown.
    if db_action in ("already_main", "set_to_main"):
        result.default_branch = "main"
    elif db_action == "read_failed":
        result.default_branch = None
    else:
        result.default_branch = get_repo_default_branch(api_base, org, repo, token)
    result.default_branch_ok = db_ok
    result.default_branch_action = db_action
    if not db_ok:
        result.needs_remediation = True

    # --- Re-import trigger: main missing OR workflow files missing -----------
    needs_reimport = db_action == "branch_not_found"

    if not needs_reimport:
        sandbox_url = f"{api_base}/repos/{org}/{repo}/contents/.github/workflows/veracode-sandbox-scan.yml"
        policy_url = f"{api_base}/repos/{org}/{repo}/contents/.github/workflows/veracode-policy-scan.yml"
        sandbox_r = request("GET", sandbox_url, token, params={"ref": "main"})
        policy_r = request("GET", policy_url, token, params={"ref": "main"})
        if sandbox_r.status_code != 200 and policy_r.status_code != 200:
            log(f"  [{org}] Workflow files missing on 'main' - triggering re-import from upstream")
            needs_reimport = True

    if needs_reimport:
        result.needs_remediation = True
        if dry_run:
            result.reimport_action = "would_reimport"
            log(f"  [{org}] Would re-import {repo} from upstream in apply mode")
        elif not check_git_available():
            result.reimport_action = "git_not_available"
            log(f"  [{org}] Git CLI not available - cannot re-import")
        else:
            ok, msg = git_mirror_import(
                INTEGRATION_SOURCE_URL, org, repo, token, web_base, cached_clone_dir,
            )
            if not ok:
                result.reimport_action = f"failed:{msg[:120]}"
                log(f"  [{org}] Re-import failed: {msg[:200]}")
                return result

            log(f"  [{org}] Re-import push succeeded - waiting for GitHub to publish 'main'...")
            if not wait_for_main_branch(api_base, org, repo, token, log=log):
                result.reimport_action = "reimport_main_not_visible"
                log(f"  [{org}] 'main' branch not visible after re-import - re-run later")
                return result

            db_ok, db_action = set_default_branch(api_base, org, repo, token, "main", log)
            if db_action in ("already_main", "set_to_main"):
                result.default_branch = "main"
            else:
                result.default_branch = get_repo_default_branch(api_base, org, repo, token)
            result.default_branch_ok = db_ok
            result.default_branch_action = db_action
            result.reimport_action = "reimported"
            log(f"  [{org}] Re-import complete; default branch action: {db_action}")

    # --- veracode.yml presence ------------------------------------------------
    yml_url = f"{api_base}/repos/{org}/{repo}/contents/veracode.yml"
    r = request("GET", yml_url, token, params={"ref": "main"})
    result.veracode_yml_present = r.status_code == 200

    effective_yml = yml_content or onboarding_yml_content
    if not result.veracode_yml_present and effective_yml:
        result.needs_remediation = True
        if not dry_run:
            yml_ok, yml_action = _put_veracode_yml_with_backup(
                api_base, org, repo, token, effective_yml,
                update_message="Add missing veracode.yml during fix-repos remediation",
                preread=r,
            )
            result.veracode_yml_action = yml_action if yml_ok else f"failed:{yml_action}"
            log(f"  [{org}] veracode.yml: {result.veracode_yml_action}")
        else:
            result.veracode_yml_action = "missing_would_add"
            log(f"  [{org}] veracode.yml missing - would add in apply mode")
    elif result.veracode_yml_present and yml_content and not dry_run:
        yml_ok, yml_action = _put_veracode_yml_with_backup(
            api_base, org, repo, token, yml_content,
            update_message="Update veracode.yml during fix-repos remediation",
            preread=r,
        )
        result.veracode_yml_action = yml_action if yml_ok else f"failed:{yml_action}"
    else:
        result.veracode_yml_action = "present_no_update" if result.veracode_yml_present else "missing_no_template"

    # --- Teams injection -------------------------------------------------------
    if teams_value:
        if not dry_run:
            teams_ok, teams_msg = inject_teams_into_workflows(
                api_base, org, repo, token, teams_value,
                update_existing=True,
                log=log,
                include_iac_rbac=include_iac_rbac,
            )
            result.teams_action = teams_msg
            if not teams_ok and teams_msg not in ("no_workflow_files_found", "teams_already_current"):
                result.needs_remediation = True
        else:
            result.teams_action = "would_check_teams"
    else:
        result.teams_action = "no_teams_configured"

    return result


# ---------------------------------------------------------------------------
# Workflow file injection
# ---------------------------------------------------------------------------

def _inject_teams_regex(content: str, teams_value: str) -> tuple[str, bool]:
    changed = False

    def replacer(m: re.Match) -> str:
        nonlocal changed
        header, body = m.group(1), m.group(2)
        if _TEAMS_ALREADY_SET_RE.search(body):
            return m.group(0)
        first_param = body.splitlines()[0]
        indent = len(first_param) - len(first_param.lstrip())
        changed = True
        safe_value = teams_value.replace('"', '\\"')
        return header + " " * indent + f'teams: "{safe_value}"\n' + body

    return _TEAMS_INJECT_RE.sub(replacer, content), changed


def _update_teams_value(content: str, teams_value: str) -> tuple[str, bool]:
    safe_value = teams_value.replace('"', '\\"')
    changed = False

    def replacer(m: re.Match) -> str:
        nonlocal changed
        prefix = m.group(1)
        current_value = m.group(2).strip()
        if current_value == teams_value or current_value == safe_value:
            return m.group(0)
        changed = True
        return f'{prefix}"{safe_value}"'

    new_content = _TEAMS_VALUE_RE.sub(replacer, content)
    return new_content, changed


# ---------------------------------------------------------------------------
# IaC/Secrets workflow: Veracode CLI with RBAC (--app-name/--create-app/--teams)
# ---------------------------------------------------------------------------
# The upstream workflow runs veracode/container_iac_secrets_scanning, which has
# no way to link results to an application profile. RBAC for container and IaC
# scans needs `veracode scan --app-name ... --create-app --teams ...` (CLI
# 2.55.0+), so the action step is replaced with the CLI step block below. The
# block is identical to the one in the reference
# .github/workflows/veracode-iac-secrets-scan.yml shipped with this script.

IAC_WORKFLOW_PATH = ".github/workflows/veracode-iac-secrets-scan.yml"
_IAC_RBAC_MARKER = "# veracode-iac-rbac"
_IAC_BLOCK_INDENT = 6
_IAC_TEAMS_PLACEHOLDER = '          VERACODE_TEAMS: ""\n'
_IAC_ACTION_USES_RE = re.compile(
    r"^(?P<lead>[ \t]*(?:-[ \t]+)?)uses:[ \t]*[\"']?veracode/container_iac_secrets_scanning@",
    re.IGNORECASE,
)
_YAML_ITEM_RE = re.compile(r"^(?P<indent>[ \t]*)-(?:[ \t]|$)")
_IAC_TEAMS_LINE_RE = re.compile(r"^(?P<prefix>[ \t]+VERACODE_TEAMS:[ \t]*)(?P<value>[^\n]*?)[ \t]*$", re.MULTILINE)

_IAC_RBAC_STEP_BLOCK = r"""      # veracode-iac-rbac (managed by Workflow-App-Bulk-Enterprise-Integration script.py)
      # Runs the Veracode CLI directly instead of veracode/container_iac_secrets_scanning so
      # IaC/secrets results are linked to the application profile and its teams (RBAC).
      # Requires Veracode CLI 2.55.0 or later; the latest CLI is installed on every run.
      - name: Run Veracode IaC/Secrets Scanning
        id: veracode_iac_scan
        shell: bash
        env:
          VERACODE_API_KEY_ID: ${{ secrets.VERACODE_API_ID }}
          VERACODE_API_KEY_SECRET: ${{ secrets.VERACODE_API_KEY }}
          # Application profile used by the static and SCA scans (default: <org>/<repo>).
          VERACODE_APP_NAME: ${{ github.event.client_payload.user_config.profile_name || github.event.client_payload.repository.full_name }}
          # Comma-separated Veracode team names. Empty: the profile is assigned to all teams of the API user.
          VERACODE_TEAMS: ""
          VERACODE_POLICY: ${{ github.event.client_payload.policy_name }}
          FAIL_BUILD: ${{ github.event.client_payload.user_config.break_build_policy_findings }}
          FAIL_BUILD_ON_ERROR: ${{ github.event.client_payload.user_config.break_build_on_error }}
          DEBUG: ${{ github.event.client_payload.user_config.debug }}
          MIN_CLI_VERSION: "2.55.0"
        run: |
          # GitHub runs bash with -e; exit codes are handled explicitly below.
          set +e
          set -uo pipefail

          lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
          is_true() { [ "$(lower "${1:-}")" = "true" ]; }
          trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
          esc() { local s="$1"; s="${s//%/%25}"; s="${s//$'\r'/%0D}"; s="${s//$'\n'/%0A}"; printf '%s' "$s"; }
          debug() { if is_true "${DEBUG:-false}"; then echo "[debug] $*"; fi; }

          SCAN_ERROR=false
          POLICY_EXIT_FAILED=false
          POLICY_FAILED=false
          scan_error() { echo "::error::$(esc "$1")"; SCAN_ERROR=true; }

          # Same encoding as the action (JavaScript encodeURIComponent).
          urlencode() {
            local LC_ALL=C
            local s="$1" out="" c i
            for (( i = 0; i < ${#s}; i++ )); do
              c="${s:i:1}"
              case "$c" in
                [A-Za-z0-9_.~*\'\(\)!-]) out="$out$c" ;;
                *) printf -v c '%%%02X' "'$c"; out="$out$c" ;;
              esac
            done
            printf '%s' "$out"
          }

          # Returns 0 when version $1 >= version $2 (major.minor.patch).
          version_ge() {
            local a b i x y
            IFS=. read -r -a a <<< "$1"
            IFS=. read -r -a b <<< "$2"
            for i in 0 1 2; do
              x="${a[i]:-0}"; y="${b[i]:-0}"
              x="${x%%[!0-9]*}"; y="${y%%[!0-9]*}"
              x="${x:-0}"; y="${y:-0}"
              if (( 10#$x > 10#$y )); then return 0; fi
              if (( 10#$x < 10#$y )); then return 1; fi
            done
            return 0
          }

          native_path() {
            if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
          }

          BASE_DIR="$(native_path "${RUNNER_TEMP:-${TMPDIR:-/tmp}}")"
          RESULTS_DIR="$BASE_DIR/veracode-iac-results"
          POLICY_DIR="$BASE_DIR/veracode-iac-policy"
          CACHE_DIR="$BASE_DIR/veracode-iac-cache"
          rm -rf "$RESULTS_DIR" "$POLICY_DIR" "$CACHE_DIR"
          mkdir -p "$RESULTS_DIR" "$POLICY_DIR" "$CACHE_DIR"

          # --- Install the Veracode CLI (same source as the action) -------------------
          if [ "${RUNNER_OS:-}" = "Windows" ]; then
            powershell.exe -NoProfile -Command "Set-ExecutionPolicy AllSigned -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://tools.veracode.com/veracode-cli/install.ps1'))"
            CLI="$(native_path "${APPDATA:-}")/veracode/veracode.exe"
          else
            CLI_DIR="$BASE_DIR/veracode-cli"
            rm -rf "$CLI_DIR"
            mkdir -p "$CLI_DIR"
            (cd "$CLI_DIR" && curl -fsS https://tools.veracode.com/veracode-cli/install | sh)
            CLI="$CLI_DIR/veracode"
          fi
          if [ ! -f "$CLI" ]; then
            echo "::error::Veracode CLI installation failed: $(esc "$CLI") not found."
            exit 1
          fi

          CLI_VERSION="$("$CLI" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
          CLI_VERSION="${CLI_VERSION#v}"
          echo "Veracode CLI version: ${CLI_VERSION:-unknown}"
          if [ -z "$CLI_VERSION" ] || ! version_ge "$CLI_VERSION" "$MIN_CLI_VERSION"; then
            echo "::error::Veracode CLI ${CLI_VERSION:-unknown} does not support --app-name/--create-app/--teams. Version $MIN_CLI_VERSION or later is required."
            exit 1
          fi

          # --- RBAC: link the scan to the application profile and its teams ----------
          APP_NAME="$(trim "${VERACODE_APP_NAME:-}")"
          TEAMS="$(printf '%s' "${VERACODE_TEAMS:-}" | tr -d '\r\n' | sed -e 's/[[:space:]]*,[[:space:]]*/,/g' -e 's/,,*/,/g' -e 's/^[[:space:]]*,*//' -e 's/,*[[:space:]]*$//')"
          rbac_args=()
          if [ -n "$APP_NAME" ]; then
            rbac_args=(--app-name "$APP_NAME" --create-app)
            if [ -n "$TEAMS" ]; then
              rbac_args+=(--teams "$TEAMS")
            fi
            echo "Application profile: $APP_NAME"
            echo "Teams: ${TEAMS:-<none: all teams of the API user>}"
          else
            echo "::warning::No application profile name available; results will only be visible to Security Leads."
          fi

          # --- Policy (same handling as the action) -----------------------------------
          POLICY="$(trim "${VERACODE_POLICY:-}")"
          policy_args=()
          POLICY_FILE=""
          if [ -n "$POLICY" ]; then
            ENCODED_POLICY="$(urlencode "$POLICY")"
            debug "Policy command: veracode policy get $ENCODED_POLICY"
            if ! (cd "$POLICY_DIR" && "$CLI" policy get "$ENCODED_POLICY"); then
              echo "::error::Failed to download policy $(esc "$POLICY")"
              exit 1
            fi
            if [ -f "$POLICY_DIR/$POLICY.rego" ]; then
              POLICY_FILE="$POLICY_DIR/$POLICY.rego"
            elif [ -f "$POLICY_DIR/$ENCODED_POLICY.rego" ]; then
              POLICY_FILE="$POLICY_DIR/$ENCODED_POLICY.rego"
            else
              echo "::warning::No matching IaC rules available in policy $(esc "$POLICY"). Proceeding without policy evaluation."
            fi
            if [ -n "$POLICY_FILE" ]; then
              policy_args=(--policy "$POLICY_FILE")
            fi
          fi

          # Exit code 3 = scan completed but did not pass policy. Anything else non-zero is an error.
          # --create-app creates the profile on the first scan and links to it when it already exists.
          run_scan() {
            local label="$1"; shift
            echo "Running: veracode $* ${rbac_args[*]-}"
            "$CLI" "$@" ${rbac_args[@]+"${rbac_args[@]}"}
            local rc=$?
            debug "$label exit code: $rc"
            if [ "$rc" -eq 3 ]; then
              POLICY_EXIT_FAILED=true
            elif [ "$rc" -ne 0 ]; then
              scan_error "Veracode CLI scan failed. Exit code: $rc, Command: veracode $*"
            fi
          }
          run_cli() {
            echo "Running: veracode $*"
            "$CLI" "$@"
            local rc=$?
            if [ "$rc" -ne 0 ]; then
              scan_error "Veracode CLI command failed. Exit code: $rc, Command: veracode $*"
            fi
          }

          # --- Scans --------------------------------------------------------------------
          run_scan "json" scan --source ./ --type directory --format json --output "$RESULTS_DIR/results.json" --temp "$CACHE_DIR" ${policy_args[@]+"${policy_args[@]}"}
          run_scan "table" scan --source ./ --type directory --format table --output "$RESULTS_DIR/results.txt" --temp "$CACHE_DIR" ${policy_args[@]+"${policy_args[@]}"}

          for sbom in "cyclonedx-xml:sbom_cyclonedx_xml.xml" "cyclonedx-json:sbom_cyclonedx_json.json" "spdx-tag-value:sbom_spdx_tag_value.json" "spdx-json:sbom_spdx_json.json" "github:sbom_github.json"; do
            run_cli sbom --source ./ --type directory --format "${sbom%%:*}" --output "$RESULTS_DIR/${sbom#*:}"
          done

          # --- Results ------------------------------------------------------------------
          if [ -f "$RESULTS_DIR/results.txt" ]; then
            echo "Veracode Container/IaC/Secrets Scan Summary"
            cat "$RESULTS_DIR/results.txt"
          else
            scan_error "Unable to locate scan results file: results.txt"
          fi

          if is_true "${FAIL_BUILD:-false}"; then
            if [ "$POLICY_EXIT_FAILED" = true ]; then
              POLICY_FAILED=true
            elif [ -f "$RESULTS_DIR/results.txt" ]; then
              if [ -n "$POLICY_FILE" ]; then
                if grep -Eq '^[[:space:]]+Failed[[:space:]]+│|│[[:space:]]+Failed[[:space:]]+│' "$RESULTS_DIR/results.txt"; then POLICY_FAILED=true; fi
              else
                if grep -Fq 'Policy Passed = false' "$RESULTS_DIR/results.txt"; then POLICY_FAILED=true; fi
              fi
            fi
          fi

          EXIT_CODE=0
          if [ "$POLICY_FAILED" = true ]; then
            echo "::error::Veracode Container Scanning failed"
            EXIT_CODE=1
          elif is_true "${FAIL_BUILD:-false}"; then
            echo "Veracode Container Scanning passed"
          fi
          if [ "$SCAN_ERROR" = true ] && is_true "${FAIL_BUILD_ON_ERROR:-false}"; then
            echo "Note: Build failed due to break_build_on_error flag being set to true."
            EXIT_CODE=1
          fi
          exit "$EXIT_CODE"

      # Upload problems never fail the job (same as the action, which ignored upload errors).
      - name: Store Veracode IaC/Secrets Scanning results
        if: ${{ !cancelled() }}
        continue-on-error: true
        uses: actions/upload-artifact@v7
        with:
          name: Veracode Container IaC Secrets Scanning Results
          path: ${{ runner.temp }}/veracode-iac-results/
          if-no-files-found: ignore
"""


def _yaml_dq(value: str) -> str:
    """YAML double-quoted scalar."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _yaml_scalar_value(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1].replace("''", "'")
    return raw


def normalize_teams_for_cli(teams_value: str) -> str:
    """CLI --teams wants comma-separated names with no spaces around the commas."""
    parts = [p.strip() for p in teams_value.replace("\r", "").replace("\n", "").split(",")]
    return ",".join(p for p in parts if p)


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _render_iac_block(teams_value: str, item_indent: int) -> str:
    block = _IAC_RBAC_STEP_BLOCK.replace(
        _IAC_TEAMS_PLACEHOLDER,
        f"          VERACODE_TEAMS: {_yaml_dq(normalize_teams_for_cli(teams_value))}\n",
        1,
    )
    delta = item_indent - _IAC_BLOCK_INDENT
    if delta == 0:
        return block
    out: list[str] = []
    for line in block.splitlines(keepends=True):
        if not line.strip():
            out.append(line)
        elif delta > 0:
            out.append(" " * delta + line)
        else:
            out.append(line[min(-delta, _indent_of(line)):])
    return "".join(out)


def _replace_iac_action_step(content: str, teams_value: str) -> tuple[str, bool]:
    """Replace the veracode/container_iac_secrets_scanning step with the CLI block.

    Returns (content, changed). Leaves the content untouched when the action
    step is not found or the surrounding YAML is not shaped as expected.
    """
    lines = content.splitlines(keepends=True)
    uses_idx = next((i for i, ln in enumerate(lines) if _IAC_ACTION_USES_RE.match(ln)), None)
    if uses_idx is None:
        return content, False

    uses_line = lines[uses_idx]
    item_m = _YAML_ITEM_RE.match(uses_line)
    if item_m:
        start, item_indent = uses_idx, len(item_m.group("indent"))
    else:
        key_indent = _indent_of(uses_line)
        start = -1
        item_indent = -1
        for i in range(uses_idx - 1, -1, -1):
            ln = lines[i]
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            m = _YAML_ITEM_RE.match(ln)
            if m and len(m.group("indent")) < key_indent:
                start, item_indent = i, len(m.group("indent"))
                break
            if _indent_of(ln) < key_indent:
                return content, False
        if start < 0:
            return content, False

    end = start + 1
    last_content = start
    while end < len(lines):
        ln = lines[end]
        if ln.strip():
            if _indent_of(ln) <= item_indent:
                break
            last_content = end
        end += 1
    end = last_content + 1

    rest = "".join(lines[end:])
    before = "".join(lines[:start])
    block = _render_iac_block(teams_value, item_indent)
    # Keep a blank line between the block and whatever followed the old step.
    sep = "\n" if rest and rest.split("\n", 1)[0].strip() else ""
    return before + block + sep + rest, True


def _update_iac_teams_value(content: str, teams_value: str, update_existing: bool) -> tuple[str, bool]:
    desired = normalize_teams_for_cli(teams_value)
    changed = False

    def replacer(m: re.Match) -> str:
        nonlocal changed
        current = _yaml_scalar_value(m.group("value"))
        if current == desired:
            return m.group(0)
        if current and not update_existing:
            return m.group(0)
        changed = True
        return m.group("prefix") + _yaml_dq(desired)

    return _IAC_TEAMS_LINE_RE.sub(replacer, content, count=1), changed


def apply_iac_rbac(content: str, teams_value: str, update_existing: bool = True) -> tuple[str, bool, str]:
    """Convert the IaC workflow to the CLI-with-RBAC step and/or set its teams.

    Returns (content, changed, action) where action is one of:
    converted, teams_updated, already_current, action_step_not_found.
    """
    if _IAC_RBAC_MARKER in content:
        new_content, changed = _update_iac_teams_value(content, teams_value, update_existing)
        return new_content, changed, "teams_updated" if changed else "already_current"
    new_content, converted = _replace_iac_action_step(content, teams_value)
    if converted:
        return new_content, True, "converted"
    return content, False, "action_step_not_found"


def _apply_teams_to_workflow(
    workflow_path: str, content: str, teams_value: str, update_existing: bool,
) -> tuple[str, bool, str]:
    """Return (new_content, changed, action) for one workflow file."""
    if workflow_path == IAC_WORKFLOW_PATH:
        return apply_iac_rbac(content, teams_value, update_existing)
    new_content, was_injected = _inject_teams_regex(content, teams_value)
    was_updated = False
    if update_existing:
        new_content, was_updated = _update_teams_value(new_content, teams_value)
    changed = was_injected or was_updated
    return new_content, changed, ("teams_updated" if changed else "already_current")


def inject_teams_into_workflows(
    api_base: str, org: str, repo: str, token: str, teams_value: str,
    update_existing: bool = False,
    log: Callable[[str], None] = tprint,
    include_iac_rbac: bool = False,
    file_actions: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Inject/update teams in the policy and sandbox scan workflows and, with
    include_iac_rbac, convert the IaC/Secrets workflow to the Veracode CLI with
    RBAC (--app-name/--create-app/--teams) and keep its teams in sync.

    file_actions, when given, receives a per-file action for the report.
    """
    workflow_files = [
        ".github/workflows/veracode-sandbox-scan.yml",
        ".github/workflows/veracode-policy-scan.yml",
    ]
    if include_iac_rbac:
        workflow_files.append(IAC_WORKFLOW_PATH)
    modified_count = 0
    files_checked = 0

    def record(path: str, action: str) -> None:
        if file_actions is not None:
            file_actions[path.split("/")[-1]] = action

    for workflow_path in workflow_files:
        file_name = workflow_path.split("/")[-1]
        url = f"{api_base}/repos/{org}/{repo}/contents/{workflow_path}"
        r = request("GET", url, token, params={"ref": "main"})
        if r.status_code != 200:
            record(workflow_path, "not_found")
            continue

        files_checked += 1
        file_data = r.json()
        sha = file_data.get("sha")
        raw_content = b64decode(file_data.get("content", "")).decode("utf-8")

        try:
            new_content, changed, action = _apply_teams_to_workflow(
                workflow_path, raw_content, teams_value, update_existing,
            )
            if not changed:
                if action == "action_step_not_found":
                    log(f"  [{org}] {file_name}: veracode/container_iac_secrets_scanning step not found - "
                        f"IaC RBAC not applied, manual review needed.")
                record(workflow_path, action)
                continue

        except Exception as exc:
            log(f"  [{org}] Regex injection error for {workflow_path}: {exc}")
            record(workflow_path, f"error:{exc}")
            continue

        if action == "converted":
            message = f"Convert {file_name} to Veracode CLI with RBAC (app profile and teams)"
        else:
            message = f"Update teams parameter in {file_name}"
        payload = {
            "message": message,
            "content": b64encode(new_content.encode("utf-8")).decode("utf-8"),
            "sha": sha,
            "branch": "main",
        }
        r = request("PUT", url, token, json=payload)

        if r.status_code == 409:
            # Stale sha race: re-fetch and retry once with fresh sha.
            log(f"  [{org}] PUT {workflow_path} returned 409 (stale sha) - refetching and retrying")
            r_refetch = request("GET", url, token, params={"ref": "main"})
            if r_refetch.status_code == 200:
                fresh_sha = r_refetch.json().get("sha")
                fresh_content = b64decode(r_refetch.json().get("content", "")).decode("utf-8")
                fresh_new, _, _ = _apply_teams_to_workflow(
                    workflow_path, fresh_content, teams_value, update_existing,
                )
                payload["sha"] = fresh_sha
                payload["content"] = b64encode(fresh_new.encode("utf-8")).decode("utf-8")
                r = request("PUT", url, token, json=payload)

        if r.status_code in (200, 201):
            modified_count += 1
            record(workflow_path, action)
            if action == "converted":
                log(f"  [{org}] {file_name}: converted to Veracode CLI with RBAC "
                    f"(teams: {normalize_teams_for_cli(teams_value) or 'none'})")
        elif r.status_code == 409:
            record(workflow_path, "failed:409")
            log(f"  [{org}] {workflow_path} on main: 409 conflict after retry. "
                f"Likely a branch protection rule requires PRs - manual fix needed.")
        elif r.status_code == 422 and "protected branch" in r.text.lower():
            record(workflow_path, "failed:protected_branch")
            log(f"  [{org}] {workflow_path} on main: protected branch - direct push rejected. "
                f"Manual fix or PR required.")
        else:
            record(workflow_path, f"failed:{r.status_code}")
            log(f"  [{org}] Failed to update {workflow_path} on main: {r.status_code} {r.text[:200]}")

    if modified_count > 0:
        return True, f"teams_updated_{modified_count}_files"
    if files_checked == 0:
        return False, "no_workflow_files_found"
    return True, "teams_already_current"


# ---------------------------------------------------------------------------
# veracode.yml helpers
# ---------------------------------------------------------------------------

def _put_veracode_yml_with_backup(
    api_base: str,
    org: str,
    repo: str,
    token: str,
    yml_content: str,
    update_message: str = "Update veracode.yml with new configuration",
    preread: requests.Response | None = None,
) -> tuple[bool, str]:
    """`preread`: reuse an existing GET of this same URL at ref=main (its sha is
    used for the update). Only valid if no write happened in between."""
    veracode_url = f"{api_base}/repos/{org}/{repo}/contents/veracode.yml"
    default_veracode_url = f"{api_base}/repos/{org}/{repo}/contents/default-veracode.yml"

    r = preread if preread is not None else request("GET", veracode_url, token, params={"ref": "main"})
    if r.status_code == 200:
        original_data = r.json()
        original_sha = original_data.get("sha")
        original_content_b64 = original_data.get("content", "")

        r_default = request("GET", default_veracode_url, token, params={"ref": "main"})
        backup_payload: dict[str, Any] = {
            "message": "Preserve current veracode.yml as default-veracode.yml before update",
            "content": original_content_b64,
            "branch": "main",
        }
        if r_default.status_code == 200:
            backup_payload["sha"] = r_default.json().get("sha")
        request("PUT", default_veracode_url, token, json=backup_payload)

        r_put = request("PUT", veracode_url, token, json={
            "message": update_message,
            "content": b64encode(yml_content.encode("utf-8")).decode("utf-8"),
            "branch": "main",
            "sha": original_sha,
        })
        return (True, "updated_with_backup") if r_put.status_code in (200, 201) else (False, f"put_failed:{r_put.status_code}")

    if r.status_code == 404:
        r_put = request("PUT", veracode_url, token, json={
            "message": "Add veracode.yml configuration",
            "content": b64encode(yml_content.encode("utf-8")).decode("utf-8"),
            "branch": "main",
        })
        return (True, "created") if r_put.status_code in (200, 201) else (False, f"put_failed:{r_put.status_code}")

    return False, f"get_failed:{r.status_code}"


def fetch_upstream_veracode_yml() -> str | None:
    url = (
        f"https://raw.githubusercontent.com/"
        f"{INTEGRATION_SOURCE_URL.removeprefix('https://github.com/').removesuffix('.git')}"
        f"/main/veracode.yml"
    )
    # Different host, own budget: not routed through the GitHub limiter.
    for attempt in range(3):
        try:
            r = _session().get(url, timeout=30)
            if r.status_code == 200:
                return r.text
            if r.status_code == 429:
                wait = parse_retry_after(r.headers)
                print(f"  [WARNING] Upstream rate limited (429), waiting {wait}s, attempt {attempt + 1}/3", file=sys.stderr)
                if attempt < 2:
                    time.sleep(min(wait, _MAX_BACKOFF_SLEEP_SECONDS) + random.uniform(0, 2))
                continue
            if r.status_code < 500:
                print(f"  [ERROR] Failed to fetch upstream veracode.yml: HTTP {r.status_code}", file=sys.stderr)
                return None
            print(f"  [WARNING] Upstream returned {r.status_code}, attempt {attempt + 1}/3", file=sys.stderr)
            if attempt < 2:
                time.sleep(_fault_backoff(attempt))
        except requests.exceptions.RequestException as exc:
            print(f"  [WARNING] Network error fetching upstream veracode.yml: {exc}, attempt {attempt + 1}/3", file=sys.stderr)
            if attempt < 2:
                time.sleep(_fault_backoff(attempt))
    print("  [ERROR] Failed to fetch upstream veracode.yml after 3 attempts", file=sys.stderr)
    return None


def inject_veracode_yml(
    api_base: str, org: str, repo: str, token: str, yml_content: str | None,
    log: Callable[[str], None] = tprint,
) -> tuple[bool, str]:
    if yml_content is None:
        log(f"  [{org}] Warning: veracode.yml not found next to script, skipping injection")
        return False, "template_not_found"
    return _put_veracode_yml_with_backup(
        api_base, org, repo, token, yml_content,
        update_message="Update Veracode workflow configuration with custom settings",
    )


def update_veracode_yml_in_repo(
    api_base: str,
    org: str,
    repo: str,
    token: str,
    yml_content: str,
    repo_is_known_present: bool = False,
    log: Callable[[str], None] = tprint,
) -> tuple[bool, str]:
    if not repo_is_known_present:
        if not repo_exists(api_base, org, repo, token):
            log(f"  [{org}] Skipping veracode.yml update - repo '{repo}' not found")
            return False, "repo_not_found"
        if repo_is_empty(api_base, org, repo, token):
            log(f"  [{org}] Skipping veracode.yml update - repo '{repo}' is empty (not yet imported)")
            return False, "repo_empty"
    return _put_veracode_yml_with_backup(api_base, org, repo, token, yml_content)


# ---------------------------------------------------------------------------
# Org discovery
# ---------------------------------------------------------------------------

# GitHub kills any GraphQL request that takes >10s server-side and returns
# 502/504 "We couldn't respond to your request in time" (and bills extra
# points for it). A timed-out page is retried from the SAME cursor with a
# halved page size, so progress is never lost and a large enterprise degrades
# to smaller pages instead of failing discovery.
_ORG_PAGE_SIZE_DEFAULT = 100          # GraphQL max for first/last
_ORG_PAGE_SIZE_MIN = 5
_ORG_PAGE_MAX_ATTEMPTS = 8            # consecutive failures on one page before giving up
_GRAPHQL_TIMEOUT_MARKERS = ("couldn't respond to your request in time", "timeout", "timedout")


class OrgDiscoveryError(RuntimeError):
    """Org discovery failed in a way that is not 'slug wrong / no orgs'."""


def _warn_if_discovery_incomplete(
    found: int,
    hidden: int,
    duplicates: int,
    total_first: int | None,
    total_last: int | None,
) -> None:
    """Compare what pagination returned with GitHub's organizations.totalCount
    and warn (never stop) if the list cannot be verified as complete."""
    problems: list[str] = []
    if total_first is None or total_last is None:
        problems.append("GitHub did not return organizations.totalCount, so completeness "
                        "cannot be verified")
    else:
        if total_first != total_last:
            problems.append(f"totalCount changed during pagination ({total_first} -> "
                            f"{total_last}); orgs were added or removed mid-run")
        if found + hidden != total_last:
            problems.append(f"GitHub reports totalCount={total_last} but pagination returned "
                            f"{found} visible + {hidden} hidden = {found + hidden}")
    if duplicates:
        problems.append(f"{duplicates} duplicate org(s) seen across pages (list shifted "
                        f"during pagination)")
    if hidden:
        problems.append(f"{hidden} org(s) are hidden from this token (usually SAML SSO not "
                        f"authorized for the PAT on those orgs) and will NOT be processed")

    if not problems:
        tprint(f"[OK] Discovery verified complete: {found} orgs == totalCount {total_last}")
        return
    tprint("  [WARNING] Org discovery could not be verified as complete:\n"
           + "\n".join(f"    - {p}" for p in problems))
    tprint("  [WARNING] Orgs not in the discovered list are out of scope for this run. "
           "Re-run, or review out/orgs.txt and use --orgs-file.")


def graphql_url_for(api_base: str) -> str:
    """GitHub.com: api.github.com/graphql. GHES: https://HOST/api/graphql
    (NOT /api/v3/graphql). GHE.com data residency: api.SUB.ghe.com/graphql."""
    base = api_base.rstrip("/")
    if "api.github.com" in base:
        return "https://api.github.com/graphql"
    if base.endswith("/api/v3"):
        return base[: -len("/v3")] + "/graphql"
    return f"{base}/graphql"


def _looks_like_graphql_timeout(errors: list[Any]) -> bool:
    for e in errors:
        text = f"{(e or {}).get('type', '')} {(e or {}).get('message', '')}".lower()
        if any(m in text for m in _GRAPHQL_TIMEOUT_MARKERS):
            return True
    return False


def list_orgs_graphql(
    api_base: str,
    token: str,
    enterprise: str,
    page_size: int = _ORG_PAGE_SIZE_DEFAULT,
) -> list[str] | None:
    """Return all org logins in the enterprise.

    After pagination the result is checked against GitHub's totalCount and a
    warning is printed if it cannot be verified complete.

    Returns None only when GitHub says the enterprise is not visible (wrong
    slug or missing read:enterprise). Raises OrgDiscoveryError on timeouts or
    other failures that persist after adaptive retries.
    """
    graphql_url = graphql_url_for(api_base)
    query = """
    query($enterprise: String!, $first: Int!, $cursor: String) {
      enterprise(slug: $enterprise) {
        organizations(first: $first, after: $cursor) {
          totalCount
          nodes { login }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
    """
    page_size = max(_ORG_PAGE_SIZE_MIN, min(int(page_size), _ORG_PAGE_SIZE_DEFAULT))
    all_orgs: list[str] = []
    seen: set[str] = set()
    skipped_null = 0
    duplicates = 0
    total_first: int | None = None
    total_last: int | None = None
    cursor: str | None = None
    attempts = 0
    page_no = 0

    def fail_or_backoff(reason: str, shrink: bool) -> None:
        nonlocal attempts, page_size
        attempts += 1
        if attempts >= _ORG_PAGE_MAX_ATTEMPTS:
            raise OrgDiscoveryError(
                f"Enterprise org discovery failed on page {page_no + 1} after {attempts} attempts "
                f"(last: {reason}; page size {page_size}; {len(all_orgs)} orgs fetched so far). "
                f"Retry later, or pass --orgs-file to bypass discovery."
            )
        if shrink and page_size > _ORG_PAGE_SIZE_MIN:
            new_size = max(_ORG_PAGE_SIZE_MIN, page_size // 2)
            tprint(f"  [GRAPHQL] {reason} at page size {page_size}; retrying same page "
                   f"with page size {new_size} (attempt {attempts + 1}/{_ORG_PAGE_MAX_ATTEMPTS})")
            page_size = new_size
        else:
            tprint(f"  [GRAPHQL] {reason}; retrying same page "
                   f"(attempt {attempts + 1}/{_ORG_PAGE_MAX_ATTEMPTS})")
        time.sleep(_fault_backoff(min(attempts - 1, 4)))

    while True:
        variables: dict[str, Any] = {"enterprise": enterprise, "first": page_size}
        if cursor:
            variables["cursor"] = cursor
        try:
            # max_retries=1: 5xx is handled here so a timed-out page is not
            # re-sent at the same size (each timeout costs extra points).
            # 403/429 rate limits are still retried inside request().
            r = request("POST", graphql_url, token, max_retries=1, graphql=True,
                        json={"query": query, "variables": variables})
        except requests.exceptions.Timeout:
            fail_or_backoff("client-side timeout", shrink=True)
            continue
        except requests.exceptions.RequestException as exc:
            fail_or_backoff(f"network error: {str(exc)[:80]}", shrink=False)
            continue

        if r.status_code in (502, 504):
            fail_or_backoff(f"HTTP {r.status_code} (GitHub 10s GraphQL timeout)", shrink=True)
            continue
        if r.status_code >= 500:
            fail_or_backoff(f"HTTP {r.status_code}", shrink=False)
            continue
        if r.status_code in (401, 403):
            raise OrgDiscoveryError(
                f"GraphQL returned HTTP {r.status_code}: {r.text[:200]}. "
                f"Check the token and its 'read:enterprise' scope / SSO authorization."
            )
        if r.status_code != 200:
            raise OrgDiscoveryError(f"GraphQL returned HTTP {r.status_code}: {r.text[:200]}")

        try:
            payload = r.json()
        except ValueError:
            fail_or_backoff("non-JSON response", shrink=False)
            continue

        errors = payload.get("errors") or []
        ent = (payload.get("data") or {}).get("enterprise")
        conn = (ent or {}).get("organizations")
        if conn is None:
            if _looks_like_graphql_timeout(errors):
                fail_or_backoff("GraphQL timeout error", shrink=True)
                continue
            if ent is None:
                # NOT_FOUND / FORBIDDEN on the enterprise itself: slug or scope.
                if errors:
                    tprint(f"  [GRAPHQL] {'; '.join(str(e.get('message', e))[:160] for e in errors[:3])}")
                if all_orgs:
                    raise OrgDiscoveryError(
                        f"Enterprise became unreadable mid-pagination after {len(all_orgs)} orgs."
                    )
                return None
            raise OrgDiscoveryError(f"Unexpected GraphQL response: {str(payload)[:300]}")

        # Partial data: GitHub nulls individual nodes it will not show this
        # token (e.g. SAML SSO not authorized for that org) and lists them in
        # `errors`. Keep the visible orgs instead of discarding the whole run.
        for node in conn.get("nodes") or []:
            login = (node or {}).get("login")
            if not login:
                skipped_null += 1
                continue
            if login in seen:
                duplicates += 1
                continue
            seen.add(login)
            all_orgs.append(login)

        tc = conn.get("totalCount")
        if isinstance(tc, int):
            if total_first is None:
                total_first = tc
            total_last = tc

        attempts = 0
        page_no += 1
        page_info = conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        next_cursor = page_info.get("endCursor")
        if not next_cursor or next_cursor == cursor:
            raise OrgDiscoveryError(
                f"GraphQL reported hasNextPage but no new cursor after {len(all_orgs)} orgs."
            )
        cursor = next_cursor
        if page_no % 10 == 0:
            tprint(f"  [GRAPHQL] ...{len(all_orgs)} orgs discovered so far")

    if not all_orgs and not skipped_null:
        return None
    _warn_if_discovery_incomplete(len(all_orgs), skipped_null, duplicates,
                                  total_first, total_last)
    return all_orgs or None


def list_orgs(api_base: str, token: str, enterprise: str | None, orgs_file: str | None) -> list[str]:
    errors: list[str] = []

    if enterprise:
        print(f'Discovering orgs via enterprise GraphQL: enterprise(slug: "{enterprise}")')
        try:
            orgs = list_orgs_graphql(api_base, token, enterprise)
            if orgs:
                print(f"[OK] Found {len(orgs)} orgs via GraphQL")
                return orgs
            print("\n[ERROR] Enterprise GraphQL returned 0 organizations", file=sys.stderr)
            for line in [
                f"Enterprise slug '{enterprise}' may be wrong, or token lacks 'read:enterprise' scope.",
                "Verify: gh auth status",
                f"Check:  https://github.com/enterprises/{enterprise}",
                "Retry without --enterprise to see accessible orgs: python script.py --dry-run",
            ]:
                print(f"  {line}", file=sys.stderr)
            raise RuntimeError(f"Enterprise '{enterprise}' returned no organizations")
        except RuntimeError:
            raise
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Network/API error accessing enterprise: {exc}")
        except Exception as exc:
            raise RuntimeError(f"Enterprise API failed: {exc}")

    if orgs_file:
        print(f"Reading orgs from file: {orgs_file}")
        try:
            with open(orgs_file, encoding="utf-8") as f:
                orgs = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
            if orgs:
                print(f"[OK] Found {len(orgs)} orgs from file")
                return orgs
            errors.append(f"File '{orgs_file}' contains no valid org names")
        except Exception as exc:
            errors.append(f"File read failed: {exc}")

    try:
        print("Discovering orgs via /user/orgs (all orgs the token user belongs to)")
        orgs = [
            o["login"]
            for o in paginate_list(f"{api_base}/user/orgs", token, params={"per_page": 100})
            if "login" in o
        ]
        if orgs:
            print(f"[OK] Found {len(orgs)} orgs via user API")
            return orgs
        errors.append("User API returned no orgs")
    except Exception as exc:
        errors.append(f"User API failed: {exc}")

    print("\n[ERROR] Unable to determine org list. Tried:", file=sys.stderr)
    for i, error in enumerate(errors, 1):
        print(f"   {i}. {error}", file=sys.stderr)
    print("\nTroubleshooting:", file=sys.stderr)
    print("  - Ensure GITHUB_TOKEN is set with a valid token", file=sys.stderr)
    print("  - Verify token has 'read:org' scope", file=sys.stderr)
    print("  - Provide --enterprise <slug> if using GHEC", file=sys.stderr)
    print("  - Provide --orgs-file <path> with one org per line", file=sys.stderr)
    raise RuntimeError("Unable to determine org list. See errors above.")


# ---------------------------------------------------------------------------
# Repo helpers
# ---------------------------------------------------------------------------

def repo_exists(api_base: str, org: str, repo: str, token: str) -> bool:
    r = request("GET", f"{api_base}/repos/{org}/{repo}", token)
    if r.status_code == 200:
        return True
    if r.status_code == 404:
        return False
    raise RuntimeError(f"{org}/{repo}: repo check failed {r.status_code} {r.text}")


def repo_is_empty(api_base: str, org: str, repo: str, token: str) -> bool:
    try:
        r = request("GET", f"{api_base}/repos/{org}/{repo}/commits", token, params={"per_page": 1})
        if r.status_code == 409:
            return True
        if r.status_code == 200:
            return len(r.json()) == 0
        return False
    except Exception:
        return False


def create_repo(api_base: str, org: str, repo: str, token: str) -> None:
    payload = {
        "name": repo,
        "private": True,
        "auto_init": False,
        "description": "Veracode GitHub Workflow Integration (imported template workflows & config).",
    }
    r = request("POST", f"{api_base}/orgs/{org}/repos", token, json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"{org}/{repo}: repo create failed {r.status_code} {r.text}")


def check_main_branch_exists(api_base: str, org: str, repo: str, token: str) -> bool:
    try:
        r = request("GET", f"{api_base}/repos/{org}/{repo}/branches/main", token)
        return r.status_code == 200
    except Exception:
        return False


def wait_for_main_branch(
    api_base: str,
    org: str,
    repo: str,
    token: str,
    timeout: int = 900,
    poll_interval: int = 10,
    log: Callable[[str], None] = tprint,
) -> bool:
    """Poll for 'main' after import. Interval doubles to _MAX_BRANCH_POLL_INTERVAL:
    a flat 10s poll costs up to 90 requests per slow org, backoff costs ~17.
    """
    start = time.time()
    deadline = start + timeout
    interval = float(poll_interval)
    while time.time() < deadline:
        if check_main_branch_exists(api_base, org, repo, token):
            return True
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sleep = min(interval, remaining)
        log(f"  [{org}] Waiting for main branch... ({int(time.time() - start)}s elapsed, "
            f"up to {int(remaining)}s remaining)")
        time.sleep(sleep)
        interval = min(interval * 2, float(_MAX_BRANCH_POLL_INTERVAL))
    return False


def ensure_veracode_repo_imported(
    api_base: str,
    org: str,
    token: str,
    do_apply: bool,
    onboarding_yml_content: str | None,
    auto_import: bool = False,
    web_base: str = "https://github.com",
    cached_clone_dir: str | None = None,
    log: Callable[[str], None] = tprint,
) -> tuple[bool, dict[str, Any]]:
    details: dict[str, Any] = {"repo": INTEGRATION_REPO_NAME}
    exists = repo_exists(api_base, org, INTEGRATION_REPO_NAME, token)
    is_empty = exists and repo_is_empty(api_base, org, INTEGRATION_REPO_NAME, token)

    def _run_post_import_steps() -> None:
        # Ensure default branch is 'main' before any content operations
        db_ok, db_action = set_default_branch(api_base, org, INTEGRATION_REPO_NAME, token, "main", log)
        details["default_branch_action"] = db_action
        if not db_ok and db_action != "already_main":
            log(f"  [{org}] Warning: could not set default branch to main ({db_action})")

        default_yml_url = f"{api_base}/repos/{org}/{INTEGRATION_REPO_NAME}/contents/default-veracode.yml"
        if request("GET", default_yml_url, token).status_code == 200:
            return
        _, yml_action = inject_veracode_yml(api_base, org, INTEGRATION_REPO_NAME, token, onboarding_yml_content, log)
        details["veracode_yml_injected"] = yml_action

    if exists and not is_empty:
        details["status"] = "repo_exists"
        details["_repo_confirmed_present"] = True
        if do_apply:
            _run_post_import_steps()
            if "veracode_yml_injected" in details:
                details["status"] = "repo_exists_post_import_incomplete"
        return True, details

    if is_empty:
        details["was_empty"] = True

    details["status"] = "missing"
    if not do_apply:
        details["note"] = "dry_run_only"
        return False, details

    if not exists:
        create_repo(api_base, org, INTEGRATION_REPO_NAME, token)
        details["created"] = True

    if auto_import:
        if not check_git_available():
            log(f"  [{org}] Git CLI not available - skipping auto import")
        else:
            ok, message = git_mirror_import(
                INTEGRATION_SOURCE_URL, org, INTEGRATION_REPO_NAME, token, web_base, cached_clone_dir
            )
            if ok:
                log(f"  [{org}] Push succeeded - waiting for GitHub to process the import (up to 15 min)...")
                branch_visible = wait_for_main_branch(api_base, org, INTEGRATION_REPO_NAME, token, log=log)
                if branch_visible:
                    details["status"] = "repo_created_and_imported"
                    details["import_method"] = "git_cli_auto"
                    details["_repo_confirmed_present"] = True
                    _run_post_import_steps()
                    return True, details
                log(f"  [{org}] Warning: main branch not visible after 15 minutes - "
                    f"GitHub may still be processing. Re-run to complete post-import steps.")
                details["status"] = "repo_created_import_incomplete"
                details["import_method"] = "git_cli_auto"
                return True, details
            else:
                log(f"  [{org}] Auto import failed: {message}")

    details["status"] = "repo_created_manual_import_required"
    details["import_instructions"] = {
        "web_importer_url": f"{web_base.rstrip('/')}/{org}/{INTEGRATION_REPO_NAME}/import",
        "source_url": INTEGRATION_SOURCE_URL,
        "note": "Manual import required - use GitHub web UI",
    }
    return False, details


# ---------------------------------------------------------------------------
# App installation helpers
# ---------------------------------------------------------------------------

def list_org_installations(api_base: str, org: str, token: str) -> list[dict[str, Any]]:
    r = request("GET", f"{api_base}/orgs/{org}/installations", token,
                params={"per_page": 100})
    if r.status_code >= 400:
        raise RuntimeError(f"{org}: cannot list installations ({r.status_code}) {r.text}")
    return r.json().get("installations", [])


def find_app_installation(api_base: str, org: str, token: str, app_slug: str) -> dict[str, Any] | None:
    for inst in list_org_installations(api_base, org, token):
        slug = inst.get("app_slug") or inst.get("app", {}).get("slug")
        if slug == app_slug:
            return inst
    return None


def get_org_id(api_base: str, org: str, token: str) -> int | None:
    try:
        r = request("GET", f"{api_base}/orgs/{org}", token)
        if r.status_code == 200:
            return r.json().get("id")
    except Exception:
        pass
    return None


def manual_install_url(web_base: str, org: str, org_id: int | None = None) -> str:
    if org_id is not None:
        return f"{web_base}/apps/{APP_SLUG}/installations/new/permissions?target_id={org_id}"
    return f"{web_base}/apps/{APP_SLUG}/installations/new"


def check_app_installed(api_base: str, web_base: str, org: str, token: str) -> tuple[bool, dict[str, Any]]:
    inst = find_app_installation(api_base, org, token, APP_SLUG)
    if inst:
        return True, {
            "status": "already_installed",
            "installation_id": inst.get("id"),
            "repository_selection": inst.get("repository_selection"),
        }
    org_id = get_org_id(api_base, org, token)
    return False, {"status": "missing", "install_url": manual_install_url(web_base, org, org_id)}


# ---------------------------------------------------------------------------
# Actions allowlist prerequisite check
# ---------------------------------------------------------------------------

def check_actions_allowlist(api_base: str, org: str, token: str) -> dict[str, Any]:
    """
    Verify the org's GitHub Actions policy permits the actions the integration needs.

    Returns a dict with:
      status: 'all_allowed' | 'local_only' | 'selected_ok' | 'selected_missing'
              | 'no_permission' | 'error'
      missing: list of required patterns not allowlisted (only for selected_missing)
      detail: short human-readable note
    """
    try:
        r = request("GET", f"{api_base}/orgs/{org}/actions/permissions", token)
        if r.status_code == 403:
            return {"status": "no_permission", "missing": [], "detail": "token lacks admin:org to read Actions policy"}
        if r.status_code != 200:
            return {"status": "error", "missing": [], "detail": f"permissions GET {r.status_code}"}

        allowed = r.json().get("allowed_actions")

        if allowed == "all":
            return {"status": "all_allowed", "missing": [], "detail": "all actions permitted"}

        if allowed == "local_only":
            return {
                "status": "local_only",
                "missing": list(_REQUIRED_ACTION_PATTERNS),
                "detail": "policy is local_only - third-party Veracode actions are blocked",
            }

        if allowed == "selected":
            sr = request("GET", f"{api_base}/orgs/{org}/actions/permissions/selected-actions", token)
            if sr.status_code == 403:
                return {"status": "no_permission", "missing": [], "detail": "token lacks admin:org to read selected-actions"}
            if sr.status_code != 200:
                return {"status": "error", "missing": [], "detail": f"selected-actions GET {sr.status_code}"}

            body = sr.json()
            github_owned_allowed = bool(body.get("github_owned_allowed"))
            patterns = set(body.get("patterns_allowed") or [])

            missing: list[str] = []
            for pat in _REQUIRED_ACTION_PATTERNS:
                if pat.startswith(_GITHUB_OWNED_PREFIX):
                    if not github_owned_allowed and pat not in patterns:
                        missing.append(pat)
                else:
                    if pat not in patterns:
                        missing.append(pat)

            if missing:
                return {
                    "status": "selected_missing",
                    "missing": missing,
                    "detail": f"{len(missing)} required action(s) not allowlisted",
                }
            return {"status": "selected_ok", "missing": [], "detail": "all required actions allowlisted"}

        return {"status": "error", "missing": [], "detail": f"unknown allowed_actions value: {allowed}"}

    except Exception as exc:
        return {"status": "error", "missing": [], "detail": str(exc)[:120]}


# ---------------------------------------------------------------------------
# Credential validation
# ---------------------------------------------------------------------------

def validate_credentials(
    api_base: str,
    token: str,
    veracode_api_id: str | None,
    veracode_api_key: str | None,
    check_veracode: bool,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    print("\n[VALIDATION] Checking credentials...")

    try:
        r = request("GET", f"{api_base}/user", token)
        if r.status_code == 200:
            username = r.json().get("login", "unknown")
            print(f"  [OK] GitHub token valid (user: {username})")
            scopes = r.headers.get("X-OAuth-Scopes", "")
            print(f"  [OK] GitHub token scopes: {scopes}" if scopes else "  [WARN] Could not determine GitHub token scopes")
        elif r.status_code == 401:
            errors.append("GitHub token is invalid or expired")
            print("  [FAIL] GitHub token authentication failed")
        elif r.status_code == 403:
            errors.append("GitHub token lacks required permissions")
            print("  [FAIL] GitHub token permission denied")
        else:
            errors.append(f"GitHub API returned unexpected status: {r.status_code}")
            print(f"  [FAIL] GitHub API error: {r.status_code}")
    except Exception as exc:
        errors.append(f"GitHub API connection failed: {str(exc)[:100]}")
        print(f"  [FAIL] GitHub API connection error: {str(exc)[:80]}")

    if check_veracode and veracode_api_id and veracode_api_key:
        try:
            r = veracode_request(
                "GET", "/srcclr/v3/workspaces", veracode_api_id, veracode_api_key,
                params={"size": 1, "page": 0},
            )
            if r.status_code == 200:
                print("  [OK] Veracode credentials valid")
            elif r.status_code == 401:
                errors.append("Veracode credentials are invalid")
                print("  [FAIL] Veracode authentication failed")
            elif r.status_code == 403:
                errors.append("Veracode credentials lack required permissions")
                print("  [FAIL] Veracode permission denied")
            else:
                errors.append(f"Veracode API returned unexpected status: {r.status_code}")
                print(f"  [FAIL] Veracode API error: {r.status_code}")
        except Exception as exc:
            errors.append(f"Veracode API connection failed: {str(exc)[:100]}")
            print(f"  [FAIL] Veracode API connection error: {str(exc)[:80]}")

    if errors:
        print(f"\n[VALIDATION] Failed with {len(errors)} error(s)")
        return False, errors
    print("[VALIDATION] All credentials validated successfully\n")
    return True, []


# ---------------------------------------------------------------------------
# Teams map loading
# ---------------------------------------------------------------------------

def load_teams_map(teams_file: str) -> dict[str, str]:
    teams_map: dict[str, str] = {}
    with open(teams_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            org_name = (row.get("org") or "").strip()
            teams_value = (row.get("teams") or "").strip().strip('"')
            if org_name:
                teams_map[org_name] = teams_value
    print(f"[teams-map] Loaded {len(teams_map)} org->teams mappings from {teams_file}")
    return teams_map


# ---------------------------------------------------------------------------
# Per-org processing
# ---------------------------------------------------------------------------

def process_org(
    org: str,
    org_idx: int,
    ctx: RunContext,
    cached_clone_dir: str | None = None,
    buf: OrgBuffer | None = None,
) -> None:
    if buf is None:
        buf = OrgBuffer(org, org_idx, ctx.total_orgs, flush_on_add=True)

    progress_pct = (org_idx / ctx.total_orgs) * 100 if ctx.total_orgs else 100.0
    if buf.flush_on_add:
        buf.add(f"\n[{org_idx}/{ctx.total_orgs} ({progress_pct:.1f}%)] Processing: {org}")

    now = datetime.now()
    entry: dict[str, Any] = {
        "org": org,
        "timestamp": now.isoformat(),
        "timestamp_readable": now.strftime("%Y-%m-%d %H:%M:%S %A"),
    }

    if ctx.do_set_teams or ctx.do_create_teams:
        if ctx.teams_mode == "auto":
            teams_value: str | None = org
        elif ctx.teams_mode == "hybrid":
            teams_value = ctx.teams_map.get(org, "").strip() or org
        else:
            teams_value = ctx.teams_map.get(org, "").strip() or None
        if teams_value and ctx.team_prefix:
            teams_value = ctx.team_prefix + teams_value
    else:
        teams_value = None

    # IDs captured during this run so the team<->workspace link step can reuse
    # them instead of re-resolving by name.
    captured_team_id: str | None = None
    captured_workspace_id: str | None = None

    # --- Fix existing repos (compensatory pass) -------------------------------
    if ctx.do_fix_repos:
        try:
            fix_teams_value: str | None = None
            if ctx.teams_mode != "none":
                if ctx.teams_mode == "auto":
                    fix_teams_value = org
                elif ctx.teams_mode == "hybrid":
                    fix_teams_value = ctx.teams_map.get(org, "").strip() or org
                else:
                    fix_teams_value = ctx.teams_map.get(org, "").strip() or None
                if fix_teams_value and ctx.team_prefix:
                    fix_teams_value = ctx.team_prefix + fix_teams_value

            health = check_repo_health(
                ctx.api_base, org, INTEGRATION_REPO_NAME, ctx.token,
                yml_content=ctx.yml_content,
                teams_value=fix_teams_value,
                onboarding_yml_content=ctx.onboarding_yml_content,
                dry_run=ctx.dry_run,
                web_base=ctx.web_base,
                cached_clone_dir=cached_clone_dir,
                log=buf.add,
                include_iac_rbac=ctx.do_iac_rbac,
            )
            entry["fix_repos"] = {
                "repo_exists": health.repo_exists,
                "repo_empty": health.repo_empty,
                "default_branch": health.default_branch,
                "default_branch_ok": health.default_branch_ok,
                "default_branch_action": health.default_branch_action,
                "veracode_yml_present": health.veracode_yml_present,
                "veracode_yml_action": health.veracode_yml_action,
                "teams_action": health.teams_action,
                "reimport_action": health.reimport_action,
                "needs_remediation": health.needs_remediation,
            }
            with ctx.stats_lock:
                ctx.stats.fix_repos_checked += 1
                if not health.repo_exists or health.repo_empty:
                    ctx.stats.fix_repos_skipped += 1
                elif health.needs_remediation:
                    ctx.stats.fix_repos_remediated += 1
                if health.default_branch_action == "already_main":
                    ctx.stats.default_branch_ok += 1
                elif health.default_branch_action == "set_to_main":
                    ctx.stats.default_branch_fixed += 1
                elif health.default_branch_action not in ("not_checked", "read_failed"):
                    ctx.stats.default_branch_failed += 1

                ta = health.teams_action
                if ta.startswith("teams_updated"):
                    ctx.stats.teams_updated += 1
                elif ta == "teams_already_current":
                    ctx.stats.teams_skipped += 1
                elif ta in ("no_workflow_files_found",):
                    ctx.stats.teams_failed += 1
                elif ta.startswith("error") or ta.startswith("failed"):
                    ctx.stats.teams_failed += 1

                ya = health.veracode_yml_action
                if ya in ("created", "updated_with_backup"):
                    ctx.stats.yml_updated += 1
                elif ya == "present_no_update":
                    ctx.stats.yml_skipped += 1
                elif ya.startswith("failed") or ya.startswith("put_failed") or ya.startswith("get_failed"):
                    ctx.stats.yml_failed += 1

                ra = health.reimport_action
                if ra == "reimported":
                    ctx.stats.reimports_done += 1
                elif ra.startswith("failed") or ra in ("git_not_available", "reimport_main_not_visible"):
                    ctx.stats.reimports_failed += 1
        except Exception as exc:
            entry["fix_repos"] = {"error": str(exc)}
            with ctx.stats_lock:
                ctx.stats.fix_repos_checked += 1
            buf.add(f"  Fix-repos error: {str(exc)[:80]}")

    # --- Repo import ----------------------------------------------------------
    repo_confirmed_present = False
    if not ctx.do_fix_repos:
        try:
            repo_ok, repo_details = ensure_veracode_repo_imported(
                ctx.api_base, org, ctx.token,
                do_apply=ctx.do_apply_repo,
                onboarding_yml_content=ctx.onboarding_yml_content,
                auto_import=ctx.do_apply_repo,
                web_base=ctx.web_base,
                cached_clone_dir=cached_clone_dir,
                log=buf.add,
            )
            repo_confirmed_present = repo_details.pop("_repo_confirmed_present", False)
            entry["veracode_repo"] = {"present": repo_ok, **repo_details}
            with ctx.stats_lock:
                if repo_ok:
                    ctx.stats.repo_success += 1
                else:
                    ctx.stats.repo_fail += 1
            if not repo_ok:
                with ctx.rows_lock:
                    ctx.missing_repo_rows.append([org, INTEGRATION_REPO_NAME, repo_details.get("status", "missing")])
        except Exception as exc:
            entry["veracode_repo"] = {"present": None, "status": "error", "error": str(exc)}
            with ctx.rows_lock:
                ctx.missing_repo_rows.append([org, INTEGRATION_REPO_NAME, f"error:{exc}"])
            with ctx.stats_lock:
                ctx.stats.repo_fail += 1
            buf.add(f"  Repo error: {str(exc)[:80]}")

    # --- Veracode platform team creation (Identity API) -----------------------
    if ctx.do_create_teams and teams_value and ctx.veracode_api_id and ctx.veracode_api_key:
        try:
            team_id, team_action = ensure_veracode_team(
                teams_value, ctx.veracode_api_id, ctx.veracode_api_key, log=buf.add,
            )
            captured_team_id = team_id
            entry["veracode_team_platform"] = {
                "team_name": teams_value,
                "team_id": team_id,
                "action": team_action,
            }
            with ctx.stats_lock:
                if team_action == "created":
                    ctx.stats.teams_created_on_platform += 1
                elif team_action == "already_exists":
                    ctx.stats.teams_already_exist_on_platform += 1
                else:
                    ctx.stats.teams_create_failed_on_platform += 1
        except Exception as exc:
            entry["veracode_team_platform"] = {
                "team_name": teams_value,
                "team_id": None,
                "action": f"error:{exc}",
            }
            with ctx.stats_lock:
                ctx.stats.teams_create_failed_on_platform += 1
            buf.add(f"  Platform team creation error: {str(exc)[:80]}")

    # --- Teams injection (independent, idempotent) ----------------------------
    if ctx.do_set_teams and teams_value and not ctx.do_fix_repos:
        try:
            if repo_confirmed_present or (
                repo_exists(ctx.api_base, org, INTEGRATION_REPO_NAME, ctx.token) and
                not repo_is_empty(ctx.api_base, org, INTEGRATION_REPO_NAME, ctx.token)
            ):
                file_actions: dict[str, str] = {}
                teams_ok, teams_msg = inject_teams_into_workflows(
                    ctx.api_base, org, INTEGRATION_REPO_NAME, ctx.token, teams_value,
                    update_existing=True,
                    log=buf.add,
                    include_iac_rbac=ctx.do_iac_rbac,
                    file_actions=file_actions,
                )
                entry["teams_injection"] = {"success": teams_ok, "action": teams_msg, "value": teams_value,
                                            "files": file_actions}
                with ctx.stats_lock:
                    if teams_ok:
                        if "updated" in teams_msg:
                            ctx.stats.teams_updated += 1
                        else:
                            ctx.stats.teams_skipped += 1
                    else:
                        ctx.stats.teams_failed += 1
            else:
                entry["teams_injection"] = {"success": False, "action": "repo_not_ready", "value": teams_value}
                with ctx.stats_lock:
                    ctx.stats.teams_skipped += 1
        except Exception as exc:
            entry["teams_injection"] = {"success": False, "action": f"error:{exc}", "value": teams_value}
            with ctx.stats_lock:
                ctx.stats.teams_failed += 1
            buf.add(f"  Teams injection error: {str(exc)[:80]}")

    # --- App install check ----------------------------------------------------
    try:
        app_ok, app_details = check_app_installed(ctx.api_base, ctx.web_base, org, ctx.token)
        entry["workflow_app"] = {"installed": app_ok, **app_details}
        with ctx.stats_lock:
            if app_ok:
                ctx.stats.app_installed += 1
            else:
                ctx.stats.app_missing += 1
        if not app_ok:
            with ctx.rows_lock:
                ctx.missing_app_rows.append([org, APP_SLUG, "missing"])
                ctx.manual_links_rows.append([org, app_details["install_url"], "manual_install_required"])
    except Exception as exc:
        entry["workflow_app"] = {"installed": None, "status": "error", "error": str(exc)}
        with ctx.rows_lock:
            ctx.missing_app_rows.append([org, APP_SLUG, f"error:{exc}"])
        with ctx.stats_lock:
            ctx.stats.app_missing += 1
        buf.add(f"  App check error: {str(exc)[:80]}")

    # --- Actions allowlist prerequisite check (warn-only) ---------------------
    try:
        allow = check_actions_allowlist(ctx.api_base, org, ctx.token)
        entry["actions_allowlist"] = allow
        status = allow["status"]
        with ctx.stats_lock:
            if status in ("all_allowed", "selected_ok"):
                ctx.stats.actions_allowed += 1
            elif status == "no_permission":
                ctx.stats.actions_no_permission += 1
            elif status in ("local_only", "selected_missing"):
                ctx.stats.actions_missing += 1
        if status in ("local_only", "selected_missing"):
            missing = allow.get("missing", [])
            preview = ", ".join(missing[:4]) + (f" (+{len(missing) - 4} more)" if len(missing) > 4 else "")
            buf.add(f"  [WARNING] Actions allowlist incomplete - integration will break: {allow['detail']}")
            if preview:
                buf.add(f"            Missing: {preview}")
            with ctx.rows_lock:
                ctx.actions_allowlist_rows.append(
                    [org, status, "; ".join(missing) if missing else allow.get("detail", "")]
                )
    except Exception as exc:
        entry["actions_allowlist"] = {"status": "error", "missing": [], "detail": str(exc)[:120]}
        buf.add(f"  Actions allowlist check error: {str(exc)[:80]}")

    # --- veracode.yml update --------------------------------------------------
    if ctx.do_update_yml and ctx.yml_content and not ctx.do_fix_repos:
        try:
            yml_ok, yml_action = update_veracode_yml_in_repo(
                ctx.api_base, org, INTEGRATION_REPO_NAME, ctx.token, ctx.yml_content,
                repo_is_known_present=repo_confirmed_present,
                log=buf.add,
            )
            entry["veracode_yml_update"] = {"success": yml_ok, "action": yml_action}
            with ctx.stats_lock:
                if yml_ok:
                    ctx.stats.yml_updated += 1
                elif yml_action in ("repo_not_found", "repo_empty"):
                    ctx.stats.yml_skipped += 1
                else:
                    ctx.stats.yml_failed += 1
        except Exception as exc:
            entry["veracode_yml_update"] = {"success": False, "action": f"error:{exc}"}
            with ctx.stats_lock:
                ctx.stats.yml_failed += 1
            buf.add(f"  veracode.yml update error: {str(exc)[:80]}")

    # --- Secrets --------------------------------------------------------------
    if ctx.dry_run or ctx.do_set_secrets:
        try:
            if ctx.dry_run:
                results = check_veracode_secrets_status(ctx.api_base, org, ctx.token)
                counts = {
                    v: sum(1 for x in results.values() if x == v)
                    for v in ("no_permission", "missing", "exists", "error")
                }
                with ctx.stats_lock:
                    ctx.stats.secrets_checked += 1
                    if counts["no_permission"] == 3:
                        status = "no_permission"
                        ctx.stats.secrets_no_permission += 1
                    elif counts["error"] == 3:
                        status = "error"
                        ctx.stats.secrets_fail += 1
                    elif counts["missing"] == 0 and counts["no_permission"] == 0 and counts["error"] == 0:
                        status = "all_exist"
                        ctx.stats.secrets_all_exist += 1
                    elif counts["exists"] == 0 and counts["no_permission"] == 0 and counts["error"] == 0:
                        status = "all_missing"
                        ctx.stats.secrets_all_missing += 1
                    else:
                        status = "partial"
                        ctx.stats.secrets_partial += 1
                entry["secrets"] = {"status": status, "results": results}

            elif ctx.do_set_secrets:
                workspace_id = create_veracode_workspace(
                    org, ctx.veracode_api_id, ctx.veracode_api_key, log=buf.add,
                )
                captured_workspace_id = workspace_id
                if not workspace_id:
                    entry["secrets"] = {"status": "error", "error": "Failed to create or find Veracode workspace"}
                    with ctx.stats_lock:
                        ctx.stats.secrets_fail += 1
                else:
                    agent_token = create_veracode_agent_token(
                        workspace_id, org, ctx.veracode_api_id, ctx.veracode_api_key, log=buf.add,
                    )
                    if not agent_token:
                        entry["secrets"] = {"status": "error", "error": "Failed to generate agent token"}
                        with ctx.stats_lock:
                            ctx.stats.secrets_fail += 1
                    else:
                        ok, set_results = set_veracode_secrets(
                            ctx.api_base, org, ctx.token,
                            ctx.veracode_sa_api_id, ctx.veracode_sa_api_key, agent_token,
                            log=buf.add,
                        )
                        entry["secrets"] = {"status": "set" if ok else "partial", "results": set_results}
                        with ctx.stats_lock:
                            if ok:
                                ctx.stats.secrets_success += 1
                            else:
                                ctx.stats.secrets_fail += 1
        except Exception as exc:
            entry["secrets"] = {"status": "error", "error": str(exc)}
            with ctx.stats_lock:
                ctx.stats.secrets_fail += 1
                if ctx.dry_run:
                    ctx.stats.secrets_checked += 1
            buf.add(f"  Secrets error: {str(exc)[:80]}")

    # --- Link team to SCA workspace (independent, idempotent) -----------------
    if ctx.do_link_teams and teams_value and ctx.veracode_api_id and ctx.veracode_api_key:
        try:
            _link_ok, link_action = ensure_team_linked_to_workspace(
                org_name=org,
                team_name=teams_value,
                api_id=ctx.veracode_api_id,
                api_key=ctx.veracode_api_key,
                workspace_id=captured_workspace_id,
                # captured_team_id is an Identity API id; the SCA API needs its own,
                # resolved by name. Wait for it when the team was handled this run.
                log=buf.add,
                wait_for_team=captured_team_id is not None,
            )
            entry["veracode_team_workspace_link"] = {
                "workspace": org,
                "team_name": teams_value,
                "action": link_action,
            }
            with ctx.stats_lock:
                if link_action == "linked":
                    ctx.stats.teams_linked_to_workspace += 1
                elif link_action == "already_linked":
                    ctx.stats.teams_link_already += 1
                else:
                    ctx.stats.teams_link_failed += 1
        except Exception as exc:
            entry["veracode_team_workspace_link"] = {
                "workspace": org,
                "team_name": teams_value,
                "action": f"error:{exc}",
            }
            with ctx.stats_lock:
                ctx.stats.teams_link_failed += 1
            buf.add(f"  Team->workspace link error: {str(exc)[:80]}")

    # --- Write report + checkpoint --------------------------------------------
    with ctx.report_lock:
        append_report_entry(ctx.report_path, entry)

    with ctx.stats_lock:
        ctx.stats.processed += 1

    with ctx.checkpoint_lock:
        ctx.completed_orgs.append(org)
        try:
            ctx.checkpoint_file.write_text(
                json.dumps(
                    {
                        "last_org": org,
                        "processed": len(ctx.completed_orgs),
                        "completed": ctx.completed_orgs,
                    },
                    indent=2,
                ),
                encoding="utf-8",
                newline="\n",
            )
        except Exception as exc:
            buf.add(f"  [WARNING] Failed to save checkpoint: {exc}")

    # --- Console summary line -------------------------------------------------
    if ctx.do_fix_repos:
        fix_info = entry.get("fix_repos", {})
        db_action = fix_info.get("default_branch_action", "?")
        yml_action = fix_info.get("veracode_yml_action", "?")
        teams_action = fix_info.get("teams_action", "?")
        reimport_action = fix_info.get("reimport_action", "not_needed")
        app_status = "[OK]" if entry.get("workflow_app", {}).get("installed") else "[FAIL]"
        reimport_detail = f"  Reimport: [{reimport_action}]" if reimport_action != "not_needed" else ""
        buf.add(
            f"  DefaultBranch: [{db_action}]{reimport_detail}  YML: [{yml_action}]  "
            f"Teams: [{teams_action}]  App: {app_status}"
        )
        return

    repo_status = "[OK]" if entry.get("veracode_repo", {}).get("present") else "[FAIL]"
    app_status = "[OK]" if entry.get("workflow_app", {}).get("installed") else "[FAIL]"

    teams_detail = ""
    if ctx.do_set_teams:
        teams_info = entry.get("teams_injection", {})
        if teams_info:
            action = teams_info.get("action", "")
            if teams_info.get("success"):
                teams_detail = f" Teams: [OK] ({action})"
            else:
                teams_detail = f" Teams: [FAIL] ({action})"
        elif not teams_value:
            teams_detail = " Teams: (no teams configured)"

    platform_team_detail = ""
    if ctx.do_create_teams:
        pt_info = entry.get("veracode_team_platform", {})
        if pt_info:
            pt_action = pt_info.get("action", "")
            platform_team_detail = f" PlatformTeam: [{pt_action}]"

    link_detail = ""
    if ctx.do_link_teams:
        lk = entry.get("veracode_team_workspace_link", {})
        if lk:
            link_detail = f" Link: [{lk.get('action', '')}]"

    yml_status = ""
    if ctx.do_update_yml:
        yml_info = entry.get("veracode_yml_update", {})
        yml_status = f"  YML: {'[OK]' if yml_info.get('success') else '[FAIL]'} ({yml_info.get('action', 'error')})"

    secrets_status = ""
    if "secrets" in entry:
        s = entry["secrets"]
        sec_status = s.get("status", "")
        if sec_status == "no_permission":
            secrets_status = "  Secrets: [WARN] (no_permission - token needs admin:org scope)"
        elif sec_status == "all_exist":
            secrets_status = "  Secrets: [OK] (all exist)"
        elif sec_status == "all_missing":
            secrets_status = "  Secrets: [FAIL] (all missing)"
        elif sec_status == "partial":
            r_map = s.get("results", {})
            ec = sum(1 for v in r_map.values() if v == "exists")
            mc = sum(1 for v in r_map.values() if v == "missing")
            secrets_status = f"  Secrets: [WARN] ({ec} exist, {mc} missing)"
        elif sec_status == "set":
            secrets_status = "  Secrets: [OK]"
        elif sec_status == "error":
            secrets_status = "  Secrets: [FAIL] (error)"
        else:
            secrets_status = "  Secrets: [FAIL]"

    buf.add(f"  Repo: {repo_status}{teams_detail}{platform_team_detail}{link_detail}  App: {app_status}{yml_status}{secrets_status}")


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Veracode GitHub Workflow Integration rollout helper")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Report status only, no changes (default).")
    mode.add_argument("--apply", action="store_true", help="Apply changes (requires action flags below).")

    ap.add_argument("--import-repo", action="store_true",
                    help="[apply] Create and import the 'veracode' repo if missing.")

    teams_group = ap.add_mutually_exclusive_group()
    teams_group.add_argument("--set-teams-auto", action="store_true",
                             help="[apply] Inject teams parameter using the org name.")
    teams_group.add_argument("--set-teams-file", metavar="FILE",
                             help="[apply] CSV file (org,teams) for per-org team injection.")
    teams_group.add_argument("--set-teams-hybrid", metavar="FILE",
                             help="[apply] CSV file (org,teams); orgs with blank teams fall back to org name.")

    ap.add_argument("--team-prefix", default="", metavar="PREFIX",
                    help="[apply] Prepend PREFIX to every injected teams value.")

    ap.add_argument("--create-teams", action="store_true",
                    help="[apply] Create teams on the Veracode platform (Identity API) if they "
                         "do not already exist. Requires VERACODE_API_ID and VERACODE_API_KEY.")

    ap.add_argument("--skip-iac-rbac", action="store_true",
                    help="[apply] Do not touch the IaC/Secrets workflow. By default, --set-teams-* "
                         "(and --fix-repos with a teams mode) replace the "
                         "veracode/container_iac_secrets_scanning step with a Veracode CLI step "
                         "(CLI 2.55.0+) that links results to the application profile with "
                         "--app-name, --create-app and --teams, and keep its teams in sync.")

    ap.add_argument("--link-teams-to-workspaces", action="store_true",
                    help="[apply] Associate each org's team with its SCA workspace so the team "
                         "can see scan results. Resolves workspace by org name and team by teams "
                         "value; creates neither. Requires VERACODE_API_ID and VERACODE_API_KEY "
                         "and an active teams mode (--set-teams-*). Composes with --create-teams "
                         "and --set-secrets.")

    ap.add_argument("--set-secrets", action="store_true",
                    help="[apply] Set VERACODE_API_ID, VERACODE_API_KEY, VERACODE_AGENT_TOKEN. "
                         "Always overwrites - safe to re-run for credential rotation.")

    ap.add_argument(
        "--update-veracode-yml", metavar="FILE", nargs="?", const="",
        help=(
            "[apply] Push a veracode.yml to the 'veracode' repo in every org, overwriting the "
            "current file. Omit FILE to fetch from upstream; pass a local FILE path for custom. "
            "The current file is backed up as default-veracode.yml before overwriting."
        ),
    )

    ap.add_argument(
        "--fix-repos", action="store_true",
        help=(
            "[apply|dry-run] Compensatory pass for already-imported repos. For each org, checks "
            "that the 'veracode' repo: (1) has 'main' as its default branch and fixes it if not, "
            "(2) has veracode.yml present and adds/updates it if missing (uses --update-veracode-yml "
            "FILE if supplied, otherwise falls back to the local veracode.yml next to this script), "
            "(3) has teams injected into workflow files if a teams mode is active. "
            "Skips orgs where the repo does not exist or is empty. "
            "Compatible with --dry-run to audit without making changes. "
            "Mutually exclusive with --import-repo during a single run."
        ),
    )

    ap.add_argument("--enterprise", help="GitHub Enterprise slug.")
    ap.add_argument("--orgs-file", help="Path to a file with one org login per line.")
    ap.add_argument("--out", default="out", help="Output directory (default: ./out).")
    ap.add_argument("--api-base", default=env("GITHUB_API_BASE", "https://api.github.com"),
                    help="GitHub API base URL.")
    ap.add_argument("--web-base", default=env("GITHUB_WEB_BASE", "https://github.com"),
                    help="GitHub web base URL (used for manual install links).")
    ap.add_argument("--token-env", default="GITHUB_TOKEN",
                    help="Environment variable holding the GitHub PAT (default: GITHUB_TOKEN).")
    ap.add_argument("--skip-to", help="Skip all orgs before this one and start from here.")
    ap.add_argument("--continue", dest="resume", action="store_true",
                    help="Resume from the last checkpoint saved in checkpoint.json.")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="Number of parallel worker threads (default: 1). Recommended: 3-5.")
    args = ap.parse_args()

    if args.workers < 1:
        print("ERROR: --workers must be at least 1.", file=sys.stderr)
        sys.exit(1)
    if args.workers > 10:
        print(f"[WARNING] --workers {args.workers} is high. The global rate limiter will pace "
              "writes to stay within content-creation limits (~60 writes/min, ~400 writes/hour), "
              "so extra workers above ~5 give diminishing returns and may stall waiting on the "
              "shared budget. Consider 3-5 workers.")

    if not args.dry_run and not args.apply:
        args.dry_run = True

    if args.fix_repos and args.import_repo:
        print("ERROR: --fix-repos and --import-repo are mutually exclusive in a single run.", file=sys.stderr)
        sys.exit(1)

    if args.apply and args.set_secrets:
        try:
            import nacl  # noqa: F401
        except ImportError:
            print("ERROR: --set-secrets requires pynacl.  Install with: pip install pynacl", file=sys.stderr)
            sys.exit(1)

    token = env(args.token_env)
    if not token:
        print(f"ERROR: Set {args.token_env} environment variable.", file=sys.stderr)
        sys.exit(1)

    api_base = args.api_base.rstrip("/")
    web_base = args.web_base.rstrip("/")

    do_apply_repo = bool(args.apply and args.import_repo)
    do_set_secrets = bool(args.apply and args.set_secrets)
    do_set_teams = bool(args.apply and (args.set_teams_auto or args.set_teams_file or args.set_teams_hybrid))
    do_update_yml = bool(args.apply and args.update_veracode_yml is not None)
    do_create_teams = bool(args.apply and args.create_teams and (args.set_teams_auto or args.set_teams_file or args.set_teams_hybrid))
    do_link_teams = bool(args.apply and args.link_teams_to_workspaces and (args.set_teams_auto or args.set_teams_file or args.set_teams_hybrid))
    do_fix_repos = bool(args.fix_repos)

    if args.set_teams_auto:
        teams_mode = "auto"
    elif args.set_teams_hybrid:
        teams_mode = "hybrid"
    elif args.set_teams_file:
        teams_mode = "file"
    else:
        teams_mode = "none"

    onboarding_yml_content: str | None = None
    onboarding_yml_path: Path | None = None
    if do_apply_repo or do_fix_repos:
        onboarding_yml_path = Path(__file__).parent / "veracode.yml"
        if onboarding_yml_path.exists():
            onboarding_yml_content = onboarding_yml_path.read_text(encoding="utf-8")
            print(f"[import-repo] Onboarding veracode.yml: {onboarding_yml_path.resolve()}")
        else:
            if do_apply_repo:
                print("[WARNING] veracode.yml not found next to script - repo will be imported but yml injection will be skipped.")
                print(f"          Expected: {onboarding_yml_path.resolve()}", file=sys.stderr)
            onboarding_yml_path = None

    yml_content: str | None = None
    yml_source_label: str | None = None
    if do_update_yml or do_fix_repos:
        raw_path = getattr(args, "update_veracode_yml", None)
        if raw_path:
            local_path = Path(raw_path)
            if not local_path.exists():
                print(f"ERROR: --update-veracode-yml file not found: {local_path}", file=sys.stderr)
                sys.exit(1)
            yml_content = local_path.read_text(encoding="utf-8")
            yml_source_label = str(local_path.resolve())
        elif do_update_yml:
            print("[update-veracode-yml] Fetching veracode.yml from upstream integration repo...")
            yml_content = fetch_upstream_veracode_yml()
            if not yml_content:
                print("ERROR: Could not fetch veracode.yml from upstream repo. "
                      "Pass a local file with --update-veracode-yml FILE.", file=sys.stderr)
                sys.exit(1)
            yml_source_label = INTEGRATION_SOURCE_URL
        if yml_source_label:
            print(f"[update-veracode-yml] Source: {yml_source_label}")

    need_veracode_creds = do_set_secrets or do_create_teams or do_link_teams
    veracode_api_id = env("VERACODE_API_ID") if need_veracode_creds else None
    veracode_api_key = env("VERACODE_API_KEY") if need_veracode_creds else None
    veracode_sa_api_id = env("VERACODE_SA_API_ID") if do_set_secrets else None
    veracode_sa_api_key = env("VERACODE_SA_API_KEY") if do_set_secrets else None

    if do_set_secrets and (not veracode_api_id or not veracode_api_key):
        print("ERROR: --set-secrets requires VERACODE_API_ID and VERACODE_API_KEY env vars.", file=sys.stderr)
        sys.exit(1)
    if do_set_secrets and (not veracode_sa_api_id or not veracode_sa_api_key):
        print("ERROR: --set-secrets requires VERACODE_SA_API_ID and VERACODE_SA_API_KEY env vars.", file=sys.stderr)
        sys.exit(1)
    if do_create_teams and (not veracode_api_id or not veracode_api_key):
        print("ERROR: --create-teams requires VERACODE_API_ID and VERACODE_API_KEY env vars "
              "(human user account with Administrator role).", file=sys.stderr)
        sys.exit(1)
    if args.apply and args.link_teams_to_workspaces and teams_mode == "none":
        print("ERROR: --link-teams-to-workspaces requires a teams mode "
              "(--set-teams-auto/-file/-hybrid).", file=sys.stderr)
        sys.exit(1)
    if do_link_teams and (not veracode_api_id or not veracode_api_key):
        print("ERROR: --link-teams-to-workspaces requires VERACODE_API_ID and "
              "VERACODE_API_KEY env vars.", file=sys.stderr)
        sys.exit(1)

    teams_map: dict[str, str] = {}
    teams_file = args.set_teams_file or args.set_teams_hybrid
    if teams_file:
        try:
            teams_map = load_teams_map(teams_file)
        except Exception as exc:
            print(f"[ERROR] Failed to load teams file '{teams_file}': {exc}", file=sys.stderr)
            sys.exit(1)

    print(f"\n{'=' * 60}")
    print(f"MODE: {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"{'=' * 60}")
    if args.apply:
        if do_fix_repos:
            print("  Fix existing repos    : YES")
            print("    - Check/fix default branch to 'main'")
            print("    - Add/update veracode.yml if missing")
            if teams_mode != "none":
                print("    - Inject/update teams in workflow files")
                if not args.skip_iac_rbac:
                    print("    - Convert IaC/Secrets workflow to Veracode CLI with RBAC")
        else:
            print(f"  Import missing repos  : {'YES' if do_apply_repo else 'NO (--import-repo)'}")
            if do_apply_repo:
                yml_note = str(onboarding_yml_path.resolve()) if onboarding_yml_path else "NOT FOUND - import only, yml injection skipped"
                print(f"    Onboarding YML      : {yml_note}")
        if do_set_teams:
            if args.set_teams_auto:
                print("  Set teams in workflows: YES (auto - org name)")
            elif args.set_teams_hybrid:
                print(f"  Set teams in workflows: YES (hybrid - from {args.set_teams_hybrid}, org name fallback)")
            else:
                print(f"  Set teams in workflows: YES (from {args.set_teams_file})")
            if args.team_prefix:
                print(f"    Team prefix         : '{args.team_prefix}'")
            print(f"    IaC/Secrets RBAC    : {'NO (--skip-iac-rbac)' if args.skip_iac_rbac else 'YES (Veracode CLI --app-name --create-app --teams)'}")
        if do_create_teams:
            print("  Create platform teams : YES (via Veracode Identity API)")
        if do_link_teams:
            print("  Link teams->workspaces: YES (via Veracode SCA API)")
        if do_update_yml:
            print(f"  Update veracode.yml   : YES (source: {yml_source_label})")
        print(f"  Set Veracode secrets  : {'YES' if do_set_secrets else 'NO (--set-secrets)'}")
    elif do_fix_repos:
        print("  Fix existing repos    : DRY-RUN (audit only, no changes)")
        print("    - Check default branch (report only)")
        print("    - Check veracode.yml presence (report only)")
        if teams_mode != "none":
            print("    - Check teams injection (report only)")
    else:
        print("  No changes will be made (use --apply to enable changes)")
    print(f"  Workers               : {args.workers}{' (parallel)' if args.workers > 1 else ' (sequential)'}")
    print(f"{'=' * 60}")

    print("\nPREREQUISITES (verify before relying on scan results):")
    print("  Auto-checked per org (warn-only): GitHub Actions allowlist permits the")
    print("    required Veracode actions. See actions_allowlist_issues.csv after the run.")
    print("  Manual - confirm yourself:")
    print("    - GitHub: you have organization owner or admin permissions to install")
    print("      third-party apps.")
    print("    - Veracode Platform: you have the Administrator or Security Lead role.")
    print("    - Veracode Platform: valid API credentials (static scans) and/or a valid")
    print("      SCA agent token (agent-based SCA scans).")
    print("    - The Veracode GitHub Workflow Integration is NOT supported in the United")
    print("      States Federal Region.")
    if "fed" in api_base.lower() or "fedramp" in web_base.lower():
        print("    [WARNING] api-base/web-base looks like a US Federal endpoint - this")
        print("              integration is not supported there.")
    print(f"{'=' * 60}\n")

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    try:
        all_orgs = list_orgs(api_base, token, args.enterprise, args.orgs_file)
    except OrgDiscoveryError as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(2)

    if args.orgs_file and args.enterprise:
        try:
            with open(args.orgs_file, encoding="utf-8") as f:
                filter_orgs = {ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")}
            filtered = [o for o in all_orgs if o in filter_orgs]
            print(f"[OK] Filtered to {len(filtered)} orgs from {args.orgs_file}")
            orgs = filtered
        except Exception as exc:
            print(f"[ERROR] Could not apply orgs-file filter: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        orgs = all_orgs

    orgs_txt_path = outdir / "orgs.txt"
    teams_map_csv_path = outdir / "teams_map.csv"

    if args.dry_run or not orgs_txt_path.exists():
        write_orgs_txt(orgs_txt_path, orgs)
    if not teams_map_csv_path.exists():
        write_teams_map_csv(teams_map_csv_path, orgs)

    validation_ok, validation_errors = validate_credentials(
        api_base=api_base,
        token=token,
        veracode_api_id=veracode_api_id,
        veracode_api_key=veracode_api_key,
        check_veracode=do_set_secrets or do_create_teams or do_link_teams,
    )
    if not validation_ok:
        print("\n[ERROR] Credential validation failed:", file=sys.stderr)
        for error in validation_errors:
            print(f"  - {error}", file=sys.stderr)
        print("\nPlease fix the credential issues and try again.", file=sys.stderr)
        sys.exit(1)

    checkpoint_file = outdir / "checkpoint.json"
    start_index = 0

    if args.resume and checkpoint_file.exists():
        try:
            checkpoint_data = json.loads(checkpoint_file.read_text(encoding="utf-8"))
            completed_set = set(checkpoint_data.get("completed", []))
            last_org = checkpoint_data.get("last_org")

            if completed_set:
                before = len(orgs)
                orgs = [o for o in orgs if o not in completed_set]
                skipped = before - len(orgs)
                print(f"[RESUME] Skipping {skipped} already-completed orgs (parallel checkpoint)\n")
            elif last_org and last_org in orgs:
                start_index = orgs.index(last_org)
                print(f"[RESUME] Restarting from: {last_org}  (skipping {start_index} orgs)\n")
        except Exception as exc:
            print(f"[WARNING] Failed to load checkpoint: {exc}")

    if args.skip_to:
        if args.skip_to in orgs:
            start_index = orgs.index(args.skip_to)
            print(f"[SKIP] Starting from: {args.skip_to}  (skipping {start_index} orgs)\n")
        else:
            print(f"[WARNING] --skip-to org '{args.skip_to}' not found in org list")

    if start_index > 0:
        orgs = orgs[start_index:]
        print(f"Processing {len(orgs)} remaining organizations\n")

    total_orgs = len(orgs)

    if args.apply and not args.resume:
        print(f"\n{'=' * 60}")
        print("   CONFIRMATION REQUIRED")
        print(f"{'=' * 60}")
        print(f"About to modify {total_orgs} organizations in APPLY mode.")
        print("Actions enabled:")
        if do_fix_repos:
            print("  - Check and fix default branch to 'main' in veracode repos")
            print("  - Add/update veracode.yml where missing")
            if teams_mode != "none":
                print("  - Inject/update teams in workflow files")
        if do_apply_repo:
            print("  - Create and import veracode repos")
        if do_create_teams:
            print("  - Create teams on Veracode platform via Identity API")
        if do_link_teams:
            print("  - Link teams to SCA workspaces on Veracode platform")
        if do_set_teams:
            print("  - Inject/update teams parameters into workflows")
            if not args.skip_iac_rbac:
                print("  - Convert IaC/Secrets workflow to Veracode CLI with RBAC (--app-name --create-app --teams)")
        if do_update_yml:
            print(f"  - Push veracode.yml from {yml_source_label}")
        if do_set_secrets:
            print("  - Set/overwrite Veracode org secrets")
        print("\nType 'yes' to continue (anything else will cancel): ", end="")
        if input().strip().lower() != "yes":
            print("\n[CANCELLED] Operation cancelled by user.")
            sys.exit(0)
        print(f"{'=' * 60}\n")

    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = outdir / f"audit_report_{run_timestamp}.json"

    ctx = RunContext(
        api_base=api_base,
        web_base=web_base,
        token=token,
        do_apply_repo=do_apply_repo,
        do_set_secrets=do_set_secrets,
        do_set_teams=do_set_teams,
        do_update_yml=do_update_yml,
        do_create_teams=do_create_teams,
        do_fix_repos=do_fix_repos,
        do_link_teams=do_link_teams,
        dry_run=args.dry_run,
        teams_mode=teams_mode,
        yml_content=yml_content,
        onboarding_yml_content=onboarding_yml_content,
        teams_map=teams_map,
        team_prefix=args.team_prefix,
        veracode_api_id=veracode_api_id,
        veracode_api_key=veracode_api_key,
        veracode_sa_api_id=veracode_sa_api_id,
        veracode_sa_api_key=veracode_sa_api_key,
        total_orgs=total_orgs,
        report_path=report_path,
        checkpoint_file=checkpoint_file,
        do_iac_rbac=not args.skip_iac_rbac,
        stats=RunStats(total_orgs=total_orgs),
    )

    workers = args.workers

    _cached_clone_dir: str | None = None
    if (do_apply_repo or (do_fix_repos and args.apply)) and check_git_available():
        label = "[PARALLEL]" if workers > 1 else ("[fix-repos]" if do_fix_repos else "[import-repo]")
        print(f"{label} Pre-cloning integration repo...")
        clone_ok, clone_msg, _cached_clone_dir = git_clone_bare(INTEGRATION_SOURCE_URL)
        if clone_ok:
            print(f"{label} Pre-clone successful\n")
        else:
            print(f"[WARNING] Pre-clone failed ({clone_msg}) - will clone per org\n")
            _cached_clone_dir = None

    try:
        if workers > 1:
            print(f"[PARALLEL] Running with {workers} workers\n")
            progress = ProgressDisplay(workers)

            _slot_sem = threading.Semaphore(workers)
            _slot_pool = list(range(workers))
            _slot_lock = threading.Lock()

            def _acquire_slot() -> int:
                _slot_sem.acquire()
                with _slot_lock:
                    return _slot_pool.pop(0)

            def _release_slot(slot_id: int) -> None:
                with _slot_lock:
                    _slot_pool.append(slot_id)
                _slot_sem.release()

            def _process_org_with_slot(
                org: str, idx: int, org_buf: OrgBuffer
            ) -> OrgBuffer:
                slot_id = _acquire_slot()
                org_buf._slot_id = slot_id  # type: ignore[attr-defined]
                progress.start(org, idx, total_orgs)
                try:
                    process_org(org, idx, ctx, _cached_clone_dir, org_buf)
                finally:
                    _release_slot(slot_id)
                return org_buf

            try:
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    all_futures: dict[Any, tuple[str, OrgBuffer]] = {}
                    for idx, org in enumerate(orgs, 1):
                        org_buf = OrgBuffer(org, idx, total_orgs, flush_on_add=False)
                        f = executor.submit(_process_org_with_slot, org, idx, org_buf)
                        all_futures[f] = (org, org_buf)

                    for future in as_completed(all_futures):
                        org_name, org_buf = all_futures[future]
                        slot_id = getattr(org_buf, "_slot_id", None)
                        try:
                            future.result()
                        except Exception as exc:
                            tprint(f"[ERROR] Unhandled exception for org {org_name}: {exc}")
                        if slot_id is not None:
                            org_buf.flush_then_clear(progress, slot_id)
                        else:
                            org_buf.flush()
            finally:
                progress.stop()
        else:
            for idx, org in enumerate(orgs, 1):
                process_org(org, idx, ctx, _cached_clone_dir)
    finally:
        if _cached_clone_dir and os.path.exists(_cached_clone_dir):
            shutil.rmtree(_cached_clone_dir, ignore_errors=True)

    finalize_report(report_path)

    write_csv(outdir / "missing_veracode_repo.csv", ["organization", "repo_name", "note"], ctx.missing_repo_rows)
    write_csv(outdir / "missing_workflow_app.csv", ["organization", "app_slug", "note"], ctx.missing_app_rows)
    write_csv(outdir / "manual_install_links.csv", ["organization", "install_link", "reason"], ctx.manual_links_rows)
    write_csv(outdir / "actions_allowlist_issues.csv", ["organization", "status", "missing_or_detail"], ctx.actions_allowlist_rows)

    st = ctx.stats
    st.end_time = datetime.now()
    duration_str = str(st.end_time - st.start_time).split(".")[0]

    print(f"\n{'=' * 70}")
    print("EXECUTION SUMMARY")
    print(f"{'=' * 70}")
    print(f"Mode            : {'APPLY' if args.apply else 'DRY-RUN'}")
    if workers > 1:
        print(f"Workers         : {workers}")
    print(f"Start Time      : {st.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"End Time        : {st.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration        : {duration_str}")
    print()
    print(f"Organizations   : {st.processed}/{st.total_orgs} processed")
    print()

    if do_fix_repos:
        fix_total = st.fix_repos_checked
        print(f"Fix-Repos       : {fix_total} checked, {st.fix_repos_remediated} remediated, {st.fix_repos_skipped} skipped (no repo)")
        db_total = st.default_branch_ok + st.default_branch_fixed + st.default_branch_failed
        if db_total > 0:
            print(f"Default Branch  : {st.default_branch_ok} already main, {st.default_branch_fixed} fixed, {st.default_branch_failed} failed (of {db_total})")
        if st.reimports_done > 0 or st.reimports_failed > 0:
            print(f"Re-imports      : {st.reimports_done} done, {st.reimports_failed} failed")
    else:
        repo_total = st.repo_success + st.repo_fail
        if repo_total > 0:
            repo_pct = (st.repo_success / repo_total) * 100
            print(f"Veracode Repos  : {st.repo_success} success, {st.repo_fail} failed ({repo_pct:.1f}% success)")

    app_total = st.app_installed + st.app_missing
    if app_total > 0:
        print(f"Workflow App    : {st.app_installed} installed, {st.app_missing} missing (see manual_install_links.csv)")

    actions_total = st.actions_allowed + st.actions_missing + st.actions_no_permission
    if actions_total > 0:
        np_suffix = "" if st.actions_no_permission == 0 else f", {st.actions_no_permission} unverifiable (no admin:org)"
        print(f"Actions Allowlist: {st.actions_allowed} ok, {st.actions_missing} incomplete{np_suffix} "
              f"(see actions_allowlist_issues.csv)")

    if do_create_teams:
        pt_total = st.teams_created_on_platform + st.teams_already_exist_on_platform + st.teams_create_failed_on_platform
        print(f"Platform Teams  : {st.teams_created_on_platform} created, "
              f"{st.teams_already_exist_on_platform} already exist, "
              f"{st.teams_create_failed_on_platform} failed (of {pt_total} orgs)")

    if do_link_teams:
        link_total = st.teams_linked_to_workspace + st.teams_link_already + st.teams_link_failed
        print(f"Team<->Workspace: {st.teams_linked_to_workspace} linked, "
              f"{st.teams_link_already} already linked, "
              f"{st.teams_link_failed} failed (of {link_total} orgs)")

    if do_set_teams:
        teams_total = st.teams_updated + st.teams_skipped + st.teams_failed
        print(f"Teams Injection : {st.teams_updated} updated, {st.teams_skipped} already current/skipped, {st.teams_failed} failed (of {teams_total} orgs)")

    if do_update_yml:
        yml_total = st.yml_updated + st.yml_skipped + st.yml_failed
        print(f"veracode.yml    : {st.yml_updated} updated, {st.yml_skipped} skipped, {st.yml_failed} failed (of {yml_total} orgs)")

    if args.dry_run and st.secrets_checked > 0:
        suffix = "" if st.secrets_no_permission == 0 else " - add admin:org scope to check secrets"
        print(
            f"Secrets (check) : {st.secrets_all_exist} all exist, {st.secrets_partial} partial, "
            f"{st.secrets_all_missing} all missing, {st.secrets_no_permission} no_permission "
            f"(of {st.secrets_checked} orgs checked){suffix}"
        )
    elif st.secrets_success > 0 or st.secrets_fail > 0:
        secrets_total = st.secrets_success + st.secrets_fail
        secrets_pct = (st.secrets_success / secrets_total) * 100
        print(f"Secrets         : {st.secrets_success} success, {st.secrets_fail} failed ({secrets_pct:.1f}% success)")

    snap = _rate_limiter.snapshot()
    print(f"Rate Limits     : {snap['requests_last_hour']}/{snap['hourly_cap']} req in last hour, "
          f"{snap['content_writes_last_hour']}/{snap['content_hour_cap']} writes in last hour, "
          f"{snap['content_writes_last_minute']}/{snap['content_min_cap']} writes in last minute")

    vc_snap = _veracode_rate_limiter.snapshot()
    if vc_snap["total_requests"]:
        print(f"Veracode Limits : {vc_snap['requests_last_minute']}/{vc_snap['minute_cap']} req in last minute, "
              f"{vc_snap['total_requests']} total this run")

    print(f"{'=' * 70}")
    print("\nOutputs written to:", outdir.resolve())
    print(" - orgs.txt")
    print(" - teams_map.csv")
    print(f" - audit_report_{run_timestamp}.json (this run)")
    print(" - missing_veracode_repo.csv")
    print(" - missing_workflow_app.csv")
    print(" - manual_install_links.csv")
    print(" - actions_allowlist_issues.csv")

    if ctx.missing_repo_rows or ctx.missing_app_rows:
        print(f"\n  Note: {len(ctx.missing_repo_rows)} org(s) have missing repos, "
              f"{len(ctx.missing_app_rows)} org(s) need app installation")
        print("    See CSV files above for details and actions needed.")

    sys.exit(0)


if __name__ == "__main__":
    main()
