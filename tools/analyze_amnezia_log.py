#!/usr/bin/env python3
"""Summarize Amnezia logs without printing server keys, URLs or raw log lines.

Usage: python tools/analyze_amnezia_log.py client.log service.log
The combined timeline uses UTC timestamps; overlapping log copies count twice.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import re
from typing import Iterable


STAMP = re.compile(r"^\[([^]]+)\]")
EXCLUSION = re.compile(r"Adding exclusion route for\s+(\S+)")
CAPTURE = re.compile(r"Capturing route to\s+(\S+)")
ERROR = re.compile(r"Failed to update route:\s*(\d+)")


def analyze(lines: Iterable[str], since: datetime | None = None) -> dict:
    events: dict[str, list[datetime]] = {}
    routes: list[ipaddress.IPv4Network] = []
    captures: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    invalid = 0
    changes = 0
    for line in lines:
        match = STAMP.match(line)
        if not match:
            continue
        try:
            stamp = datetime.fromisoformat(match[1].replace("Z", "+00:00"))
        except ValueError:
            continue
        if since is not None and stamp < since:
            continue
        for event, marker in (
            ("connection_started", "Trying to connect to VPN"),
            ("tunnel_started", "Startup complete"),
            ("handshake_received", "Received handshake response"),
            ("client_connected", "Parse command: connected"),
            ("route_changes", "WindowsRouteMonitor : Routes changed"),
            ("exclusions", "Adding exclusion route for"),
            ("app_rules_started", "WindowsSplitTunnel : Pushing new Ruleset for Split-Tunnel"),
            ("app_rules_applied", "WindowsSplitTunnel : New Configuration applied"),
        ):
            if marker in line:
                events.setdefault(event, []).append(stamp)
        if "WindowsRouteMonitor : Routes changed" in line:
            changes += 1
        if match := ERROR.search(line):
            errors[match[1]] += 1
        if match := CAPTURE.search(line):
            try:
                captures[str(ipaddress.ip_network(match[1]))] += 1
            except ValueError:
                pass
        if match := EXCLUSION.search(line):
            try:
                network = ipaddress.ip_network(match[1])
                if network.version == 4:
                    routes.append(network)
            except ValueError:
                invalid += 1

    def duration(start: str, end: str) -> float | None:
        # Only compare first events when their order makes sense. Multiple
        # attempts are identified in event counts and need separate log slices.
        if not events.get(start) or not events.get(end):
            return None
        seconds = (min(events[end]) - min(events[start])).total_seconds()
        return round(seconds, 3) if seconds >= 0 else None

    return {
        "events": {
            name: {"count": len(times), "first": min(times).isoformat(), "last": max(times).isoformat()}
            for name, times in sorted(events.items())
        },
        "first_connection_seconds": duration("connection_started", "client_connected"),
        "first_handshake_to_connected_seconds": duration("handshake_received", "client_connected"),
        "route_change_notifications": changes,
        "route_update_errors": dict(errors.most_common()),
        "most_captured_routes": dict(captures.most_common(10)),
        "route_candidates": len(routes),
        "unique_routes": len(set(routes)),
        "compacted_routes": len(list(ipaddress.collapse_addresses(routes))),
        "invalid_route_additions": invalid,
    }


def analyze_attempts(lines: Iterable[str], since: datetime | None = None) -> list[dict]:
    """Group attempts by connection starts; never compare events across attempts."""
    stamped = []
    for line in lines:
        if not (match := STAMP.match(line)):
            continue
        try:
            stamp = datetime.fromisoformat(match[1].replace("Z", "+00:00"))
        except ValueError:
            continue
        if since is None or stamp >= since:
            stamped.append((stamp, line))
    stamped.sort(key=lambda item: item[0])
    attempts: list[list[str]] = []
    for _, line in stamped:
        if "Trying to connect to VPN" in line:
            attempts.append([])
        if attempts:
            attempts[-1].append(line)
    return [analyze(attempt) for attempt in attempts]


def compare_state(report: dict, state: dict) -> dict:
    """Counts can reveal a stale client; equal counts cannot prove equal routes."""
    started = report.get("events", {}).get("connection_started", {}).get("first")
    expected = state.get("entry_count")
    if not started or not isinstance(expected, int) or state.get("manual_entries_preserved", 0):
        return {"status": "unavailable", "reason": "need a connection log and a plan without manual domain entries"}
    if datetime.fromisoformat(started) < datetime.fromisoformat(state["updated_at"].replace("Z", "+00:00")):
        return {"status": "unavailable", "reason": "connection log predates the saved plan"}
    observed = report["unique_routes"] + report["invalid_route_additions"]
    return {
        "status": "excess_routes" if observed > expected else "counts_match" if observed == expected else "incomplete_or_different_routes",
        "expected_entries": expected,
        "observed_unique_exclusions": observed,
        "active_routes_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    period = parser.add_mutually_exclusive_group()
    period.add_argument("--since", type=datetime.fromisoformat, help="UTC ISO timestamp, e.g. 2026-01-01T12:00:00+00:00")
    period.add_argument("--latest-connection", action="store_true", help="ignore earlier attempts")
    parser.add_argument("--attempts", action="store_true", help="summarize each connection attempt separately")
    parser.add_argument("--state", type=Path, help="compare with updater status.json (read only)")
    args = parser.parse_args()

    def lines():
        for path in args.logs:
            with path.open(encoding="utf-8-sig", errors="replace") as stream:
                yield from stream

    try:
        since = args.since
        if args.attempts and args.latest_connection:
            parser.error("--attempts and --latest-connection cannot be combined")
        if since is not None and since.tzinfo is None:
            parser.error("--since must include a timezone")
        if args.latest_connection:
            starts = []
            for line in lines():
                if "Trying to connect to VPN" in line and (match := STAMP.match(line)):
                    try:
                        starts.append(datetime.fromisoformat(match[1].replace("Z", "+00:00")))
                    except ValueError:
                        pass
            if not starts:
                parser.exit(1, "No connection start in these logs\n")
            since = max(starts)
        state = json.loads(args.state.read_text(encoding="utf-8-sig")) if args.state else None
        if args.attempts:
            reports = analyze_attempts(lines(), since)
            if state is not None:
                for report in reports:
                    report["plan_comparison"] = compare_state(report, state)
            output = {"attempts": reports}
        else:
            report = analyze(lines(), since)
            if state is not None:
                report["plan_comparison"] = compare_state(report, state)
            output = report
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Cannot read log: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
