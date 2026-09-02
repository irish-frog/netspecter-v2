#!/usr/bin/env python3
"""Profile NetSpecter report context generation for common date ranges."""

import argparse
import time
from datetime import datetime, timedelta
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netspecter_db import query  # noqa: E402
from services.report_context_service import build_reporting_context_from_request  # noqa: E402


class ReportArgs(dict):
    def getlist(self, key):
        value = self.get(key)
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]


def _dt_text(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _scalar(sql, params=()):
    rows = query(sql, params)
    if not rows:
        return 0
    row = rows[0]
    try:
        return int(row[0] or 0)
    except Exception:
        return int(next(iter(row), 0) or 0)


def range_counts(start_time, end_time):
    return {
        "traffic_rows": _scalar(
            "SELECT COUNT(*) FROM traffic_intervals WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "estimated_rows": _scalar(
            "SELECT COUNT(*) FROM estimated_app_traffic WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "destination_rows": _scalar(
            "SELECT COUNT(*) FROM remote_traffic_intervals WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "dns_rows": _scalar(
            "SELECT COUNT(*) FROM dns_querylog WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "quality_rows": _scalar(
            "SELECT COUNT(*) FROM internet_quality WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
        "unique_ips": _scalar(
            "SELECT COUNT(DISTINCT ip) FROM traffic_intervals WHERE ts BETWEEN ? AND ?",
            (start_time, end_time),
        ),
    }


def profile_range(days, report_type):
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(days=days)
    start_time = _dt_text(start_dt)
    end_time = _dt_text(end_dt)
    args = ReportArgs({
        "report_type": report_type,
        "start": start_time,
        "end": end_time,
        "period": "custom",
    })
    counts = range_counts(start_time, end_time)
    started = time.perf_counter()
    context = build_reporting_context_from_request(args)
    elapsed = time.perf_counter() - started
    perf = context.get("performance") or {}
    return {
        "days": days,
        "elapsed_s": elapsed,
        "sql_queries": int(perf.get("sql_queries") or 0),
        "sql_ms": float(perf.get("sql_query_ms") or 0),
        "category_ms": float(perf.get("category_summary_ms") or 0),
        "identity_calls": int(perf.get("add_device_identity_mappings_calls") or 0),
        "identity_queries": int(perf.get("add_device_identity_mappings_queries") or 0),
        "identity_ips": int(perf.get("identity_mapping_ips") or 0),
        **counts,
    }


def main():
    parser = argparse.ArgumentParser(description="Profile report generation without a web timeout.")
    parser.add_argument("--report-type", default="internet", choices=["internet", "management"])
    parser.add_argument("--days", nargs="*", type=int, default=[1, 2, 7, 30])
    args = parser.parse_args()

    print(f"NetSpecter report generation profile ({args.report_type})")
    print(
        "days elapsed_s sql_queries sql_ms category_ms identity_calls identity_queries "
        "identity_ips traffic_rows estimated_rows destination_rows dns_rows quality_rows unique_ips"
    )
    for days in args.days:
        row = profile_range(days, args.report_type)
        print(
            f"{row['days']} "
            f"{row['elapsed_s']:.3f} "
            f"{row['sql_queries']} "
            f"{row['sql_ms']:.1f} "
            f"{row['category_ms']:.1f} "
            f"{row['identity_calls']} "
            f"{row['identity_queries']} "
            f"{row['identity_ips']} "
            f"{row['traffic_rows']} "
            f"{row['estimated_rows']} "
            f"{row['destination_rows']} "
            f"{row['dns_rows']} "
            f"{row['quality_rows']} "
            f"{row['unique_ips']}"
        )


if __name__ == "__main__":
    main()
