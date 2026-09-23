#!/usr/bin/env python3
"""Record authenticated /auth/me availability without logging credentials."""

import argparse
import datetime as dt
import signal
import subprocess
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Full gateway-api /auth/me URL")
    parser.add_argument("curl_config", help="Private curl config containing authentication header")
    parser.add_argument("output", help="TSV log path")
    # nginx limits /api/gateway/ to 60 requests/minute per client address.
    # Leave headroom for concurrent authenticated operation-status polling.
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--expected", type=int, default=200)
    args = parser.parse_args()
    if args.interval <= 0 or not args.url.endswith("/auth/me"):
        parser.error("positive interval and an /auth/me URL are required")

    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    total = failures = 0
    with open(args.output, "w", encoding="utf-8") as log:
        log.write("timestamp_utc\tstatus\tseconds\tresult\n")
        log.flush()
        while not stopping:
            started = time.monotonic()
            result = subprocess.run(
                [
                    "curl", "--silent", "--output", "/dev/null", "--max-time", "3",
                    "--config", args.curl_config, "--write-out", "%{http_code} %{time_total}",
                    args.url,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            status, _, seconds = result.stdout.partition(" ")
            ok = result.returncode == 0 and status == str(args.expected)
            total += 1
            failures += not ok
            now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
            log.write(f"{now}\t{status or '000'}\t{seconds.strip() or '-'}\t{'ok' if ok else 'fail'}\n")
            log.flush()
            time.sleep(max(0, args.interval - (time.monotonic() - started)))
        log.write(f"# total={total} failures={failures}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
