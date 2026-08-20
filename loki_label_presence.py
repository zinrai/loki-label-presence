#!/usr/bin/env python3
"""Check whether an expected set of label values is present in Loki over a time range.

Loki is queried through logcli. The report carries the resolved absolute range, the digest
of the expectation file and the versions in use, so the same check can be repeated later.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta

# Not a single non-zero code: callers have to tell "no logs were found" apart from
# "the check could not be made".
EXIT_ALL_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_ERROR = 2

DEFAULT_TIMEOUT = 60.0

STATUS_FOUND = "found"
STATUS_NOT_FOUND = "not_found"


# Not reported as not_found: a check that could not run must never read as one that ran.
class ProbeError(Exception):
    pass


_DURATION = re.compile(r"(\d+)([dhms])")
_DURATION_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def parse_duration(text):
    if not text or not re.fullmatch(r"(\d+[dhms])+", text):
        raise ProbeError("invalid duration %r (expected forms like 7d or 24h)" % text)

    seconds = 0
    for number, unit in _DURATION.findall(text):
        seconds = seconds + int(number) * _DURATION_UNITS[unit]

    if seconds <= 0:
        raise ProbeError("duration %r must be positive" % text)
    return timedelta(seconds=seconds)


def parse_time(text):
    s = text.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        ts = datetime.fromisoformat(s)
    except ValueError:
        raise ProbeError("invalid timestamp %r (expected RFC3339)" % text)

    # Not defaulted to the local zone: the range recorded in the report would then depend
    # on the host the check happened to run on.
    if ts.tzinfo is None:
        raise ProbeError("invalid timestamp %r (missing timezone offset)" % text)
    return ts


def resolve_range(since, start, end, now):
    has_absolute = bool(start) or bool(end)

    # Not both: a range assembled from two sources leaves the reader of the report unable
    # to tell which one it followed.
    if since and has_absolute:
        raise ProbeError("--since cannot be combined with --start/--end")
    if not since and not has_absolute:
        raise ProbeError("either --since, or --start and --end, is required")

    if since:
        return now - parse_duration(since), now

    if not start or not end:
        raise ProbeError("--start and --end must be given together")

    start_ts = parse_time(start)
    end_ts = parse_time(end)
    if start_ts >= end_ts:
        raise ProbeError("--start must be earlier than --end")
    return start_ts, end_ts


_EXPECTATION_KEYS = ("label", "values")
_ENTRY_KEYS = ("description", "value")


def unknown_keys(mapping, allowed):
    unknown = []
    for key in mapping:
        if key not in allowed:
            unknown.append(key)
    unknown.sort()
    return unknown


def parse_expectations(data):
    if not isinstance(data, dict):
        raise ProbeError("the expectation file must be an object")

    # Not ignored: a key written to narrow the check would silently widen it instead, and
    # the wider result would still look like a valid report.
    unknown = unknown_keys(data, _EXPECTATION_KEYS)
    if unknown:
        raise ProbeError("unknown key in the expectation file: %s" % ", ".join(unknown))

    label = data.get("label")
    if not isinstance(label, str) or not label.strip():
        raise ProbeError("label must be a non-empty string")

    values = data.get("values")
    if not isinstance(values, list) or not values:
        raise ProbeError("values must be a non-empty array")

    entries = []
    seen = {}
    for item in values:
        description, value = parse_entry(item)
        if value not in seen:
            seen[value] = description
            entries.append({"description": description, "value": value})
            continue
        # Not merged: one query would then stand as evidence for two subjects, and either
        # of them falling silent would still read as found.
        if seen[value] != description:
            raise ProbeError(
                "value %r carries two descriptions: %r and %r"
                % (value, seen[value], description)
            )

    return label.strip(), entries


def parse_entry(item):
    if not isinstance(item, dict):
        raise ProbeError("each entry in values must be an object: %r" % (item,))

    unknown = unknown_keys(item, _ENTRY_KEYS)
    if unknown:
        raise ProbeError("unknown key in a values entry: %s" % ", ".join(unknown))

    # Not a bare value: a lookup key on its own says nothing about what is expected to be
    # there, and a changed key becomes indistinguishable from a replaced subject.
    description = item.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ProbeError(
            "description in a values entry must be a non-empty string: %r" % (item,)
        )

    value = item.get("value")
    if not isinstance(value, str) or not value.strip():
        raise ProbeError(
            "value in a values entry must be a non-empty string: %r" % (item,)
        )

    return description.strip(), value.strip()


def load_expectations(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ProbeError("cannot read the expectation file: %s" % e)

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ProbeError("cannot parse the expectation file as JSON: %s" % e)

    label, entries = parse_expectations(data)

    # Not digested over the parsed entries: the file as committed is what identifies the
    # check that was made.
    identity = {
        "path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "count": len(entries),
    }
    return identity, label, entries


def build_query(label, value):
    # Not plain interpolation: the value has to reach LogQL quoted and escaped.
    return "{%s=%s}" % (label, json.dumps(value, ensure_ascii=False))


def non_empty_lines(text):
    lines = []
    for line in text.splitlines():
        if line.strip():
            lines.append(line.strip())
    return lines


def check_exit(code, argv, stderr):
    if code == 0:
        return

    # Not folded into an empty result: an authentication error or a rejected query would
    # then be indistinguishable from a value that is genuinely absent.
    raise ProbeError(
        "logcli failed with exit code %d: %s\n%s"
        % (code, " ".join(argv), stderr.strip())
    )


def read_version(stdout, stderr):
    # Not taken from stdout alone: logcli prints --version on stderr.
    text = stdout.strip()
    if not text:
        text = stderr.strip()
    if not text:
        return ""

    lines = text.splitlines()
    return lines[0].strip()


def read_query_output(stdout):
    lines = non_empty_lines(stdout)
    if not lines:
        return None

    try:
        record = json.loads(lines[0])
    except ValueError as e:
        raise ProbeError("cannot parse logcli output as JSON: %s\n%s" % (e, lines[0]))

    timestamp = record.get("timestamp")
    # Not left unset: a change in logcli's output has to surface as a failed run rather
    # than as a found value carrying no evidence of when it was seen.
    if not timestamp:
        raise ProbeError("logcli output has no timestamp field: %s" % lines[0])
    return timestamp


def check_label_present(names, label):
    if label in names:
        return

    present = ", ".join(names)
    if not present:
        present = "(none)"

    raise ProbeError(
        "label %r is not a stream label in this range, so every value would be "
        "reported as not_found\nlabels present in the range: %s" % (label, present)
    )


def subprocess_runner(argv, timeout):
    try:
        p = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise ProbeError("cannot execute logcli: %s" % argv[0])
    except subprocess.TimeoutExpired:
        raise ProbeError(
            "logcli timed out after %s seconds: %s" % (timeout, " ".join(argv))
        )
    return p.returncode, p.stdout, p.stderr


class Logcli:
    def __init__(self, binary="logcli", timeout=DEFAULT_TIMEOUT):
        self.binary = binary
        self.timeout = timeout

    def _run(self, args):
        argv = [self.binary] + args
        code, out, err = subprocess_runner(argv, self.timeout)
        check_exit(code, argv, err)
        return out, err

    def version(self):
        out, err = self._run(["--version"])
        return read_version(out, err)

    def label_names(self, start, end):
        out, _ = self._run(["labels", "--from", _fmt(start), "--to", _fmt(end), "-q"])
        return non_empty_lines(out)

    def last_seen(self, query, start, end):
        args = [
            "query",
            query,
            "--from",
            _fmt(start),
            "--to",
            _fmt(end),
            "--limit",
            "1",
            "-o",
            "jsonl",
            "-q",
        ]
        out, _ = self._run(args)
        return read_query_output(out)


def _fmt(ts):
    return ts.isoformat()


def probe(logcli, label, entries, start, end, progress=None):
    results = []
    for index, entry in enumerate(entries, 1):
        if progress:
            progress(index, len(entries), entry["value"])

        query = build_query(label, entry["value"])
        timestamp = logcli.last_seen(query, start, end)

        status = STATUS_NOT_FOUND
        if timestamp:
            status = STATUS_FOUND

        results.append(
            {
                "description": entry["description"],
                "value": entry["value"],
                "status": status,
                "last_seen": timestamp,
            }
        )
    return results


def build_report(now, addr, label, start, end, expectations, versions, results):
    found = 0
    for result in results:
        if result["status"] == STATUS_FOUND:
            found = found + 1

    return {
        "executed_at": _fmt(now),
        "query": {
            "addr": addr,
            "label": label,
            "start": _fmt(start),
            "end": _fmt(end),
        },
        "expectations": expectations,
        "tool": versions,
        "summary": {"found": found, "not_found": len(results) - found},
        "results": results,
    }


def write_report(report, path):
    body = json.dumps(report, indent=2, ensure_ascii=False) + "\n"

    if not path:
        sys.stdout.write(body)
        return

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
    except OSError as e:
        raise ProbeError("cannot write the report: %s" % e)


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="loki-label-presence",
        description="Check whether an expected set of label values is present in Loki.",
        epilog="The endpoint and credentials come from logcli's environment variables "
        "(LOKI_ADDR, LOKI_USERNAME, LOKI_BEARER_TOKEN_FILE, LOKI_ORG_ID and so on).",
    )
    p.add_argument("--expectations", required=True, help="path to the expectation file")
    p.add_argument("--since", help="range relative to now, for example 7d")
    p.add_argument("--start", help="start of the range (RFC3339)")
    p.add_argument("--end", help="end of the range (RFC3339)")
    p.add_argument("--output", help="where to write the report (default: stdout)")
    p.add_argument("--logcli", default="logcli", help="path to logcli")
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="timeout per query, in seconds",
    )
    return p.parse_args(argv)


def _progress(index, total, value):
    sys.stderr.write("\r%d/%d %s\033[K" % (index, total, value))
    if index == total:
        sys.stderr.write("\n")
    sys.stderr.flush()


def run(argv, now):
    args = parse_args(argv)
    start, end = resolve_range(args.since, args.start, args.end, now)

    addr = os.environ.get("LOKI_ADDR", "").strip()
    # Not left to logcli's own default: an implicit localhost target would leave the
    # report unable to say where the check was made.
    if not addr:
        raise ProbeError("LOKI_ADDR is not set")

    expectations, label, entries = load_expectations(args.expectations)

    logcli = Logcli(args.logcli, args.timeout)
    versions = {"logcli": logcli.version(), "python": sys.version.split()[0]}

    # Not deferred to the probe loop: a label that is not indexed returns nothing for
    # every value, which on the report is indistinguishable from a total outage.
    names = logcli.label_names(start, end)
    check_label_present(names, label)

    # Not written when stderr is redirected: a collected run stays free of progress lines.
    progress = None
    if sys.stderr.isatty():
        progress = _progress

    results = probe(logcli, label, entries, start, end, progress)
    report = build_report(now, addr, label, start, end, expectations, versions, results)
    write_report(report, args.output)

    if report["summary"]["not_found"]:
        return EXIT_NOT_FOUND
    return EXIT_ALL_FOUND


def main(argv=None, now=None):
    if argv is None:
        argv = sys.argv[1:]
    if now is None:
        now = datetime.now().astimezone().replace(microsecond=0)

    try:
        return run(argv, now)
    except ProbeError as e:
        sys.stderr.write("loki-label-presence: %s\n" % e)
        return EXIT_ERROR
    # Not left to propagate: an uncaught exception exits with 1, which here would be read
    # as a completed check that found missing values.
    except Exception as e:
        sys.stderr.write("loki-label-presence: unexpected error: %r\n" % e)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
