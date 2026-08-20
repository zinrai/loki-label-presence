# loki-label-presence

Check whether a known set of label values is present as logs in Loki over a given time range.

The point is not fault detection but making the check repeatable. The expected values are input, and a run produces a JSON report holding the range that was covered and the grounds for each verdict.

Loki is queried through [logcli](https://grafana.com/docs/loki/latest/query/logcli/).

## Requirements

- Python, using the standard library only
- logcli on the machine that runs the check

## Usage

`LOKI_ADDR` is required. Without it, logcli would quietly fall back to a local endpoint and the report could not say where the check was made.

```
export LOKI_ADDR=http://loki.example.net/read
python3 loki_label_presence.py --expectations hosts.json --since 7d
```

| Option | Required | Description |
|---|---|---|
| `--expectations` | yes | Path to the expectation file. See [expectations.json.example](expectations.json.example) for the shape |
| `--since`, or `--start` and `--end` | yes | The range to cover. Relative forms such as `7d` or `12h`, or absolute RFC3339 timestamps |
| `--output` | no | Where to write the report. Defaults to stdout |
| `--logcli` | no | Path to logcli |
| `--timeout` | no | Timeout per query, in seconds |

## The report

```json
{
  "executed_at": "2026-08-19T21:39:03+09:00",
  "query": {
    "addr": "http://loki.example.net/read",
    "label": "host",
    "start": "2026-08-12T21:39:03+09:00",
    "end": "2026-08-19T21:39:03+09:00"
  },
  "expectations": {
    "path": "hosts.json",
    "sha256": "9f79817e3815be518f4f795f6b59e9383a522755dcf35ac24d603f9f0c777a56",
    "count": 2
  },
  "tool": {
    "logcli": "logcli, version 3.7.6 (branch: release-3.7.x, revision: 5003600d)",
    "python": "3.14.6"
  },
  "summary": {"found": 1, "not_found": 1},
  "results": [
    {"description": "app-01", "value": "10.0.0.1", "status": "found", "last_seen": "2026-08-19T21:38:54.951356879+09:00"},
    {"description": "app-02", "value": "10.0.0.2", "status": "not_found", "last_seen": null}
  ]
}
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every expected value was found |
| 1 | At least one value was not found. The run itself completed |
| 2 | The run failed: logcli error, invalid input, or an unexpected exception |

A failed run writes no report. To check several expectation files, loop outside the tool, keeping in mind that exit code 1 is not a reason to stop it but exit code 2 is.

```sh
for f in expectations/*.json; do
  rc=0
  python3 loki_label_presence.py --expectations "$f" --since 7d \
    --output "reports/$(basename "$f" .json).json" || rc=$?
  case $rc in
    0) ;;
    1) echo "values missing: $f" >&2 ;;
    *) echo "check failed: $f" >&2; exit 2 ;;
  esac
done
```

## License

This project is licensed under the [MIT License](LICENSE).
