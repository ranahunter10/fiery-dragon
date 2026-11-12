import sys
from p15 import wal as W
run = W.read_run(__import__("pathlib").Path(sys.argv[1]))
errors, last, n = [], None, 0
for r in run.ring_records(2, errors):
    if r.name == "FILE_STATS":
        last, n = r, n + 1
print("file_stats records", n, "read errors", len(errors))
if last is not None:
    print("last at ts_ns", last.h["ts_ns"])
    for k, v in last.f.items():
        print(f"  {k} {v}")
