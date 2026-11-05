# python/: the analysis tier

It reads what the capture wrote. Nothing here runs during capture: the daemon writes the WAL, and this code reads it later, at its own pace (ADR-0007).

| Module | Job |
|---|---|
| [`p15/wal.py`](p15/wal.py) | P15W segments and runs ([format](../docs/formats/p15w-v1.md)): header checks, the §4 walk with torn and corrupt stops, run rules, records merged by time |
| [`p15/records.py`](p15/records.py) | ADR-0008 records decoded from the generated layouts ([`schema/generated/p15_records.py`](../schema/generated/p15_records.py)), checked like `p15_rec_check`, with no defaults |

```bash
python3 -m pip install --require-hashes --only-binary=:all: -r python/requirements.txt   # in the venv (STATE decision 9)
PYTHONPATH=python python3 -m p15.wal /var/lib/p15/<run-id>      # check a run and count its records
python3 -m unittest -v python/tests/test_wal.py python/tests/test_records.py
make it-pyreader                                                 # against the C writer, field by field
```

The packages are pinned with hashes in [`requirements.txt`](requirements.txt). `google-crc32c` must be its C implementation: the reader refuses to import if it isn't.
