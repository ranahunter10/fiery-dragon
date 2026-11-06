set -u
T=$(mktemp -d /tmp/c6neg-XXXX)
build/p15d --no-net --wal-dir $T/c6 --duration 5 --stats-ms 500 2>$T/err & P=$!
for i in $(seq 150); do grep -q code=start $T/err 2>/dev/null && break; sleep 0.1; done
python3 daemon/tests/it_provenance.py workload $T
wait $P; echo "p15d exit=$?"; kill $(cat $T/c6-live.pid)
d=$(ls -d $T/c6/*/ | head -1); [ -n "$d" ] || { cat $T/err; exit 1; }
PYTHONPATH=python python3 daemon/tests/it_provenance.py check $d $T >$T/o; echo "untampered: exit=$? ok=$(grep -c '^ok' $T/o) fail=$(grep -c '^FAIL' $T/o)"
for t in 'e["streams"]["stdin"]["ino"]+=1' 'e["streams"]["stderr"]["mode"]=0o010600' 'e["live_pid"]+=1' 'e["memfd_exit"]=1' 'e["pipe_exit"]=[0,1]'; do
  cp $T/c6-expect.json $T/keep.json
  python3 -c "import json,sys;p=sys.argv[1];e=json.load(open(p));$t;json.dump(e,open(p,'w'))" $T/c6-expect.json
  PYTHONPATH=python python3 daemon/tests/it_provenance.py check $d $T >$T/o; rc=$?
  echo "tampered $t: exit=$rc; $(grep '^FAIL' $T/o | cut -c1-90 | tr '\n' '|')"
  cp $T/keep.json $T/c6-expect.json
done
rm -rf $T
