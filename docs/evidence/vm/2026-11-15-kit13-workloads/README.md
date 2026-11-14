# Kit fd-vm-test13 on the VM, 2026-11-15: the masquerade scenario

`vm/integration-12` (`manifest.txt`, tree `aa77458…`): kit 12's tree with a4 dropping a copy of bash.
Journal: E-0324.

a4-masquerade ran (workload rc 0) and every check holds (`workloads/a4-masquerade/compare.txt`):
- processes 6/6, parent links 5/5, execs 6/6, opens 80/80; bytes exact in all 6 processes;
- R1 fired: the dropped `.X11/kworker` was written by cp and run by another process;
- the rename to `kworker/0:1` (prctl) is in the graph;
- the forward walk does not reach the cron line from the dropped program (expected: the program
  wrote nothing), so the graph does not over-connect here.

With kits 11 to 13, all 12 scenarios have run on the VM with every capture and graph check holding;
the only detection gap is R4 on the reverse shell (E-0322).
