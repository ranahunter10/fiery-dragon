# open_sections: where the file programs' time goes

Run: 20 rounds of 200,000 open+close, pinned.

Host speed: a null syscall cost 85.9 ns (median of 20 rounds; 83.1 to 100.0).

| section | samples per open | ns per sample (median) | cheapest to dearest round | net of the bracket |
|---|---|---|---|---|
| empty | 1.000 | 14.9 | 14.5 to 16.5 |  |
| open_all | 1.000 | 507.5 | 485.3 to 531.5 | 492.5 |
| open_claim | 1.000 | 23.3 | 22.5 to 23.9 | 8.2 |
| open_hdr | 1.000 | 30.8 | 29.7 to 32.0 | 15.8 |
| open_facts | 1.000 | 21.1 | 20.0 to 22.1 | 5.9 |
| open_obj | 1.000 | 32.4 | 30.6 to 35.4 | 17.4 |
| open_file | 1.000 | 28.1 | 27.0 to 29.7 | 13.1 |
| open_dpath | 1.000 | 109.0 | 104.0 to 117.4 | 93.7 |
| open_output | 1.000 | 52.5 | 48.5 to 57.0 | 37.6 |
| sess_entry | 1.000 | 154.6 | 145.8 to 165.8 | 139.6 |
| sess_file | 1.000 | 97.4 | 90.7 to 107.2 | 82.4 |
| sess_return | 1.000 | 35.3 | 33.6 to 37.5 | 20.3 |
| free_all | 1.000 | 260.0 | 251.0 to 274.5 | 244.9 |
| free_lookup | 1.000 | 39.8 | 36.0 to 42.7 | 25.0 |
| free_ring | 1.000 | 67.4 | 63.4 to 74.3 | 52.6 |
| free_delete | 1.000 | 58.5 | 56.2 to 62.2 | 43.7 |

- open_all: 507.5 ns, of which its 7 timed sections 297.0; the rest, 210.5 ns, is untimed code and the inner brackets' own cost.
- sess_entry: 154.6 ns, of which its 1 timed sections 97.4; the rest, 57.2 ns, is untimed code and the inner brackets' own cost.
- free_all: 260.0 ns, of which its 3 timed sections 165.8; the rest, 94.2 ns, is untimed code and the inner brackets' own cost.

