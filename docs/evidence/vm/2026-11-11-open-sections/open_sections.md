# open_sections: where the file programs' time goes

Run: 20 rounds of 200,000 open+close, pinned.

Host speed: a null syscall cost 93.4 ns (median of 20 rounds; 83.7 to 106.9).

| section | samples per open | ns per sample (median) | cheapest to dearest round | net of the bracket |
|---|---|---|---|---|
| empty | 1.000 | 15.7 | 14.8 to 16.4 |  |
| open_all | 1.000 | 640.0 | 609.2 to 677.4 | 624.3 |
| open_claim | 1.000 | 23.1 | 22.1 to 24.4 | 7.6 |
| open_hdr | 1.000 | 69.6 | 66.0 to 73.1 | 54.0 |
| open_facts | 1.000 | 80.9 | 76.8 to 84.0 | 65.1 |
| open_obj | 1.000 | 29.9 | 28.3 to 31.3 | 14.1 |
| open_file | 1.000 | 28.5 | 27.3 to 30.1 | 13.0 |
| open_dpath | 1.000 | 102.5 | 97.3 to 106.4 | 86.7 |
| open_output | 1.000 | 52.5 | 50.0 to 68.2 | 36.7 |
| sess_entry | 1.000 | 265.6 | 251.3 to 286.9 | 250.2 |
| sess_file | 1.000 | 109.3 | 101.7 to 118.0 | 93.9 |
| sess_return | 1.000 | 38.0 | 35.5 to 39.8 | 22.1 |
| free_all | 1.000 | 320.3 | 306.2 to 335.2 | 304.7 |
| free_lookup | 1.000 | 28.3 | 27.1 to 29.7 | 12.7 |
| free_ring | 1.000 | 131.3 | 125.6 to 139.6 | 115.6 |
| free_delete | 1.000 | 62.0 | 59.1 to 66.2 | 46.2 |

- open_all: 640.0 ns, of which its 7 timed sections 387.1; the rest, 252.9 ns, is untimed code and the inner brackets' own cost.
- sess_entry: 265.6 ns, of which its 1 timed sections 109.3; the rest, 156.4 ns, is untimed code and the inner brackets' own cost.
- free_all: 320.3 ns, of which its 3 timed sections 221.6; the rest, 98.7 ns, is untimed code and the inner brackets' own cost.

