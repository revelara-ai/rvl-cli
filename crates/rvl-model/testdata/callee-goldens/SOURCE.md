# Decision-model callee goldens

The training packets' callee block was written by the decision model's
private training exporter, from the site's own file: a name called on the
site line, its definition in that file, and 40 numbered lines from it.
`render::callee_definition` ports that function, and these files hold it to
the exporter's bytes with no network:

- The fixture files (`client.py`, `store.go`, `api.ts`, `worker.js`,
  `lib.rs`, `Gateway.java`, `Fetcher.cs`, `long.py`, `edges.txt`): small
  sources with the cases that matter. Two calls on one line, a call into
  another file, a definition near the end of the file, one longer than the
  block, each language's definition form. `edges.txt` has a CRLF definition
  and the characters where Go's regular expressions and the regex crate's
  differ (no-break space, vertical tab, a non-ASCII letter).
- `callee-goldens.jsonl`: one row per line of each fixture, from line 0 to
  two past the last line, `{"file", "line", "name", "block"}`, written by
  running the exporter's function on each fixture. An empty name is no
  callee block.

When a fixture or the exporter's function changes, run that function on the
fixtures again and write `callee-goldens.jsonl` again.
