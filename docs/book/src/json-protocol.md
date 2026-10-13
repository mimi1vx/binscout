# JSON protocol

Every command prints exactly one JSON value to stdout and exits 0.
A runtime failure prints a single `{"error": "..."}` value and exits 1,
so stdout is always valid JSON. (Clap usage errors for unknown
flags/subcommands still go to stderr with exit 2.)

Real example — opening the repo's `tests/fixtures/raw-x64.bin`:

```sh
$ binscout load tests/fixtures/raw-x64.bin
{"annotations":0,"arch":"x86_64","binary":"tests/fixtures/raw-x64.bin","blocks":1,"content_hash":13197063251454239466,"db_path":"tests/fixtures/raw-x64.rsdbg.redb","entry":null,"format":"raw","functions":1,"insns":3,"size":3,"strings":0,"version":"0.1.0","xrefs":0}
```

List commands (`functions`, `xrefs`, `strings`) paginate with `--offset`
and `--limit`; limits are capped server-side (1024 rows).
