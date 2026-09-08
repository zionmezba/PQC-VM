# Superseded measurement scripts

These are the original shell scripts that produced `results/metrics.csv`. They
are kept for provenance — the manuscript's audit section refers to them — and
**must not be run to produce results.** Every number they emit is wrong, in the
following specific ways:

| script | defect |
|---|---|
| `collect_metrics.sh` | `time_cmd` brackets the command with two separate `python3` heredoc invocations. The timed window contains interpreter teardown, `fork`/`exec` of `verify_cms.sh`, two `openssl` subprocesses each `dlopen`-ing `oqsprovider.so`, and a second interpreter startup. The recorded 176–214 ms is that overhead, not cryptography. `run_case` also writes an empty string into `sign_ms` on every row, so no signing time was ever measured. |
| `collect_metrics.sh` | `$(...)` captures `openssl dgst -verify`'s `Verified OK` stdout into the `verify_ms` column, breaking CSV rows across newlines. |
| `sign_cms.sh` | `openssl cms -sign` fails for PQC certificates and the script falls through to `openssl dgst -sign` without signalling failure, leaving every `.p7s` at 0 bytes. The `.hybrid` artifact is `printf "HYBRID:"` + CMS envelope + `printf "PQC:"` + a raw signature blob — not a CMS structure. |
| `sign_cms_fallback.sh` | uses `echo` between binary blobs, injecting newlines into binary data. |
| `verify_cms.sh` | prints "not implemented yet" and exits 1 for `.hybrid` inputs. Classical verification omits `-CAfile`/`-noverify` against a self-signed certificate, so every classical row reports `pass=0`. |
| `make_keys.sh` | emits PEM files whose on-disk sizes (241 / 3036 / 8196 B) were reported as "key sizes". They are base64 with headers, not key sizes. |

The replacement lives in [`bench/`](../../bench/). See the repository README.
