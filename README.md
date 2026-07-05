# integrity-check — Log File Integrity Checker

A command-line tool that detects tampering in log files using **SHA-256**
hashes. On first run it records a *baseline* (a hash database); on later
runs it recomputes the hashes and compares them against the baseline,
reporting any discrepancy.

## Requirements

- Python 3.10+ (standard library only, no dependencies)

## Usage

```bash
# Initialize the baseline (single file or directory, recursive)
python integrity_check.py init /var/log
Hashes stored successfully. (3 file(s), database: ...)

# Check a single file
python integrity_check.py check /var/log/syslog
Status: Modified (Hash mismatch)

python integrity_check.py check /var/log/auth.log
Status: Unmodified

# Check an entire directory
python integrity_check.py check /var/log
[OK]       /var/log/auth.log
[MODIFIED] /var/log/syslog  (hash mismatch)
[NEW]      /var/log/new.log  (not in baseline)
[MISSING]  /var/log/old.log  (in baseline but not on disk)

# Accept a legitimate change (re-record the hash)
python integrity_check.py update /var/log/syslog
Hash updated successfully. (1 file(s))

# Filter by name pattern
python integrity_check.py check /var/log --pattern "*.log"
```

On Windows there is an `integrity-check.cmd` shim, so you can call
`integrity-check init C:\logs` directly from the terminal.

### Exit codes (useful for automation / cron)

| Code | Meaning |
|------|---------|
| 0 | No discrepancies |
| 1 | Discrepancy found (modified / new / missing) |
| 2 | Error (no baseline, tampered database, invalid path) |

## Where the hashes live (the "secure location")

By default under `~/.integrity-check/` (customizable via the
`INTEGRITY_CHECK_HOME` environment variable):

- `hashes.json` — the baseline: path → SHA-256 hash, size and mtime.
- `secret.key` — a random 256-bit key generated on first run.

Two protections are applied:

1. **Restricted permissions** — the directory is locked to the current
   user (`icacls` on Windows, `chmod 600/700` on Linux).
2. **HMAC-SHA256 signature** — the whole database is signed with the
   secret key. If someone edits or corrupts `hashes.json` (for example, to
   "update" the hash of a tampered log and hide the trail), the HMAC check
   fails and the tool refuses the database with a security warning instead
   of reporting a false "Unmodified".

## Concepts involved

- **Cryptographic hash (SHA-256):** a one-way function; changing a single
  bit of the file produces a completely different hash. Comparing hashes
  is a cheap and reliable way to detect content changes.
- **Hash ≠ authentication:** a hash on its own does not stop an attacker
  from recomputing and replacing the stored hash. That's why the baseline
  is signed with **HMAC**, which requires the secret key to produce a
  valid signature.
- **Baseline / FIM (File Integrity Monitoring):** the same principle used
  by tools like Tripwire and AIDE — record the known-good state and alert
  on any deviation.

## Testing

Run the automated test suite (isolated temp directory, does not touch your
real baseline):

```bash
python run_tests.py
```

It exercises 21 scenarios: clean check, tampered log, new/missing files,
`update`, missing baseline, tampered database (HMAC), rebuild from a
corrupted database, and `--pattern` filtering.

## Limitations (honest ones)

- If the attacker has the same privileges as the user running the tool,
  they can read the key and re-sign the database. In production the
  baseline should live on a separate machine or read-only media.
- Legitimate logs grow constantly; `check` will flag that as a change. The
  expected flow is to run `check` to audit and `update` to accept
  legitimate growth — or to monitor only already-rotated logs.
