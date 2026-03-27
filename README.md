# lolbin-watcher

**Lightweight, snapshot-based process activity monitor for Windows.**  
Detects suspicious process behavior — LOLBin execution, temp-directory launches, and unknown executables — and logs structured events to JSONL.

> ⚠️ **This is an educational proof-of-concept, not a production security tool.**  
> lolbin-watcher is a **detection and logging tool only**

---

## What It Does

lolbin-watcher periodically snapshots running processes and flags suspicious activity based on a set of heuristic rules:

- 🔍 **Process snapshot collection** via `sysinfo` — captures PID, name, and executable path
- 🚩 **Rule-based detection** — flags LOLBins, executions from `%TEMP%`, `Downloads`, and `AppData`
- #️⃣ **On-demand SHA-256 hashing** — only hashes executables that trip a suspicious flag (performance-conscious)
- 📄 **Structured JSONL logging** — one JSON object per event, append-only, easy to pipe into SIEM or `jq`
- 📋 **Allowlist support** — skip known-good process names via a plain-text file
- 🔁 **Continuous or one-shot mode** — run once (`--once`) or poll on a configurable interval

---

## Quick Start

### Prerequisites

- Rust toolchain (`rustup` + `cargo`) — [install here](https://rustup.rs)
- Windows OS (path heuristics are Windows-specific)
- **Run as Administrator** for full visibility into system-level processes (see [Known Issues](#known-issues--roadmap))

### Build

```bash
git clone https://github.com/stevjoo/lolbin-watcher
cd lolbin-watcher
cargo build --release
```

### Run

```bash
# One-shot scan, output to default log file
.\target\release\lolbin-watcher.exe --once

# Continuous polling every 30 seconds
.\target\release\lolbin-watcher.exe --interval 30

# Custom output path and allowlist
.\target\release\lolbin-watcher.exe --out C:\Logs\lolbin.jsonl --allowlist rules\allowlist.txt
```

### CLI Arguments

| Flag | Default | Description |
|---|---|---|
| `--once` | `false` | Run a single snapshot then exit |
| `--interval <secs>` | `10` | Polling interval in seconds |
| `--out <path>` | `logs/lolbin-watcher.jsonl` | Output JSONL log file path |
| `--allowlist <path>` | `rules/allowlist.txt` | Allowlist of trusted process names (one per line) |

---

## Detection Logic

### Flags

| Flag | Trigger Condition |
|---|---|
| `lolbin_process` | Process name matches a known Living-off-the-Land Binary |
| `exec_from_temp` | Executable path contains `\AppData\Local\Temp\` or `\Windows\Temp\` |
| `exec_from_downloads` | Executable path contains `\Downloads\` |
| `exec_from_appdata` | Executable path contains `\AppData\Roaming\` or `\AppData\Local\` |
| `no_exe_path` | Could not resolve executable path (often a privilege issue — see [#3][i3]) |
| `no_hash` | SHA-256 hash was not computed (only hashed when a suspicious flag is present) |
| `allowlisted_name` | Process name is in the allowlist; no further analysis performed |

### Severity

| Severity | Condition |
|---|---|
| `High` | `exec_from_temp` **AND** `lolbin_process` both present |
| `Medium` | Any `exec_from_*` flag **OR** `lolbin_process` alone |
| `Low` | No flags, or only metadata flags (`no_exe_path`, `no_hash`) |

### LOLBins Monitored

`powershell.exe` · `pwsh.exe` · `cmd.exe` · `wscript.exe` · `cscript.exe` · `mshta.exe` · `rundll32.exe` · `regsvr32.exe` · `certutil.exe` · `bitsadmin.exe` · `wmic.exe`

---

## Log Format

Each event is a single JSON line:

```json
{
  "ts_utc": "2025-07-10T14:32:01.123456Z",
  "pid": 4821,
  "name": "powershell.exe",
  "exe_path": "C:\\Windows\\Temp\\dropper\\powershell.exe",
  "sha256": "a3f1c2d4...",
  "flags": ["exec_from_temp", "lolbin_process"],
  "severity": "High"
}
```

Events with `Medium` or `High` severity are also printed to stdout in real time.

### Querying Logs with `jq`

```bash
# Show all High-severity events
jq 'select(.severity == "High")' logs/lolbin-watcher.jsonl

# Show events with a specific flag
jq 'select(.flags[] == "exec_from_temp")' logs/lolbin-watcher.jsonl

# Count events by severity
jq -r '.severity' logs/lolbin-watcher.jsonl | sort | uniq -c
```

---

## Allowlist

Create or edit `rules/allowlist.txt`. One process name per line. Lines starting with `#` are comments.

```text
# Trusted browsers
chrome.exe
firefox.exe
msedge.exe

# Development tools
code.exe
cargo.exe
rustc.exe
```

> Names are matched case-insensitively.

---

## Project Structure

```
lolbin-watcher/
├── src/
│   ├── main.rs              # CLI entrypoint, polling loop, orchestration
│   ├── lib.rs               # Crate root, module exports
│   ├── models.rs            # ProcEvent, DetectionResult, Severity
│   ├── collector/
│   │   ├── mod.rs
│   │   └── process.rs       # sysinfo-based process snapshot collector
│   ├── detector/
│   │   ├── mod.rs
│   │   └── rules.rs         # RuleEngine — flag and severity logic
│   └── logger/
│       ├── mod.rs
│       └── jsonl.rs         # Append-only JSONL writer
├── rules/
│   └── allowlist.txt        # Trusted process name list
├── logs/                    # Default log output directory (auto-created)
└── Cargo.toml
```

---

## Dependencies

| Crate | Purpose |
|---|---|
| `sysinfo` | Cross-platform process enumeration |
| `sha2` | SHA-256 hashing of executables |
| `serde` / `serde_json` | JSON serialization for log events |
| `chrono` | UTC timestamps |
| `clap` | CLI argument parsing |
| `anyhow` | Ergonomic error handling |