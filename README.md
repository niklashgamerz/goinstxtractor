<div align="center">

```
  ██████╗  ██████╗ ██╗███╗   ██╗███████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗████████╗ ██████╗ ██████╗
  ██╔════╝ ██╔═══██╗██║████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
  ██║  ███╗██║   ██║██║██╔██╗ ██║███████╗ ╚███╔╝    ██║   ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝
  ██║   ██║██║   ██║██║██║╚██╗██║╚════██║ ██╔██╗    ██║   ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗
  ╚██████╔╝╚██████╔╝██║██║ ╚████║███████║██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║
   ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

**Like pyinstxtractor — but for Go binaries**

<br/>

*Extract build info, symbols, packages, source paths, strings, embedded files,*
*and full C pseudocode from any compiled Go executable — zero dependencies.*

</div>

---

## ⚡ Quickstart

```bash
# Core extraction — zero dependencies, pure Python stdlib
python goinsxtractor.py mybinary

# + Ghidra decompilation (C pseudocode for every function)
python goinsxtractor.py mybinary --ghidra
```

---

## 🗂️ What gets extracted

| # | Step | What you get | Requires |
|:-:|------|--------------|:--------:|
| 1 | 🔍 **Binary metadata** | Format (ELF/PE/Mach-O), OS, arch, strip status, sections | always |
| 2 | 📦 **Go build info** | Go version, module path, full `go.mod` dependency tree, build flags, VCS commit | always |
| 3 | 🔧 **Symbols** | Every function and method name (from pclntab + regex fallback) | always |
| 4 | 📁 **Packages** | Full package list derived from symbol names | always |
| 5 | 🔑 **Strings** | URLs, env var names, email addresses, Unix file paths | always |
| 6 | 📎 **Embedded files** | `//go:embed` files extracted and saved to disk | always |
| 7 | 🧬 **Decompilation** | Every user function as readable C pseudocode | `--ghidra` |

---

## 📂 Output structure

```
mybinary_extracted/
│
├── 📄 build_info.txt      ← Go version · module · all go.mod deps · build flags
├── 📄 packages.txt        ← Every package the binary uses
├── 📄 functions.txt       ← All function / method names (one per line)
├── 📄 source_files.txt    ← Original .go source paths recovered from the binary
├── 📄 strings.txt         ← URLs · env vars · emails · file paths
├── 📄 metadata.txt        ← Format · OS · arch · SHA-256 · sections list
├── 📄 report.json         ← Full machine-readable JSON of everything above
│
├── 📁 embedded/           ← go:embed files extracted (if any found)
│   ├── static/index.html
│   ├── static/app.js
│   └── config/defaults.yaml
│
├── 📄 decompiled.c        ← [--ghidra] All functions as C pseudocode, one file
└── 📁 decompiled/         ← [--ghidra] One .c file per function
    ├── main.main.c
    ├── main.handleRequest.c
    └── …
```

---

## 🚀 Installation

```bash
git clone https://github.com/yourname/goinsxtractor
cd goinsxtractor

# That's it — no pip install, no venv needed
python goinsxtractor.py --help
```

> **Requirements:** Python 3.6+ · No third-party packages

---

## 📖 Usage

```bash
# Basic extraction
python goinsxtractor.py <binary>
python goinsxtractor.py <binary> <output_dir>

# With Ghidra decompilation (auto-detects GHIDRA_HOME env var)
python goinsxtractor.py <binary> --ghidra

# Specify Ghidra path manually
python goinsxtractor.py <binary> --ghidra --ghidra-home ~/ghidra_11.0

# Cap to first 500 user functions (much faster on large binaries)
python goinsxtractor.py <binary> --ghidra --max-funcs 500

# Include stdlib & runtime functions too (warning: very large output)
python goinsxtractor.py <binary> --ghidra --no-skip-stdlib

# Raise timeout for very large binaries (default 600s)
python goinsxtractor.py <binary> --ghidra --timeout 1800
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `binary` | *(required)* | Go executable to analyse |
| `output_dir` | `<binary>_extracted/` | Where to write all output files |
| `--ghidra` | off | Enable step 7: Ghidra headless decompilation |
| `--ghidra-home PATH` | `$GHIDRA_HOME` | Path to Ghidra installation directory |
| `--no-skip-stdlib` | off | Include Go stdlib/runtime in Ghidra output |
| `--max-funcs N` | `0` (unlimited) | Cap Ghidra to first N user functions |
| `--timeout SECS` | `600` | Ghidra analysis timeout in seconds |

---

## 🧬 Ghidra setup

<details>
<summary><b>▶ Click to expand — Installing Ghidra</b></summary>

<br/>

**1. Download Ghidra**

Go to **[ghidra-sre.org](https://ghidra-sre.org/)** → Download → extract the zip anywhere.
Free, open source, no account needed.

**2. Install Java 17+**

```bash
# Check your version
java -version   # must print 17 or higher

# Ubuntu / Debian
sudo apt install openjdk-17-jdk

# macOS
brew install openjdk@17

# Windows — download from https://adoptium.net/
```

**3. Point goinsxtractor at Ghidra**

```bash
# Option A: set the env var (add to ~/.bashrc or ~/.zshrc)
export GHIDRA_HOME=~/ghidra_11.0.3_PUBLIC

# Option B: pass it directly
python goinsxtractor.py mybinary --ghidra --ghidra-home ~/ghidra_11.0.3_PUBLIC
```

**How it works under the hood:**

1. goinsxtractor writes a Jython script to a temp directory
2. Runs `analyzeHeadless` — Ghidra imports and auto-analyses the binary
3. The script calls `DecompInterface.decompileFunction()` on every non-stdlib function
4. Output is saved to `decompiled.c` and split into individual `decompiled/<fn>.c` files
5. The temp Ghidra project is deleted automatically

</details>

---

## 🔬 How it works

<details>
<summary><b>▶ Click to expand — Go binary internals</b></summary>

<br/>

### Why this isn't exactly like pyinstxtractor

**pyinstxtractor** works because PyInstaller bundles `.pyc` bytecode files inside the exe, which can be decompiled back to `.py`. Go compiles to **native machine code** — no bytecode bundle exists.

However, every unstripped Go binary embeds a lot of structured data:

| Data | Where it lives in the binary |
|------|------------------------------|
| Go version, module, deps, build flags | `\xff Go buildinf:` block (Go 1.18+) |
| All function names + addresses | `.gopclntab` — program counter line table |
| Original source file paths | `.gopclntab` file table |
| Type and interface descriptors | `.typelink`, `.itablink` sections |
| Embedded assets | Zip archive stored inline (`go:embed`) |
| C pseudocode (decompiled) | DWARF debug info + Ghidra engine |

None of this requires debug symbols — it exists in **every non-stripped Go binary by default.**

### pclntab version support

| Magic bytes | Go version |
|-------------|------------|
| `\xfb\xff\xff\xff` | Go 1.2 |
| `\xfa\xff\xff\xff` | Go 1.16 |
| `\xf0\xff\xff\xff` | Go 1.18 |
| `\xf1\xff\xff\xff` | Go 1.20+ |

### Stripped binaries

```diff
- go build -ldflags="-s -w" .   # strips DWARF + symbol table — reduced extraction
+ go build .                    # full symbols — maximum extraction
```

If stripped, goinsxtractor warns you and falls back to regex scanning. Ghidra can still decompile the machine code even without symbol names.

</details>

---

## 📟 Example output

```
  Target   : /home/user/myapp
  Size     : 8,421,376 bytes
  Format   : ELF
  [OK] Go build-info block detected
  Output   : myapp_extracted/

  [1/7] Parsing binary metadata… done
         OS: Linux/GNU  Arch: x86_64  Stripped: False
         Sections (28): .text .rodata .typelink .gopclntab .gosymtab …

  [2/7] Extracting Go build info… done
         Go version : go1.22.3
         Module     : github.com/myorg/myapp v1.4.2
         Deps found : 47
         build GOARCH=amd64
         build vcs.revision=a3f91bc2e1d4

  [3/7] Recovering symbols from pclntab… done
         Functions    : 12,847
         Source paths : 1,203

  [4/7] Deducing package list… done
         Packages: 312

  [5/7] Scanning for interesting strings… done
         Strings: 841

  [6/7] Searching for embedded files (go:embed)… done
         Found 3 embedded file(s)

  [7/7] Ghidra decompilation… [stdlib skipped]
         ✓ Decompiled 3,241 functions → decompiled.c + decompiled/ (3241 files)

  ──────────────────────────────────────────────────────────
  Extraction complete! → myapp_extracted/

    build_info.txt       Go version, module, 47 deps
    packages.txt         312 packages
    functions.txt        12,847 function symbols
    source_files.txt     1,203 recovered source paths
    strings.txt          841 interesting strings
    embedded/            3 embedded file(s)
    metadata.txt         binary metadata & sections
    report.json          full machine-readable report
    decompiled.c         3,241 functions — C pseudocode
    decompiled/          3,241 individual .c files
```

---

## ✅ Supported targets

| Format | Platforms | Architectures |
|--------|-----------|---------------|
| **ELF** | Linux, FreeBSD, OpenBSD, Solaris | x86, x86\_64, arm, arm64, MIPS, PowerPC |
| **PE** `.exe` | Windows | x86, x86\_64, arm, arm64 |
| **Mach-O** | macOS | x86\_64, arm64 (Apple Silicon) |

Go versions **1.2 → 1.22+** supported.

---

## ⚠️ Limitations

- **No .go source recovery** — Go compiles to native machine code. Ghidra gives you C pseudocode, not original Go source.
- **Ghidra output is C pseudocode** — variable names are mangled, signatures differ from originals.
- **Stripped binaries** (`-s -w`) have reduced symbol coverage. Build without these flags for best results.
- **CGO binaries** may have mixed Go/C symbols — both portions are decompiled by Ghidra.
- **Ghidra is slow** on large binaries (5–20 min). Use `--max-funcs` to limit scope.

---

## 📄 License

MIT

---

<div align="center">

Inspired by [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) &nbsp;·&nbsp;
Decompilation by [Ghidra](https://ghidra-sre.org/) &nbsp;·&nbsp;
Go pclntab: [golang.org/s/go12symtab](https://golang.org/s/go12symtab)

<br/>

**Drop a ⭐ if this helped you**

</div>
