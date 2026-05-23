#!/usr/bin/env python3
"""
goinsxtractor.py — Go binary extractor + Ghidra decompiler
Extracts build info, symbols, packages, source paths, strings, embedded files,
and optionally decompiles every function to C pseudocode via Ghidra headless.

Usage:
    python goinsxtractor.py <go_binary> [output_dir] [options]

Requirements: Python 3.6+ (stdlib only for core extraction)
              Ghidra 10+ + Java 17+ for the --ghidra decompilation step
"""

import sys
import os
import re
import json
import struct
import io
import shutil
import hashlib
import subprocess
import tempfile
import argparse
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers (graceful fallback on Windows without ANSI)
# ─────────────────────────────────────────────────────────────────────────────

def _supports_colour():
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOUR = _supports_colour()

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text

def green(t):  return c(t, "92")
def cyan(t):   return c(t, "96")
def yellow(t): return c(t, "93")
def red(t):    return c(t, "91")
def bold(t):   return c(t, "1")
def dim(t):    return c(t, "2")
def magenta(t): return c(t, "95")


# ─────────────────────────────────────────────────────────────────────────────
# Binary format detection
# ─────────────────────────────────────────────────────────────────────────────

ELF_MAGIC   = b"\x7fELF"
PE_MAGIC    = b"MZ"
MACHO_MAGIC = {0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE}

def detect_format(data: bytes) -> str:
    if data[:4] == ELF_MAGIC:
        return "ELF"
    if data[:2] == PE_MAGIC:
        return "PE"
    magic = struct.unpack("<I", data[:4])[0]
    if magic in MACHO_MAGIC:
        return "Mach-O"
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be in MACHO_MAGIC:
        return "Mach-O"
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Go build info extraction  (Go 1.18+ embed a self-describing block)
# ─────────────────────────────────────────────────────────────────────────────

BUILDINFO_MAGIC = b"\xff Go buildinf:"

def parse_build_info_text(block: bytes) -> dict:
    info = {
        "goVersion": "",
        "modulePath": None,
        "moduleVersion": None,
        "settings": [],
        "dependencies": [],
    }
    try:
        text = block.decode("utf-8", errors="replace")
    except Exception:
        return info

    for line in text.splitlines():
        line = line.strip("\x00 \t")
        if not line:
            continue
        if line.startswith("go"):
            ver = line.split()[0] if " " in line else line
            info["goVersion"] = ver
        elif line.startswith("path\t"):
            info["modulePath"] = line.split("\t", 2)[1] if "\t" in line else None
        elif line.startswith("mod\t"):
            parts = line.split("\t")
            if len(parts) >= 3:
                info["modulePath"] = parts[1]
                info["moduleVersion"] = parts[2] if len(parts) > 2 else None
        elif line.startswith("dep\t"):
            parts = line.split("\t")
            dep = {"path": parts[1] if len(parts) > 1 else "",
                   "version": parts[2] if len(parts) > 2 else "",
                   "sum": parts[3] if len(parts) > 3 else None,
                   "replace": None}
            info["dependencies"].append(dep)
        elif line.startswith("=>\t"):
            parts = line.split("\t")
            if info["dependencies"]:
                info["dependencies"][-1]["replace"] = parts[1] if len(parts) > 1 else None
        elif line.startswith("build\t"):
            rest = line[6:]
            if "=" in rest:
                k, v = rest.split("=", 1)
                info["settings"].append({"key": k, "value": v})
            else:
                info["settings"].append({"key": rest, "value": ""})
    return info


def extract_build_info(data: bytes) -> dict | None:
    pos = data.find(BUILDINFO_MAGIC)
    if pos == -1:
        return None
    header = data[pos:pos + 32]
    if len(header) < 32:
        return None
    flags    = header[15]
    block_start = pos + 32
    if flags & 2:
        end = data.find(b"\x00", block_start)
        if end == -1:
            end = block_start + 4096
        block = data[block_start:end]
    else:
        block = data[block_start:block_start + 4096]
    return parse_build_info_text(block)


# ─────────────────────────────────────────────────────────────────────────────
# pclntab — function & source file names
# ─────────────────────────────────────────────────────────────────────────────

PCLNTAB_MAGICS = [
    b"\xf1\xff\xff\xff\x00\x00",
    b"\xf0\xff\xff\xff\x00\x00",
    b"\xfa\xff\xff\xff\x00\x00",
    b"\xfb\xff\xff\xff\x00\x00",
]


def find_pclntab(data: bytes) -> tuple[int, bytes] | tuple[None, None]:
    for magic in PCLNTAB_MAGICS:
        pos = data.find(magic)
        if pos != -1:
            return pos, magic
    return None, None


def extract_symbols_from_pclntab(data: bytes) -> tuple[list[str], list[str]]:
    functions = []
    sources   = []
    seen_fn   = set()
    seen_src  = set()

    pos, magic = find_pclntab(data)
    if pos is None:
        return functions, sources

    version_magic = magic[:4]
    hdr_offset = pos
    ptr_size = data[hdr_offset + 7]
    if ptr_size not in (4, 8):
        ptr_size = 8

    def read_uint(buf: bytes, off: int) -> int:
        if ptr_size == 8:
            return struct.unpack_from("<Q", buf, off)[0]
        return struct.unpack_from("<I", buf, off)[0]

    nfunc_off = hdr_offset + 8
    if nfunc_off + ptr_size > len(data):
        return functions, sources

    nfunc = read_uint(data, nfunc_off)
    if nfunc == 0 or nfunc > 500_000:
        return functions, sources

    if version_magic in (b"\xf0\xff\xff\xff", b"\xf1\xff\xff\xff"):
        hdr_size = 8 + ptr_size * 7
    elif version_magic == b"\xfa\xff\xff\xff":
        hdr_size = 8 + ptr_size * 6
    else:
        hdr_size = 8 + ptr_size * 2

    func_table_off = hdr_offset + hdr_size
    entry_size = ptr_size * 2

    for i in range(min(nfunc, 200_000)):
        row_off = func_table_off + i * entry_size
        if row_off + entry_size > len(data):
            break
        func_data_off = read_uint(data, row_off + ptr_size)
        abs_off = hdr_offset + func_data_off
        if abs_off + ptr_size + 4 > len(data):
            continue
        nameoff = struct.unpack_from("<I", data, abs_off + ptr_size)[0]
        name_abs = hdr_offset + nameoff
        if 0 < name_abs < len(data):
            end = data.find(b"\x00", name_abs)
            if end == -1 or end - name_abs > 512:
                end = name_abs + 256
            try:
                name = data[name_abs:end].decode("utf-8", errors="replace").strip()
                if name and name not in seen_fn and _is_go_symbol(name):
                    functions.append(name)
                    seen_fn.add(name)
            except Exception:
                pass

    src_pattern = re.compile(rb"(?:[\w.\-/]+/)*[\w.\-]+\.go\x00")
    for m in src_pattern.finditer(data):
        try:
            path = m.group(0)[:-1].decode("utf-8", errors="replace")
            if path not in seen_src and len(path) < 512:
                sources.append(path)
                seen_src.add(path)
        except Exception:
            pass

    return functions, sources


# ─────────────────────────────────────────────────────────────────────────────
# Fallback: regex-based symbol & string scanning
# ─────────────────────────────────────────────────────────────────────────────

_GO_PKG_CHARS = re.compile(r'^[a-zA-Z0-9_/.\-]+$')

def _is_go_symbol(name: str) -> bool:
    if "." not in name:
        return False
    if len(name) < 3 or len(name) > 256:
        return False
    parts = name.split(".")
    if len(parts) < 2:
        return False
    return all(_GO_PKG_CHARS.match(p) for p in parts if p)


def scan_symbols_regex(data: bytes) -> tuple[list[str], list[str]]:
    functions = []
    sources   = []
    seen_fn   = set()
    seen_src  = set()

    fn_re = re.compile(rb"[a-zA-Z0-9_/.\-]{3,256}\.[a-zA-Z_][a-zA-Z0-9_*(){}]{1,255}\x00")
    for m in fn_re.finditer(data):
        try:
            name = m.group(0)[:-1].decode("utf-8", errors="replace")
            if name not in seen_fn and _is_go_symbol(name):
                functions.append(name)
                seen_fn.add(name)
        except Exception:
            pass

    src_re = re.compile(rb"(?:[a-zA-Z0-9_.\-]+/)*[a-zA-Z0-9_.\-]+\.go\x00")
    for m in src_re.finditer(data):
        try:
            path = m.group(0)[:-1].decode("utf-8", errors="replace")
            if path not in seen_src and len(path) < 512:
                sources.append(path)
                seen_src.add(path)
        except Exception:
            pass

    return functions, sources


# ─────────────────────────────────────────────────────────────────────────────
# Interesting string extraction
# ─────────────────────────────────────────────────────────────────────────────

_INTERESTING_RE = re.compile(
    rb"(?:"
    rb"https?://[^\x00\s\"']{10,}"
    rb"|/[a-zA-Z0-9_.\-/]{6,80}"
    rb"|[A-Z][A-Z0-9_]{3,}(?:_[A-Z0-9_]+)+"
    rb"|[a-z0-9._%+\-]{3,}@[a-z0-9.\-]{2,}\.[a-z]{2,6}"
    rb")"
)

def extract_interesting_strings(data: bytes) -> list[str]:
    seen = set()
    results = []
    for m in _INTERESTING_RE.finditer(data):
        try:
            s = m.group(0).decode("utf-8", errors="replace").strip()
            if s and s not in seen and len(s) < 512:
                results.append(s)
                seen.add(s)
        except Exception:
            pass
    return results


# ─────────────────────────────────────────────────────────────────────────────
# ELF section parser (minimal)
# ─────────────────────────────────────────────────────────────────────────────

def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int]]:
    sections = {}
    if data[:4] != ELF_MAGIC:
        return sections

    ei_class = data[4]
    ei_data  = data[5]
    endian   = "<" if ei_data == 1 else ">"

    if ei_class == 2:
        hdr_fmt = endian + "QQIHHHHHH"
        (e_shoff, _, e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(hdr_fmt, data, 24)
        sh_size = 64
    else:
        hdr_fmt = endian + "IIIHHHHHH"
        (e_shoff, _, e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(hdr_fmt, data, 20)
        sh_size = 40

    if e_shoff == 0 or e_shnum == 0:
        return sections

    strtab_hdr = e_shoff + e_shstrndx * sh_size
    if ei_class == 2:
        strtab_off, strtab_sz = struct.unpack_from(endian + "QQ", data, strtab_hdr + 24)
    else:
        strtab_off, strtab_sz = struct.unpack_from(endian + "II", data, strtab_hdr + 16)

    def get_str(off: int) -> str:
        end = data.find(b"\x00", strtab_off + off)
        return data[strtab_off + off:end].decode("utf-8", errors="replace")

    for i in range(e_shnum):
        sh_off = e_shoff + i * sh_size
        if sh_off + sh_size > len(data):
            break
        if ei_class == 2:
            nameoff = struct.unpack_from(endian + "I", data, sh_off)[0]
            sec_off, sec_size = struct.unpack_from(endian + "QQ", data, sh_off + 24)
        else:
            nameoff = struct.unpack_from(endian + "I", data, sh_off)[0]
            sec_off, sec_size = struct.unpack_from(endian + "II", data, sh_off + 16)
        try:
            name = get_str(nameoff)
            sections[name] = (sec_off, sec_size)
        except Exception:
            pass

    return sections


# ─────────────────────────────────────────────────────────────────────────────
# Embedded files via go:embed
# ─────────────────────────────────────────────────────────────────────────────

def extract_embedded_files(data: bytes, out_dir: Path) -> list[dict]:
    embedded = []
    out_embed = out_dir / "embedded"
    zip_magic = b"PK\x03\x04"

    pos = 0
    while True:
        pos = data.find(zip_magic, pos)
        if pos == -1:
            break
        try:
            buf = io.BytesIO(data[pos:])
            import zipfile as _zf
            with _zf.ZipFile(buf) as zf:
                names = zf.namelist()
                if names:
                    out_embed.mkdir(parents=True, exist_ok=True)
                    for name in names:
                        try:
                            content = zf.read(name)
                            dest = out_embed / name
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            dest.write_bytes(content)
                            preview = None
                            if dest.suffix in (".txt", ".json", ".yaml", ".yml",
                                              ".html", ".css", ".js", ".go",
                                              ".md", ".toml", ".env"):
                                try:
                                    preview = content[:512].decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                            embedded.append({"path": name, "size": len(content), "preview": preview})
                        except Exception:
                            pass
        except Exception:
            pass
        pos += 1

    return embedded


# ─────────────────────────────────────────────────────────────────────────────
# ELF/PE/Mach-O metadata
# ─────────────────────────────────────────────────────────────────────────────

_ELF_OSABI = {0: "Linux/GNU", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 12: "OpenBSD"}
_ELF_ARCH  = {0x3e: "x86_64", 0xb7: "arm64", 0x08: "MIPS", 0x14: "PowerPC",
              0x03: "x86", 0x28: "arm"}
_PE_ARCH   = {0x014c: "x86", 0x8664: "x86_64", 0xaa64: "arm64",
              0x01c4: "arm", 0x0200: "ia64"}
_PE_SUBSYS = {1: "Native", 2: "Windows GUI", 3: "Windows CUI", 9: "Windows CE"}


def parse_binary_metadata(data: bytes, filename: str) -> dict:
    fmt = detect_format(data)
    meta = {
        "fileSize": len(data),
        "format": fmt,
        "os": None,
        "arch": None,
        "isStripped": True,
        "sections": [],
    }

    if fmt == "ELF":
        ei_data = data[5]
        endian  = "<" if ei_data == 1 else ">"
        ei_class = data[4]
        osabi    = data[7]
        meta["os"]   = _ELF_OSABI.get(osabi, "Linux")
        arch_val     = struct.unpack_from(endian + "H", data, 18)[0]
        meta["arch"] = _ELF_ARCH.get(arch_val, f"0x{arch_val:04x}")
        secs = parse_elf_sections(data)
        meta["sections"] = list(secs.keys())
        meta["isStripped"] = ".debug_info" not in secs and ".gosymtab" not in secs
        if ".gosymtab" in secs:
            meta["isStripped"] = False
    elif fmt == "PE":
        if len(data) > 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
            if e_lfanew + 24 < len(data):
                machine  = struct.unpack_from("<H", data, e_lfanew + 4)[0]
                meta["arch"] = _PE_ARCH.get(machine, f"0x{machine:04x}")
                meta["os"]   = "Windows"
                opt_off = e_lfanew + 24
                if opt_off + 68 < len(data):
                    subsys = struct.unpack_from("<H", data, opt_off + 68)[0]
                    meta["os"] = _PE_SUBSYS.get(subsys, "Windows")
    elif fmt == "Mach-O":
        magic    = struct.unpack_from("<I", data, 0)[0]
        swap     = magic in (0xCEFAEDFE, 0xCFFAEDFE)
        endian   = ">" if swap else "<"
        cpu_type = struct.unpack_from(endian + "I", data, 4)[0]
        meta["os"]   = "macOS"
        meta["arch"] = {0x0c: "arm64", 0x07: "x86", 0x01000007: "x86_64",
                        0x0100000c: "arm64"}.get(cpu_type, f"0x{cpu_type:08x}")

    if b".debug_info" in data or b"__debug_info" in data:
        meta["isStripped"] = False

    return meta


# ─────────────────────────────────────────────────────────────────────────────
# Package name deduction
# ─────────────────────────────────────────────────────────────────────────────

def deduce_packages(symbols: list[str]) -> list[str]:
    pkgs = set()
    for sym in symbols:
        parts = sym.split(".")
        if len(parts) >= 2:
            pkg = ".".join(parts[:-1])
            pkg = re.sub(r"\(\*?\w+\)$", "", pkg).rstrip(".")
            if pkg:
                pkgs.add(pkg)
    return sorted(pkgs)


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write(path: Path, lines: list[str], header: str = ""):
    with open(path, "w", encoding="utf-8") as f:
        if header:
            f.write(header + "\n" + "─" * 60 + "\n\n")
        f.write("\n".join(lines))
        f.write("\n")


# ─────────────────────────────────────────────────────────────────────────────
# Ghidra integration
# ─────────────────────────────────────────────────────────────────────────────

GHIDRA_COMMON_PATHS = [
    "/opt/ghidra",
    "/opt/ghidra_*",
    "/usr/local/ghidra",
    os.path.expanduser("~/ghidra"),
    os.path.expanduser("~/tools/ghidra"),
    os.path.expanduser("~/ghidra_*"),
    "C:/ghidra",
    "C:/Program Files/ghidra",
    "C:/Tools/ghidra",
    "/Applications/ghidra",
]

# Jython script that runs inside Ghidra headless — written to a temp file
_GHIDRA_SCRIPT = r'''# GhidraDecompileAll.py — auto-generated by goinsxtractor
# @category GoInsXtractor

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os

args = getScriptArgs()
out_path    = args[0] if len(args) > 0 else "/tmp/decompiled.c"
skip_stdlib = (args[1].lower() == "true") if len(args) > 1 else True
max_funcs   = int(args[2]) if len(args) > 2 else 0

# Go standard library and well-known packages to skip
STDLIB_PACKAGES = {
    "runtime", "reflect", "sync", "syscall", "fmt",
    "os", "io", "net", "math", "sort", "strings",
    "strconv", "bytes", "unicode", "errors", "log",
    "bufio", "encoding", "crypto", "compress", "archive",
    "internal", "vendor", "unsafe", "builtin",
    "time", "context", "path", "flag", "debug",
    "regexp", "text", "html", "image", "testing",
    "expvar", "plugin", "signal", "atomic",
}

ifc = DecompInterface()
opts = DecompileOptions()
ifc.setOptions(opts)
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

funcs   = list(currentProgram.getFunctionManager().getFunctions(True))
results = []
count   = 0
skipped = 0

for func in funcs:
    full_name = func.getName(True)
    # Derive package name: Ghidra represents Go methods as Namespace::func
    pkg = full_name.split("::")[0] if "::" in full_name else full_name.split(".")[0]
    pkg = pkg.lstrip("*").split("/")[-1]

    if skip_stdlib and pkg in STDLIB_PACKAGES:
        skipped += 1
        continue

    if max_funcs > 0 and count >= max_funcs:
        break

    try:
        res = ifc.decompileFunction(func, 120, monitor)
        if res and res.decompileCompleted():
            c_code = res.getDecompiledFunction().getC()
            addr   = str(func.getEntryPoint())
            header = "// \u2550\u2550\u2550 {} @ {} \u2550\u2550\u2550".format(full_name, addr)
            results.append("{}\n{}".format(header, c_code))
            count += 1
    except Exception as e:
        pass

with open(out_path, "w") as f:
    f.write("// Generated by goinsxtractor Ghidra decompiler\n")
    f.write("// Binary: {}\n".format(currentProgram.getName()))
    f.write("// Decompiled: {} functions  Skipped (stdlib): {}\n\n".format(count, skipped))
    f.write("\n\n".join(results))

print("[goinsxtractor] Decompiled {} functions ({} stdlib skipped)".format(count, skipped))
'''


def find_ghidra(ghidra_home_arg: str | None = None) -> str | None:
    """
    Locate the Ghidra installation directory by checking (in order):
      1. --ghidra-home argument
      2. GHIDRA_HOME environment variable
      3. Common installation paths
    Returns the path to the Ghidra home dir, or None if not found.
    """
    import glob as _glob

    candidates = []
    if ghidra_home_arg:
        candidates.append(ghidra_home_arg)
    env = os.environ.get("GHIDRA_HOME")
    if env:
        candidates.append(env)
    for p in GHIDRA_COMMON_PATHS:
        expanded = _glob.glob(p)
        if expanded:
            candidates.extend(expanded)
        else:
            candidates.append(p)

    for raw in candidates:
        p = Path(raw)
        headless     = p / "support" / "analyzeHeadless"
        headless_bat = p / "support" / "analyzeHeadless.bat"
        if headless.exists() or headless_bat.exists():
            return str(p)
        # Maybe the user pointed at the support dir directly
        if (p / "analyzeHeadless").exists() or (p / "analyzeHeadless.bat").exists():
            return str(p.parent)

    return None


def _split_decompiled_c(content: str, out_dir: Path):
    """Split the monolithic decompiled.c into one file per function."""
    sep = re.compile(r"(?=// \u2550\u2550\u2550 )")
    parts = sep.split(content)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        m = re.match(r"// \u2550+ (.+?) @", part)
        if not m:
            continue
        name = m.group(1).strip()
        safe = re.sub(r"[^\w.\-]", "_", name)[:120]
        dest = out_dir / f"{safe}.c"
        i = 1
        while dest.exists():
            dest = out_dir / f"{safe}_{i}.c"
            i += 1
        dest.write_text(part + "\n", encoding="utf-8")


def run_ghidra_decompile(
    binary_path: Path,
    out_dir: Path,
    ghidra_home: str,
    skip_stdlib: bool = True,
    max_funcs: int = 0,
    timeout: int = 600,
) -> dict:
    """
    Run Ghidra headless analysis + decompile all (user) functions.
    Returns a result dict with: success, funcsDecompiled, outputFile, error.
    """
    result = {"success": False, "funcsDecompiled": 0, "outputFile": None, "error": None}

    with tempfile.TemporaryDirectory(prefix="goinsxtractor_") as tmpdir:
        tmp = Path(tmpdir)

        # Write the Jython decompile script into the temp dir
        script_path = tmp / "GhidraDecompileAll.py"
        script_path.write_text(_GHIDRA_SCRIPT, encoding="utf-8")

        decompiled_out = out_dir / "decompiled.c"
        project_dir    = tmp / "ghidra_project"
        project_dir.mkdir()
        project_name   = "GoInsX_" + re.sub(r"[^\w]", "_", binary_path.stem)

        # Resolve the headless launcher
        ghidra_path = Path(ghidra_home)
        if os.name == "nt":
            headless = ghidra_path / "support" / "analyzeHeadless.bat"
        else:
            headless = ghidra_path / "support" / "analyzeHeadless"

        if not headless.exists():
            result["error"] = f"Ghidra analyzeHeadless not found at: {headless}"
            return result

        cmd = [
            str(headless),
            str(project_dir),
            project_name,
            "-import", str(binary_path.resolve()),
            "-postScript", "GhidraDecompileAll.py",
                str(decompiled_out.resolve()),
                "true" if skip_stdlib else "false",
                str(max_funcs),
            "-scriptPath", str(tmp),
            "-deleteProject",
            "-log", str(tmp / "ghidra.log"),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if decompiled_out.exists() and decompiled_out.stat().st_size > 10:
                result["success"] = True
                result["outputFile"] = str(decompiled_out)
                content = decompiled_out.read_text(encoding="utf-8", errors="replace")
                result["funcsDecompiled"] = content.count("// ═══")

                # Split into per-function files
                funcs_dir = out_dir / "decompiled"
                funcs_dir.mkdir(exist_ok=True)
                _split_decompiled_c(content, funcs_dir)
            else:
                # Collect error info
                log_path = tmp / "ghidra.log"
                if log_path.exists():
                    log_tail = log_path.read_text(errors="replace")[-3000:]
                else:
                    log_tail = (proc.stdout + proc.stderr)[-3000:]
                result["error"] = log_tail.strip() or f"Exit code {proc.returncode}"

        except subprocess.TimeoutExpired:
            result["error"] = (
                f"Ghidra timed out after {timeout}s.\n"
                f"Try --timeout <seconds> with a higher value, or --max-funcs to limit scope."
            )
        except FileNotFoundError:
            result["error"] = f"Could not execute: {headless}"
        except Exception as e:
            result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic tracing (step 8)
# Runs the binary for real and intercepts everything it does at runtime.
#
# Why this works:
#   The CPU executes machine code, but every meaningful action the program
#   takes — opening a file, connecting to a network, spawning a process —
#   must go through the OS kernel via a system call.  We intercept those calls
#   with strace (Linux) / dtruss (macOS).  The Go runtime also exposes its
#   own internal event stream via GODEBUG env vars, giving us GC traces,
#   scheduler events, and goroutine stacks.  Together these reveal the actual
#   runtime behaviour of the binary: what code paths ran, what data it touched.
# ─────────────────────────────────────────────────────────────────────────────

def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _detect_tracer() -> str | None:
    """Return the best available syscall tracer for this platform."""
    if sys.platform.startswith("linux"):
        if _tool_exists("strace"):
            return "strace"
        if _tool_exists("perf"):
            return "perf"
    elif sys.platform == "darwin":
        if _tool_exists("dtruss"):
            return "dtruss"
        if _tool_exists("dtrace"):
            return "dtrace"
    elif sys.platform == "win32":
        if _tool_exists("procmon"):
            return "procmon"
    return None


def _parse_strace(log: str) -> dict:
    """Parse strace -f output into categorised events."""
    files_read    = []
    files_written = []
    network       = []
    processes     = []
    env_vars      = []
    seen          = set()

    for line in log.splitlines():
        # openat / open — file access
        m = re.search(r'openat?\([^,]*,\s*"([^"]+)"[^)]*O_RDONLY', line)
        if m:
            f = m.group(1)
            if f not in seen and not f.startswith("/proc") and not f.startswith("/sys"):
                files_read.append(f); seen.add(f)
        m = re.search(r'openat?\([^,]*,\s*"([^"]+)"[^)]*O_(?:WRONLY|RDWR|CREAT)', line)
        if m:
            f = m.group(1)
            key = "w:" + f
            if key not in seen:
                files_written.append(f); seen.add(key)

        # connect — outbound network
        m = re.search(r'connect\(.*sa_family=AF_INET6?.*sin_addr=inet_addr\("([^"]+)"\).*sin6?_port=htons\((\d+)\)', line)
        if m:
            entry = f"{m.group(1)}:{m.group(2)}"
            if entry not in seen:
                network.append(entry); seen.add(entry)
        # inet_addr fallback
        m = re.search(r'connect\(.*"([\d.]+)".*port=(\d+)', line)
        if m:
            entry = f"{m.group(1)}:{m.group(2)}"
            if entry not in seen:
                network.append(entry); seen.add(entry)

        # execve — subprocess spawning
        m = re.search(r'execve\("([^"]+)"', line)
        if m:
            proc = m.group(1)
            if proc not in seen:
                processes.append(proc); seen.add(proc)

        # getenv / environ — env var reads
        for ev in re.findall(r'"([A-Z][A-Z0-9_]{2,})=', line):
            if ev not in seen:
                env_vars.append(ev); seen.add(ev)

    return {
        "filesRead": files_read,
        "filesWritten": files_written,
        "networkConnections": network,
        "processesSpawned": processes,
        "envVarsAccessed": env_vars,
    }


def _parse_godebug(output: str) -> dict:
    """Extract structured data from GODEBUG runtime output."""
    gc_events   = []
    sched_lines = []
    goroutines  = []
    panics      = []

    for line in output.splitlines():
        if line.startswith("gc ") and "ms" in line:
            gc_events.append(line.strip())
        elif line.startswith("SCHED"):
            sched_lines.append(line.strip())
        elif "goroutine " in line and ("running" in line or "waiting" in line):
            goroutines.append(line.strip())
        elif "panic:" in line.lower() or "fatal error:" in line.lower():
            panics.append(line.strip())

    return {
        "gcEvents": gc_events[:200],
        "schedEvents": sched_lines[:100],
        "goroutineSnapshots": goroutines[:100],
        "panics": panics,
    }


def _get_proc_maps(pid: int) -> list[str]:
    """Read /proc/<pid>/maps on Linux for live memory layout."""
    maps_path = Path(f"/proc/{pid}/maps")
    if not maps_path.exists():
        return []
    try:
        return maps_path.read_text(errors="replace").splitlines()
    except Exception:
        return []


def run_dynamic_trace(
    binary_path: Path,
    out_dir: Path,
    trace_args: list[str],
    trace_timeout: int = 30,
    known_symbols: list[str] | None = None,
) -> dict:
    """
    Execute the binary in a controlled environment and capture everything:
      - All syscalls (strace / dtruss)
      - Go runtime internal events (GODEBUG)
      - stdout / stderr output
      - Live memory map (/proc/PID/maps on Linux)
      - Functions actually called (via gdb breakpoints if available)

    Returns a rich result dict.  Writes files into out_dir/trace/.
    """
    result = {
        "success": False,
        "tracer": None,
        "exitCode": None,
        "timedOut": False,
        "stdout": "",
        "stderr": "",
        "godebug": {},
        "syscallTrace": {},
        "memoryMap": [],
        "functionsCalled": [],
        "error": None,
    }

    trace_dir = out_dir / "trace"
    trace_dir.mkdir(exist_ok=True)

    tracer = _detect_tracer()
    result["tracer"] = tracer

    # ── Environment: activate ALL Go runtime debug streams ───────────────────
    env = os.environ.copy()
    env.update({
        "GOTRACEBACK":       "all",        # full stack trace on any crash
        "GODEBUG":           "gctrace=1,schedtrace=500,cgocheck=0",
        "GORACE":            "log_path=stdout",
        "GOMAXPROCS":        "1",          # deterministic single-threaded execution
    })

    # ── Build the command ────────────────────────────────────────────────────
    strace_log = trace_dir / "strace_raw.log"
    binary_cmd = [str(binary_path.resolve())] + trace_args

    if tracer == "strace":
        # -f  follow forks
        # -e  trace every syscall category
        # -s  print up to 256 chars of string args
        # -T  show time spent in each syscall
        # -tt timestamp each call
        cmd = [
            "strace", "-f",
            "-e", "trace=file,network,process,signal,ipc,desc",
            "-s", "256",
            "-T", "-tt",
            "-o", str(strace_log),
        ] + binary_cmd

    elif tracer == "dtruss":
        # macOS — requires sudo; warn the user but try anyway
        cmd = ["dtruss", "-f"] + binary_cmd

    elif tracer == "perf":
        # Fallback on Linux when strace missing
        cmd = ["perf", "trace", "--no-syscalls", "--call-graph", "dwarf",
               "-o", str(strace_log)] + binary_cmd
    else:
        # No tracer — run bare with GODEBUG only
        cmd = binary_cmd

    # ── gdb function-call logging (if gdb is available + we have symbols) ───
    gdb_log = trace_dir / "gdb_calls.log"
    gdb_proc = None
    if _tool_exists("gdb") and known_symbols:
        # Build a gdb script that logs when each known user function is entered
        user_syms = [s for s in (known_symbols or [])
                     if not any(s.startswith(p) for p in (
                         "runtime.", "reflect.", "sync.", "syscall.",
                         "internal/", "vendor/"))][:300]
        gdb_script = trace_dir / "gdb_trace.gdb"
        gdb_lines = [
            "set pagination off",
            "set confirm off",
            f'set logging file {gdb_log}',
            "set logging on",
        ]
        for sym in user_syms:
            # Escape parentheses in symbol names
            safe = sym.replace("(", r"\(").replace(")", r"\)")
            gdb_lines.append(f'break {safe}')
            gdb_lines.append(f'commands')
            gdb_lines.append(f'  silent')
            gdb_lines.append(f'  printf "CALL: {sym}\\n"')
            gdb_lines.append(f'  continue')
            gdb_lines.append(f'end')
        gdb_lines += ["run", "quit"]
        gdb_script.write_text("\n".join(gdb_lines), encoding="utf-8")

        gdb_cmd = ["gdb", "-batch", "-x", str(gdb_script),
                   "--args", str(binary_path.resolve())] + trace_args

    # ── Run the binary ───────────────────────────────────────────────────────
    combined_stderr = ""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=trace_timeout,
            env=env,
            cwd=str(binary_path.parent),
        )
        result["exitCode"]  = proc.returncode
        result["stdout"]    = proc.stdout[:50_000]
        result["stderr"]    = proc.stderr[:50_000]
        combined_stderr     = proc.stderr
        result["success"]   = True

    except subprocess.TimeoutExpired as exc:
        result["timedOut"]  = True
        result["stdout"]    = (exc.stdout or b"")[:50_000].decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")[:50_000]
        result["stderr"]    = (exc.stderr or b"")[:50_000].decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")[:50_000]
        combined_stderr     = result["stderr"]
        result["success"]   = True   # timed-out is still a valid trace run
        result["exitCode"]  = "timeout"

    except PermissionError:
        result["error"] = (
            f"Permission denied executing {binary_path.name}.\n"
            f"Run: chmod +x {binary_path}"
        )
        return result

    except FileNotFoundError:
        result["error"] = f"Binary not found: {binary_path}"
        return result

    except Exception as e:
        result["error"] = str(e)
        return result

    # ── Parse GODEBUG output from stderr ─────────────────────────────────────
    result["godebug"] = _parse_godebug(combined_stderr)

    # ── Parse strace log ─────────────────────────────────────────────────────
    if strace_log.exists():
        raw = strace_log.read_text(errors="replace")
        result["syscallTrace"] = _parse_strace(raw)
        # Keep a trimmed copy of the raw strace
        (trace_dir / "strace.log").write_text(raw[:500_000], encoding="utf-8")
    elif tracer == "strace":
        # strace writes to stderr when -o is not used by dtruss path
        result["syscallTrace"] = _parse_strace(combined_stderr)

    # ── gdb function call log ─────────────────────────────────────────────────
    if gdb_log.exists():
        calls_raw = gdb_log.read_text(errors="replace")
        calls = [l[6:].strip() for l in calls_raw.splitlines() if l.startswith("CALL: ")]
        result["functionsCalled"] = list(dict.fromkeys(calls))

    # ── Write output files ───────────────────────────────────────────────────
    (trace_dir / "stdout.txt").write_text(result["stdout"], encoding="utf-8")
    (trace_dir / "stderr_godebug.txt").write_text(result["stderr"], encoding="utf-8")

    sc = result["syscallTrace"]
    if sc:
        _write(trace_dir / "files_read.txt",
               sc.get("filesRead", []),    "FILES READ")
        _write(trace_dir / "files_written.txt",
               sc.get("filesWritten", []), "FILES WRITTEN")
        _write(trace_dir / "network.txt",
               sc.get("networkConnections", []), "NETWORK CONNECTIONS")
        _write(trace_dir / "processes.txt",
               sc.get("processesSpawned", []), "PROCESSES SPAWNED")
        _write(trace_dir / "env_vars.txt",
               sc.get("envVarsAccessed", []), "ENV VARS ACCESSED")

    if result["functionsCalled"]:
        _write(trace_dir / "functions_called.txt",
               result["functionsCalled"], "FUNCTIONS CALLED AT RUNTIME")

    gd = result["godebug"]
    if gd.get("gcEvents") or gd.get("goroutineSnapshots"):
        lines = []
        if gd["gcEvents"]:
            lines += ["── GC Events ──────────────────────────────────────"] + gd["gcEvents"]
        if gd["schedEvents"]:
            lines += ["", "── Scheduler Events ───────────────────────────────"] + gd["schedEvents"]
        if gd["goroutineSnapshots"]:
            lines += ["", "── Goroutine Snapshots ────────────────────────────"] + gd["goroutineSnapshots"]
        if gd["panics"]:
            lines += ["", "── Panics / Fatal Errors ──────────────────────────"] + gd["panics"]
        _write(trace_dir / "runtime_events.txt", lines, "GO RUNTIME EVENTS (GODEBUG)")

    # ── Summary file ─────────────────────────────────────────────────────────
    summary = [
        f"Binary      : {binary_path.name}",
        f"Tracer      : {tracer or 'none (GODEBUG only)'}",
        f"Exit code   : {result['exitCode']}",
        f"Timed out   : {result['timedOut']} (limit: {trace_timeout}s)",
        "",
        f"Files read     : {len(sc.get('filesRead', []))}",
        f"Files written  : {len(sc.get('filesWritten', []))}",
        f"Network conns  : {len(sc.get('networkConnections', []))}",
        f"Processes      : {len(sc.get('processesSpawned', []))}",
        f"Env vars read  : {len(sc.get('envVarsAccessed', []))}",
        f"Functions hit  : {len(result['functionsCalled'])}",
        f"GC events      : {len(gd.get('gcEvents', []))}",
        f"Goroutines     : {len(gd.get('goroutineSnapshots', []))}",
        f"Panics         : {len(gd.get('panics', []))}",
    ]
    _write(trace_dir / "summary.txt", summary, "DYNAMIC TRACE SUMMARY")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    print()
    print(bold(cyan("  ██████╗  ██████╗ ██╗███╗   ██╗███████╗██╗  ██╗")))
    print(bold(cyan("  ██╔════╝ ██╔═══██╗██║████╗  ██║██╔════╝╚██╗██╔╝")))
    print(bold(cyan("  ██║  ███╗██║   ██║██║██╔██╗ ██║███████╗ ╚███╔╝ ")))
    print(bold(cyan("  ██║   ██║██║   ██║██║██║╚██╗██║╚════██║ ██╔██╗ ")))
    print(bold(cyan("  ╚██████╔╝╚██████╔╝██║██║ ╚████║███████║██╔╝ ██╗")))
    print(bold(cyan("   ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝")))
    print(bold(cyan("  ████████╗██████╗  █████╗  ██████╗████████╗ ██████╗ ██████╗")))
    print(bold(cyan("     ██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗")))
    print(bold(cyan("     ██║   ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝")))
    print(bold(cyan("     ██║   ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗")))
    print(bold(cyan("     ██║   ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║")))
    print(bold(cyan("     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝")))
    print()
    print(bold("  goinsxtractor.py") + dim(" — Go binary extractor + Ghidra decompiler"))
    print(dim("  Recovers build info · symbols · packages · sources · strings · embeds · C pseudocode"))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main extraction pipeline
# ─────────────────────────────────────────────────────────────────────────────

def extract(
    binary_path: str,
    output_dir: str | None = None,
    use_ghidra: bool = False,
    ghidra_home_arg: str | None = None,
    skip_stdlib: bool = True,
    max_funcs: int = 0,
    timeout: int = 600,
    use_trace: bool = False,
    trace_args: list[str] | None = None,
    trace_timeout: int = 30,
) -> int:
    banner()

    path = Path(binary_path)
    if not path.exists():
        print(red(f"  [ERROR] File not found: {binary_path}"))
        return 1
    if not path.is_file():
        print(red(f"  [ERROR] Not a file: {binary_path}"))
        return 1

    print(f"  {bold('Target')}   : {path.resolve()}")
    print(f"  {bold('Size')}     : {path.stat().st_size:,} bytes")

    data = path.read_bytes()
    fmt  = detect_format(data)
    print(f"  {bold('Format')}   : {fmt}")
    if fmt == "Unknown":
        print(yellow("  [WARN] Not a recognised executable format — attempting anyway…"))

    if BUILDINFO_MAGIC not in data:
        print(yellow("  [WARN] No Go build-info magic found — may not be a Go binary, "
                     "pre-1.18, or stripped with -w."))
    else:
        print(f"  {green('[OK]')} Go build-info block detected")

    # Ghidra pre-check
    ghidra_home = None
    if use_ghidra:
        ghidra_home = find_ghidra(ghidra_home_arg)
        if ghidra_home:
            print(f"  {green('[OK]')} Ghidra found: {ghidra_home}")
        else:
            print(red("  [ERROR] Ghidra not found. Install Ghidra and set GHIDRA_HOME, "
                      "or pass --ghidra-home <path>."))
            print(red("          Download: https://ghidra-sre.org/"))
            return 1

    if output_dir is None:
        out_dir = Path(path.stem + "_extracted")
    else:
        out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"  {bold('Output')}   : {out_dir.resolve()}")
    print()

    report = {
        "tool": "goinsxtractor",
        "version": "1.1.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file": str(path.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    total_steps = 6 + (1 if use_ghidra else 0) + (1 if use_trace else 0)

    # ── 1. Binary metadata ───────────────────────────────────────────────────
    print(f"  [{bold(f'1/{total_steps}')}] Parsing binary metadata…", end=" ", flush=True)
    meta = parse_binary_metadata(data, path.name)
    report["metadata"] = meta
    print(green("done"))
    print(f"         OS: {meta['os'] or 'unknown'}  "
          f"Arch: {meta['arch'] or 'unknown'}  "
          f"Stripped: {meta['isStripped']}")
    if meta["sections"]:
        print(f"         Sections ({len(meta['sections'])}): "
              + ", ".join(meta["sections"][:12])
              + (" …" if len(meta["sections"]) > 12 else ""))

    # ── 2. Build info ────────────────────────────────────────────────────────
    print(f"\n  [{bold(f'2/{total_steps}')}] Extracting Go build info…", end=" ", flush=True)
    build_info = extract_build_info(data) or {
        "goVersion": "unknown (stripped or pre-1.18)",
        "modulePath": None,
        "moduleVersion": None,
        "settings": [],
        "dependencies": [],
    }
    report["buildInfo"] = build_info
    print(green("done"))
    print(f"         Go version : {bold(build_info['goVersion'])}")
    if build_info.get("modulePath"):
        print(f"         Module     : {build_info['modulePath']} "
              f"{build_info.get('moduleVersion') or ''}")
    print(f"         Deps found : {len(build_info['dependencies'])}")
    for s in build_info.get("settings", []):
        print(f"         build {s['key']}={s['value']}")

    # ── 3. Symbols & source files ────────────────────────────────────────────
    print(f"\n  [{bold(f'3/{total_steps}')}] Recovering symbols from pclntab…", end=" ", flush=True)
    sym_p, src_p = extract_symbols_from_pclntab(data)
    sym_r, src_r = scan_symbols_regex(data)
    all_syms = list(dict.fromkeys(sym_p + sym_r))
    all_srcs = list(dict.fromkeys(src_p + src_r))
    report["symbols"]     = all_syms
    report["sourcePaths"] = all_srcs
    print(green("done"))
    print(f"         Functions    : {len(all_syms)}")
    print(f"         Source paths : {len(all_srcs)}")

    # ── 4. Package names ─────────────────────────────────────────────────────
    print(f"\n  [{bold(f'4/{total_steps}')}] Deducing package list…", end=" ", flush=True)
    packages = deduce_packages(all_syms)
    report["packages"] = packages
    print(green("done"))
    print(f"         Packages: {len(packages)}")
    if packages[:8]:
        print("         " + "  ".join(packages[:8]) + (" …" if len(packages) > 8 else ""))

    # ── 5. Interesting strings ───────────────────────────────────────────────
    print(f"\n  [{bold(f'5/{total_steps}')}] Scanning for interesting strings…", end=" ", flush=True)
    strings = extract_interesting_strings(data)
    report["strings"] = strings
    print(green("done"))
    print(f"         Strings: {len(strings)}")

    # ── 6. Embedded files ────────────────────────────────────────────────────
    print(f"\n  [{bold(f'6/{total_steps}')}] Searching for embedded files (go:embed)…", end=" ", flush=True)
    embedded = extract_embedded_files(data, out_dir)
    report["embeddedFiles"] = embedded
    print(green("done"))
    if embedded:
        print(f"         Found {len(embedded)} embedded file(s):")
        for ef in embedded[:10]:
            print(f"           {ef['path']}  ({ef['size']:,} bytes)")
    else:
        print("         No embedded zip archives found.")

    # ── 7. Ghidra decompilation ──────────────────────────────────────────────
    ghidra_result = None
    if use_ghidra and ghidra_home:
        scope_msg = ""
        if skip_stdlib:
            scope_msg += " [stdlib skipped]"
        if max_funcs:
            scope_msg += f" [max {max_funcs} funcs]"
        print(f"\n  [{bold(f'7/{total_steps}')}] {magenta('Ghidra decompilation')}{scope_msg}…")
        print(f"         This may take several minutes for large binaries.")
        print(f"         Timeout: {timeout}s  |  Ctrl-C to abort and keep partial results")
        print()

        ghidra_result = run_ghidra_decompile(
            binary_path=path,
            out_dir=out_dir,
            ghidra_home=ghidra_home,
            skip_stdlib=skip_stdlib,
            max_funcs=max_funcs,
            timeout=timeout,
        )
        report["ghidra"] = ghidra_result

        if ghidra_result["success"]:
            n = ghidra_result["funcsDecompiled"]
            print(f"         {green('✓')} Decompiled {bold(str(n))} functions  →  "
                  f"decompiled.c  +  decompiled/ ({n} files)")
        else:
            print(f"         {red('✗')} Ghidra decompilation failed:")
            for line in (ghidra_result.get("error") or "unknown error").splitlines()[-8:]:
                print(f"           {dim(line)}")

    # ── 8. Dynamic trace ─────────────────────────────────────────────────────
    trace_result = None
    if use_trace:
        step_n = 7 + (1 if use_ghidra else 0)
        tracer = _detect_tracer()
        tracer_label = tracer or dim("none — GODEBUG only")
        print(f"\n  [{bold(f'{step_n}/{total_steps}')}] {yellow('Dynamic trace')}  "
              f"[tracer: {tracer_label}]")
        print(f"         {yellow('⚠  WARNING:')} This EXECUTES the binary on your machine.")
        print(f"         Do NOT use on untrusted / malware samples without a sandbox.")
        print(f"         Timeout: {trace_timeout}s")
        if trace_args:
            print(f"         Args: {' '.join(trace_args)}")
        print()

        trace_result = run_dynamic_trace(
            binary_path=path,
            out_dir=out_dir,
            trace_args=trace_args or [],
            trace_timeout=trace_timeout,
            known_symbols=all_syms,
        )
        report["dynamicTrace"] = trace_result

        if trace_result["success"]:
            sc = trace_result.get("syscallTrace", {})
            gd = trace_result.get("godebug", {})
            fc = trace_result.get("functionsCalled", [])
            timed = " (timed out)" if trace_result["timedOut"] else ""
            print(f"         {green('✓')} Trace complete{timed}  "
                  f"exit={trace_result['exitCode']}")
            print(f"         Files read   : {len(sc.get('filesRead', []))}")
            print(f"         Files written: {len(sc.get('filesWritten', []))}")
            print(f"         Network conns: {len(sc.get('networkConnections', []))}")
            print(f"         Procs spawned: {len(sc.get('processesSpawned', []))}")
            print(f"         Funcs called : {len(fc)}  (via gdb)")
            print(f"         GC events    : {len(gd.get('gcEvents', []))}")
            print(f"         Goroutines   : {len(gd.get('goroutineSnapshots', []))}")
            if gd.get("panics"):
                for p in gd["panics"][:3]:
                    print(f"         {red('PANIC:')} {p}")
        else:
            print(f"         {red('✗')} Trace failed: {trace_result.get('error', 'unknown')}")

    # ── Write static output files ────────────────────────────────────────────
    print()
    print(bold("  Writing output…"))

    bi_lines = [
        f"Go Version : {build_info['goVersion']}",
        f"Module     : {build_info.get('modulePath') or 'n/a'}",
        f"Version    : {build_info.get('moduleVersion') or 'n/a'}",
        "",
        "Build settings:",
    ] + [f"  {s['key']}={s['value']}" for s in build_info.get("settings", [])] + [
        "",
        f"Dependencies ({len(build_info['dependencies'])}):",
    ] + [
        f"  {d['path']}  {d['version']}" + (f"  => {d['replace']}" if d.get("replace") else "")
        for d in build_info["dependencies"]
    ]
    _write(out_dir / "build_info.txt",   bi_lines,  "BUILD INFO")
    _write(out_dir / "packages.txt",     packages,  f"PACKAGES ({len(packages)} total)")
    _write(out_dir / "functions.txt",    all_syms,  f"FUNCTIONS ({len(all_syms)} total)")
    _write(out_dir / "source_files.txt", all_srcs,  f"SOURCE FILE PATHS ({len(all_srcs)} total)")
    _write(out_dir / "strings.txt",      strings,   f"INTERESTING STRINGS ({len(strings)} total)")
    _write(out_dir / "metadata.txt", [
        f"File      : {path.name}",
        f"SHA-256   : {report['sha256']}",
        f"Size      : {meta['fileSize']:,} bytes",
        f"Format    : {meta['format']}",
        f"OS        : {meta['os'] or 'unknown'}",
        f"Arch      : {meta['arch'] or 'unknown'}",
        f"Stripped  : {meta['isStripped']}",
        "",
        "Sections:",
    ] + [f"  {s}" for s in meta["sections"]], "BINARY METADATA")

    (out_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("  " + "─" * 62)
    print(f"  {bold(green('Extraction complete!'))}  →  {bold(str(out_dir))}/")
    print()
    print(f"    {'build_info.txt':<26} Go version, module, {len(build_info['dependencies'])} deps")
    print(f"    {'packages.txt':<26} {len(packages)} packages")
    print(f"    {'functions.txt':<26} {len(all_syms)} function symbols")
    print(f"    {'source_files.txt':<26} {len(all_srcs)} recovered source paths")
    print(f"    {'strings.txt':<26} {len(strings)} interesting strings")
    print(f"    {'embedded/':<26} {len(embedded)} embedded file(s)")
    print(f"    {'metadata.txt':<26} binary metadata & sections")
    print(f"    {'report.json':<26} full machine-readable report")

    if use_ghidra and ghidra_result:
        if ghidra_result["success"]:
            n = ghidra_result["funcsDecompiled"]
            print(f"    {magenta('decompiled.c'):<26} {n} functions — C pseudocode (monolithic)")
            print(f"    {magenta('decompiled/'):<26} {n} individual .c files (one per function)")
        else:
            print(f"    {red('decompiled.c'):<26} {red('FAILED — see error above')}")

    if use_trace and trace_result:
        sc = trace_result.get("syscallTrace", {})
        if trace_result["success"]:
            print(f"    {yellow('trace/summary.txt'):<26} dynamic trace summary")
            print(f"    {yellow('trace/files_read.txt'):<26} {len(sc.get('filesRead', []))} files read")
            print(f"    {yellow('trace/files_written.txt'):<26} {len(sc.get('filesWritten', []))} files written")
            print(f"    {yellow('trace/network.txt'):<26} {len(sc.get('networkConnections', []))} network connections")
            print(f"    {yellow('trace/functions_called.txt'):<26} {len(trace_result.get('functionsCalled', []))} funcs hit at runtime")
            print(f"    {yellow('trace/runtime_events.txt'):<26} GC + goroutine events")
            print(f"    {yellow('trace/stdout.txt'):<26} binary stdout output")
            if (out_dir / "trace" / "strace.log").exists():
                print(f"    {yellow('trace/strace.log'):<26} raw syscall log")
            if (out_dir / "trace" / "gdb_calls.log").exists():
                print(f"    {yellow('trace/gdb_calls.log'):<26} raw gdb breakpoint log")
        else:
            print(f"    {red('trace/'):<26} {red('FAILED — see error above')}")
    print()

    # ── Tips ─────────────────────────────────────────────────────────────────
    tips = []
    if not use_ghidra:
        tips.append("--ghidra       decompile every function to C pseudocode (needs Ghidra 10+)")
    if not use_trace:
        tips.append("--trace        run the binary live and intercept all syscalls + runtime events")
    if tips:
        print(dim("  More power: " + "  |  ".join(tips)))
        print()

    if meta["isStripped"]:
        print(yellow("  ⚠  Binary is stripped (-ldflags='-s -w'). Symbol coverage is reduced."))
        print(yellow("     Rebuild without -s -w for maximum extraction."))
        print()

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="goinsxtractor",
        description=(
            "Extract build info, symbols, packages, source paths, strings, and embedded\n"
            "files from a compiled Go binary. Optionally decompile to C pseudocode via Ghidra."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python goinsxtractor.py mybinary
  python goinsxtractor.py mybinary.exe output/
  python goinsxtractor.py mybinary --ghidra
  python goinsxtractor.py mybinary --ghidra --ghidra-home ~/ghidra_11.0
  python goinsxtractor.py mybinary --ghidra --no-skip-stdlib --max-funcs 500
  python goinsxtractor.py mybinary --ghidra --timeout 1200

ghidra decompilation notes:
  • Requires Ghidra 10+ and Java 17+  →  https://ghidra-sre.org/
  • Set GHIDRA_HOME env var or pass --ghidra-home
  • By default stdlib/runtime functions are skipped (use --no-skip-stdlib to include them)
  • Large binaries may take 5-20 minutes; use --max-funcs to cap scope
  • Output: decompiled.c (all functions) + decompiled/<function>.c (one file each)
        """,
    )
    p.add_argument("binary",      help="Path to the Go executable to analyse")
    p.add_argument("output_dir",  nargs="?", default=None,
                   help="Output directory (default: <binary>_extracted/)")

    g = p.add_argument_group("Ghidra decompilation (step 7)")
    g.add_argument("--ghidra",    action="store_true",
                   help="Run Ghidra headless decompilation")
    g.add_argument("--ghidra-home", metavar="PATH", default=None,
                   help="Path to Ghidra installation (overrides GHIDRA_HOME env var)")
    g.add_argument("--no-skip-stdlib", action="store_true",
                   help="Include Go stdlib/runtime functions in Ghidra output (slow, very large)")
    g.add_argument("--max-funcs", type=int, default=0, metavar="N",
                   help="Limit Ghidra to first N user functions (0 = unlimited)")
    g.add_argument("--timeout",   type=int, default=600, metavar="SECS",
                   help="Ghidra analysis timeout in seconds (default: 600)")

    t = p.add_argument_group("Dynamic trace — execute the binary and intercept everything (step 8)")
    t.add_argument("--trace",     action="store_true",
                   help="Run the binary live and capture syscalls, runtime events, function calls")
    t.add_argument("--trace-timeout", type=int, default=30, metavar="SECS",
                   help="Kill the binary after N seconds (default: 30)")
    t.add_argument("--trace-args", nargs=argparse.REMAINDER, default=[], metavar="ARG",
                   help="Arguments to pass to the binary (put after --)")

    args = p.parse_args()

    return extract(
        binary_path     = args.binary,
        output_dir      = args.output_dir,
        use_ghidra      = args.ghidra,
        ghidra_home_arg = args.ghidra_home,
        skip_stdlib     = not args.no_skip_stdlib,
        max_funcs       = args.max_funcs,
        timeout         = args.timeout,
        use_trace       = args.trace,
        trace_args      = args.trace_args or [],
        trace_timeout   = args.trace_timeout,
    )


if __name__ == "__main__":
    sys.exit(main())
