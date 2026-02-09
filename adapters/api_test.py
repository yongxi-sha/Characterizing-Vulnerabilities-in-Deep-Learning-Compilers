from __future__ import annotations

import argparse
import csv
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


DATASET_FIELDS: Sequence[str] = (
    "vuln_id",
    "source",
    "compiler",
    "compiler_version",
    "root_cause",
    "impact",
    "compilation_stage",
    "description",
    "fix_status",
    "references",
    "reported_time",
)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "t", "yes", "y"}


def _clean_text(s: Any, *, limit: int = 2000, flatten_newlines: bool = True) -> str:
    if s is None:
        return ""
    txt = str(s)
    # Remove null bytes that can break CSV consumers
    txt = txt.replace("\x00", "")
    # Normalize whitespace a bit (keep newlines for readability)
    txt = re.sub(r"[ \t]+", " ", txt)
    txt = txt.replace("\r\n", "\n").replace("\r", "\n")
    txt = re.sub(r"\n{3,}", "\n\n", txt)
    txt = txt.strip()
    if flatten_newlines:
        # Keep the data CSV-friendly: preserve intent using literal "\n"
        txt = txt.replace("\n", "\\n")
    if len(txt) > limit:
        txt = txt[: limit - 3].rstrip() + "..."
    return txt


def _cache_security_reason(cache_entry: Any) -> str:
    if isinstance(cache_entry, dict):
        return _clean_text(cache_entry.get("reason", ""), limit=2000)
    return ""


def _infer_root_cause(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["shape", "reshape", "broadcast", "dimension mismatch"]):
        return "shape inference error"
    if any(k in t for k in ["type confusion", "type mismatch", "expected", "dtype"]):
        return "type system/type confusion issue"
    if any(
        k in t
        for k in [
            "buffer overflow",
            "out-of-bounds",
            "oob",
            "segmentation fault",
            "sigsegv",
            "invalid pointer",
            "use-after-free",
            "double free",
            "heap corruption",
            "stack smashing",
        ]
    ):
        return "memory safety issue"
    if any(k in t for k in ["race condition", "data race", "thread safety"]):
        return "concurrency issue"
    if any(k in t for k in ["codegen", "code generation", "llvm", "cuda", "opencl", "metal"]):
        return "codegen/lowering bug"
    if any(k in t for k in ["check failed", "internalerror", "assert fail", "invariant"]):
        return "IR invariant violation"
    if any(k in t for k in ["hlo", "stablehlo", "mhlo", "mlir"]):
        return "IR invariant violation"
    return "unknown"


def _infer_impacts(text: str) -> str:
    t = text.lower()
    impacts: List[str] = []

    def add(label: str, *keywords: str) -> None:
        if any(k in t for k in keywords) and label not in impacts:
            impacts.append(label)

    add("denial of service", "denial of service", "dos", "crash", "segmentation fault", "sigsegv", "abort", "core dumped", "stack overflow")
    add("memory corruption", "memory corruption", "buffer overflow", "out-of-bounds", "use-after-free", "double free", "heap corruption", "invalid pointer", "stack smashing")
    add("remote code execution", "remote code execution", "rce", "arbitrary code execution")
    add("information leakage", "information leak", "leak", "secrets leakage", "private key")
    add("integrity violation", "integrity", "data corruption")
    add("reliability degradation", "hang", "resource exhaustion", "memory leak", "unbounded memory")
    add("silent misclassification", "silent", "misclassification", "wrong result", "incorrect result")

    return "; ".join(impacts) if impacts else "unknown"


def _infer_compilation_stage(text: str) -> str:
    t = text.lower()
    stages: List[str] = []

    def add(stage: str, *keywords: str) -> None:
        if any(k in t for k in keywords) and stage not in stages:
            stages.append(stage)

    add("frontend/IR construction", "onnx", "pytorch", "relay", "frontend", "import")
    add("frontend/IR construction", "jax", "tensorflow", "torch", "stablehlo", "mhlo", "hlo")
    add("graph optimization", "opt", "optimize", "transform", "pass", "fuse", "fold", "simplif")
    add("lowering", "lower", "tir", "tensorir", "schedule", "te")
    add("backend", "codegen", "llvm", "cuda", "opencl", "metal", "vulkan", "wasm", "link", "compile")
    add("runtime/execution", "runtime", "vm execution", "virtualmachine", "rpc", "load_module", "dlopen")
    add("lowering", "mlir", "mhlo", "stablehlo", "hlo")

    return "; ".join(stages) if stages else "unknown"


def iter_tvm_rows(path: Path) -> Iterable[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            yield {k: (v if v is not None else "") for k, v in row.items()}


def extract_compiler_version_from_text(text: str) -> str:
    """
    Best-effort extraction of TVM version/commit from issue text.

    Returns a semicolon-separated string (e.g., "v0.21.0; commit abcdef...") or "".
    """
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    out: List[str] = []

    # Common issue template fields
    version_patterns = [
        r"(?:TVM\s*[Vv]ersion|tvm\s*[Vv]ersion)\s*[:=]\s*([^\n]+)",
        r"(?:TVM\s+version\s+is|tvm\s+version\s+is)\s*[:=]?\s*([^\n]+)",
    ]
    for pat in version_patterns:
        m = re.search(pat, t)
        if m:
            raw = m.group(1).strip()
            # Trim overly long trailing info
            raw = re.split(r"\s{2,}|[,;]\s*(?:python|llvm|os|cuda|pytorch)\b", raw, maxsplit=1, flags=re.I)[0].strip()
            if raw:
                # Prefer a "v0.x.y" token if present
                mver = re.search(r"\bv?0\.\d+\.\d+(?:\.\d+)?(?:[a-z0-9.+-]*)?\b", raw, flags=re.I)
                out.append(mver.group(0) if mver else raw)
            break

    # Commit hashes
    commit_patterns = [
        r"(?:TVM\s*commit|tvm\s*commit)\s*[:=]?\s*([0-9a-f]{7,40})",
        r"(?:TVM\s*SHA|tvm\s*sha)\s*[:=]?\s*([0-9a-f]{7,40})",
    ]
    for pat in commit_patterns:
        m = re.search(pat, t, flags=re.I)
        if m:
            sha = m.group(1).lower()
            out.append(f"commit {sha}")
            break

    # Sometimes only a "release v0.xx.x" appears
    m = re.search(r"\brelease\s+(v0\.\d+\.\d+(?:\.\d+)?)\b", t, flags=re.I)
    if m and m.group(1) not in out:
        out.append(m.group(1))

    # Also handle cases like: "libtvm_runtime.so (v0.18.0)" or "TVM (release v0.21.0)"
    m = re.search(
        r"\b(?:TVM|tvm|libtvm(?:_runtime)?\.so)\b[^\n]{0,120}\b(v?0\.\d+\.\d+(?:\.\d+)?(?:[a-z0-9.+-]*)?)\b",
        t,
        flags=re.I,
    )
    if m:
        v = m.group(1)
        if v and v not in out:
            out.append(v)

    # Dedupe while preserving order
    deduped: List[str] = []
    for x in out:
        if x and x not in deduped:
            deduped.append(x)
    return "; ".join(deduped)


def github_issue_api_fetch(repo: str, number: str, *, timeout_s: float = 20.0) -> Optional[Dict[str, Any]]:
    """
    Fetch issue/PR JSON via GitHub REST API (unauthenticated; rate-limited).
    repo: "apache/tvm"
    number: "17386"
    """
    url = f"https://api.github.com/repos/{repo}/issues/{number}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AI-Security-dataset-builder",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(data)
            return parsed if isinstance(parsed, dict) else None
    except urllib.error.HTTPError as e:
        # Rate limit or not found
        _ = e
        return None
    except Exception:
        return None


def fill_dataset_compiler_versions(
    dataset_in: Path,
    dataset_out: Path,
    tvm_csv_path: Path,
    *,
    use_online_fallback: bool = True,
    online_max_fetches: int = 50,
    online_min_interval_s: float = 1.2,
    fill_unknown: bool = False,
) -> None:
    # Build mapping from issue URL -> full tvm.csv row
    tvm_by_url: Dict[str, Dict[str, str]] = {}
    for r in iter_tvm_rows(tvm_csv_path):
        url = (r.get("url") or "").strip()
        if url:
            tvm_by_url[url] = r

    rows: List[Dict[str, str]] = []
    with dataset_in.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k: (v if v is not None else "") for k, v in row.items()})

    updated = 0
    missing: List[int] = []
    for i, row in enumerate(rows):
        if row.get("compiler", "").strip().upper() != "TVM":
            continue
        if row.get("compiler_version", "").strip():
            continue

        url = row.get("references", "").strip()
        tvm_row = tvm_by_url.get(url)
        if tvm_row:
            # Prefer full issue text (title + body) from tvm.csv (dataset.csv 'description' is truncated).
            text = (tvm_row.get("title", "") or "") + "\n" + (tvm_row.get("body", "") or "")
            ver = extract_compiler_version_from_text(text)
            if ver:
                row["compiler_version"] = ver
                updated += 1
                continue

        missing.append(i)

    # Online fallback for any remaining (best effort; rate-limited)
    if use_online_fallback and missing:
        fetches = 0
        last_ts = 0.0
        for idx in missing:
            if fetches >= online_max_fetches:
                break

            row = rows[idx]
            url = row.get("references", "").strip()
            m = re.match(r"^https?://github\.com/([^/]+/[^/]+)/(?:issues|pull)/(\d+)$", url)
            if not m:
                continue
            repo, number = m.group(1), m.group(2)

            now = time.time()
            sleep_s = (last_ts + online_min_interval_s) - now
            if sleep_s > 0:
                time.sleep(sleep_s)

            data = github_issue_api_fetch(repo, number)
            last_ts = time.time()
            fetches += 1
            if not data:
                continue

            body = str(data.get("body") or "")
            ver = extract_compiler_version_from_text(body)
            if ver:
                row["compiler_version"] = ver
                updated += 1

    if fill_unknown:
        for row in rows:
            if row.get("compiler", "").strip().upper() != "TVM":
                continue
            if not row.get("compiler_version", "").strip():
                row["compiler_version"] = "unknown"

    # Write dataset
    dataset_out.parent.mkdir(parents=True, exist_ok=True)
    with dataset_out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(DATASET_FIELDS))
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in DATASET_FIELDS})

    total = len([r for r in rows if (r.get("compiler") or "").strip().upper() == "TVM"])
    filled = len([r for r in rows if (r.get("compiler_version") or "").strip()])
    print(f"Updated compiler_version for {updated} rows.")
    print(f"Rows: {len(rows)} (TVM rows: {total}, with compiler_version: {filled})")
    print(f"Output: {dataset_out}")


def write_dataset_csv(path: Path, rows: Iterable[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(DATASET_FIELDS))
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in DATASET_FIELDS})


def build_dataset_row(tvm_row: Dict[str, str], cache_entry: Any) -> Dict[str, str]:
    repo = tvm_row.get("repository", "").strip()
    number = tvm_row.get("number", "").strip()
    is_pr = _normalize_bool(tvm_row.get("is_pull_request"))
    source = "GitHub Pull Request" if is_pr else "GitHub Issue"

    url = tvm_row.get("url", "").strip()
    title = _clean_text(tvm_row.get("title", ""), limit=300, flatten_newlines=True)
    body = _clean_text(tvm_row.get("body", ""), limit=1500, flatten_newlines=True)
    security_reason = _cache_security_reason(cache_entry)

    combined_text = "\n".join(x for x in [title, body, security_reason] if x).strip()

    state = tvm_row.get("state", "").strip().lower() or "unknown"
    created_at = tvm_row.get("created_at", "").strip()

    vuln_id = f"{repo}#{number}" if repo and number else (tvm_row.get("id", "").strip() or "unknown")

    return {
        "vuln_id": vuln_id,
        "source": source,
        "compiler": "TVM",
        "compiler_version": "",
        "root_cause": _infer_root_cause(combined_text),
        "impact": _infer_impacts(combined_text),
        "compilation_stage": _infer_compilation_stage(combined_text),
        "description": _clean_text(combined_text, limit=2000, flatten_newlines=True),
        "fix_status": state,
        "references": url,
        "reported_time": created_at,
    }


SECURITY_VULN_REGEX = re.compile(
    r"("
    r"cve-\d{4}-\d+|"
    r"\bvulnerab(?:ility|ilities)\b|"
    r"\buse[- ]after[- ]free\b|\buaf\b|heap[- ]use[- ]after[- ]free|"
    r"\bdouble[- ]free\b|"
    r"\bbuffer[- ]overflow\b|stack[- ]smashing|"
    r"\bout[- ]of[- ]bounds\b|\boob\b|"
    r"heap[- ]corruption|"
    r"\binteger[- ]overflow\b|signed[- ]overflow"
    r")",
    flags=re.IGNORECASE,
)


GLOW_VULN_REGEX = re.compile(
    r"("
    r"cve-\d{4}-\d+|"
    r"\bvulnerab(?:ility|ilities)\b|"
    r"\buse[- ]after[- ]free\b|\buaf\b|heap[- ]use[- ]after[- ]free|"
    r"\bdouble[- ]free\b|"
    r"\bbuffer[- ]overflow\b|stack[- ]smashing|"
    r"\bout[- ]of[- ]bounds\b|\boob\b|"
    r"heap[- ]corruption|corrupted double-linked list|"
    r"\bundefined memory\b|accessing undefined memory|illegal memory|"
    r"\binteger[- ]overflow\b|signed[- ]overflow"
    r")",
    flags=re.IGNORECASE,
)


def is_security_vulnerability_issue(row: Dict[str, str]) -> bool:
    """
    XLA CSV doesn't contain an explicit security flag, so we treat issues mentioning
    common vulnerability classes (UAF/OOB/overflow/CVE/...) as security vulnerabilities.
    """
    text = "\n".join(
        [
            row.get("title", "") or "",
            row.get("labels", "") or "",
            row.get("body", "") or "",
        ]
    )
    return bool(SECURITY_VULN_REGEX.search(text))


def is_glow_vulnerability_issue(row: Dict[str, str]) -> bool:
    """
    Glow CSV doesn't contain an explicit security flag. We filter for likely
    vulnerability-class bugs (OOB/UAF/heap corruption/overflow/undefined memory).
    """
    text = "\n".join(
        [
            row.get("title", "") or "",
            row.get("labels", "") or "",
            row.get("body", "") or "",
        ]
    )
    return bool(GLOW_VULN_REGEX.search(text))


def extract_xla_compiler_version_from_text(text: str) -> str:
    """
    Best-effort extraction for XLA-related version info.
    We keep it conservative; if not clearly present, return "".
    """
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    out: List[str] = []

    # "XLA version: ..." or "openxla/xla version: ..."
    m = re.search(r"\b(?:XLA|xla)\s*version\s*[:=]\s*([^\n]+)", t)
    if m:
        raw = m.group(1).strip()
        mver = re.search(r"\bv?\d+\.\d+\.\d+(?:\.\d+)?\b", raw)
        out.append(mver.group(0) if mver else raw)

    # Commit SHA if explicitly stated
    m = re.search(r"\b(?:XLA|xla)\s*commit\s*[:=]?\s*([0-9a-f]{7,40})\b", t, flags=re.I)
    if m:
        out.append(f"commit {m.group(1).lower()}")

    # Sometimes "commit <sha>" appears near file paths in reports; capture only if labeled
    # (avoid grabbing random SHAs from stack traces by requiring the word 'commit')
    m = re.search(r"\bcommit\s+([0-9a-f]{7,40})\b", t, flags=re.I)
    if m and not any(x.startswith("commit ") for x in out):
        out.append(f"commit {m.group(1).lower()}")

    deduped: List[str] = []
    for x in out:
        if x and x not in deduped:
            deduped.append(x)
    return "; ".join(deduped)


def build_dataset_row_from_github_issue(row: Dict[str, str], *, compiler: str) -> Dict[str, str]:
    repo = (row.get("repository") or "").strip()
    number = (row.get("number") or "").strip()
    is_pr = _normalize_bool(row.get("is_pull_request"))
    source = "GitHub Pull Request" if is_pr else "GitHub Issue"

    url = (row.get("url") or "").strip()
    title = _clean_text(row.get("title", ""), limit=300, flatten_newlines=True)
    body = _clean_text(row.get("body", ""), limit=1500, flatten_newlines=True)

    combined_text = "\n".join(x for x in [title, body] if x).strip()

    state = (row.get("state") or "").strip().lower() or "unknown"
    created_at = (row.get("created_at") or "").strip()

    vuln_id = f"{repo}#{number}" if repo and number else (row.get("id", "").strip() or "unknown")

    compiler_version = ""
    if compiler.strip().upper() == "XLA":
        compiler_version = extract_xla_compiler_version_from_text((row.get("title") or "") + "\n" + (row.get("body") or ""))
    elif compiler.strip().upper() == "GLOW":
        # Glow issues rarely include explicit version; keep unknown unless present.
        compiler_version = ""

    return {
        "vuln_id": vuln_id,
        "source": source,
        "compiler": compiler,
        "compiler_version": compiler_version or "unknown",
        "root_cause": _infer_root_cause(combined_text),
        "impact": _infer_impacts(combined_text),
        "compilation_stage": _infer_compilation_stage(combined_text),
        "description": _clean_text(combined_text, limit=2000, flatten_newlines=True),
        "fix_status": state,
        "references": url,
        "reported_time": created_at,
    }


def append_xla_security_issues_to_dataset(
    *,
    dataset_path: Path,
    xla_csv_path: Path,
    dry_run: bool = False,
) -> None:
    # Read existing dataset and build a dedupe set
    existing_rows: List[Dict[str, str]] = []
    existing_ids: Set[str] = set()
    with dataset_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            row = {k: (v if v is not None else "") for k, v in r.items()}
            existing_rows.append(row)
            vid = (row.get("vuln_id") or "").strip()
            if vid:
                existing_ids.add(vid)

    # Filter XLA issues and map to dataset schema
    new_rows: List[Dict[str, str]] = []
    total = 0
    matched = 0
    deduped = 0
    for r in iter_tvm_rows(xla_csv_path):  # same CSV schema
        total += 1
        if not is_security_vulnerability_issue(r):
            continue
        matched += 1
        ds_row = build_dataset_row_from_github_issue(r, compiler="XLA")
        vid = (ds_row.get("vuln_id") or "").strip()
        if vid and vid in existing_ids:
            deduped += 1
            continue
        if vid:
            existing_ids.add(vid)
        new_rows.append(ds_row)

    print(f"XLA rows scanned: {total}")
    print(f"Matched (security-vuln heuristic): {matched}")
    print(f"New rows to append (after dedupe): {len(new_rows)} (deduped: {deduped})")

    if dry_run:
        return

    combined = existing_rows + new_rows
    write_dataset_csv(dataset_path, combined)
    print(f"Appended. Output: {dataset_path} (total rows now: {len(combined)})")


def append_glow_vulns_to_dataset(
    *,
    dataset_path: Path,
    glow_csv_path: Path,
    dry_run: bool = False,
) -> None:
    existing_rows: List[Dict[str, str]] = []
    existing_ids: Set[str] = set()
    with dataset_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            row = {k: (v if v is not None else "") for k, v in r.items()}
            existing_rows.append(row)
            vid = (row.get("vuln_id") or "").strip()
            if vid:
                existing_ids.add(vid)

    new_rows: List[Dict[str, str]] = []
    total = 0
    matched = 0
    deduped = 0
    for r in iter_tvm_rows(glow_csv_path):  # same CSV schema
        total += 1
        if not is_glow_vulnerability_issue(r):
            continue
        matched += 1
        ds_row = build_dataset_row_from_github_issue(r, compiler="GLOW")
        vid = (ds_row.get("vuln_id") or "").strip()
        if vid and vid in existing_ids:
            deduped += 1
            continue
        if vid:
            existing_ids.add(vid)
        new_rows.append(ds_row)

    print(f"GLOW rows scanned: {total}")
    print(f"Matched (vuln heuristic): {matched}")
    print(f"New rows to append (after dedupe): {len(new_rows)} (deduped: {deduped})")

    if dry_run:
        return

    combined = existing_rows + new_rows
    write_dataset_csv(dataset_path, combined)
    print(f"Appended. Output: {dataset_path} (total rows now: {len(combined)})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build dataset.csv and/or fill compiler_version from GitHub issues."
    )
    parser.add_argument(
        "--mode",
        choices=["build_dataset", "fill_versions", "append_xla_security", "append_glow_vulns"],
        default="build_dataset",
        help="Operation mode",
    )
    parser.add_argument(
        "--tvm_csv",
        default=str(Path("results/github/tvm.csv")),
        help="Input TVM issues/PRs CSV",
    )
    parser.add_argument(
        "--security_cache",
        default=str(Path("results/github/tvm_security_cache_security.json")),
        help="JSON with security_related=true cache entries (keys are tvm.csv 'id')",
    )
    parser.add_argument(
        "--output",
        default=str(Path("results/ground truth/dataset.csv")),
        help="Output dataset CSV",
    )
    parser.add_argument(
        "--dataset_in",
        default=str(Path("results/ground truth/dataset.csv")),
        help="Existing dataset CSV (for fill_versions mode)",
    )
    parser.add_argument(
        "--online_fallback",
        action="store_true",
        help="When filling versions, fetch from GitHub API if not found in tvm.csv body (rate-limited)",
    )
    parser.add_argument(
        "--fill_unknown",
        action="store_true",
        help="When filling versions, set compiler_version='unknown' for rows where no version/commit is found",
    )
    parser.add_argument(
        "--xla_csv",
        default=str(Path("results/github/xla.csv")),
        help="Input XLA issues/PRs CSV (for append_xla_security mode)",
    )
    parser.add_argument(
        "--glow_csv",
        default=str(Path("results/github/glow.csv")),
        help="Input Glow issues/PRs CSV (for append_glow_vulns mode)",
    )
    parser.add_argument(
        "--dry_run",
        action="store_true",
        help="Do not write outputs (for append_xla_security mode)",
    )
    args = parser.parse_args()

    tvm_csv_path = Path(args.tvm_csv)
    cache_path = Path(args.security_cache)
    output_path = Path(args.output)

    if args.mode == "fill_versions":
        dataset_in = Path(args.dataset_in)
        fill_dataset_compiler_versions(
            dataset_in=dataset_in,
            dataset_out=output_path,
            tvm_csv_path=tvm_csv_path,
            use_online_fallback=bool(args.online_fallback),
            fill_unknown=bool(args.fill_unknown),
        )
        return

    if args.mode == "append_xla_security":
        append_xla_security_issues_to_dataset(
            dataset_path=output_path,
            xla_csv_path=Path(args.xla_csv),
            dry_run=bool(args.dry_run),
        )
        return

    if args.mode == "append_glow_vulns":
        append_glow_vulns_to_dataset(
            dataset_path=output_path,
            glow_csv_path=Path(args.glow_csv),
            dry_run=bool(args.dry_run),
        )
        return

    cache = _read_json(cache_path)
    if not isinstance(cache, dict):
        raise ValueError(f"Security cache JSON must be an object/dict: {cache_path}")

    wanted_ids: Set[str] = set(str(k) for k in cache.keys())

    matched: List[Dict[str, str]] = []
    for row in iter_tvm_rows(tvm_csv_path):
        row_id = str(row.get("id", "")).strip()
        if row_id and (row_id in wanted_ids):
            matched.append(build_dataset_row(row, cache.get(row_id)))

    write_dataset_csv(output_path, matched)

    print(f"Matched rows: {len(matched)}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
