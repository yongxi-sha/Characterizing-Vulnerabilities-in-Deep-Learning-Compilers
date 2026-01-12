import argparse
import csv
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


def extract_cwe_ids(raw: str) -> list[str]:
    if not raw:
        return []
    # Handles formats like: "CWE-119;CWE-416" or "CWE-119, CWE-416"
    return re.findall(r"CWE-\d+", raw)


# High-level categories. These are intentionally coarse so they work across many CWEs.
#
# NOTE: This mapping is based on common CWE themes (memory safety, injection, access control, etc.).
# It is not a substitute for the official CWE taxonomy and may be adjusted for your reporting needs.
CWE_TO_CATEGORY: dict[str, str] = {
    # Configuration / environment / path search
    "CWE-15": "Configuration / Environment",
    "CWE-276": "Configuration / Environment",
    "CWE-427": "Configuration / Environment",

    # Input validation / canonicalization / error handling
    "CWE-20": "Input Validation / Error Handling",
    "CWE-178": "Input Validation / Error Handling",
    "CWE-697": "Input Validation / Error Handling",
    "CWE-754": "Input Validation / Error Handling",
    "CWE-755": "Input Validation / Error Handling",
    "CWE-807": "Input Validation / Error Handling",
    "CWE-1284": "Input Validation / Error Handling",

    # Injection (web + general)
    "CWE-74": "Injection",
    "CWE-76": "Injection",
    "CWE-77": "Injection",
    "CWE-78": "Injection",
    "CWE-79": "Injection",
    "CWE-80": "Injection",
    "CWE-89": "Injection",
    "CWE-94": "Injection",
    "CWE-95": "Injection",
    "CWE-98": "Injection",
    "CWE-116": "Injection",
    "CWE-611": "Injection",
    "CWE-1236": "Injection",
    "CWE-1321": "Injection",
    "CWE-1336": "Injection",

    # SSRF / request forgery
    "CWE-352": "Request Forgery (CSRF/SSRF)",
    "CWE-918": "Request Forgery (CSRF/SSRF)",

    # Path / file handling (including traversal, symlinks, and uploads)
    "CWE-22": "File / Path Handling",
    "CWE-23": "File / Path Handling",
    "CWE-29": "File / Path Handling",
    "CWE-35": "File / Path Handling",
    "CWE-36": "File / Path Handling",
    "CWE-59": "File / Path Handling",
    "CWE-219": "File / Path Handling",
    "CWE-434": "File / Path Handling",
    "CWE-552": "File / Path Handling",
    "CWE-598": "File / Path Handling",
    "CWE-646": "File / Path Handling",

    # Access control / authorization / privilege
    "CWE-250": "Access Control / Authorization",
    "CWE-264": "Access Control / Authorization",
    "CWE-266": "Access Control / Authorization",
    "CWE-269": "Access Control / Authorization",
    "CWE-284": "Access Control / Authorization",
    "CWE-285": "Access Control / Authorization",
    "CWE-425": "Access Control / Authorization",
    "CWE-639": "Access Control / Authorization",
    "CWE-732": "Access Control / Authorization",
    "CWE-862": "Access Control / Authorization",
    "CWE-863": "Access Control / Authorization",
    "CWE-1220": "Access Control / Authorization",

    # Authentication / credentials / account security
    "CWE-257": "Authentication / Credentials",
    "CWE-287": "Authentication / Credentials",
    "CWE-288": "Authentication / Credentials",
    "CWE-290": "Authentication / Credentials",
    "CWE-302": "Authentication / Credentials",
    "CWE-305": "Authentication / Credentials",
    "CWE-306": "Authentication / Credentials",
    "CWE-307": "Authentication / Credentials",
    "CWE-522": "Authentication / Credentials",
    "CWE-640": "Authentication / Credentials",
    "CWE-798": "Authentication / Credentials",
    "CWE-1390": "Authentication / Credentials",

    # Cryptography / data protection
    "CWE-310": "Cryptography / Data Protection",
    "CWE-311": "Cryptography / Data Protection",
    "CWE-312": "Cryptography / Data Protection",
    "CWE-319": "Cryptography / Data Protection",
    "CWE-323": "Cryptography / Data Protection",
    "CWE-326": "Cryptography / Data Protection",
    "CWE-328": "Cryptography / Data Protection",
    "CWE-330": "Cryptography / Data Protection",
    "CWE-335": "Cryptography / Data Protection",
    "CWE-339": "Cryptography / Data Protection",
    "CWE-345": "Cryptography / Data Protection",
    "CWE-354": "Cryptography / Data Protection",

    # Information disclosure / side-channels / privacy
    "CWE-200": "Information Disclosure / Side-Channel",
    "CWE-203": "Information Disclosure / Side-Channel",
    "CWE-208": "Information Disclosure / Side-Channel",
    "CWE-532": "Information Disclosure / Side-Channel",
    "CWE-548": "Information Disclosure / Side-Channel",

    # Denial of Service / resource exhaustion
    "CWE-399": "Denial of Service / Resource Exhaustion",
    "CWE-400": "Denial of Service / Resource Exhaustion",
    "CWE-401": "Denial of Service / Resource Exhaustion",
    "CWE-440": "Denial of Service / Resource Exhaustion",
    "CWE-617": "Denial of Service / Resource Exhaustion",
    "CWE-670": "Denial of Service / Resource Exhaustion",
    "CWE-674": "Denial of Service / Resource Exhaustion",
    "CWE-770": "Denial of Service / Resource Exhaustion",
    "CWE-835": "Denial of Service / Resource Exhaustion",
    "CWE-1333": "Denial of Service / Resource Exhaustion",

    # Concurrency
    "CWE-362": "Concurrency / Race Condition",
    "CWE-367": "Concurrency / Race Condition",
    "CWE-662": "Concurrency / Race Condition",
    "CWE-665": "Input Validation / Error Handling",
    "CWE-667": "Concurrency / Race Condition",
    "CWE-668": "Access Control / Authorization",

    # Deserialization
    "CWE-502": "Deserialization",

    # Session management
    "CWE-613": "Session Management",

    # Web redirect
    "CWE-601": "Web Redirect",

    # Integer/arithmetic issues
    "CWE-189": "Integer / Arithmetic",
    "CWE-190": "Integer / Arithmetic",
    "CWE-191": "Integer / Arithmetic",
    "CWE-193": "Integer / Arithmetic",
    "CWE-323": "Cryptography / Data Protection",
    "CWE-369": "Integer / Arithmetic",
    "CWE-681": "Integer / Arithmetic",
    "CWE-682": "Integer / Arithmetic",

    # Memory safety (bounds, UAF, null deref, etc.)
    "CWE-119": "Memory Safety",
    "CWE-120": "Memory Safety",
    "CWE-121": "Memory Safety",
    "CWE-122": "Memory Safety",
    "CWE-125": "Memory Safety",
    "CWE-126": "Memory Safety",
    "CWE-131": "Memory Safety",
    "CWE-134": "Memory Safety",
    "CWE-415": "Memory Safety",
    "CWE-416": "Memory Safety",
    "CWE-475": "Memory Safety",
    "CWE-476": "Memory Safety",
    "CWE-704": "Memory Safety",
    "CWE-787": "Memory Safety",
    "CWE-824": "Memory Safety",
    "CWE-841": "Input Validation / Error Handling",
    "CWE-843": "Memory Safety",
    "CWE-908": "Memory Safety",
    "CWE-1220": "Access Control / Authorization",
    "CWE-1284": "Input Validation / Error Handling",
    "CWE-1321": "Injection",

    # Supply chain / integrity (non-crypto)
    "CWE-494": "Supply Chain / Integrity",
    "CWE-829": "Supply Chain / Integrity",

    # Misc
    "CWE-356": "Other",
    "CWE-598": "Information Disclosure / Side-Channel",
    "CWE-1039": "Other",
    "CWE-1236": "Injection",
    "CWE-1321": "Injection",
    "CWE-1333": "Denial of Service / Resource Exhaustion",
    "CWE-1336": "Injection",
}


def category_for_cwe(cwe_id: str) -> str:
    return CWE_TO_CATEGORY.get(cwe_id, "Other")


def join_unique(values: Iterable[str]) -> str:
    seen = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return ";".join(out)


def run(input_csv: Path, output_csv: Path, summary_csv: Path, unmapped_csv: Path | None) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    summary_csv.parent.mkdir(parents=True, exist_ok=True)
    if unmapped_csv is not None:
        unmapped_csv.parent.mkdir(parents=True, exist_ok=True)

    category_counts = Counter()
    cwe_counts = Counter()
    unmapped = Counter()
    rows_per_category: dict[str, int] = defaultdict(int)

    with input_csv.open("r", encoding="utf-8", errors="replace", newline="") as fin, \
            output_csv.open("w", encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            raise ValueError(f"No header found in {input_csv}")

        extra_cols = ["cwe_ids_normalized", "cwe_categories"]
        writer = csv.DictWriter(fout, fieldnames=list(reader.fieldnames) + extra_cols)
        writer.writeheader()

        for row in reader:
            cwe_ids = extract_cwe_ids(row.get("cwes", "") or "")
            if cwe_ids:
                for cwe in cwe_ids:
                    cwe_counts[cwe] += 1
            else:
                unmapped["(missing)"] += 1

            cats = [category_for_cwe(cwe) for cwe in cwe_ids]
            if not cats:
                cats = ["Unknown (Missing CWE)"]
            # Count categories per CWE occurrence and per-row presence.
            for c in cats:
                category_counts[c] += 1
            for c in set(cats):
                rows_per_category[c] += 1

            for cwe in cwe_ids:
                if cwe not in CWE_TO_CATEGORY:
                    unmapped[cwe] += 1

            out_row = dict(row)
            out_row["cwe_ids_normalized"] = join_unique(cwe_ids)
            out_row["cwe_categories"] = join_unique(cats)
            writer.writerow(out_row)

    # Summary CSV: categories + top CWEs
    with summary_csv.open("w", encoding="utf-8", newline="") as fsum:
        w = csv.writer(fsum)
        w.writerow(["type", "name", "count", "rows_with_category"])
        for cat, cnt in category_counts.most_common():
            w.writerow(["category", cat, cnt, rows_per_category.get(cat, 0)])
        for cwe, cnt in cwe_counts.most_common():
            w.writerow(["cwe", cwe, cnt, ""])

    if unmapped_csv is not None:
        with unmapped_csv.open("w", encoding="utf-8", newline="") as fun:
            w = csv.writer(fun)
            w.writerow(["cwe_id", "count"])
            for cwe, cnt in unmapped.most_common():
                w.writerow([cwe, cnt])


def main() -> None:
    parser = argparse.ArgumentParser(description="Categorize CVEs in nvd_ai.csv by CWE into high-level vulnerability categories")
    parser.add_argument("--input", default="results/cve/nvd_ai.csv", help="Input CSV path")
    parser.add_argument("--output", default="results/cve/nvd_ai_categorized.csv", help="Output CSV path (adds category columns)")
    parser.add_argument("--summary", default="results/cve/cwe_category_summary.csv", help="Summary CSV path (category and CWE counts)")
    parser.add_argument("--unmapped", default="results/cve/cwe_unmapped.csv", help="CSV path for missing/unmapped CWEs")
    args = parser.parse_args()

    run(
        input_csv=Path(args.input),
        output_csv=Path(args.output),
        summary_csv=Path(args.summary),
        unmapped_csv=Path(args.unmapped) if args.unmapped else None,
    )


if __name__ == "__main__":
    main()


