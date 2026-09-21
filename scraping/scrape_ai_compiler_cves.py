"""Collect AI-compiler CVEs from the NVD CVE API 2.0.

The scraper searches NVD with compiler-specific terms, deduplicates CVEs
returned by multiple searches, and writes one CSV row per CVE. An NVD API key
is optional and is read from the NVD_API_KEY environment variable.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_OUTPUT = Path("datasets/raw dataset/CVE/ai_compiler_cves.csv")

# Queries are deliberately more specific than bare names such as "Glow" and
# "Thunder", which otherwise produce many unrelated NVD records.
COMPILER_QUERIES: dict[str, tuple[str, ...]] = {
    "tvm": ("TVM",),
    "xla": ("OpenXLA", "XLA"),
    "onnxruntime": ("ONNX Runtime",),
    "openvino": ("OpenVINO",),
    "glow": ("Glow", "PyTorch Glow"),
    "tensorrt": ("NVIDIA TensorRT", "TensorRT"),
    "fuser": ("NVIDIA Fuser", "nvFuser"),
    "torchdynamo": ("TorchDynamo",),
    "plaidml": ("PlaidML",),
    "lightning-thunder": ("Lightning Thunder",),
    "rocm": ("ROCm",),
}

COMPILER_NAMES = {
    "tvm": "TVM",
    "xla": "XLA",
    "onnxruntime": "ONNX Runtime",
    "openvino": "OpenVINO",
    "glow": "Glow",
    "tensorrt": "TensorRT",
    "fuser": "Fuser",
    "torchdynamo": "TorchDynamo",
    "plaidml": "PlaidML",
    "lightning-thunder": "Lightning Thunder",
    "rocm": "ROCm",
}

CSV_FIELDS = (
    "cve_id",
    "compilers",
    "published",
    "last_modified",
    "vulnerability_status",
    "severity",
    "cvss_score",
    "cvss_vector",
    "cwes",
    "affected_products",
    "references",
    "description",
    "source_identifier",
    "matched_queries",
    "collected_at",
)


def unique(values: Iterable[str]) -> list[str]:
    """Return non-empty values in first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = str(value or "").strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for description in descriptions:
        if description.get("lang") == "en":
            return " ".join(str(description.get("value") or "").split())
    if descriptions:
        return " ".join(str(descriptions[0].get("value") or "").split())
    return ""


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").strip()
            if re.fullmatch(r"CWE-\d+", value, flags=re.IGNORECASE):
                values.append(value.upper())
    return sorted(set(values))


def extract_cpes(cve: dict[str, Any]) -> list[str]:
    values: list[str] = []
    stack: list[Any] = list(cve.get("configurations") or [])
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        stack.extend(node.get("nodes") or [])
        stack.extend(node.get("children") or [])
        for match in node.get("cpeMatch") or []:
            if isinstance(match, dict):
                criteria = match.get("criteria") or match.get("cpe23Uri")
                if criteria:
                    values.append(str(criteria))
    return sorted(set(values))


def extract_references(cve: dict[str, Any]) -> list[str]:
    return unique(
        str(reference.get("url") or "")
        for reference in cve.get("references") or []
        if isinstance(reference, dict)
    )


def extract_cvss(cve: dict[str, Any]) -> tuple[str, str, str]:
    """Return severity, score, and vector from the best available CVSS metric."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) or []
        if not candidates:
            continue
        metric = next(
            (
                candidate
                for candidate in candidates
                if str(candidate.get("type") or "").lower() == "primary"
            ),
            candidates[0],
        )
        data = metric.get("cvssData") or {}
        severity = data.get("baseSeverity") or metric.get("baseSeverity") or ""
        score = data.get("baseScore")
        vector = data.get("vectorString") or ""
        return str(severity), "" if score is None else str(score), str(vector)
    return "", "", ""


def cve_sort_key(cve_id: str) -> tuple[int, int, str]:
    match = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id, flags=re.IGNORECASE)
    if not match:
        return sys.maxsize, sys.maxsize, cve_id
    return int(match.group(1)), int(match.group(2)), cve_id


class NvdClient:
    def __init__(
        self,
        api_key: str | None,
        delay: float,
        timeout: float,
        retries: int,
        results_per_page: int,
    ) -> None:
        self.api_key = api_key
        self.delay = delay
        self.timeout = timeout
        self.retries = retries
        self.results_per_page = results_per_page
        self.session = requests.Session()
        self.last_request_at = 0.0

    def _wait_for_rate_limit(self) -> None:
        remaining = self.delay - (time.monotonic() - self.last_request_at)
        if remaining > 0:
            time.sleep(remaining)

    def _request(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "ai-compiler-cve-artifact/1.0",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        delay = 1.0
        last_error = "unknown error"
        for attempt in range(1, self.retries + 1):
            self._wait_for_rate_limit()
            response: requests.Response | None = None
            try:
                response = self.session.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )
                self.last_request_at = time.monotonic()
                if response.status_code == 200:
                    return response.json()

                message = response.headers.get("message") or response.text[:500]
                last_error = f"HTTP {response.status_code}: {message}"
                if response.status_code not in {403, 429, 500, 502, 503, 504}:
                    response.raise_for_status()
            except (requests.RequestException, ValueError) as error:
                last_error = str(error)

            if attempt < self.retries:
                retry_after = (
                    response.headers.get("Retry-After")
                    if response is not None
                    else None
                )
                try:
                    sleep_for = max(delay, float(retry_after)) if retry_after else delay
                except ValueError:
                    sleep_for = delay
                time.sleep(sleep_for)
                delay = min(delay * 2, 60.0)

        raise RuntimeError(f"NVD request failed after {self.retries} attempts: {last_error}")

    def search(
        self,
        query: str,
        max_results: int | None,
        verbose: bool,
    ) -> list[dict[str, Any]]:
        start_index = 0
        results: list[dict[str, Any]] = []

        while True:
            page_size = self.results_per_page
            if max_results is not None:
                remaining = max_results - len(results)
                if remaining <= 0:
                    break
                page_size = min(page_size, remaining)

            data = self._request(
                {
                    "keywordSearch": query,
                    "startIndex": start_index,
                    "resultsPerPage": page_size,
                }
            )
            page = data.get("vulnerabilities") or []
            results.extend(item for item in page if isinstance(item, dict))

            total = int(data.get("totalResults") or 0)
            if verbose:
                print(
                    f"[{query}] fetched {len(results)}/{total}",
                    file=sys.stderr,
                )
            if not page or len(results) >= total:
                break
            start_index += len(page)

        return results


def collect(
    client: NvdClient,
    compiler_keys: list[str],
    max_results_per_query: int | None,
    include_rejected: bool,
    verbose: bool,
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}

    for compiler_key in compiler_keys:
        for query in COMPILER_QUERIES[compiler_key]:
            for item in client.search(query, max_results_per_query, verbose):
                cve = item.get("cve") or {}
                cve_id = str(cve.get("id") or "").strip().upper()
                if not cve_id:
                    continue
                status = str(cve.get("vulnStatus") or "").strip()
                if not include_rejected and status.lower() == "rejected":
                    continue

                record = records.setdefault(
                    cve_id,
                    {
                        "cve": cve,
                        "compiler_keys": set(),
                        "queries": set(),
                    },
                )
                record["compiler_keys"].add(compiler_key)
                record["queries"].add(query)

    return records


def to_csv_row(
    cve_id: str,
    record: dict[str, Any],
    collected_at: str,
) -> dict[str, str]:
    cve = record["cve"]
    severity, score, vector = extract_cvss(cve)
    compiler_names = sorted(
        COMPILER_NAMES[key] for key in record["compiler_keys"]
    )
    return {
        "cve_id": cve_id,
        "compilers": ";".join(compiler_names),
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "vulnerability_status": str(cve.get("vulnStatus") or ""),
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cwes": ";".join(extract_cwes(cve)),
        "affected_products": ";".join(extract_cpes(cve)),
        "references": ";".join(extract_references(cve)),
        "description": english_description(cve),
        "source_identifier": str(cve.get("sourceIdentifier") or ""),
        "matched_queries": ";".join(sorted(record["queries"])),
        "collected_at": collected_at,
    }


def write_csv(
    output: Path,
    records: dict[str, dict[str, Any]],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    collected_at = datetime.now(timezone.utc).isoformat()
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for cve_id in sorted(records, key=cve_sort_key):
            writer.writerow(to_csv_row(cve_id, records[cve_id], collected_at))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Search NVD for CVEs associated with AI compilers and write a "
            "deduplicated CSV dataset."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"CSV output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--compiler",
        action="append",
        choices=sorted(COMPILER_QUERIES),
        help="Compiler to query; repeat for multiple compilers (default: all)",
    )
    parser.add_argument(
        "--max-results-per-query",
        type=int,
        default=None,
        help="Optional result cap for each NVD keyword query",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=2000,
        help="NVD page size from 1 to 2000 (default: 2000)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=None,
        help=(
            "Minimum seconds between requests; defaults to 0.6 with an API "
            "key and 6.0 without one"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="HTTP timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help="Maximum attempts per NVD request (default: 5)",
    )
    parser.add_argument(
        "--include-rejected",
        action="store_true",
        help="Include CVEs whose NVD status is Rejected",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-query progress",
    )
    args = parser.parse_args()

    if args.max_results_per_query is not None and args.max_results_per_query < 1:
        parser.error("--max-results-per-query must be at least 1")
    if not 1 <= args.results_per_page <= 2000:
        parser.error("--results-per-page must be between 1 and 2000")
    if args.delay is not None and args.delay < 0:
        parser.error("--delay cannot be negative")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.retries < 1:
        parser.error("--retries must be at least 1")
    return args


def main() -> None:
    args = parse_args()
    api_key = os.getenv("NVD_API_KEY")
    delay = args.delay if args.delay is not None else (0.6 if api_key else 6.0)
    compiler_keys = args.compiler or sorted(COMPILER_QUERIES)

    client = NvdClient(
        api_key=api_key,
        delay=delay,
        timeout=args.timeout,
        retries=args.retries,
        results_per_page=args.results_per_page,
    )
    records = collect(
        client=client,
        compiler_keys=compiler_keys,
        max_results_per_query=args.max_results_per_query,
        include_rejected=args.include_rejected,
        verbose=not args.quiet,
    )
    write_csv(args.output, records)
    print(f"Saved {len(records)} CVEs to {args.output}")


if __name__ == "__main__":
    main()
