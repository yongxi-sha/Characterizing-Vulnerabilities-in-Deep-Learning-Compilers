#!/usr/bin/env python3
"""
ai_cves_fetcher_v2.py
---------------------
Patched version: robust to 'configurations' being a list or dict in NVD CVE 2.0.
Other minor hardening around optional fields.

Usage examples:
  python ai_cves_fetcher_v2.py --out ai_cves
  python ai_cves_fetcher_v2.py --per-page 200 --max 20000 --verbose
  python ai_cves_fetcher_v2.py --no-filter
"""

import csv
import json
import os
import re
import sys
import time
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode

import requests

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


DEFAULT_KEYWORDS = [
    "ai", "artificial intelligence", "machine learning", "ml", "deep learning", "neural network",
    "large language model", "llm", "transformer model", "foundation model",
    "prompt injection", "prompt-injection", "data poisoning", "model poisoning",
    "model inversion", "membership inference",
    "tensorflow", "tf.", "keras", "pytorch", "torch", "onnx", "xgboost", "lightgbm",
    "scikit-learn", "sklearn", "huggingface", "diffusers",
    "openai", "anthropic", "cohere", "ollama", "vllm", "tensorRT", "mlflow", "ray serve",
]

STRICT_TERMS = [
    r"\bartificial intelligence\b",
    r"\bmachine learning\b",
    r"\bdeep learning\b",
    r"\bneural network",
    r"\bLLM\b|\blarge language model",
    r"\bprompt injection\b",
    r"\bmodel (poisoning|inversion)\b",
    r"\bmembership inference\b",
    r"\btensorflow\b|\bpytorch\b|\bkeras\b|\bonnx\b|\bhuggingface\b|\bscikit-learn\b|\bsklearn\b",
    r"\bOpenAI\b|\bAnthropic\b|\bCohere\b|\bOllama\b|\bvLLM\b",
]


@dataclass
class CVEItem:
    cve_id: str
    published: str
    last_modified: str
    descriptions: str
    severity: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwes: List[str]
    products: List[str]
    references: List[str]


def best_cvss(metrics: Dict[str, Any] | None) -> (Optional[str], Optional[float], Optional[str]):
    if not metrics or not isinstance(metrics, dict):
        return None, None, None
    try:
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            data = v31[0].get("cvssData", {})
            return v31[0].get("baseSeverity"), float(data.get("baseScore")), data.get("vectorString")
    except Exception:
        pass
    try:
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            data = v30[0].get("cvssData", {})
            return v30[0].get("baseSeverity"), float(data.get("baseScore")), data.get("vectorString")
    except Exception:
        pass
    try:
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            data = v2[0].get("cvssData", {})
            return v2[0].get("baseSeverity"), float(data.get("baseScore")), data.get("vectorString")
    except Exception:
        pass
    return None, None, None


def _collect_products_from_node(node: Dict[str, Any], products: set) -> None:
    for cpe in node.get("cpeMatch", []):
        uri = cpe.get("criteria") or cpe.get("cpe23Uri")
        if uri:
            products.add(uri)
    for child in node.get("children", []):
        _collect_products_from_node(child, products)


def extract_products(configurations: Any) -> List[str]:
    """
    Flatten products from NVD 'configurations' field.
    NVD 2.0 may present 'configurations' as a dict OR a list of dicts.
    """
    products: set = set()
    if not configurations:
        return []
    conf_list: List[Dict[str, Any]] = []
    if isinstance(configurations, list):
        conf_list = [c for c in configurations if isinstance(c, dict)]
    elif isinstance(configurations, dict):
        conf_list = [configurations]
    else:
        return []  # unknown shape

    for conf in conf_list:
        for node in conf.get("nodes", []):
            if isinstance(node, dict):
                _collect_products_from_node(node, products)
    return sorted(products)


def extract_cwes(weaknesses: Any) -> List[str]:
    ids = set()
    if not isinstance(weaknesses, list):
        return []
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value")
            if val and val.startswith("CWE-"):
                ids.add(val)
    return sorted(ids)


def strict_ai_match(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    if any(k in lower for k in ["artificial intelligence", "machine learning", "deep learning", "neural network", "large language model", " llm "]):
        return True
    for pat in STRICT_TERMS:
        if re.search(pat, text, flags=re.IGNORECASE):
            return True
    return False


def fetch_page(session: requests.Session, params: Dict[str, Any], api_key: Optional[str], retries: int = 5, backoff: float = 1.5) -> Dict[str, Any]:
    headers = {"User-Agent": "ai-cves-fetcher/1.1"}
    if api_key:
        headers["apiKey"] = api_key
    url = f"{NVD_ENDPOINT}?{urlencode(params, doseq=True)}"
    print("***********************************url*********************************")
    print(url)
    print("***********************************url*********************************")
    last_err = None
    for attempt in range(retries):
        try:
            resp = session.get(url, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in (429, 500, 502, 503, 504):
                last_err = f"{resp.status_code} {resp.text[:200]}"
                time.sleep(backoff * (attempt + 1))
            else:
                resp.raise_for_status()
        except Exception as e:
            last_err = str(e)
            time.sleep(backoff * (attempt + 1))
    raise RuntimeError(f"Failed to fetch: {last_err}")


def query_nvd(keywords: List[str], max_results: int, per_page: int, verbose: bool = True) -> List[Dict[str, Any]]:
    api_key = "cf44acd1-1751-4091-b761-ac153f1a2b6c"
    results: List[Dict[str, Any]] = []
    session = requests.Session()


    for kb in keywords:
        start = 0
        while True:
            params = {
                "startIndex": start,
                "resultsPerPage": per_page,
                "keywordSearch": kb,
            }
            if verbose:
                print(f"[fetch] batch={kb} startIndex={start}")
            data = fetch_page(session, params, api_key=api_key)
            page_items = data.get("vulnerabilities", [])
            if not page_items:
                break
            results.extend(page_items)
            got = len(page_items)
            start += got
            if got < per_page or len(results) >= max_results:
                break
            time.sleep(0.6 if api_key else 1.2)

    seen = set()
    unique = []
    for item in results:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique.append(item)
    return unique[:max_results]


def filter_ai(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filtered = []
    for it in items:
        cve = it.get("cve", {})
        desc = " ".join([d.get("value", "") for d in cve.get("descriptions", [])]) if isinstance(cve.get("descriptions"), list) else ""
        ref_list = cve.get("references", [])
        refs = " ".join([(r.get("url") or "") for r in ref_list]) if isinstance(ref_list, list) else ""
        prods = " ".join(extract_products(cve.get("configurations")))
        blob = " ".join([desc, refs, prods])
        if strict_ai_match(blob):
            filtered.append(it)
    return filtered


def normalize(items: List[Dict[str, Any]]) -> List[CVEItem]:
    norm: List[CVEItem] = []
    for it in items:
        cve = it.get("cve", {})
        metrics = cve.get("metrics", {})
        severity, score, vector = best_cvss(metrics if isinstance(metrics, dict) else {})
        desc = " ".join([d.get("value", "") for d in cve.get("descriptions", [])]).strip() if isinstance(cve.get("descriptions"), list) else ""
        cwes = extract_cwes(cve.get("weaknesses", []))
        products = extract_products(cve.get("configurations"))
        refs = [r.get("url") for r in (cve.get("references") or []) if isinstance(r, dict) and r.get("url")]

        norm.append(CVEItem(
            cve_id=cve.get("id", ""),
            published=cve.get("published") or "",
            last_modified=cve.get("lastModified") or "",
            descriptions=desc,
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            cwes=cwes,
            products=products,
            references=refs
        ))
    return norm


def save_json(items: List[CVEItem], path: str, append: bool = False) -> None:
    mode = "a" if append and os.path.exists(path) else "w"
    with open(path, mode, encoding="utf-8") as f:
        json.dump([asdict(x) for x in items], f, ensure_ascii=False, indent=2)


def save_csv(items: List[CVEItem], path: str, append: bool = False) -> None:
    mode = "a" if append and os.path.exists(path) else "w"
    with open(path, mode, newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if mode == "w":
            writer.writerow(["cve_id", "published", "last_modified", "severity", "cvss_score",
                             "cvss_vector", "cwes", "products", "references", "descriptions"])
        for x in items:
            writer.writerow([
                x.cve_id,
                x.published,
                x.last_modified,
                x.severity or "",
                x.cvss_score if x.cvss_score is not None else "",
                x.cvss_vector or "",
                ";".join(x.cwes),
                ";".join(x.products),
                ";".join(x.references),
                x.descriptions.replace("\n", " ").strip()
            ])


def main():
    parser = argparse.ArgumentParser(description="Fetch AI-related CVEs from NVD API (v2.0).")
    parser.add_argument("--out", default="ai_cves", help="Output base path (without extension).")
    parser.add_argument("--max", type=int, default=20000, help="Max total CVEs to retrieve (before filtering & dedup).")
    parser.add_argument("--per-page", type=int, default=200, help="NVD resultsPerPage (max 200).")
    parser.add_argument("--keywords", default=",".join(DEFAULT_KEYWORDS),
                        help="Comma-separated keyword list used for NVD keywordSearch OR queries.")
    parser.add_argument("--append", action="store_true", help="Append to existing files instead of overwrite.")
    parser.add_argument("--no-filter", action="store_true",
                        help="Disable strict AI filter and keep all keyword matches.")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging.")
    args = parser.parse_args()

    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]
    if not keywords:
        print("No keywords provided.", file=sys.stderr)
        sys.exit(2)

    if args.verbose:
        print(f"Using {len(keywords)} keywords. API key set? {'yes' if os.getenv('NVD_API_KEY') else 'no'}")

    raw = query_nvd(keywords, max_results=args.max, per_page=args.per_page, verbose=args.verbose)
    print("**********************************************************")
    print(len(raw))
    print("**********************************************************")
    
    kept = raw if args.no_filter else filter_ai(raw)
    norm = normalize(kept)
    print("-------------------------------------------------")
    print(len(norm))
    print("-------------------------------------------------")
    json_path = f"{args.out}.json"
    csv_path = f"{args.out}.csv"
    save_json(norm, json_path, append=args.append)
    save_csv(norm, csv_path, append=args.append)

    print(f"Done. Saved {len(norm)} AI-related CVEs to:")
    print(f" - {json_path}")
    print(f" - {csv_path}")
    if not os.getenv("NVD_API_KEY"):
        print("Note: Consider setting NVD_API_KEY for higher rate limits.", file=sys.stderr)

if __name__ == "__main__":
    main()
