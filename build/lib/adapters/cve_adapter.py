import csv
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode
import requests
from scraping.bench_adapter import BenchAdapter
from pathlib import Path

@dataclass
class CVEItem:
    cve_id: str # CVE ID
    published: str # Published date
    last_modified: str # Last modified date
    descriptions: str # Description
    severity: Optional[str] # Severity
    cvss_score: Optional[float] # CVSS score
    cvss_vector: Optional[str] # CVSS vector
    cwes: List[str] # CWEs
    products: List[str] # Products
    references: List[str] # References

class CVEAdapter(BenchAdapter):

    def __init__(self, dataset):
        super().__init__(dataset)
        self.keywords = [
            "ai", "artificial intelligence", "machine learning", "ml", "deep learning", "neural network",
            "large language model", "llm", "transformer model", "foundation model",
            "prompt injection", "prompt-injection", "data poisoning", "model poisoning",
            "model inversion", "membership inference",
            "tensorflow", "tf.", "keras", "pytorch", "torch", "onnx", "xgboost", "lightgbm",
            "scikit-learn", "sklearn", "huggingface", "diffusers",
            "openai", "anthropic", "cohere", "ollama", "vllm", "tensorRT", "mlflow", "ray serve",
        ]
        self.api_key="cf44acd1-1751-4091-b761-ac153f1a2b6c"
        self.url="https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.path=Path(f"results/{self.dataset}")
        self.path.mkdir(parents=True, exist_ok=True)

    def best_cvss(self, metrics: Dict[str, Any] | None) -> (Optional[str], Optional[float], Optional[str]):
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
    
    @staticmethod
    def collect_products_from_node(root: Dict[str, Any], products: set) -> None:
        if not isinstance(root, dict):
            return
        stack = [root]
        while stack:
            node = stack.pop()
            for cpe in (node.get("cpeMatch") or []):
                if isinstance(cpe, dict):
                    uri = cpe.get("criteria") or cpe.get("cpe23Uri")
                    if uri:
                        products.add(uri)
            for child in (node.get("children") or []):
                if isinstance(child, dict):
                    stack.append(child)

    def extract_products(self, configurations: Any) -> List[str]:
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
                    self.collect_products_from_node(node, products)
        return sorted(products)

    def extract_cwes(self, weaknesses: Any) -> List[str]:
        ids = set()
        if not isinstance(weaknesses, list):
            return []
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value")
                if val and val.startswith("CWE-"):
                    ids.add(val)
        return sorted(ids)

    def fetch_page(self, session: requests.Session, params: Dict[str, Any], api_key: Optional[str], retries: int = 5, backoff: float = 1.5) -> Dict[str, Any]:
        headers = {"User-Agent": "ai-cves-fetcher/1.1"}
        if api_key:
            headers["apiKey"] = api_key
        url = f"{self.url}?{urlencode(params, doseq=True)}"
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
    
    def query_nvd(self, keywords: List[str], max_results: int, per_page: int, verbose: bool = True) -> List[Dict[str, Any]]:
        api_key = self.api_key
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
                data = self.fetch_page(session, params, api_key=api_key)
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
    
    def normalize(self, items: List[Dict[str, Any]]) -> List[CVEItem]:
        norm: List[CVEItem] = []
        for it in items:
            cve = it.get("cve", {})
            metrics = cve.get("metrics", {})
            severity, score, vector = self.best_cvss(metrics if isinstance(metrics, dict) else {})
            desc = " ".join([d.get("value", "") for d in cve.get("descriptions", [])]).strip() if isinstance(cve.get("descriptions"), list) else ""
            cwes = self.extract_cwes(cve.get("weaknesses", []))
            products = self.extract_products(cve.get("configurations"))
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
    
    @staticmethod
    def save_json(items: List[CVEItem], path: str, append: bool = False) -> None:
        mode = "a" if append and os.path.exists(path) else "w"
        with open(path, mode, encoding="utf-8") as f:
            json.dump([asdict(x) for x in items], f, ensure_ascii=False, indent=2)

    @staticmethod
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
    
    def start_scraping(self):
        raw = self.query_nvd(self.keywords, max_results=20000, per_page=200, verbose=True)
        print("**********************************************************")
        print(len(raw))
        print("**********************************************************")
        
        self.norm = self.normalize(raw)

        print("-------------------------------------------------")
        print(len(self.norm))
        print("-------------------------------------------------")

    
    def save(self):
        json_path = f"{self.path}/nvd.json"
        csv_path = f"{self.path}/nvd.csv"
        self.save_json(self.norm, json_path, append=True)
        self.save_csv(self.norm, csv_path, append=True)
        print(f"Done. Saved {len(self.norm)} AI-related CVEs to:")
        print(f" - {json_path}")
        print(f" - {csv_path}")

