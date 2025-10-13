import csv
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from pathlib import Path
from urllib.parse import urlencode

import requests

from scraping.bench_adapter import BenchAdapter


@dataclass
class GitHubIssue:
    id: int
    repository: str
    number: int
    title: str
    state: str
    labels: List[str]
    is_pull_request: bool
    created_at: str
    updated_at: str
    closed_at: Optional[str]
    author: Optional[str]
    comments: int
    url: str
    body: str


class GitHubAdapter(BenchAdapter):

    def __init__(self, dataset: str):
        super().__init__(dataset)
        self.keywords = [
            "ai", "artificial intelligence", "machine learning", "deep learning", "neural network",
            "large language model", "llm", "transformer model", "foundation model",
            "prompt injection", "data poisoning", "model inversion", "membership inference",
            "tensorflow", "keras", "pytorch", "onnx", "xgboost", "lightgbm",
            "scikit-learn", "sklearn", "huggingface", "diffusers",
            "openai", "anthropic", "cohere", "ollama", "vllm", "tensorRT", "mlflow", "ray serve",
        ]
        self.base_url = "https://api.github.com/search/issues"
        self.per_page = 100
        self.max_results = 5000
        self.token = "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"
        self.path = Path(f"results/{self.dataset}")
        self.path.mkdir(parents=True, exist_ok=True)
        self._seen_urls: set[str] = set()

    # The following abstract methods exist in BenchAdapter but are CVE-specific.
    # Provide no-op or lightweight implementations to satisfy interface.
    def best_cvss(self, metrics: Dict[str, Any] | None):
        return None, None, None

    def collect_products_from_node(self, root: Dict[str, Any], products: set):
        return

    def extract_cwes(self, weaknesses: Any):
        return []

    def fetch_page(self, session: requests.Session, params: Dict[str, Any], api_key: Optional[str], retries: int = 5, backoff: float = 1.5) -> Dict[str, Any]:
        headers = {
            "User-Agent": "ai-github-issues-fetcher/1.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"{self.base_url}?{urlencode(params, doseq=True)}"
        last_err = "Unknown error"
        for attempt in range(retries):
            try:
                resp = session.get(url, headers=headers, timeout=30)
                status = resp.status_code
                text_snippet = (resp.text or "")[:200]
                # Successful
                if status == 200:
                    return resp.json()
                # Rate limiting: 403 with remaining=0 or explicit 429
                rate_remaining = resp.headers.get("X-RateLimit-Remaining")
                rate_reset = resp.headers.get("X-RateLimit-Reset")
                if status in (403, 429) or (rate_remaining is not None and rate_remaining == "0"):
                    try:
                        reset_epoch = int(rate_reset) if rate_reset else 0
                        now = int(time.time())
                        wait_seconds = max(reset_epoch - now, 1)
                    except Exception:
                        wait_seconds = 60
                    last_err = f"{status} rate limited; waiting {wait_seconds}s (remaining={rate_remaining})"
                    print(last_err)
                    time.sleep(wait_seconds)
                    continue
                # Server errors -> backoff retry
                if status in (500, 502, 503, 504):
                    last_err = f"{status} server error: {text_snippet}"
                    time.sleep(backoff * (attempt + 1))
                    continue
                # Other HTTP errors
                last_err = f"{status} {text_snippet}"
            except Exception as e:
                last_err = f"exception: {str(e)[:200]}"
            # Backoff before next retry if not returned yet
            time.sleep(backoff * (attempt + 1))
        raise RuntimeError(f"Failed to fetch: {last_err}")

    def query_nvd(self, keywords: List[str], max_results: int, per_page: int, verbose: bool = True):
        # Not used for GitHub; map to GitHub search
        return self.query_github(keywords, max_results, per_page, verbose)

    def extract_products(self, configurations: Any):
        return []

    def query_github(self, keywords: List[str], max_results: int, per_page: int, verbose: bool = True) -> List[Dict[str, Any]]:
        session = requests.Session()
        all_items: List[Dict[str, Any]] = []
        per_page = min(max(per_page, 1), 100)
        for kb in keywords:
            # GitHub search qualifier: issues only, exclude PRs if desired; we will keep both then mark PRs
            q = f"{kb} in:title,body"
            page = 1
            while True:
                params = {
                    "q": q,
                    "per_page": per_page,
                    "page": page,
                    "sort": "updated",
                    "order": "desc",
                }
                if verbose:
                    print(f"[github] keyword={kb} page={page}")
                data = self.fetch_page(session, params, api_key=None)
                items = data.get("items", [])
                if not items:
                    break
                all_items.extend(items)
                # GitHub search caps results to 1000 per query => page up to 10 when per_page=100
                if len(items) < per_page or len(all_items) >= max_results or page >= 10:
                    break
                page += 1
                # Respect secondary rate limits
                time.sleep(1.5 if self.token else 4.0)
            if len(all_items) >= max_results:
                break
        # Deduplicate by unique issue URL
        seen = set()
        unique: List[Dict[str, Any]] = []
        for it in all_items:
            url = it.get("html_url") or it.get("url")
            if url and url not in seen:
                seen.add(url)
                unique.append(it)
        return unique[:max_results]

    def query_github_single(self, keyword: str, per_page: int, verbose: bool = True) -> List[Dict[str, Any]]:
        session = requests.Session()
        per_page = min(max(per_page, 1), 100)
        q = f"{keyword} in:title,body"
        page = 1
        collected: List[Dict[str, Any]] = []
        while True:
            params = {
                "q": q,
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "order": "desc",
            }
            if verbose:
                print(f"[github] keyword={keyword} page={page}")
            data = self.fetch_page(session, params, api_key=None)
            items = data.get("items", [])
            if not items:
                break
            collected.extend(items)
            if len(items) < per_page or page >= 10:
                break
            page += 1
            time.sleep(1.5 if self.token else 4.0)
        return collected

    def normalize(self, items: List[Dict[str, Any]]) -> List[GitHubIssue]:
        norm: List[GitHubIssue] = []
        for it in items:
            repository = ""
            try:
                # html_url like https://github.com/owner/repo/issues/123
                html_url = it.get("html_url", "")
                parts = html_url.split("/")
                if len(parts) >= 7:
                    repository = f"{parts[3]}/{parts[4]}"
            except Exception:
                repository = ""
            labels = [lb.get("name") for lb in (it.get("labels") or []) if isinstance(lb, dict) and lb.get("name")]
            is_pr = it.get("pull_request") is not None
            body = it.get("body") or ""
            norm.append(GitHubIssue(
                id=int(it.get("id")),
                repository=repository,
                number=int(it.get("number")),
                title=it.get("title") or "",
                state=it.get("state") or "",
                labels=labels,
                is_pull_request=is_pr,
                created_at=it.get("created_at") or "",
                updated_at=it.get("updated_at") or "",
                closed_at=it.get("closed_at"),
                author=(it.get("user") or {}).get("login"),
                comments=int(it.get("comments") or 0),
                url=it.get("html_url") or it.get("url") or "",
                body=body.strip(),
            ))
        return norm

    @staticmethod
    def save_json(items: List[GitHubIssue], path: str, append: bool = False) -> None:
        # Write as JSON Lines (NDJSON) to support efficient appends
        mode = "a" if append and os.path.exists(path) else "w"
        with open(path, mode, encoding="utf-8") as f:
            for x in items:
                f.write(json.dumps(asdict(x), ensure_ascii=False) + "\n")

    @staticmethod
    def save_csv(items: List[GitHubIssue], path: str, append: bool = False) -> None:
        mode = "a" if append and os.path.exists(path) else "w"
        with open(path, mode, newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if mode == "w":
                writer.writerow([
                    "id", "repository", "number", "state", "title", "labels", "is_pull_request",
                    "created_at", "updated_at", "closed_at", "author", "comments", "url", "body"
                ])
            for it in items:
                writer.writerow([
                    it.id,
                    it.repository,
                    it.number,
                    it.state,
                    it.title,
                    ";".join(it.labels),
                    it.is_pull_request,
                    it.created_at,
                    it.updated_at,
                    it.closed_at or "",
                    it.author or "",
                    it.comments,
                    it.url,
                    it.body.replace("\n", " ").strip(),
                ])

    def start_scraping(self):
        json_path = f"{self.path}/issues.jsonl"
        csv_path = f"{self.path}/issues.csv"
        self.norm = []
        self._seen_urls.clear()
        for kb in self.keywords:
            raw_items = self.query_github_single(kb, per_page=self.per_page, verbose=True)
            # Deduplicate across the entire run by URL
            new_items: List[Dict[str, Any]] = []
            for it in raw_items:
                url = it.get("html_url") or it.get("url")
                if url and url not in self._seen_urls:
                    self._seen_urls.add(url)
                    new_items.append(it)
            norm = self.normalize(new_items)
            if norm:
                # Save incrementally after each keyword
                self.save_json(norm, json_path, append=True)
                self.save_csv(norm, csv_path, append=True)
                print(f"Saved {len(norm)} items for keyword '{kb}' to:\n - {json_path}\n - {csv_path}")
            self.norm.extend(norm)

    def save(self):
        # Files already saved per keyword during start_scraping
        print(f"Done. Total unique issues this run: {len(self.norm)}")
        print(f"Outputs in {self.path} (issues.jsonl, issues.csv)")


