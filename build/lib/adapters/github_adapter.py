import csv
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from pathlib import Path

import requests

from scraping.bench_adapter import BenchAdapter


@dataclass
class GitHubIssue:
    id: int #Unique GitHub numeric identifier for the issue/PR.
    repository: str #Repository full name in owner/repo format.
    number: int #Issue/PR number.
    title: str #Issue/PR title.
    state: str #State of the issue/PR (open, closed, etc.).
    labels: List[str] #List of labels applied to the issue/PR.
    is_pull_request: bool #True if the issue/PR is a pull request.
    created_at: str #Date and time the issue/PR was created.
    updated_at: str #Date and time the issue/PR was last updated.
    closed_at: Optional[str] #Date and time the issue/PR was closed.
    author: Optional[str] #Username of the author of the issue/PR.
    comments: int #Number of comments on the issue/PR.  
    url: str #URL of the issue/PR.
    body: str #Body of the issue/PR.    


class GitHubAdapter(BenchAdapter):

    def __init__(self, dataset: str):
        super().__init__(dataset)
        self.keywords = [
        ]
        self.graphql_url = "https://api.github.com/graphql"
        self.max_results = 50000
        self.token = "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"
        self.repos_list: List[dict[str, str]] = [
            {
                "owner": "apache",
                "repo": "tvm",
            },
            {
                "owner": "openxla",
                "repo": "xla",
            },
            {
                "owner": "microsoft",
                "repo": "onnxruntime",
            },
            {
                "owner": "openvinotoolkit",
                "repo": "openvino",
            },
            {
                "owner": "pytorch",
                "repo": "glow",
            },
            {
                "owner": "NVIDIA",
                "repo": "TensorRT",
            },
            {
                "owner": "NVIDIA",
                "repo": "Fuser",
            },
            {
                "owner": "pytorch",
                "repo": "torchdynamo",
            },
            {
                "owner": "plaidml",
                "repo": "plaidml",
            },
            {
                "owner": "Lightning-AI",
                "repo": "lightning-thunder",
            },
            {
                "owner": "ROCm",
                "repo": "ROCm",
            },
            {
                "owner": "triton-lang",
                "repo": "triton",
            }
        ]
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

    

    def fetch_graphql(self, session: requests.Session, query: str, variables: Dict[str, Any] | None = None, retries: int = 5, backoff: float = 1.5) -> Dict[str, Any]:
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN is required for GraphQL API")
        headers = {
            "User-Agent": "ai-github-issues-fetcher/1.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {self.token}",
        }
        body = {"query": query, "variables": variables or {}}
        last_err = "Unknown error"
        for attempt in range(retries):
            try:
                resp = session.post(self.graphql_url, headers=headers, json=body, timeout=45)
                status = resp.status_code
                text_snippet = (resp.text or "")[:200]
                if status == 200:
                    data = resp.json()
                    # GraphQL can return 200 with errors in payload
                    if data.get("errors"):
                        last_err = json.dumps(data.get("errors")[:1])
                        # Some errors are transient rate limits
                        # Fallthrough to retry below
                    else:
                        return data
                # Rate limiting
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
                if status in (500, 502, 503, 504):
                    last_err = f"{status} server error: {text_snippet}"
                    time.sleep(backoff * (attempt + 1))
                    continue
                last_err = f"{status} {text_snippet}"
            except Exception as e:
                last_err = f"exception: {str(e)[:200]}"
            time.sleep(backoff * (attempt + 1))
        raise RuntimeError(f"Failed GraphQL fetch: {last_err}")

    def query_nvd(self, keywords: List[str], max_results: int, per_page: int, verbose: bool = True):
        # Not used for GitHub
        return []

    def extract_products(self, configurations: Any):
        return []

    def fetch_page(self, session: Any, params: Dict[str, Any], api_key: Optional[str], retries, backoff: float) -> Dict[str, Any]:
        return {}

    def search_graphql_repo(self, repo: Dict[str, str] | str, keyword: Optional[str], max_results: int, verbose: bool = True) -> List[Dict[str, Any]]:
        """Fetch ALL issues in a repo using the repository issues connection (not Search),
        which avoids the 1,000-result Search cap. Accepts either "owner/repo" or {owner, repo}.
        The keyword parameter is ignored in this mode.
        """
        session = requests.Session()
        collected: List[Dict[str, Any]] = []
        if isinstance(repo, dict):
            owner = (repo.get("owner") or "").strip()
            name = (repo.get("repo") or "").strip()
            repo_slug = f"{owner}/{name}" if owner and name else ""
        else:
            repo_slug = str(repo).strip()
            parts = repo_slug.split("/")
            owner = parts[0] if len(parts) > 1 else ""
            name = parts[1] if len(parts) > 1 else ""
        if not owner or not name:
            return []

        def fetch_all_issues_for_states(states: List[str]) -> None:
            cursor: Optional[str] = None
            while True:
                if verbose:
                    print(f"[github-graphql] repo={repo_slug} states={states} cursor={bool(cursor)}")
                gql = (
                    "query($owner:String!, $name:String!, $cursor:String, $states:[IssueState!]) {\n"
                    "  repository(owner:$owner, name:$name) {\n"
                    "    issues(first: 100, after: $cursor, states: $states, orderBy: {field: CREATED_AT, direction: ASC}) {\n"
                    "      pageInfo { hasNextPage endCursor }\n"
                    "      nodes {\n"
                    "        __typename\n"
                    "        databaseId\n"
                    "        number\n"
                    "        title\n"
                    "        state\n"
                    "        createdAt\n"
                    "        updatedAt\n"
                    "        closedAt\n"
                    "        url\n"
                    "        bodyText\n"
                    "        author { login }\n"
                    "        comments { totalCount }\n"
                    "        labels(first: 50) { nodes { name } }\n"
                    "        repository { nameWithOwner }\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}"
                )
                payload = {"owner": owner, "name": name, "cursor": cursor, "states": states}
                data = self.fetch_graphql(session, gql, payload)
                repo_data = (data.get("data") or {}).get("repository") or {}
                issues = (repo_data.get("issues") or {})
                nodes = issues.get("nodes") or []
                if not nodes:
                    break
                collected.extend(nodes)
                page_info = issues.get("pageInfo") or {}
                has_next = page_info.get("hasNextPage")
                cursor = page_info.get("endCursor")
                if not has_next or len(collected) >= max_results:
                    break
                time.sleep(0.5)

        # Fetch open and closed issues completely
        fetch_all_issues_for_states(["OPEN"])
        if len(collected) < max_results:
            fetch_all_issues_for_states(["CLOSED"])

        # Deduplicate by URL and truncate to max_results
        seen: set[str] = set()
        uniq: List[Dict[str, Any]] = []
        for n in collected:
            url = n.get("url")
            if url and url not in seen:
                seen.add(url)
                uniq.append(n)
            if len(uniq) >= max_results:
                break
        return uniq

    

    def normalize(self, items: List[Dict[str, Any]]) -> List[GitHubIssue]:
        norm: List[GitHubIssue] = []
        for it in items:
            # GraphQL search result node (Issue or PullRequest)
            repository = ((it.get("repository") or {}).get("nameWithOwner")) or ""
            labels = [lb.get("name") for lb in (((it.get("labels") or {}).get("nodes")) or []) if isinstance(lb, dict) and lb.get("name")]
            typename = it.get("__typename") or ""
            is_pr = typename == "PullRequest"
            body = it.get("bodyText") or ""
            comments_total = ((it.get("comments") or {}).get("totalCount")) or 0
            dbid = it.get("databaseId")
            if dbid is None:
                # Fallback to number as identifier if databaseId missing
                dbid = it.get("number")
            norm.append(GitHubIssue(
                id=int(dbid),
                repository=repository,
                number=int(it.get("number")),
                title=it.get("title") or "",
                state=it.get("state") or "",
                labels=labels,
                is_pull_request=is_pr,
                created_at=it.get("createdAt") or "",
                updated_at=it.get("updatedAt") or "",
                closed_at=it.get("closedAt"),
                author=((it.get("author") or {}).get("login")),
                comments=int(comments_total or 0),
                url=it.get("url") or "",
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

        self.norm = []
        self._seen_urls.clear()
        # Require repositories and token for GraphQL flow
        if not self.repos_list:
            raise RuntimeError("GITHUB_REPOS is required.")
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN is required to use GraphQL.")
        # If no keywords configured, still fetch by repo without keyword filter
        keywords = self.keywords or [None]
        for repo in self.repos_list:
            csv_path = f"{self.path}/{repo['repo']}.csv"
            if os.path.exists(csv_path):
                continue
            for kb in keywords:
                raw_nodes = self.search_graphql_repo(repo, kb, max_results=self.max_results, verbose=True)
                # Deduplicate by URL across entire run
                new_nodes: List[Dict[str, Any]] = []
                for node in raw_nodes:
                    url = node.get("url")
                    if url and url not in self._seen_urls:
                        self._seen_urls.add(url)
                        new_nodes.append(node)
                norm = self.normalize(new_nodes)
                if norm:
                    self.save_csv(norm, csv_path, append=True)
                    if isinstance(repo, dict):
                        owner = (repo.get("owner") or "").strip()
                        name = (repo.get("repo") or "").strip()
                        repo_slug = f"{owner}/{name}" if owner and name else str(repo)
                    else:
                        repo_slug = str(repo)
                    print(f"Saved {len(norm)} items for repo '{repo_slug}' keyword '{kb or ''}' to: - {csv_path}")
                self.norm.extend(norm)

    def save(self):
        # Files already saved per keyword during start_scraping
        print(f"Done. Total unique issues this run: {len(self.norm)}")
        print(f"Outputs in {self.path} (issues.jsonl, issues.csv)")


