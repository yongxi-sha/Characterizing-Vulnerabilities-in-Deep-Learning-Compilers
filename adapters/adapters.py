from adapters.cve_adapter import CVEAdapter
from adapters.github_adapter import GithubAdapter

ADAPTERS = {
    "github": GithubAdapter,
    "cve": CVEAdapter,
}
