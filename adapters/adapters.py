from adapters.cve_adapter import CVEAdapter
from adapters.github_adapter import GitHubAdapter
ADAPTERS = {
    "cve": CVEAdapter,
    "github": GitHubAdapter,
}
