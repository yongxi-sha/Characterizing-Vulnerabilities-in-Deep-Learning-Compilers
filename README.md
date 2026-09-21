# AI Compiler Security Artifact

This repository contains the datasets and research code for an empirical study
of vulnerabilities in AI compilers. The artifact includes raw GitHub issue
records, a curated vulnerability dataset, research-question-specific data, and
results from repeated evaluations of compiler testing tools.

## Artifact at a glance

- **27,730 raw GitHub records** collected from 12 AI compiler and runtime
  repositories.
- **621 curated vulnerability records** from Apache TVM (424), Glow (104), and
  XLA (93).
- Curated labels for vulnerability type, root cause, impact, and affected
  compilation stage.
- Five evaluation runs over 83 vulnerabilities for NNSmith, MT-DLComp, and
  TVMFuzz.
- Python utilities for GitHub/NVD collection, AI-related CVE filtering, CWE
  categorization, and LLM-assisted issue classification.

The provided datasets can be inspected without installing any third-party
software.

## Repository structure

```text
.
├── datasets/
│   ├── groundtruth_summary.csv       # Complete curated dataset
│   ├── RQ1/                          # Vulnerability-type data
│   ├── RQ2/                          # Root-cause data
│   ├── RQ3/                          # Impact data
│   ├── RQ4/                          # Testing-tool evaluation data
│   └── raw dataset/                  # Raw records grouped by compiler
├── adapters/                         # Data-source and LLM adapters
├── scraping/                         # Collection and classification utilities
├── requirements.txt
└── setup.py
```

## Dataset guide

### Complete curated dataset

`datasets/groundtruth_summary.csv` is the primary artifact. It contains 621
rows and the following fields:

- `vuln_id`: issue identifier within the source repository.
- `compiler`: source compiler repository.
- `compiler_version`: affected version or `unknown`.
- `vulnerability_type`: assigned vulnerability class or CWE.
- `root_cause`: high-level root-cause category.
- `root_cause_detail`: more specific cause.
- `impact`: observed security or reliability impact.
- `compilation_stage`: affected stage (`Frontend`, `Backend`, `Runtime`, or
  `Model load`).
- `description`: concise vulnerability description.
- `reported_time`: original report timestamp.
- `reference`: source issue URL.

`vuln_id` is repository-local. Use `(compiler, vuln_id)` or `reference` as the
record key when combining projects.

The curated records cover:

- `apache/tvm`: 424
- `pytorch/glow`: 104
- `openxla/xla`: 93

### Research-question datasets

- **RQ1:** `datasets/RQ1/dataset with vulnerability type.csv` contains the
  vulnerability-type labels used for RQ1.
- **RQ2:** `datasets/RQ2/dataset with root cause.csv` adds high-level and
  detailed root-cause labels.
- **RQ3:** `datasets/RQ3/dataset with impact.csv` contains the impact labels
  used for RQ3.
- **RQ4:** `datasets/RQ4/` contains five repeated tool-evaluation runs over 83
  vulnerabilities.
  - `run_1.csv` through `run_5.csv` contain per-run results.
  - `vulnerability discovery by testing tools summary.csv` reports whether
    each tool detected each vulnerability (`Y` or `N`).
  - `vulnerability discovery by testing tools.csv` aggregates detections across
    runs. Each `<tool>_count` is the number of successful runs, and
    `<tool>_runs` identifies those runs.

In the supplied RQ4 summary, NNSmith detects 17 of 83 vulnerabilities,
MT-DLComp detects 22, and TVMFuzz detects 6 in at least one run.

### Raw data

`datasets/raw dataset/<compiler>/<compiler>.csv` contains the raw GitHub
records for each compiler. The common schema includes repository and issue
identifiers, state, title, labels, timestamps, author, comment count, URL, and
issue body.

The TVM directory also contains classification caches and two derived CSV
files. The supplied `tvm_security.csv` and `tvm_with_root_cause.csv` currently
contain headers only; the corresponding cache files preserve intermediate
classification results.

## Quick start

Clone the repository and create an isolated Python environment:

```bash
git clone https://github.com/yongxi-sha/AI-Security.git
cd AI-Security
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Python 3.10 or newer is recommended.

## Validate the supplied artifact

The following dependency-free check verifies the principal dataset sizes:

```bash
python - <<'PY'
import csv
from pathlib import Path

expected = {
    Path("datasets/groundtruth_summary.csv"): 621,
    Path("datasets/RQ1/dataset with vulnerability type.csv"): 621,
    Path("datasets/RQ2/dataset with root cause.csv"): 621,
    Path("datasets/RQ3/dataset with impact.csv"): 621,
    Path("datasets/RQ4/vulnerability discovery by testing tools summary.csv"): 83,
}

for path, expected_rows in expected.items():
    with path.open(encoding="utf-8-sig", newline="") as file:
        rows = sum(1 for _ in csv.DictReader(file))
    assert rows == expected_rows, (path, rows, expected_rows)
    print(f"{path}: {rows} rows")
PY
```

## Reproduce the RQ4 detection totals

```bash
python - <<'PY'
import csv
from pathlib import Path

path = Path(
    "datasets/RQ4/vulnerability discovery by testing tools summary.csv"
)
with path.open(encoding="utf-8-sig", newline="") as file:
    rows = list(csv.DictReader(file))

for tool in ("NNSmith", "MT-DLComp", "TVMFuzz"):
    detected = sum(row[tool].strip().upper() == "Y" for row in rows)
    print(f"{tool}: {detected}/{len(rows)}")
PY
```

Expected output:

```text
NNSmith: 17/83
MT-DLComp: 22/83
TVMFuzz: 6/83
```

## Optional data-collection pipeline

The repository includes research scripts for regenerating intermediate data.
These commands contact live services, so their results can change as upstream
records and models change.

Show the available collectors:

```bash
python -m scraping.main --help
```

Collect GitHub issues or NVD records:

```bash
python -m scraping.main --dataset github
python -m scraping.main --dataset cve
```

Outputs are written under `results/`. Before running a collector, review its
repository list, query terms, rate limits, output paths, and API
authentication in `adapters/`. Never commit API credentials.

Collect AI-compiler CVEs from the NVD:

```bash
# Optional but recommended for a higher NVD rate limit:
export NVD_API_KEY="your-nvd-api-key"

python -m scraping.scrape_ai_compiler_cves
```

The command searches for all configured compilers and writes the deduplicated
results to `datasets/raw dataset/CVE/ai_compiler_cves.csv`. To collect a
subset or run a small trial:

```bash
python -m scraping.scrape_ai_compiler_cves \
  --compiler tvm \
  --compiler xla \
  --max-results-per-query 10
```

Run `python -m scraping.scrape_ai_compiler_cves --help` for rate-limit,
pagination, filtering, and output options. Without an NVD API key, the scraper
uses the public API's slower request interval.

Categorize an AI-related NVD dataset by CWE:

```bash
python -m scraping.cwe_classify \
  --input results/cve/nvd_ai.csv \
  --output results/cve/nvd_ai_categorized.csv \
  --summary results/cve/cwe_category_summary.csv \
  --unmapped results/cve/cwe_unmapped.csv
```

The scripts in `adapters/google_genai.py`, `adapters/gemma.py`, and
`scraping/filter_nvd_ai.py` perform model-assisted classification. They require
the relevant provider SDK or API access in addition to `requirements.txt`.
Model outputs may vary by provider, model version, and execution time; use the
supplied datasets and caches when reproducing the reported artifact results.

## Reproducibility notes

- The curated artifact is static; collection scripts query mutable external
  APIs.
- Raw records cover 12 repositories, while the curated dataset covers TVM,
  Glow, and XLA.
- Labels produced or assisted by automated methods should be interpreted with
  the study's validation procedure.
- No dependency lock file is provided. `requirements.txt` contains the core
  HTTP dependency, while model-specific scripts require optional packages.
- GitHub issue text can contain personal identifiers or sensitive technical
  details. Use the data in accordance with GitHub's terms and applicable
  research-ethics requirements.

## Citation

Until the accompanying paper citation is available, cite this repository:

```bibtex
@misc{sha2026aicompilersecurity,
  author       = {Yongxi Sha},
  title        = {AI Compiler Security Artifact},
  year         = {2026},
  howpublished = {\url{https://github.com/yongxi-sha/AI-Security}},
  note         = {Research artifact}
}
```

## License

This repository does not currently include a license file. Unless a license is
added, default copyright restrictions apply. Contact the repository author
before redistributing or modifying the artifact outside fair-use or other
applicable exceptions.