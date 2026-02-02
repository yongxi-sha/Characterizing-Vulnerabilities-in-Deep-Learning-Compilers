"""
Analyze GitHub issue CSV rows (e.g. results/github/tvm.csv) and add a "root_cause" column using an LLM.

This script uses OpenRouter's OpenAI-compatible Chat Completions endpoint via `requests`
so you don't need the `openai` Python package installed.

Usage (PowerShell):
  $env:OPENROUTER_API_KEY="sk-or-..."
  python adapters/gemma.py --input results/github/tvm.csv --output results/github/tvm_with_root_cause.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"


def compact_text(s: str, head: int = 2000, tail: int = 1000) -> str:
    s = (s or "").strip()
    if len(s) <= head + tail + 80:
        return s
    return s[:head].rstrip() + "\n\n[... truncated ...]\n\n" + s[-tail:].lstrip()


def build_prompt(row: dict[str, str]) -> str:
    repo = (row.get("repository") or "").strip()
    number = (row.get("number") or "").strip()
    title = (row.get("title") or "").strip()
    labels = (row.get("labels") or "").strip()
    url = (row.get("url") or "").strip()
    body = compact_text(row.get("body") or "")

    return (
        "You are a senior compiler/runtime engineer triaging GitHub issues.\n"
        "Task: infer the likely ROOT CAUSE (not the symptom) from the issue content.\n\n"
        f"Repository: {repo}\n"
        f"Issue: #{number}\n"
        f"URL: {url}\n"
        f"Title: {title}\n"
        f"Labels: {labels}\n\n"
        "Issue body (may include stack traces / repro code):\n"
        f"{body}\n\n"
        "Output rules:\n"
        "- Output ONLY the root cause as a single concise sentence.\n"
        "- No markdown, no bullet points, no quotes.\n"
        "- Be specific (e.g., 'FuseTIR assumes prim func body is root block but got Evaluate(0) / missing BlockRealize').\n"
        "- Max 200 characters.\n"
    )


def call_openrouter_chat(
    api_key: str,
    model: str,
    prompt: str,
    temperature: float,
    http_referer: str | None = None,
    x_title: str | None = None,
    timeout_sec: int = 60,
    max_retries: int = 5,
) -> str:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if http_referer:
        headers["HTTP-Referer"] = http_referer
    if x_title:
        headers["X-Title"] = x_title

    payload: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
    }

    delay = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(OPENROUTER_CHAT_URL, headers=headers, json=payload, timeout=timeout_sec)
            if resp.status_code == 200:
                data = resp.json()
                return str(data["choices"][0]["message"]["content"]).strip()

            # Rate limit and transient errors: backoff
            if resp.status_code in (408, 429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except Exception:
                        pass
                if attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue

            # Non-retryable error
            try:
                err = resp.json()
            except Exception:
                err = {"text": resp.text[:512]}
            raise RuntimeError(f"OpenRouter error {resp.status_code}: {err}")

        except requests.RequestException as e:
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"OpenRouter request failed after retries: {e}") from e

    raise RuntimeError("OpenRouter request failed: exceeded retries")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def get_row_key(row: dict[str, str]) -> str:
    # Prefer stable numeric id if present.
    if (row.get("id") or "").strip():
        return row["id"].strip()
    if (row.get("url") or "").strip():
        return row["url"].strip()
    repo = (row.get("repository") or "").strip()
    number = (row.get("number") or "").strip()
    return f"{repo}#{number}".strip("#")


def read_existing_output_ids(output_csv: Path) -> set[str]:
    if not output_csv.exists():
        return set()
    done: set[str] = set()
    try:
        with output_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                k = get_row_key(row)
                if k:
                    done.add(k)
    except Exception:
        return set()
    return done


def main() -> None:
    parser = argparse.ArgumentParser(description="Add a 'root_cause' column to a GitHub issues CSV using OpenRouter Gemma")
    parser.add_argument("--input", default="results/github/tvm.csv", help="Input CSV path")
    parser.add_argument("--output", default="results/github/tvm_with_root_cause.csv", help="Output CSV path")
    parser.add_argument("--cache", default="results/github/tvm_root_cause_cache.json", help="Cache JSON path")
    parser.add_argument("--model", default="google/gemma-3-27b-it:free", help="OpenRouter model id")
    parser.add_argument("--temperature", type=float, default=0.2, help="Sampling temperature")
    parser.add_argument("--limit", type=int, default=None, help="Process at most N rows")
    parser.add_argument("--resume", action="store_true", help="Resume by skipping rows already in output/cache")
    parser.add_argument("--sleep", type=float, default=1, help="Sleep seconds between requests (rate limiting)")
    parser.add_argument("--http_referer", default=None, help="Optional OpenRouter HTTP-Referer header")
    parser.add_argument("--x_title", default=None, help="Optional OpenRouter X-Title header")
    args = parser.parse_args()

    api_key = "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"
    if not api_key:
        raise RuntimeError("Missing OPENROUTER_API_KEY environment variable (do NOT hardcode API keys in code).")

    input_csv = Path(args.input)
    output_csv = Path(args.output)
    cache_path = Path(args.cache) if args.cache else None

    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    cache: dict[str, Any] = load_json(cache_path) if cache_path else {}
    done_ids = read_existing_output_ids(output_csv) if args.resume else set()

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with input_csv.open("r", encoding="utf-8", errors="replace", newline="") as fin:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            raise ValueError(f"No header found in {input_csv}")

        fieldnames = list(reader.fieldnames)
        if "root_cause" not in fieldnames:
            fieldnames.append("root_cause")

        mode = "a" if args.resume and output_csv.exists() else "w"
        with output_csv.open(mode, encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=fieldnames)
            if mode == "w":
                writer.writeheader()

            processed = 0
            for row in reader:
                if args.limit is not None and processed >= args.limit:
                    break

                key = get_row_key(row)
                if args.resume and key and (key in done_ids):
                    continue

                cached = cache.get(key) if key else None
                if isinstance(cached, dict) and "root_cause" in cached:
                    root_cause = str(cached.get("root_cause", "")).strip()
                elif isinstance(cached, str):
                    root_cause = cached.strip()
                else:
                    prompt = build_prompt(row)
                    root_cause = call_openrouter_chat(
                        api_key=api_key,
                        model=args.model,
                        prompt=prompt,
                        temperature=args.temperature,
                        http_referer=args.http_referer,
                        x_title=args.x_title,
                    )
                    root_cause = " ".join(root_cause.split())
                    if len(root_cause) > 200:
                        root_cause = root_cause[:197].rstrip() + "..."
                    if cache_path is not None and key:
                        cache[key] = {"root_cause": root_cause}
                        save_json(cache_path, cache)
                    if args.sleep:
                        time.sleep(args.sleep)

                out_row = dict(row)
                out_row["root_cause"] = root_cause
                writer.writerow(out_row)
                processed += 1


if __name__ == "__main__":
    main()