import argparse
import csv
import json
import re
import time
from pathlib import Path

from google import genai
from google.genai import errors as genai_errors

DEFAULT_RPM = 30
DEFAULT_TPM = 15000
DEFAULT_MODEL = "gemma-3-27b-it"


def build_prompt(row: dict) -> str:
    title = (row.get("title") or "").strip()
    labels = (row.get("labels") or "").strip()
    body = (row.get("body") or "").strip()
    url = (row.get("url") or "").strip()

    return (
        "You are a security analyst. Determine if the GitHub issue is security-related.\n"
        "Security-related means vulnerabilities, security bugs, exploits, CVEs, "
        "memory safety issues, auth/ACL bypass, RCE, XSS, injection, secrets leakage, "
        "or other security weaknesses. Performance bugs, build errors, and generic crashes "
        "are not security-related unless they indicate a vulnerability.\n\n"
        f"Title: {title}\n"
        f"Labels: {labels}\n"
        f"URL: {url}\n"
        f"Body: {body}\n\n"
        "Answer strictly in JSON with keys: "
        "{\"security_related\": true|false, \"reason\": string}. No extra text."
    )


def parse_response(text: str) -> dict:
    try:
        data = json.loads(text)
        security_related = bool(data.get("security_related"))
        reason = str(data.get("reason", "")).strip()
        return {"security_related": security_related, "reason": reason}
    except Exception:
        lowered = text.lower()
        security_related = ("true" in lowered) and (
            "false" not in lowered or lowered.find("true") < lowered.find("false")
        )
        return {"security_related": security_related, "reason": text.strip()[:500]}


def filter_csv(
    input_csv: Path,
    output_csv: Path,
    model: str,
    temperature: float,
    limit: int | None,
    cache_path: Path | None,
    min_interval_sec: float,
    append: bool,
    max_tokens_per_minute: int,
    log_every: int,
    resume_from_id: str | None,
):
    client = genai.Client()

    cache = {}
    if cache_path and cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            cache = {}

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"

    with input_csv.open("r", encoding="utf-8", errors="replace", newline="") as fin, \
         output_csv.open(mode, encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames or []
        extra_cols = ["security_related", "security_reason"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames + extra_cols)
        if mode == "w":
            writer.writeheader()

        count = 0
        kept = 0
        last_request_ts = 0.0
        window_start_ts = time.time()
        window_tokens = 0

        started = resume_from_id is None
        for row in reader:
            if limit is not None and count >= limit:
                break

            issue_id = (row.get("id") or "").strip()
            if not issue_id:
                continue
            if not started:
                if issue_id != resume_from_id:
                    continue
                started = True

            if issue_id in cache:
                res = cache[issue_id]
            else:
                prompt = build_prompt(row)

                # Basic client-side rate limiting and TPM windowing
                now = time.time()
                sleep_needed = min_interval_sec - (now - last_request_ts)
                if sleep_needed > 0:
                    time.sleep(sleep_needed)

                now = time.time()
                if now - window_start_ts >= 60:
                    window_start_ts = now
                    window_tokens = 0

                estimated_tokens = max(1, len(prompt) // 4)
                if window_tokens + estimated_tokens > max_tokens_per_minute:
                    time.sleep(max(0.0, 60 - (now - window_start_ts)))
                    window_start_ts = time.time()
                    window_tokens = 0

                response = None
                delay = 2.0
                for attempt in range(1, 7):
                    try:
                        response = client.models.generate_content(
                            model=model,
                            contents=prompt,
                            config=genai.types.GenerateContentConfig(
                                temperature=temperature
                            ),
                        )
                        break
                    except (genai_errors.ServerError, genai_errors.ClientError) as e:
                        msg = str(e)
                        retry_match = re.search(r"Please retry in ([0-9.]+)s", msg)
                        if retry_match:
                            time.sleep(float(retry_match.group(1)))
                        else:
                            time.sleep(delay)
                            delay = min(delay * 2, 60.0)
                if response is None:
                    print(
                        f"LLM request failed after retries for issue {issue_id}; skipping."
                    )
                    count += 1
                    if log_every > 0 and (count % log_every == 0):
                        print(f"Processed: {count}, Kept: {kept}, Last ID: {issue_id}")
                    continue
                last_request_ts = time.time()
                res = parse_response(response.text or "")
                window_tokens += estimated_tokens

                if cache_path:
                    cache[issue_id] = res
                    try:
                        cache_path.write_text(
                            json.dumps(cache, ensure_ascii=False, indent=2),
                            encoding="utf-8",
                        )
                    except Exception:
                        pass

            count += 1
            if res.get("security_related"):
                kept += 1
                out_row = dict(row)
                out_row["security_related"] = "true"
                out_row["security_reason"] = res.get("reason", "")
                writer.writerow(out_row)
            if log_every > 0 and (count % log_every == 0):
                print(f"Processed: {count}, Kept: {kept}, Last ID: {issue_id}")

    print(f"Processed: {count}, Kept (security-related): {kept}, Output: {output_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Filter GitHub issues CSV with Gemini security classifier"
    )
    parser.add_argument(
        "--input",
        default=str(Path("results/github/tvm.csv")),
        help="Path to input CSV",
    )
    parser.add_argument(
        "--output",
        default=str(Path("results/github/tvm_security.csv")),
        help="Path to output filtered CSV",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Gemini model name",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.2,
        help="Sampling temperature",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max number of rows to process",
    )
    parser.add_argument(
        "--cache",
        default=str(Path("results/github/tvm_security_cache.json")),
        help="Path to JSON cache for classifications",
    )
    parser.add_argument(
        "--min_interval",
        type=float,
        default=60.0 / DEFAULT_RPM,
        help="Minimum seconds between requests",
    )
    parser.add_argument(
        "--tpm",
        type=int,
        default=DEFAULT_TPM,
        help="Max tokens per minute (approximate)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        default=True,
        help="Append to output CSV instead of overwriting",
    )
    parser.add_argument(
        "--log_every",
        type=int,
        default=10,
        help="Print progress every N processed rows (0 disables)",
    )
    parser.add_argument(
        "--resume_from_id",
        default="968441953",
        help="Start processing when this issue id is reached (inclusive)",
    )
    args = parser.parse_args()

    input_csv = Path(args.input)
    output_csv = Path(args.output)
    cache_path = Path(args.cache) if args.cache else None

    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    filter_csv(
        input_csv=input_csv,
        output_csv=output_csv,
        model=args.model,
        temperature=args.temperature,
        limit=args.limit,
        cache_path=cache_path,
        min_interval_sec=args.min_interval,
        append=args.append,
        max_tokens_per_minute=args.tpm,
        log_every=args.log_every,
        resume_from_id=args.resume_from_id,
    )


if __name__ == "__main__":
    main()