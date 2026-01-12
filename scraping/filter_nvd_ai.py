import argparse
import csv
import json
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path so that 'adapters' package can be imported
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))
from adapters.LLM import DPAgent, OpenAIAgent


def build_agent(backend: str, model: str, temperature: float):
    backend_lower = backend.lower()
    if backend_lower in ("together", "dp", "dpagent"):
        return DPAgent(model=model, temperature=temperature)
    if backend_lower in ("openai", "oai"):
        return OpenAIAgent(model=model, temperature=temperature)
    raise ValueError(f"Unknown backend: {backend}")


def build_prompt(cve_row: dict) -> str:
    cve_id = cve_row.get("cve_id", "").strip()
    desc = cve_row.get("descriptions", "").strip()
    products = cve_row.get("products", "").strip()
    cwes = cve_row.get("cwes", "").strip()
    refs = cve_row.get("references", "").strip()

    return (
        "You are an expert security analyst specializing in AI/ML software and systems.\n"
        "Task: Determine if the following CVE is AI-related.\n\n"
        f"CVE ID: {cve_id}\n"
        f"Description: {desc}\n"
        f"Products: {products}\n"
        f"CWEs: {cwes}\n"
        f"References: {refs}\n\n"
        "Definition of AI-related: The vulnerability primarily involves AI/ML models, frameworks, tooling, inference/training systems, AI runtimes, model-serving, LLMs, data/poisoning specific to ML, or attacks unique to AI (prompt injection, model inversion, membership inference).\n\n"
        "Answer strictly in JSON with keys: {\"ai_related\": true|false, \"reason\": string}. No extra text."
    )


def classify_row(agent, row: dict) -> dict:
    # Reuse DPAgent/OpenAIAgent minimal chat interface via get_opt_values_prompt-like usage
    # We'll dispatch through DPAgent._post_prompt or OpenAIAgent client directly via a small shim
    prompt = build_prompt(row)
    content: str
    if hasattr(agent, "_post_prompt"):
        content = agent._post_prompt(prompt)  # DPAgent
    else:
        # OpenAIAgent path uses the same API as in generate_seeds/get_opt_values
        content = agent.client.chat.completions.create(
            model=agent.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=agent.temperature
        ).choices[0].message.content
    try:
        data = json.loads(content)
        ai_related = bool(data.get("ai_related"))
        reason = str(data.get("reason", "")).strip()
    except Exception:
        # Fallback: heuristic parse
        lowered = content.lower()
        ai_related = ("true" in lowered) and ("false" not in lowered or lowered.find("true") < lowered.find("false"))
        reason = content.strip()[:500]
    return {"ai_related": ai_related, "reason": reason}


def filter_csv(input_csv: Path, output_csv: Path, backend: str, model: str, temperature: float, limit: int | None, cache_path: Path | None, start_from: str | None, append: bool):
    agent = build_agent(backend=backend, model=model, temperature=temperature)

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
        extra_cols = ["ai_related", "ai_reason"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames + extra_cols)
        if mode == "w":
            writer.writeheader()

        count = 0
        kept = 0
        started = start_from is None
        for row in reader:
            cve_id = (row.get("cve_id") or "").strip()
            if not cve_id:
                continue
            if not started:
                if cve_id == start_from:
                    started = True
                else:
                    continue
            if limit is not None and count >= limit:
                break

            if cve_id in cache:
                res = cache[cve_id]
            else:
                res = classify_row(agent, row)
                if cache_path:
                    cache[cve_id] = res
                    try:
                        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
                    except Exception:
                        pass

            count += 1
            if res.get("ai_related"):
                kept += 1
                out_row = dict(row)
                out_row["ai_related"] = "true"
                out_row["ai_reason"] = res.get("reason", "")
                writer.writerow(out_row)

    print(f"Processed: {count}, Kept (AI-related): {kept}, Output: {output_csv}")


def main():
    parser = argparse.ArgumentParser(description="Filter NVD CSV with LLM AI-related classifier")
    parser.add_argument("--input", default=str(Path("results/cve/nvd.csv")), help="Path to input NVD CSV")
    parser.add_argument("--output", default=str(Path("results/cve/nvd_ai.csv")), help="Path to output filtered CSV")
    parser.add_argument("--backend", default="together", choices=["together", "dp", "dpagent", "openai", "oai"], help="LLM backend")
    parser.add_argument("--model", default="mistralai/Mistral-7B-Instruct-v0.1", help="Model name for the backend")
    parser.add_argument("--temperature", type=float, default=0.3, help="Sampling temperature")
    parser.add_argument("--limit", type=int, default=None, help="Max number of rows to process")
    parser.add_argument("--cache", default=str(Path("results/cve/nvd_ai_cache.json")), help="Path to JSON cache for classifications")
    parser.add_argument("--start_from", default=None, help="Resume processing starting from this CVE ID (inclusive)")
    parser.add_argument("--append", action="store_true", help="Append to the output CSV instead of overwriting")
    args = parser.parse_args()

    input_csv = Path(args.input)
    output_csv = Path(args.output)
    cache_path = Path(args.cache) if args.cache else None

    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    filter_csv(
        input_csv=input_csv,
        output_csv=output_csv,
        backend=args.backend,
        model=args.model,
        temperature=args.temperature,
        limit=args.limit,
        cache_path=cache_path,
        start_from=args.start_from,
        append=args.append,
    )


if __name__ == "__main__":
    main()


