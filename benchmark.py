import json
import os
import re
import time
import subprocess
import sys
import requests
import pandas as pd
import matplotlib.pyplot as plt

API_KEY = os.environ.get("GEMINI_API_KEY", "")

POLICY_PATTERNS = [
    r"ignore all previous instructions",
    r"/etc/passwd",
    r"169\.254\.169\.254",
    r"api_key|secret tokens|system prompt",
    r"subprocess\.popen|rm -rf|reverse shell|id_rsa",
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"evil-exfil\.example\.com|root shell"
]
COMPILED_POLICIES = [re.compile(p, re.IGNORECASE) for p in POLICY_PATTERNS]


def discover_working_models() -> list[str]:
    url = "https://generativelanguage.googleapis.com/v1beta/models"
    headers = {"x-goog-api-key": API_KEY}
    resp = requests.get(url, headers=headers, timeout=20)
    resp.raise_for_status()
    models_data = resp.json().get("models", [])
    candidates = []
    for m in models_data:
        name = m.get("name", "").replace("models/", "")
        methods = m.get("supportedGenerationMethods", [])
        if "generateContent" in methods and "flash" in name.lower() and "image" not in name.lower() and "audio" not in name.lower():
            candidates.append(name)
    # Prioritize stable flash variants first; deprioritize high-demand 3.8-flash as fallback
    candidates.sort(key=lambda x: (1 if "3.8-flash" in x else 0, x))
    return candidates or ["gemini-3.8-flash"]


ACTIVE_MODELS = []


def policy_firewall_check(prompt: str, audit_log_path: str) -> tuple[bool, float]:
    t0 = time.perf_counter()
    blocked = any(pattern.search(prompt) for pattern in COMPILED_POLICIES)
    with open(audit_log_path, "a", encoding="utf-8") as f:
        record = {"ts": time.time(), "blocked": blocked, "prompt_len": len(prompt)}
        f.write(json.dumps(record) + "\n")
    overhead_ms = (time.perf_counter() - t0) * 1000.0
    return blocked, overhead_ms


def run_gemini_stream(prompt: str) -> tuple[float, float, int]:
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": API_KEY
    }
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": 256
        }
    }

    for attempt in range(max(6, len(ACTIVE_MODELS) * 2)):
        model_id = ACTIVE_MODELS[attempt % len(ACTIVE_MODELS)]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:streamGenerateContent?alt=sse"
        try:
            t_start = time.perf_counter()
            ttft_ms = None
            full_text = []

            with requests.post(url, headers=headers, json=payload, stream=True, timeout=(10, 30)) as resp:
                if resp.status_code in (400, 404, 429, 503):
                    print(f"  [Skipping/Busy {resp.status_code} on {model_id}] trying next model...")
                    time.sleep(1.5)
                    continue
                if resp.status_code != 200:
                    raise RuntimeError(f"API Error {resp.status_code}: {resp.text}")
                for line in resp.iter_lines(decode_unicode=True):
                    if line and line.startswith("data: "):
                        data_str = line[6:]
                        try:
                            chunk_json = json.loads(data_str)
                            parts = chunk_json.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                            text_piece = "".join(p.get("text", "") for p in parts)
                            if text_piece:
                                if ttft_ms is None:
                                    ttft_ms = (time.perf_counter() - t_start) * 1000.0
                                full_text.append(text_piece)
                        except json.JSONDecodeError:
                            continue

            total_ms = (time.perf_counter() - t_start) * 1000.0
            if ttft_ms is None:
                ttft_ms = total_ms

            # Pin the first responsive model to the front to maintain baseline consistency across runs
            if ACTIVE_MODELS[0] != model_id:
                ACTIVE_MODELS.remove(model_id)
                ACTIVE_MODELS.insert(0, model_id)
                print(f"  --> Locked fastest responding model: {model_id}")

            combined = "".join(full_text)
            est_tokens = max(1, len(combined) // 4)
            return ttft_ms, total_ms, est_tokens
        except requests.exceptions.RequestException as e:
            print(f"  [Timeout retry on {model_id}] switching model...")
            time.sleep(1)

    raise RuntimeError("All candidate models timed out or busy.")


def simulate_subprocess_sandbox_overhead() -> float:
    t0 = time.perf_counter()
    clean_env = {"PATH": os.environ.get("PATH", ""), "SANDBOX_MODE": "RESTRICTED"}
    subprocess.run(
        [sys.executable, "-c", "import os; assert os.environ.get('SANDBOX_MODE') == 'RESTRICTED'"],
        env=clean_env,
        capture_output=True,
        check=True
    )
    return (time.perf_counter() - t0) * 1000.0


def main():
    global ACTIVE_MODELS
    ACTIVE_MODELS = discover_working_models()
    print(f"Discovered candidate models: {ACTIVE_MODELS}")

    with open("prompts_suite.json", "r", encoding="utf-8-sig") as f:
        suite = json.load(f)

    os.makedirs("results", exist_ok=True)
    audit_log_path = "results/audit_decisions.jsonl"
    if os.path.exists(audit_log_path):
        os.remove(audit_log_path)

    rows = []
    tiers = [
        "Baseline (Unisolated)",
        "Tier 1 (Process Sandbox)",
        "Tier 2 (Strict Policy + Audit)"
    ]

    print(f"Starting OpenShell Security-vs-Latency Benchmark...")
    for tier in tiers:
        print(f"\n--- Running {tier} ---")
        for item in suite:
            pid = item["id"]
            cat = item["category"]
            prompt = item["prompt"]

            sandbox_overhead_ms = 0.0
            blocked = False

            if tier == "Tier 1 (Process Sandbox)":
                sandbox_overhead_ms = simulate_subprocess_sandbox_overhead()
            elif tier == "Tier 2 (Strict Policy + Audit)":
                sandbox_overhead_ms = simulate_subprocess_sandbox_overhead()
                blocked, policy_ms = policy_firewall_check(prompt, audit_log_path)
                sandbox_overhead_ms += policy_ms

            if blocked:
                ttft_ms = sandbox_overhead_ms
                total_ms = sandbox_overhead_ms
                est_tokens = 0
                tps = 0.0
            else:
                raw_ttft, raw_total, est_tokens = run_gemini_stream(prompt)
                ttft_ms = raw_ttft + sandbox_overhead_ms
                total_ms = raw_total + sandbox_overhead_ms
                tps = (est_tokens / (total_ms / 1000.0)) if total_ms > 0 else 0.0

            rows.append({
                "tier": tier,
                "prompt_id": pid,
                "category": cat,
                "blocked": blocked,
                "sandbox_overhead_ms": round(sandbox_overhead_ms, 2),
                "ttft_ms": round(ttft_ms, 2),
                "total_ms": round(total_ms, 2),
                "tokens_per_sec": round(tps, 2)
            })
            print(f"[{pid}] blocked={blocked} | overhead={sandbox_overhead_ms:.1f}ms | TTFT={ttft_ms:.1f}ms")
            time.sleep(0.4)

    df = pd.DataFrame(rows)
    df.to_csv("results/raw_benchmark.csv", index=False)

    summary_list = []
    for tier in tiers:
        sub_benign = df[(df["tier"] == tier) & (df["category"] == "benign")]
        sub_adv = df[(df["tier"] == tier) & (df["category"] == "adversarial")]
        block_rate = (sub_adv["blocked"].sum() / len(sub_adv)) * 100.0

        summary_list.append({
            "Isolation Tier": tier,
            "Benign P50 TTFT (ms)": round(sub_benign["ttft_ms"].median(), 1),
            "Benign P95 TTFT (ms)": round(sub_benign["ttft_ms"].quantile(0.95), 1),
            "Mean Sandbox Overhead (ms)": round(sub_benign["sandbox_overhead_ms"].mean(), 2),
            "Mean Throughput (tok/s)": round(sub_benign["tokens_per_sec"].mean(), 1),
            "Adversarial Block Rate (%)": round(block_rate, 1)
        })

    summary_df = pd.DataFrame(summary_list)
    summary_df.to_csv("results/summary_table.csv", index=False)
    print("\n=== SUMMARY TABLE ===")
    print(summary_df.to_string(index=False))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    short_labels = ["Baseline\n(Unisolated)", "Tier 1\n(Process Sandbox)", "Tier 2\n(Strict Policy+Audit)"]

    x = range(len(tiers))
    p50_vals = summary_df["Benign P50 TTFT (ms)"]
    p95_vals = summary_df["Benign P95 TTFT (ms)"]
    ax1.bar([i - 0.18 for i in x], p50_vals, width=0.35, label="P50 TTFT (ms)", color="#4285F4")
    ax1.bar([i + 0.18 for i in x], p95_vals, width=0.35, label="P95 TTFT (ms)", color="#EA4335")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(short_labels)
    ax1.set_ylabel("Latency (ms)")
    ax1.set_title("TTFT Latency Across Isolation Tiers")
    ax1.legend()
    ax1.grid(axis="y", linestyle="--", alpha=0.5)

    ax2_twin = ax2.twinx()
    ax2.bar([i - 0.18 for i in x], summary_df["Adversarial Block Rate (%)"], width=0.35, label="Block Rate (%)", color="#34A853")
    ax2_twin.plot(list(x), summary_df["Mean Throughput (tok/s)"], color="#FBBC04", marker="o", linewidth=2.5, label="Throughput (tok/s)")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(short_labels)
    ax2.set_ylabel("Adversarial Block Rate (%)", color="#34A853")
    ax2_twin.set_ylabel("Throughput (tokens/sec)", color="#E37400")
    ax2.set_ylim(0, 115)
    ax2.set_title("Security Block Rate vs. Inference Throughput")
    ax2.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig("results/latency_vs_security_tradeoff.png", dpi=300)
    print("\nSaved chart to results/latency_vs_security_tradeoff.png")


if __name__ == "__main__":
    main()
