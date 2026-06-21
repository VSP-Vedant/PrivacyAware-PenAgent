"""LLM Benchmark Script for PrivacyAware-PenAgent (Member A)"""

import time
import json
from datetime import datetime
from typing import Dict

import ollama

def run_ollama_prompt(model: str, prompt: str, temperature: float = 0.7) -> Dict:
    start_time = time.time()
    try:
        response = ollama.chat(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            options={'temperature': temperature}
        )
        output = response['message']['content']
        latency = round(time.time() - start_time, 2)
        
        return {
            "model": model,
            "prompt_preview": prompt[:80] + "..." if len(prompt) > 80 else prompt,
            "response_preview": output[:150] + "..." if len(output) > 150 else output,
            "latency_seconds": latency,
            "success": True
        }
    except Exception as e:
        return {
            "model": model,
            "prompt_preview": prompt[:80],
            "error": str(e),
            "latency_seconds": round(time.time() - start_time, 2),
            "success": False
        }


def main():
    prompts = [
        "Summarize the following Nmap scan result: Open ports 22, 80, 445 on target 10.10.10.5",
        "Suggest best Metasploit module for vsftpd 2.3.4 vulnerability",
        "Analyze this service: Apache 2.4.41 with CVE-2021-41773",
        "Generate post-mortem for failed exploit: no session opened after using eternalblue",
        "What are safe next steps after gaining www-data shell on Linux target?"
    ]

    results = []
    models = ["llama3:8b", "mistral:7b"]

    print("🚀 Starting LLM Benchmark for PrivacyAware-PenAgent...\n")
    
    for model in models:
        print(f"Testing {model}...")
        for i, prompt in enumerate(prompts, 1):
            print(f"  Prompt {i}/5...")
            result = run_ollama_prompt(model, prompt)
            results.append(result)
            if result["success"]:
                print(f"    ✅ Latency: {result['latency_seconds']}s")
            else:
                print(f"    ❌ Error: {result.get('error')}")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    report = {
        "timestamp": timestamp,
        "models_tested": models,
        "results": results
    }
    
    with open(f"docs/llm_benchmarks_{timestamp}.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Benchmark completed! Results saved.")
    print("\nSummary:")
    for model in models:
        model_results = [r for r in results if r["model"] == model and r.get("success", False)]
        avg_latency = sum(r["latency_seconds"] for r in model_results) / len(model_results) if model_results else 0
        print(f"  {model}: {len(model_results)}/5 successful | Avg latency: {avg_latency:.2f}s")


if __name__ == "__main__":
    main()
