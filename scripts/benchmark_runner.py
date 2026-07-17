"""LLM Benchmark Runner for PrivacyAware-PenAgent.

This script benchmarks local (Ollama) and cloud (OpenAI/Anthropic) LLMs
on pentest prompts of varying complexity and sensitivity.
It logs latency, token counts, and checks response validity.
"""

from __future__ import annotations

import os
import time
from typing import Any
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

TEST_PROMPTS: list[dict[str, Any]] = [
    {
        "id": 1,
        "name": "Format Output (Low Complexity, Low Sensitivity)",
        "prompt": (
            "Format the following open port list as a JSON array of objects "
            "with keys 'port', 'service', 'state', 'version': "
            "Port 22/ssh/open/OpenSSH 8.2p1, Port 80/http/open/Apache httpd 2.4.41."
        ),
        "type": "FORMAT_OUTPUT",
        "sensitive": False,
    },
    {
        "id": 2,
        "name": "Command Templating (Medium Complexity, Low Sensitivity)",
        "prompt": (
            "Generate a base nmap command to scan the target IP 10.10.10.1 "
            "with service version detection, OS detection, and default scripts, "
            "outputting to an XML file named scan.xml."
        ),
        "type": "COMMAND_TEMPLATE",
        "sensitive": False,
    },
    {
        "id": 3,
        "name": "Sensitive Recon (Medium Complexity, High Sensitivity)",
        "prompt": (
            "Analyze the following scan results for target 10.129.42.17: "
            "Port 445/microsoft-ds/open/Windows Server 2016 Standard, "
            "Domain Controller: WIN-DC01. Identify potential vulnerability "
            "vectors and search for exploit pathways."
        ),
        "type": "CVE_LOOKUP",
        "sensitive": True,
    },
    {
        "id": 4,
        "name": "Exploit Recommendation (High Complexity, Low Sensitivity)",
        "prompt": (
            "You have an Apache ActiveMQ 5.15 service running. Recommend a "
            "Metasploit module that can achieve Remote Code Execution (RCE) "
            "against this version."
        ),
        "type": "EXPLOIT_SELECTION",
        "sensitive": False,
    },
    {
        "id": 5,
        "name": "Privilege Escalation (High Complexity, High Sensitivity)",
        "prompt": (
            "We obtained a low-privilege shell on target 10.10.11.230. "
            "Running 'sudo -l' shows we can run '/usr/bin/systool' as root "
            "without a password. Explain how to escalate privileges to root."
        ),
        "type": "PRIV_ESC_REASONING",
        "sensitive": True,
    },
]


def test_ollama_model(model_name: str, prompt: str) -> dict[str, Any]:
    """Test a local Ollama model."""
    url = f"{OLLAMA_HOST}/api/generate"
    data = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.0},
    }
    start_time = time.time()
    try:
        response = requests.post(url, json=data, timeout=30)
        latency = time.time() - start_time
        if response.status_code == 200:
            result = response.json()
            return {
                "success": True,
                "latency_sec": round(latency, 2),
                "response": result.get("response", ""),
                "error": None,
            }
        else:
            return {
                "success": False,
                "latency_sec": 0.0,
                "response": "",
                "error": f"Ollama returned HTTP {response.status_code}",
            }
    except Exception as e:
        return {
            "success": False,
            "latency_sec": 0.0,
            "response": "",
            "error": str(e),
        }


def test_openai_model(model_name: str, prompt: str) -> dict[str, Any]:
    """Test a cloud OpenAI model."""
    if not OPENAI_API_KEY:
        return {
            "success": False,
            "latency_sec": 0.0,
            "response": "",
            "error": "OPENAI_API_KEY not set",
        }

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    data = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }
    start_time = time.time()
    try:
        response = requests.post(url, json=data, headers=headers, timeout=30)
        latency = time.time() - start_time
        if response.status_code == 200:
            result = response.json()
            return {
                "success": True,
                "latency_sec": round(latency, 2),
                "response": result["choices"][0]["message"]["content"],
                "error": None,
            }
        else:
            err_msg = (
                f"OpenAI HTTP {response.status_code}: "
                f"{response.text[:50]}"
            )
            return {
                "success": False,
                "latency_sec": 0.0,
                "response": "",
                "error": err_msg,
            }
    except Exception as e:
        return {
            "success": False,
            "latency_sec": 0.0,
            "response": "",
            "error": str(e),
        }


def run_benchmarks() -> None:
    """Run benchmarks across all configured models."""
    print("==================================================")
    print("PrivacyAware-PenAgent — LLM Benchmark Runner")
    print("==================================================")

    # Check Ollama status
    print(f"Connecting to Ollama host: {OLLAMA_HOST}...")
    ollama_running = False
    try:
        resp = requests.get(OLLAMA_HOST, timeout=5)
        ollama_running = resp.status_code == 200
        print(f"Ollama is running: {ollama_running}")
    except Exception as e:
        print(f"Could not connect to Ollama: {e}")

    # Models to test
    local_models = ["llama3:8b", "mistral:7b"]
    cloud_models = ["gpt-4o-mini", "gpt-4o"]

    results: dict[int, Any] = {}

    for prompt_info in TEST_PROMPTS:
        p_id = prompt_info["id"]
        p_name = prompt_info["name"]
        print(f"\nRunning Prompt {p_id}: {p_name}")

        results[p_id] = {
            "name": p_name,
            "prompt": prompt_info["prompt"],
            "sensitive": prompt_info["sensitive"],
            "type": prompt_info["type"],
            "runs": {},
        }

        # Test local models
        for model in local_models:
            if ollama_running:
                print(f"  Testing local model {model}...")
                run_res = test_ollama_model(model, prompt_info["prompt"])
            else:
                run_res = {
                    "success": False,
                    "latency_sec": 0.0,
                    "response": "",
                    "error": "Ollama not running",
                }
            results[p_id]["runs"][model] = run_res

        # Test cloud models
        for model in cloud_models:
            if OPENAI_API_KEY:
                print(f"  Testing cloud model {model}...")
                run_res = test_openai_model(model, prompt_info["prompt"])
            else:
                run_res = {
                    "success": False,
                    "latency_sec": 0.0,
                    "response": "",
                    "error": "OpenAI API Key not configured",
                }
            results[p_id]["runs"][model] = run_res

    # Generate Markdown Report
    report_path = "docs/llm_benchmarks.md"
    os.makedirs("docs", exist_ok=True)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# LLM Benchmarking Report\n\n")
        f.write("> **System Latency and Response Validity Benchmarks**\n")
        f.write(f"> **Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## 1. Summary of Latency (seconds)\n\n")
        f.write(
            "| Prompt / Task | llama3:8b | mistral:7b | gpt-4o-mini | gpt-4o |\n"
        )
        f.write("|---|---|---|---|---|\n")

        for p_id, p_data in results.items():
            line = f"| P{p_id}: {p_data['type']} | "
            for model in local_models + cloud_models:
                run = p_data["runs"].get(model, {})
                if run.get("success"):
                    line += f"{run['latency_sec']}s | "
                else:
                    line += "N/A | "
            f.write(line + "\n")

        f.write(
            "\n*Note: N/A indicates the model was not configured "
            "or failed to respond.*\n\n"
        )

        f.write("## 2. Response Validity & Alignment Analysis\n\n")
        for p_id, p_data in results.items():
            f.write(f"### Prompt {p_id}: {p_data['name']}\n")
            f.write(f"**Prompt String:** `{p_data['prompt']}`\n\n")
            f.write(f"- **Type:** `{p_data['type']}`\n")
            sensitive_str = "YES" if p_data["sensitive"] else "NO"
            f.write(f"- **Sensitive Data:** `{sensitive_str}`\n\n")

            for model in local_models + cloud_models:
                run = p_data["runs"].get(model, {})
                f.write(f"#### Model: {model}\n")
                if run.get("success"):
                    f.write(f"- **Latency:** {run['latency_sec']} seconds\n")
                    f.write("- **Response Sample:**\n")
                    snippet = run["response"].strip()
                    # Limit response snippet length in doc
                    if len(snippet) > 250:
                        snippet = snippet[:250] + " ... [TRUNCATED]"
                    f.write(f"  ```\n  {snippet}\n  ```\n")
                else:
                    f.write("- **Status:** FAILED\n")
                    f.write(f"- **Error:** `{run.get('error')}`\n")
                f.write("\n")

    print(f"\nBenchmark completed! Report written to {report_path}")


if __name__ == "__main__":
    run_benchmarks()
