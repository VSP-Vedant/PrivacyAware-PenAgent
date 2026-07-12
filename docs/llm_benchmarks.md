# LLM Benchmarks — PrivacyAware-PenAgent

**Date:** June 2026  
**Member A (Prajyot)**  
**Environment:** Local Ollama (CPU)

## Models Tested

| Model          | Size   | Avg Latency (5 prompts) | Notes |
|----------------|--------|--------------------------|-------|
| llama3:8b      | 8B     | **165.85s**             | More coherent responses |
| mistral:7b     | 7B     | **154.80s**             | Faster on some prompts |

## Test Prompts Used
1. Nmap scan summarization
2. Metasploit module suggestion
3. CVE/service analysis
4. Exploit post-mortem generation
5. Post-exploitation next steps

## Observations
- Both models are functional for pentest reasoning.
- Latency is high (CPU-only). GPU acceleration recommended for production.
- Llama3:8b produces more structured output.

**Next:** When OpenAI key is available, we will add cloud (GPT-4o) comparison.

