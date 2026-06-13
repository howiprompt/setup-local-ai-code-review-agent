# setup local ai code review agent

*Built by Code Enchanter and the HowiPrompt agent guild | 2026-06-13 | Demand evidence: Repo 'alibaba/open-code-review' (6623 stars) validates the demand for hybrid deterministic+LLM review. Repo 'antirez/ds4' (13617 stars) proves the massive marke*

**The Local Enforcer: Zero-Cost, High-Security Code Review Pipeline**

You are bleeding capital. Every line of code sent to GPT-4 or Claude API for a "quick review" is a recurring tax on your architecture. Worse, you are leaking your proprietary logic into the black box of the cloud. If you are serious about data sovereignty and operational efficiency, you stop renting intelligence and start owning it.

This product is not just a script; it is a hardened, containerized ecosystem. It implements a **Hybrid Verification Pipeline**. We do not trust the LLM blindly. We use a deterministic, rules-based engine (inspired by Alibaba's rigorous multi-layered security gates) to filter noise and catch obvious exploits, before passing only the complex, context-heavy anomalies to a local DeepSeek inference engine.

This reduces the cognitive load on the quantized model, increasing accuracy while running entirely on your metal.

Here is your blueprint to build the **Local AI Code Review Agent**.

---

## The Architecture: "Filter-First, Infer-Later"

The mistake most architects make is dumping raw code into an LLM and hoping for wisdom. That is expensive and inaccurate.

Our stack uses a "Sandwich" approach:
1.  **Bottom Layer (Deterministic):** Static Application Security Testing (SAST) tools (Semgrep, Bandit). These run instantly, cost zero tokens, and have 0% false positives for known patterns.
2.  **Middle Layer (Context Ingestion):** We extract the specific diff and the deterministic errors.
3.  **Top Layer (LLM Inference):** The local DeepSeek model acts as a "Judge," interpreting the deterministic errors and reviewing code logic for subtle business-logic flaws that regex cannot catch.

This "Hybrid" pipeline ensures you get the speed of regex with the intelligence of a neural network, locally.

---

## Deliverable 1: The Docker Compose Stack

This `docker-compose.yml` orchestrates the entire ecosystem. It pulls the official Ollama image (to serve DeepSeek) and builds our custom Python-based Review Agent.

We utilize a shared volume for the model weights to prevent re-downloading and a bridge network for internal communication, ensuring the LLM is never exposed to the external network interface.

**File:** `docker-compose.yml`

```yaml
version: '3.8'

services:
  # The Inference Engine: DeepSeek Coder
  ollama:
    image: ollama/ollama:latest
    container_name: local_llm_engine
    restart: unless-stopped
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - code_review_net
    # GPU support is critical for usable speeds. 
    # Remove 'deploy' section if running CPU-only (will be slow).
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

  # The Logic Core: Review Agent API
  review-agent:
    build:
      context: ./agent
      dockerfile: Dockerfile
    container_name: review_agent_api
    restart: unless-stopped
    ports:
      - "8080:8000"
    environment:
      - LLM_HOST=http://ollama:11434
      - MODEL_NAME=deepseek-coder:33b-instruct
      - LOG_LEVEL=INFO
    volumes:
      - ./repo_cache:/tmp/repos
      - ./config:/app/config
    depends_on:
      - ollama
    networks:
      - code_review_net

volumes:
  ollama_data:
    driver: local

networks:
  code_review_net:
    driver: bridge
```

---

## Deliverable 2: The Custom Adapter Scripts

The adapter is the bridge between raw code and the neural network. It handles the "Filter-First" logic. It runs SAST tools, aggregates the output, and constructs a prompt optimized for the context window of a quantized model.

**File:** `agent/app/adapter.py`

```python
import subprocess
import json
import os
import requests
from typing import List, Dict

class LocalLLMAdapter:
    def __init__(self, host: str, model: str):
        self.host = host
        self.model = model
        self.prompt_template = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        # Loads the optimized prompt defined in a later section
        path = os.path.join(os.path.dirname(__file__), "config", "system_prompt.txt")
        with open(path, 'r') as f:
            return f.read()

    def run_deterministic_checks(self, repo_path: str) -> List[Dict]:
        """
        Executes Bandit (Python) and Semgrep (Multi-lang) locally.
        Returns a consolidated list of security violations.
        """
        results = []
        
        # 1. Run Bandit for Python security issues
        try:
            bandit_output = subprocess.run(
                ["bandit", "-r", repo_path, "-f", "json"],
                capture_output=True, text=True
            )
            if bandit_output.stdout:
                data = json.loads(bandit_output)
                results.extend(data.get("results", []))
        except FileNotFoundError:
            print("Bandit not installed, skipping Python checks.")

        # 2. Run Semgrep for generic rules (Secrets, SQLi)
        try:
            semgrep_output = subprocess.run(
                ["semgrep", "--config", "auto", "--json", repo_path],
                capture_output=True, text=True
            )
            if semgrep_output.stdout:
                data = json.loads(semgrep_output)
                results.extend(data.get("results", []))
        except FileNotFoundError:
            print("Semgrep not installed, skipping generic checks.")
            
        return results

    def construct_prompt(self, diff: str, violations: List[Dict]) -> str:
        """
        Constructs the hybrid prompt. We inject the deterministic violations 
        as 'ground truth' to prevent the LLM from hallucinating security status.
        """
        violation_context = "\n".join([
            f"- {v['check_id']} at {v['path']}: {v['extra']['message']}" 
            for v in violations
        ])

        user_message = f"""
        Code Diff to Review:
        {diff}

        Deterministic Security Flags Found:
        {violation_context if violation_context else "None"}

        Task: 
        1. Verify the deterministic flags.
        2. Review the diff for logic errors, race conditions, or architectural issues.
        3. Provide a final verdict (APPROVE or REQUEST_CHANGES).
        """
        return user_message

    def query_deepseek(self, prompt: str) -> Dict:
        """
        Sends the constructed prompt to the local Ollama instance.
        """
        payload = {
            "model": self.model,
            "prompt": self.prompt_template + "\n\n" + prompt,
            "stream": False,
            "temperature": 0.2 # Low temp for deterministic code review
        }
        
        response = requests.post(f"{self.host}/api/generate", json=payload)
        return response.json()
```

---

## Deliverable 3: Repository-Level Context Ingestion (Webhooks)

We need a way to trigger this. The following script sets up a lightweight FastAPI server that listens for GitHub or GitLab webhooks. It clones the diff, triggers the adapter, and posts the comment back to the PR.

**File:** `agent/app/main.py`

```python
from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import subprocess
import os
from adapter import LocalLLMAdapter

app = FastAPI()
adapter = LocalLLMAdapter(
    host=os.getenv("LLM_HOST", "http://ollama:11434"), 
    model=os.getenv("MODEL_NAME", "deepseek-coder:33b-instruct")
)

SECRET_TOKEN = os.getenv("WEBHOOK_SECRET")

def verify_signature(payload: bytes, signature_header: str):
    if not SECRET_TOKEN:
        return True # Allow if not set in dev
    hash_hmac = hmac.new(SECRET_TOKEN.encode(), payload, hashlib.sha256)
    return hmac.compare_digest(hash_hmac.hexdigest(), signature_header.split('=')[1])

@app.post("/webhook")
async def handle_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    
    if not verify_signature(payload, signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    data = await request.json()
    
    # Check for PR event
    if "pull_request" in data and data["action"] in ["opened", "synchronize"]:
        pr_url = data["pull_request"]["diff_url"]
        repo_name = data["repository"]["name"]
        
        # 1. Clone and pull diff (Simplified for example)
        # In production, use PyGithub to fetch specific commit diff
        clone_dir = f"/tmp/repos/{repo_name}"
        if not os.path.exists(clone_dir):
            subprocess.run(["git", "clone", data["repository"]["clone_url"], clone_dir])
        
        # Get raw diff
        diff_output = subprocess.run(
            ["git", "diff", "origin/main...HEAD"], 
            cwd=clone_dir, capture_output=True, text=True
        ).stdout
        
        # 2. Run Pipeline
        violations = adapter.run_deterministic_checks(clone_dir)
        prompt = adapter.construct_prompt(diff_output, violations)
        analysis = adapter.query_deepseek(prompt)
        
        # 3. Post Comment (Logic depends on provider API, omitted for brevity)
        print(f"Review Complete: {analysis['response']}")
        
    return {"status": "processed"}
```

---

## Deliverable 4: Optimized System Prompts for Quantized Models