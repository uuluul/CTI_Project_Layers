from __future__ import annotations
import json
import os
from typing import Any, Dict, List
import httpx
from .utils import env

class LLMClient:
    def __init__(self) -> None:
        self.azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.api_key = os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.chat_deployment = os.getenv("AZURE_OPENAI_CHAT_DEPLOYMENT", "gpt-4o")
        self.embedding_deployment = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "text-embedding-3-small")
        self.api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
        self.timeout = float(os.getenv("OPENAI_TIMEOUT", "60"))
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")

        if not self.api_key:
            raise RuntimeError("Missing API Key! Please set AZURE_OPENAI_API_KEY in .env")

    def extract_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        執行 Chat Completion (自動判斷是 Azure 還是標準 OpenAI)
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        if self.azure_endpoint:
            base = self.azure_endpoint.rstrip('/')
            url = f"{base}/openai/deployments/{self.chat_deployment}/chat/completions"
            params = {"api-version": self.api_version}
            headers = {
                "api-key": self.api_key, 
                "Content-Type": "application/json"
            }
            payload = {
                "messages": messages,
                "temperature": 0,
                "response_format": {"type": "json_object"},
            }
        else:
            url = f"{self.base_url}/chat/completions"
            params = {}
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": 0,
                "response_format": {"type": "json_object"},
            }

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload, params=params)
            resp.raise_for_status()
            data = resp.json()

        content = data["choices"][0]["message"]["content"]
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"LLM returned non-JSON output: {content[:2000]}") from e

    def get_embedding(self, text: str) -> List[float]:
        """
        跑Embedding看是Azure還是OpenAI
        """
        if self.azure_endpoint:
            base = self.azure_endpoint.rstrip('/')
            url = f"{base}/openai/deployments/{self.embedding_deployment}/embeddings"
            params = {"api-version": self.api_version}
            headers = {
                "api-key": self.api_key,
                "Content-Type": "application/json"
            }
            payload = {
                "input": text
            }
        else:
            url = f"{self.base_url}/embeddings"
            params = {}
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": "text-embedding-3-small",
                "input": text
            }

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, headers=headers, json=payload, params=params)
            resp.raise_for_status()
            data = resp.json()

        return data["data"][0]["embedding"]