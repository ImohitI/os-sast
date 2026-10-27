"""LLM providers for AI triage. Each one turns (prompt, JSON schema) into a JSON string.

  ollama     local model through Ollama (default; code never leaves the machine)
  openai     OpenAI, or any OpenAI-compatible server (vLLM, llama.cpp, LM Studio, Ollama's /v1)
  anthropic  Claude through the Anthropic API
  bedrock    AWS Bedrock Converse API (Claude, Llama, Mistral, Nova ... in your AWS account)

Every provider asks for structured output, so the answer is constrained to the verdict schema:
Ollama `format`, OpenAI `response_format: json_schema`, and a forced tool call for Anthropic and
Bedrock. Only the standard library is used, except Bedrock, which needs boto3 for AWS request signing.
"""

import json
import os
import urllib.error
import urllib.request

TOOL_NAME = "report_verdict"
MAX_TOKENS = 512
DEFAULT_TIMEOUT = 120.0


class LLMError(Exception):
    """A provider is misconfigured or returned something that isn't a usable answer."""


def _post_json(url: str, body: dict, headers: dict, timeout: float) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _http_error_text(error: urllib.error.HTTPError) -> str:
    try:
        return error.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _json_from_text(text: str) -> str:
    """Pull the JSON object out of a free-text answer (code fences, a sentence before it, ...)."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("no JSON object in the model's answer")
    return text[start:end + 1]


def _is_local(url: str) -> bool:
    return url.startswith(("http://localhost", "http://127.0.0.1", "http://[::1]"))


def _require_env(name: str, provider: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise LLMError(f"{provider}: set {name}")
    return value


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, base_url: str | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.model = model
        self.base_url = (base_url or os.environ.get("OLLAMA_URL") or "http://localhost:11434").rstrip("/")
        self.timeout = timeout
        self.sends_code_off_machine = not _is_local(self.base_url)

    def complete_json(self, prompt: str, schema: dict) -> str:
        body = {"model": self.model, "prompt": prompt, "stream": False, "format": schema,
                "options": {"temperature": 0}}
        return _post_json(f"{self.base_url}/api/generate", body, {}, self.timeout)["response"]


class OpenAIProvider:
    """OpenAI Chat Completions with a strict JSON schema. Also works with OpenAI-compatible servers:
    set the base URL (e.g. http://localhost:8000/v1 for vLLM) and any non-empty API key."""

    name = "openai"

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.model = model
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or _require_env("OPENAI_API_KEY", "openai")
        self.timeout = timeout
        self.sends_code_off_machine = not _is_local(self.base_url)

    def complete_json(self, prompt: str, schema: dict) -> str:
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": TOOL_NAME, "strict": True, "schema": schema}},
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        url = f"{self.base_url}/chat/completions"
        try:
            data = _post_json(url, body, headers, self.timeout)
        except urllib.error.HTTPError as error:
            # Some reasoning models only accept their default temperature: retry once without it.
            if error.code != 400 or "temperature" not in _http_error_text(error):
                raise
            del body["temperature"]
            data = _post_json(url, body, headers, self.timeout)
        message = data["choices"][0]["message"]
        if message.get("refusal"):
            raise LLMError(f"openai refused: {message['refusal']}")
        return message["content"]


class AnthropicProvider:
    """Claude through the Anthropic Messages API. The verdict comes back as a forced tool call,
    so its input is already validated against the schema."""

    name = "anthropic"
    sends_code_off_machine = True
    API_VERSION = "2023-06-01"

    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.model = model
        self.base_url = (base_url or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
        self.api_key = api_key or _require_env("ANTHROPIC_API_KEY", "anthropic")
        self.timeout = timeout

    def complete_json(self, prompt: str, schema: dict) -> str:
        body = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [{"name": TOOL_NAME, "description": "Report the triage verdict for this finding.",
                       "input_schema": schema}],
            "tool_choice": {"type": "tool", "name": TOOL_NAME},
        }
        headers = {"x-api-key": self.api_key, "anthropic-version": self.API_VERSION}
        data = _post_json(f"{self.base_url}/v1/messages", body, headers, self.timeout)
        for block in data.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == TOOL_NAME:
                return json.dumps(block["input"])
        raise LLMError("anthropic: no tool_use block in the answer")


class BedrockProvider:
    """AWS Bedrock Converse API: one request shape for every model family on Bedrock.
    Credentials come from the normal AWS chain (env vars, ~/.aws, IAM role). Asks for a forced tool
    call; if the model doesn't support that, retries once asking for JSON in plain text."""

    name = "bedrock"
    sends_code_off_machine = True

    def __init__(self, model: str, region: str | None = None, client=None, timeout: float = DEFAULT_TIMEOUT):
        self.model = model
        if client is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as error:
                raise LLMError('bedrock: pip install "os-sast[bedrock]" (needs boto3)') from error
            config = Config(read_timeout=timeout, retries={"max_attempts": 3, "mode": "standard"})
            client = boto3.client("bedrock-runtime", region_name=region, config=config)
        self.client = client

    def complete_json(self, prompt: str, schema: dict) -> str:
        messages = [{"role": "user", "content": [{"text": prompt}]}]
        inference = {"temperature": 0, "maxTokens": MAX_TOKENS}
        tools = {"tools": [{"toolSpec": {"name": TOOL_NAME, "description": "Report the triage verdict.",
                                         "inputSchema": {"json": schema}}}],
                 "toolChoice": {"tool": {"name": TOOL_NAME}}}
        # Exceptions are caught broadly because they are botocore types and boto3 is optional.
        try:
            response = self.client.converse(modelId=self.model, messages=messages,
                                            inferenceConfig=inference, toolConfig=tools)
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") != "ValidationException":
                raise LLMError(f"bedrock: {error}") from error
            # Typically "this model doesn't support tool use / toolChoice": ask for plain JSON instead.
            try:
                response = self.client.converse(
                    modelId=self.model, inferenceConfig=inference,
                    messages=[{"role": "user", "content": [{"text": prompt + "\n\nReply with the JSON object only."}]}],
                )
            except Exception as retry_error:
                raise LLMError(f"bedrock: {retry_error}") from retry_error
        for block in response["output"]["message"]["content"]:
            if "toolUse" in block:
                return json.dumps(block["toolUse"]["input"])
            if "text" in block:
                return _json_from_text(block["text"])
        raise LLMError("bedrock: empty answer")


PROVIDERS = {"ollama": OllamaProvider, "openai": OpenAIProvider,
             "anthropic": AnthropicProvider, "bedrock": BedrockProvider}

DEFAULT_MODELS = {"ollama": "qwen2.5-coder:7b"}


def make_provider(name: str, model: str | None, base_url: str | None = None,
                  region: str | None = None, timeout: float = DEFAULT_TIMEOUT):
    """Build a provider, failing fast on missing config instead of once per finding."""
    if name not in PROVIDERS:
        raise LLMError(f"unknown AI provider {name!r}: choose one of {', '.join(PROVIDERS)}")
    model = model or DEFAULT_MODELS.get(name)
    if not model:
        raise LLMError(f"{name}: pass --model (model names change too often to default)")
    if name == "bedrock":
        return BedrockProvider(model, region=region, timeout=timeout)
    return PROVIDERS[name](model, base_url=base_url, timeout=timeout)
