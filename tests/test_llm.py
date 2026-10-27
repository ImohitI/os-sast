"""Request shapes and answer parsing for each provider. No network: HTTP and boto3 are faked."""

import io
import json
import urllib.error

import pytest

from os_sast import cli, llm
from os_sast.llm import (AnthropicProvider, BedrockProvider, LLMError, OllamaProvider, OpenAIProvider,
                         make_provider)
from os_sast.triage import RESPONSE_SCHEMA

VERDICT = {"verdict": "likely_tp", "confidence": 0.8, "reason": "tainted", "suggestedFix": "parameterize"}


@pytest.fixture
def http(monkeypatch):
    """Replace _post_json. Queue answers (dicts, or exceptions to raise); inspect .requests after."""

    class FakeHttp:
        def __init__(self):
            self.answers, self.requests = [], []

        def __call__(self, url, body, headers, timeout):
            self.requests.append({"url": url, "body": json.loads(json.dumps(body)), "headers": headers})
            answer = self.answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

    fake = FakeHttp()
    monkeypatch.setattr(llm, "_post_json", fake)
    return fake


def http_error(code, text):
    return urllib.error.HTTPError("u", code, "err", {}, io.BytesIO(text.encode()))


def test_ollama_uses_format_schema_and_is_local(http):
    http.answers.append({"response": json.dumps(VERDICT)})
    provider = OllamaProvider("qwen2.5-coder:7b")
    assert json.loads(provider.complete_json("p", RESPONSE_SCHEMA)) == VERDICT
    request = http.requests[0]
    assert request["url"] == "http://localhost:11434/api/generate"
    assert request["body"]["format"] == RESPONSE_SCHEMA and request["body"]["options"]["temperature"] == 0
    assert provider.sends_code_off_machine is False
    assert OllamaProvider("m", base_url="http://gpu-box:11434").sends_code_off_machine is True


def test_openai_sends_strict_json_schema(http, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    http.answers.append({"choices": [{"message": {"content": json.dumps(VERDICT)}}]})
    provider = OpenAIProvider("some-model")
    assert json.loads(provider.complete_json("p", RESPONSE_SCHEMA)) == VERDICT
    request = http.requests[0]
    assert request["url"] == "https://api.openai.com/v1/chat/completions"
    assert request["headers"]["Authorization"] == "Bearer sk-test"
    fmt = request["body"]["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True
    assert provider.sends_code_off_machine is True


def test_openai_compatible_local_server(http):
    http.answers.append({"choices": [{"message": {"content": "{}"}}]})
    provider = OpenAIProvider("llama", base_url="http://localhost:8000/v1/", api_key="unused")
    provider.complete_json("p", RESPONSE_SCHEMA)
    assert http.requests[0]["url"] == "http://localhost:8000/v1/chat/completions"
    assert provider.sends_code_off_machine is False


def test_openai_retries_without_temperature_when_the_model_rejects_it(http):
    http.answers += [http_error(400, '{"error": {"param": "temperature"}}'),
                     {"choices": [{"message": {"content": json.dumps(VERDICT)}}]}]
    OpenAIProvider("reasoning-model", api_key="k").complete_json("p", RESPONSE_SCHEMA)
    assert "temperature" in http.requests[0]["body"] and "temperature" not in http.requests[1]["body"]


def test_openai_other_errors_are_not_retried(http):
    http.answers.append(http_error(401, "bad key"))
    with pytest.raises(urllib.error.HTTPError):
        OpenAIProvider("m", api_key="k").complete_json("p", RESPONSE_SCHEMA)
    assert len(http.requests) == 1


def test_openai_refusal_is_an_error(http):
    http.answers.append({"choices": [{"message": {"content": None, "refusal": "no"}}]})
    with pytest.raises(LLMError):
        OpenAIProvider("m", api_key="k").complete_json("p", RESPONSE_SCHEMA)


def test_anthropic_forces_a_tool_call_and_reads_its_input(http, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    http.answers.append({"content": [{"type": "text", "text": "ok"},
                                     {"type": "tool_use", "name": "report_verdict", "input": VERDICT}]})
    answer = AnthropicProvider("claude-haiku-5-5").complete_json("p", RESPONSE_SCHEMA)
    assert json.loads(answer) == VERDICT
    request = http.requests[0]
    assert request["url"] == "https://api.anthropic.com/v1/messages"
    assert request["headers"] == {"x-api-key": "ak-test", "anthropic-version": "2023-06-01"}
    body = request["body"]
    assert body["tool_choice"] == {"type": "tool", "name": "report_verdict"}
    assert body["tools"][0]["input_schema"] == RESPONSE_SCHEMA and body["max_tokens"] > 0


def test_anthropic_without_tool_use_is_an_error(http):
    http.answers.append({"content": [{"type": "text", "text": "I think it's fine"}]})
    with pytest.raises(LLMError):
        AnthropicProvider("m", api_key="k").complete_json("p", RESPONSE_SCHEMA)


class FakeBedrock:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return {"output": {"message": {"role": "assistant", "content": answer}}}


class ValidationException(Exception):
    response = {"Error": {"Code": "ValidationException", "Message": "toolChoice is not supported"}}


class ThrottlingException(Exception):
    response = {"Error": {"Code": "ThrottlingException", "Message": "slow down"}}


def test_bedrock_uses_converse_with_a_forced_tool():
    client = FakeBedrock([{"toolUse": {"toolUseId": "1", "name": "report_verdict", "input": VERDICT}}])
    answer = BedrockProvider("some.model-id", client=client).complete_json("p", RESPONSE_SCHEMA)
    assert json.loads(answer) == VERDICT
    call = client.calls[0]
    assert call["modelId"] == "some.model-id"
    assert call["toolConfig"]["toolChoice"] == {"tool": {"name": "report_verdict"}}
    assert call["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"] == {"json": RESPONSE_SCHEMA}


def test_bedrock_falls_back_to_plain_json_for_models_without_tool_choice():
    client = FakeBedrock(ValidationException(), [{"text": "Here you go:\n```json\n" + json.dumps(VERDICT) + "\n```"}])
    answer = BedrockProvider("m", client=client).complete_json("p", RESPONSE_SCHEMA)
    assert json.loads(answer) == VERDICT
    assert "toolConfig" not in client.calls[1]


def test_bedrock_other_errors_become_llm_errors():
    with pytest.raises(LLMError):
        BedrockProvider("m", client=FakeBedrock(ThrottlingException())).complete_json("p", RESPONSE_SCHEMA)


def test_make_provider_fails_fast_on_bad_config(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMError, match="OPENAI_API_KEY"):
        make_provider("openai", "m")
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        make_provider("anthropic", "m")
    with pytest.raises(LLMError, match="--model"):
        make_provider("anthropic", None)
    with pytest.raises(LLMError, match="unknown"):
        make_provider("gemini", "m")
    assert make_provider("ollama", None).model == "qwen2.5-coder:7b"


def test_cli_rejects_missing_key_before_scanning(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(cli, "run_opengrep", lambda *a: pytest.fail("scanned before checking AI config"))
    code = cli.main(["scan", str(tmp_path), "--repo", "r", "--build", "1", "--out", str(tmp_path / "o.json"),
                     "--ai-triage", "--ai-provider", "anthropic", "--model", "claude-haiku-5-5"])
    assert code == 2 and "ANTHROPIC_API_KEY" in capsys.readouterr().err
