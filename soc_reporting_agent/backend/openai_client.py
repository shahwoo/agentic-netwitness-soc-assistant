from __future__ import annotations

import json
import os
import re
from typing import Any


LATEST_MODEL_PREFIXES = ("gpt-5", "o5")


def is_placeholder_key(key: str | None) -> bool:
    value = (key or "").strip()
    if not value:
        return True
    lowered = value.lower()
    return lowered.startswith("replace_") or "your_openai_api_key" in lowered or lowered in {"changeme", "sk-replace_me"}


def latest_model(model: str | None) -> bool:
    model = (model or "").strip().lower()
    return model.startswith(LATEST_MODEL_PREFIXES)


def supports_temperature(model: str | None) -> bool:
    # GPT-5.x reasoning/frontier models commonly reject temperature on the Responses API.
    return not latest_model(model)


def build_client(timeout: float | int | None = None):
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if is_placeholder_key(api_key):
        raise RuntimeError("OPENAI_API_KEY is missing or still set to a placeholder")
    try:
        from openai import OpenAI
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"openai package is not installed or too old: {exc}") from exc

    kwargs: dict[str, Any] = {"api_key": api_key, "max_retries": 1}
    base_url = os.getenv("OPENAI_BASE_URL", "").strip()
    if base_url:
        kwargs["base_url"] = base_url
    if timeout:
        kwargs["timeout"] = float(timeout)
    return OpenAI(**kwargs)


def _extract_responses_text(response: Any) -> str:
    text = getattr(response, "output_text", None)
    if text:
        return str(text).strip()
    chunks: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            part = getattr(content, "text", None)
            if part:
                chunks.append(str(part))
    return "\n".join(chunks).strip()


def invoke_openai_text(
    prompt: str,
    *,
    system: str | None = None,
    model: str | None = None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
    timeout: float | int | None = None,
    text_format: dict[str, Any] | None = None,
) -> str:
    """Call OpenAI using the Responses API first, with a safe legacy fallback.

    The rest of the app previously mixed Chat Completions, LangChain ChatOpenAI,
    and Responses API calls. Latest GPT-5.x models are documented for the
    Responses API, so this helper centralises the call path and avoids passing
    unsupported parameters such as temperature to GPT-5.x models.
    """
    selected = (model or os.getenv("OPENAI_MODEL") or "gpt-5.4-mini").strip()
    client = build_client(timeout=timeout or 120)

    input_payload: Any
    if system:
        input_payload = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
    else:
        input_payload = prompt

    if not hasattr(client, "responses"):
        if latest_model(selected):
            raise RuntimeError(
                "The installed openai package does not expose client.responses. "
                "Upgrade it with: python -m pip install --upgrade openai"
            )
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        chat_args: dict[str, Any] = {"model": selected, "messages": messages}
        if temperature is not None and supports_temperature(selected):
            chat_args["temperature"] = temperature
        if max_output_tokens:
            chat_args["max_tokens"] = max_output_tokens
        response = client.chat.completions.create(**chat_args)
        return str(response.choices[0].message.content or "").strip()

    request_args: dict[str, Any] = {"model": selected, "input": input_payload}
    if max_output_tokens:
        request_args["max_output_tokens"] = max_output_tokens
    if temperature is not None and supports_temperature(selected):
        request_args["temperature"] = temperature
    if text_format:
        request_args["text"] = {"format": text_format}

    try:
        response = client.responses.create(**request_args)
    except Exception as exc:
        message = str(exc).lower()
        if text_format and (
            "unsupported" in message
            or "unknown parameter" in message
            or "unrecognized" in message
            or "not supported" in message
            or "invalid type" in message
        ) and ("text" in message or "format" in message or "schema" in message or "json_schema" in message):
            request_args.pop("text", None)
            response = client.responses.create(**request_args)
        elif "unsupported" in message and "temperature" in message:
            request_args.pop("temperature", None)
            response = client.responses.create(**request_args)
        elif latest_model(selected):
            raise RuntimeError(
                f"OpenAI Responses API call failed for model {selected}: {exc}"
            ) from exc
        else:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            chat_args = {"model": selected, "messages": messages}
            if temperature is not None and supports_temperature(selected):
                chat_args["temperature"] = temperature
            if max_output_tokens:
                chat_args["max_tokens"] = max_output_tokens
            response = client.chat.completions.create(**chat_args)
            return str(response.choices[0].message.content or "").strip()

    text = _extract_responses_text(response)
    if not text:
        raise RuntimeError("OpenAI returned an empty text response")
    return text


def _strip_markdown_fences(text: str) -> str:
    cleaned = str(text or "").strip()
    match = re.fullmatch(r"```(?:json|JSON)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL)
    if match:
        return match.group(1).strip()
    cleaned = re.sub(r"^\s*```(?:json|JSON)?\s*", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.DOTALL)
    return cleaned.strip()


def _first_balanced_json_object(text: str) -> str | None:
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(text)):
            char = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:idx + 1]
        start = text.find("{", start + 1)
    return None


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = str(text or "").strip()
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass

    cleaned = _strip_markdown_fences(cleaned)
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass

    candidate = _first_balanced_json_object(cleaned)
    if candidate:
        try:
            obj = json.loads(candidate)
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}
    return {}
