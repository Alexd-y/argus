"""Prompt/Response Redaction — hashing and API key masking.

Default: prompts hashed, responses summary_only.
Never logs raw API keys, bearer tokens, or credentials.
"""

import hashlib
import re
from typing import Any


def hash_prompt(prompt: str) -> str:
    return hashlib.blake2b(prompt.encode("utf-8"), digest_size=16).hexdigest()


def redact_api_keys(text: str) -> str:
    patterns = [
        (r'sk-[a-zA-Z0-9]{20,}', '<REDACTED:openai_key>'),
        (r'sk-or-[a-zA-Z0-9]{20,}', '<REDACTED:openrouter_key>'),
        (r'pplx-[a-zA-Z0-9]{20,}', '<REDACTED:perplexity_key>'),
        (r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}', '<REDACTED:bearer_token>'),
        (r'AKIA[0-9A-Z]{16}', '<REDACTED:aws_key>'),
        (r'ghp_[a-zA-Z0-9]{36}', '<REDACTED:github_token>'),
        (r'gho_[a-zA-Z0-9]{36}', '<REDACTED:github_oauth>'),
        (r'(?i)api[_-]?key[=:]\s*[a-zA-Z0-9\-_]{8,}', '<REDACTED:api_key_param>'),
        (r'(?i)password[=:]\s*\S+', '<REDACTED:password_param>'),
        (r'(?i)secret[=:]\s*\S+', '<REDACTED:secret_param>'),
        (r'(?i)token[=:]\s*\S+', '<REDACTED:token_param>'),
        (r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----(?s).*?-----END\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----', '<REDACTED:private_key>'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def redact_response(content: str) -> str:
    return redact_api_keys(content)


def summary_response(content: str, max_length: int = 500) -> str:
    clean = redact_api_keys(content)
    if len(clean) <= max_length:
        return clean
    return clean[:max_length] + "..."


def log_prompt(prompt: str, mode: str = "hashed") -> str:
    if mode == "full":
        return redact_api_keys(prompt)
    if mode == "hashed":
        return hash_prompt(prompt)
    return "<prompt_logging_off>"


def log_response(response: str, mode: str = "summary_only") -> str:
    if mode == "full":
        return redact_api_keys(response)
    if mode == "summary_only":
        return summary_response(response)
    return "<response_logging_off>"
