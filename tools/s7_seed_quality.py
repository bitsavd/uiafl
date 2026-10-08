#!/usr/bin/env python3
"""
S7COMM seed quality assessment using LangChain and LLMs.

This module provides a model-driven interface to score or classify S7COMM seed
candidates for AFLNet. The user may later supply an OpenAI API key to enable
real LLM evaluation.
"""

import json
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from langchain.chat_models import init_chat_model
    from langchain.messages import HumanMessage, SystemMessage
except ImportError:  # pragma: no cover
    init_chat_model = None
    HumanMessage = None
    SystemMessage = None

try:
    from anthropic import Anthropic, HUMAN_PROMPT, AI_PROMPT
except ImportError:  # pragma: no cover
    Anthropic = None
    HUMAN_PROMPT = None
    AI_PROMPT = None

try:
    import openai as openai_api
except ImportError:  # pragma: no cover
    openai_api = None

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


def describe_seed(seed_bytes: bytes) -> str:
    """Convert seed bytes into a compact human-readable description."""
    description = []
    description.append(f"length={len(seed_bytes)}")
    if len(seed_bytes) >= 4 and seed_bytes[0] == 0x03:
        description.append("tpkt")
    if b"\x32" in seed_bytes:
        description.append("s7-header")
    if b"\x02\xF0\x80" in seed_bytes:
        description.append("cotp-data")
    if any(len(seed_bytes) > i + 5 and seed_bytes[i] == 0x03 and (seed_bytes[i + 5] & 0xF0) == 0xE0 for i in range(len(seed_bytes))):
        description.append("cotp-connect-request")
    return ", ".join(description)


def build_quality_prompt(seed_bytes: bytes) -> str:
    """Build a prompt for the LLM to evaluate S7COMM seed quality."""
    text = seed_bytes.hex()
    desc = describe_seed(seed_bytes)
    prompt = (
        "You are evaluating a raw S7COMM seed for a fuzzing campaign. "
        "The seed is represented as a hex string. "
        "Assess whether it is likely a valid S7COMM client-to-server message, "
        "whether it contains protocol structure, and whether it is useful for "
        "stateful AFLNet fuzzing. Return a JSON object with keys:"
        " score (0-100), richness_score (0-100), valid_protocol (true/false), "
        "stateful_hint (string), coverage_hint (string), recommendation (string)."
        "\n\n"
        f"Seed description: {desc}\n"
        f"Seed hex: {text}\n"
        "Use domain knowledge of Siemens S7COMM, TPKT/COTP/S7 structure, "
        "and fuzz seed richness. Evaluate whether this seed covers diverse "
        "S7 paths or message types. Do not add extra keys."
    )
    return prompt


def extract_json_like_text(output: str) -> str:
    """Extract the first JSON object substring from the model output."""
    start = output.find("{")
    end = output.rfind("}")
    if start != -1 and end != -1 and end > start:
        return output[start : end + 1]
    return output


def parse_quality_output(output: str) -> Dict[str, object]:
    """Try to parse the model output into a JSON dictionary."""
    try:
        result = json.loads(output)
    except json.JSONDecodeError:
        try:
            result = json.loads(extract_json_like_text(output))
        except json.JSONDecodeError:
            result = {
                "score": 0,
                "richness_score": 0,
                "valid_protocol": False,
                "stateful_hint": "could not parse model output",
                "coverage_hint": "could not parse model output",
                "recommendation": output.strip(),
            }
            return result

    if "richness_score" not in result:
        result["richness_score"] = 0
    if "coverage_hint" not in result:
        result["coverage_hint"] = "no coverage hint provided"
    return result


def assess_seed_with_anthropic(
    seed_bytes: bytes,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model_name: Optional[str] = None,
) -> Dict[str, object]:
    """Assess one seed using Anthropic API directly."""
    if Anthropic is None:
        raise ImportError(
            "Anthropic SDK is not installed. Install it with `pip install anthropic`."
        )

    api_key = api_key or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    if not api_key:
        raise ValueError("Missing Anthropic auth token. Set ANTHROPIC_AUTH_TOKEN.")

    base_url = base_url or os.environ.get("ANTHROPIC_BASE_URL")
    model_name = model_name or os.environ.get("ANTHROPIC_MODEL", "claude-3.0")

    client_kwargs = {}
    if base_url:
        client_kwargs["base_url"] = base_url

    client = Anthropic(api_key=api_key, **client_kwargs)
    prompt = build_quality_prompt(seed_bytes)
    prompt_text = f"{HUMAN_PROMPT}{prompt}{AI_PROMPT}"

    response = client.completions.create(
        model=model_name,
        prompt=prompt_text,
        max_tokens_to_sample=300,
        temperature=0,
    )
    text = getattr(response, "completion", None) or response.text
    return parse_quality_output(text)


def assess_seed_with_llm(
    seed_bytes: bytes,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model_name: Optional[str] = None,
) -> Dict[str, object]:
    """Assess one seed using LangChain or direct OpenAI-compatible LLM endpoints."""
    if model_name is None:
        model_name = "gpt-4o-mini"
        if base_url and "deepseek.com" in base_url:
            model_name = "deepseek-v4-pro"

    prompt = build_quality_prompt(seed_bytes)

    if base_url and httpx is not None:
        endpoint = base_url.rstrip("/")
        if endpoint.endswith("/v1"):
            endpoint = endpoint[:-3]
        url = f"{endpoint}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": "You are a security engineer evaluating S7COMM fuzzing seeds."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "max_tokens": 300,
        }
        response = httpx.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        text = ""
        for choice in data.get("choices", []):
            msg = choice.get("message", {})
            if isinstance(msg, dict):
                text += msg.get("content", "") or ""
                if not text:
                    text += msg.get("reasoning_content", "") or ""
            if not text:
                text += choice.get("text", "") or ""
        return parse_quality_output(text)

    if openai_api is not None:
        if api_key:
            openai_api.api_key = api_key
        if base_url:
            openai_api.api_base = base_url

        response = openai_api.responses.create(
            model=model_name,
            input=[
                {"role": "system", "content": "You are a security engineer evaluating S7COMM fuzzing seeds."},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
            max_output_tokens=300,
        )
        text = getattr(response, "output_text", None)
        if text is None:
            text = ""
            for item in getattr(response, "output", []):
                if isinstance(item, dict):
                    text += item.get("content", "")
        return parse_quality_output(text)

    if init_chat_model is None:
        raise ImportError(
            "langchain is not installed. Install it with `pip install langchain openai`."
        )

    llm_kwargs = {
        "model": model_name,
        "openai_api_key": api_key,
    }
    if base_url:
        llm_kwargs["openai_api_base"] = base_url

    llm = init_chat_model(model_provider="openai", **llm_kwargs)
    messages = [
        [
            SystemMessage(content="You are a security engineer evaluating S7COMM fuzzing seeds."),
            HumanMessage(content=prompt),
        ]
    ]
    response = llm.generate(messages)
    text = ""
    if response.generations:
        first_gen = response.generations[0][0]
        text = getattr(first_gen, "text", None)
        if text is None:
            msg = getattr(first_gen, "message", None)
            if msg is not None:
                text = getattr(msg, "content", "")
    if text is None:
        text = ""
    return parse_quality_output(text)


def heuristic_seed_score(seed_bytes: bytes) -> Dict[str, object]:
    """A lightweight heuristic fallback when LLM support is unavailable."""
    score = 0
    richness = 0
    hints = []
    penalty = 0
    has_tpkt = seed_bytes[:2] == b"\x03\x00" and len(seed_bytes) >= 7
    has_cotp_data = b"\x02\xF0\x80" in seed_bytes
    has_cotp_cr = any(
        len(seed_bytes) > i + 5
        and seed_bytes[i] == 0x03
        and (seed_bytes[i + 5] & 0xF0) == 0xE0
        for i in range(len(seed_bytes))
    )
    has_s7 = b"\x32" in seed_bytes
    has_setup = b"\xF0\x00" in seed_bytes
    has_var_param = b"\x04\x01" in seed_bytes or b"\x05\x01" in seed_bytes

    if len(seed_bytes) >= 24:
        score += 25
        richness += 20
    if has_tpkt:
        score += 30
        richness += 20
        hints.append("contains TPKT header")
    if has_cotp_data:
        score += 20
        richness += 15
        hints.append("contains COTP data header")
    if has_cotp_cr:
        score += 20
        richness += 20
        hints.append("contains COTP connection request")
    if has_s7:
        score += 10
        richness += 15
        hints.append("contains S7 protocol ID")
    if has_setup:
        score += 10
        richness += 10
        hints.append("contains setup communication function")
    if has_var_param:
        score += 10
        richness += 10
        hints.append("contains S7 parameter type indicators")
    if len(set(seed_bytes)) > 8:
        richness += 10

    if has_cotp_cr and has_setup and has_var_param:
        score += 15
        richness += 10
        hints.append("looks like a complete setup plus variable request session")

    if len(seed_bytes) > 256 and not (has_setup and has_var_param):
        penalty += 35
        hints.append("large frame without setup/read structure")

    if len(seed_bytes) >= 128:
        byte_diversity = len(set(seed_bytes)) / 256.0
        if byte_diversity > 0.55 and not has_setup:
            penalty += 25
            hints.append("high-entropy payload, likely upload/download blob")

    if penalty:
        score = max(0, score - penalty)
        richness = max(0, richness - penalty)

    if richness > 100:
        richness = 100
    if score > 100:
        score = 100
    return {
        "score": score,
        "richness_score": richness,
        "valid_protocol": score >= 60,
        "stateful_hint": ", ".join(hints) if hints else "no obvious S7 structure detected",
        "coverage_hint": ("seed appears structurally diverse" if richness >= 50 else "seed appears protocol-light or shallow"),
        "recommendation": (
            "Keep this seed for further review." if score >= 60 else "Discard or refine this seed."
        ),
    }


def score_seed_file(
    seed_path: Path,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    base_url: Optional[str] = None,
    backend: Optional[str] = None,
) -> Dict[str, object]:
    """Score a single seed file and return enriched metadata."""
    data = seed_path.read_bytes()
    result = assess_seed(
        data,
        api_key=api_key,
        model_name=model_name,
        base_url=base_url,
        backend=backend,
    )
    result.update(
        {
            "file": str(seed_path),
            "name": seed_path.name,
            "size": len(data),
        }
    )
    return result


def score_seed_directory(
    directory: Path,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    base_url: Optional[str] = None,
    backend: Optional[str] = None,
) -> List[Dict[str, object]]:
    """Score all seed files in a directory and return sorted results."""
    files = sorted(
        [p for p in directory.iterdir() if p.is_file() and p.suffix == ".raw"]
    )
    if not files:
        files = sorted([p for p in directory.iterdir() if p.is_file()])

    results = []
    for seed_path in files:
        result = score_seed_file(
            seed_path,
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            backend=backend,
        )
        results.append(result)

    return sorted(
        results,
        key=lambda r: (
            r.get("score", 0),
            r.get("richness_score", 0),
            r.get("valid_protocol", False),
            -abs(int(r.get("size", 0)) - 120),
            r.get("name", ""),
        ),
        reverse=True,
    )


def select_top_seeds(
    scored_seeds: List[Dict[str, object]],
    top_n: int,
    output_dir: Optional[Path] = None,
) -> List[Dict[str, object]]:
    """Return the top N scored seeds and optionally copy them to output_dir."""
    selected = scored_seeds[:top_n]
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        for seed in selected:
            src = Path(seed["file"])
            dst = output_dir / src.name
            shutil.copy2(src, dst)
    return selected


def assess_seed(
    seed_bytes: bytes,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    base_url: Optional[str] = None,
    backend: Optional[str] = None,
) -> Dict[str, object]:
    """Assess a seed, preferring Anthropic or OpenAI if configured."""
    anthropic_token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if backend == "anthropic":
        try:
            return assess_seed_with_anthropic(
                seed_bytes,
                api_key=api_key or anthropic_token,
                base_url=base_url or os.environ.get("ANTHROPIC_BASE_URL"),
                model_name=model_name,
            )
        except Exception as exc:
            return {"error": str(exc), **heuristic_seed_score(seed_bytes)}

    if backend == "openai":
        try:
            return assess_seed_with_llm(
                seed_bytes,
                api_key=api_key or openai_key,
                base_url=base_url or os.environ.get("OPENAI_API_BASE"),
                model_name=model_name,
            )
        except Exception as exc:
            return {"error": str(exc), **heuristic_seed_score(seed_bytes)}

    if anthropic_token is not None or api_key is not None:
        try:
            return assess_seed_with_anthropic(
                seed_bytes,
                api_key=api_key or anthropic_token,
                base_url=base_url or os.environ.get("ANTHROPIC_BASE_URL"),
                model_name=model_name,
            )
        except Exception as exc:
            if openai_key is not None and init_chat_model is not None:
                try:
                    return assess_seed_with_llm(
                        seed_bytes,
                        api_key=openai_key,
                        base_url=os.environ.get("OPENAI_API_BASE"),
                        model_name=model_name,
                    )
                except Exception:
                    pass
            return {"error": str(exc), **heuristic_seed_score(seed_bytes)}

    if openai_key is not None and init_chat_model is not None:
        try:
            return assess_seed_with_llm(
                seed_bytes,
                api_key=openai_key,
                base_url=os.environ.get("OPENAI_API_BASE"),
                model_name=model_name,
            )
        except Exception as exc:
            return {"error": str(exc), **heuristic_seed_score(seed_bytes)}

    return heuristic_seed_score(seed_bytes)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Assess S7COMM seed quality.")
    parser.add_argument("seed_file", help="Path to a raw seed file")
    parser.add_argument("--api-key", help="API key for Anthropic or OpenAI evaluation", default=None)
    parser.add_argument("--base-url", help="OpenAI-compatible API base URL (for langchain/openai)", default=None)
    parser.add_argument("--model", help="LLM model name", default=None)
    parser.add_argument(
        "--backend",
        choices=["anthropic", "openai"],
        default=None,
        help="Choose the LLM backend. If omitted, environment variables decide.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=None,
        help="If seed_file is a directory, keep only the top N seeds.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional destination directory for selected top seeds.",
    )
    args = parser.parse_args()

    seed_path = Path(args.seed_file)
    if seed_path.is_dir():
        if args.backend == "openai" and init_chat_model is None and httpx is None and openai_api is None:
            raise ImportError("Install openai or langchain to use OpenAI-compatible evaluation.")
        if args.backend == "anthropic" and Anthropic is None:
            raise ImportError("anthropic SDK is not installed; install it to use Anthropic.")

        scored = score_seed_directory(
            seed_path,
            api_key=args.api_key,
            model_name=args.model,
            base_url=args.base_url,
            backend=args.backend,
        )
        if args.top is not None:
            output_path = Path(args.output_dir) if args.output_dir else None
            selected = select_top_seeds(scored, args.top, output_path)
            result = {
                "seed_directory": str(seed_path),
                "top": args.top,
                "selected_count": len(selected),
                "selected": selected,
            }
        else:
            result = {
                "seed_directory": str(seed_path),
                "count": len(scored),
                "scored": scored,
            }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        exit(0)

    with open(seed_path, "rb") as f:
        data = f.read()

    if args.backend == "openai" and args.api_key is None:
        args.api_key = os.environ.get("OPENAI_API_KEY")
    elif args.backend == "anthropic" and args.api_key is None:
        args.api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN")

    if args.backend == "openai" and init_chat_model is None and httpx is None and openai_api is None:
        raise ImportError("Install openai or langchain to use OpenAI-compatible evaluation.")
    if args.backend == "anthropic" and Anthropic is None:
        raise ImportError("anthropic SDK is not installed; install it to use Anthropic.")

    result = assess_seed(
        data,
        api_key=args.api_key,
        base_url=args.base_url,
        model_name=args.model,
        backend=args.backend,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
