import os
import time
import subprocess
from typing import Optional


def call_llm(
    *,
    prompt: str,
    model: str,
    temperature: float,
    max_tokens: int,
) -> str:
    """
    Call an LLM and return RAW TEXT output.

    IMPORTANT BEHAVIOR:
    - NEVER hard-fails the pipeline
    - If LLM succeeds → logs clearly
    - If LLM fails → logs warning and re-raises (caller may catch)

    Env:
      - OBLIVION_LLM_BACKEND=openai|local
      - OBLIVION_OPENAI_MODEL=...
      - OBLIVION_LLM_DEBUG=1
    """

    backend = os.environ.get("OBLIVION_LLM_BACKEND", "openai").strip().lower()
    debug = os.environ.get("OBLIVION_LLM_DEBUG", "0").lower() in ("1", "true", "yes")

    # Allow env override for model
    model = (os.environ.get("OBLIVION_OPENAI_MODEL") or model or "").strip()

    print(f"[LLM] backend={backend} model={model} temperature={temperature} max_tokens={max_tokens}")

    try:
        if backend == "openai":
            out = _call_openai(
                prompt=prompt,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                debug=debug,
            )
        elif backend == "local":
            out = _call_local_model(prompt, debug=debug)
        else:
            raise RuntimeError(f"Unknown LLM backend: {backend}")

        # 🔥 SUCCESS LOG (this is what you wanted)
        print(f"[LLM] ✅ LLM RESPONSE RECEIVED (chars={len(out)})")
        return out

    except Exception as e:
        # ⚠️ Soft failure only
        print(f"[LLM] ⚠️ LLM call failed (backend={backend}): {e}")
        print("[LLM] Continuing pipeline without guaranteed LLM output")
        raise


# ------------------------
# OpenAI-compatible backend
# ------------------------

def _call_openai(
    *,
    prompt: str,
    model: str,
    temperature: float,
    max_tokens: int,
    debug: bool = False,
) -> str:
    """
    OpenAI-compatible API call.

    Requires:
      export OPENAI_API_KEY="sk-..."
    """

    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. "
            "Use: export OPENAI_API_KEY=\"sk-...\""
        )

    try:
        from openai import OpenAI
    except ImportError as e:
        raise RuntimeError("openai package not installed. pip install openai") from e

    base_url = (os.environ.get("OPENAI_BASE_URL") or "").strip() or None
    client = OpenAI(api_key=api_key, base_url=base_url)

    last_err: Optional[Exception] = None

    for attempt in range(1, 4):
        try:
            if debug:
                print(f"[LLM] OpenAI attempt {attempt}/3")

            response = client.chat.completions.create(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security-aware Solidity obfuscation planner.\n"
                            "Return ONLY valid JSON that matches the required schema.\n"
                            "Do NOT include markdown, comments, or explanations."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )

            content = response.choices[0].message.content
            if not content or not content.strip():
                raise RuntimeError("OpenAI returned empty response")

            if debug:
                print("[LLM] OpenAI request sent successfully")

            return content.strip()

        except Exception as e:
            last_err = e
            time.sleep(0.6 * attempt)

    raise RuntimeError(f"OpenAI call failed after retries: {last_err}")


# ------------------------
# Local / CLI backend
# ------------------------

def _call_local_model(prompt: str, *, debug: bool = False) -> str:
    """
    Local backend via CLI.

    Env:
      export OBLIVION_LLM_BACKEND=local
      export OBLIVION_LOCAL_LLM_CMD="ollama run llama3"
    """

    cmd = (os.environ.get("OBLIVION_LOCAL_LLM_CMD") or "").strip()
    if not cmd:
        raise RuntimeError("OBLIVION_LOCAL_LLM_CMD not set")

    if debug:
        print(f"[LLM] local cmd={cmd}")

    proc = subprocess.run(
        cmd,
        input=prompt.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"Local LLM failed: {err}")

    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if not out:
        raise RuntimeError("Local LLM returned empty output")

    return out
