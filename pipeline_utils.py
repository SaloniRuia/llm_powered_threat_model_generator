"""
pipeline_utils.py — Shared utilities for the STRIDE threat-modelling pipeline.

All notebooks import from this module. Nothing is copy-pasted between notebooks.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

# ── Logging ───────────────────────────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """Return a consistently-formatted logger for a pipeline step."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s — %(message)s",
                              datefmt="%H:%M:%S")
        )
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


# ── GitHub API helper ─────────────────────────────────────────────────────────

def github_get(url: str, headers: dict, max_retries: int = 5, logger: logging.Logger | None = None):
    """
    HTTP GET with exponential back-off and GitHub rate-limit detection.

    Returns a Response on success, None on 404, raises RuntimeError after
    exhausting retries.
    """
    import requests

    log = logger or get_logger("github")

    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as exc:
            wait = 2 ** attempt
            log.warning("Network error (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, exc, wait)
            time.sleep(wait)
            continue

        remaining = int(resp.headers.get("X-RateLimit-Remaining", "60"))
        if remaining < 5:
            reset_at  = int(resp.headers.get("X-RateLimit-Reset", str(int(time.time()) + 65)))
            wait_secs = max(reset_at - time.time() + 1, 1)
            log.warning("Rate limit low (%d remaining) — sleeping %.0fs", remaining, wait_secs)
            time.sleep(wait_secs)

        if resp.status_code == 200:
            return resp
        if resp.status_code == 404:
            log.info("404 Not Found: %s", url)
            return None
        if resp.status_code in (403, 429):
            wait = 2 ** attempt
            log.warning("HTTP %d (attempt %d/%d) — retrying in %ds",
                        resp.status_code, attempt + 1, max_retries, wait)
            time.sleep(wait)
            continue
        resp.raise_for_status()

    raise RuntimeError(f"GitHub request failed after {max_retries} attempts: {url}")


# ── Threat Location Validator ─────────────────────────────────────────────────

def extract_threat_location(threat: dict, valid_paths: set[str]) -> str | None:
    """
    Scan a threat's evidence field for a known repo file path or basename.

    Uses exact path matching first (full relative path), then falls back to
    basename matching to handle evidence that omits directory prefixes.
    Returns the matched path string, or None if no valid citation is found.

    Args:
        threat:      A threat dict with an 'evidence' key.
        valid_paths: Set of full relative paths from the repo tree
                     (e.g. "fastapi/routing.py", not just "routing.py").
    """
    evidence = (threat.get("evidence") or "").strip()
    if not evidence or evidence.lower() in {"n/a", "null", "none", ""}:
        return None

    # 1. Exact full-path match (most specific — avoids basename collisions)
    for path in valid_paths:
        if path in evidence:
            return path

    # 2. Basename fallback: only accept if the basename is ≥4 chars to avoid
    #    false positives from short tokens like "db", "api", "io".
    basenames: dict[str, str] = {
        Path(p).name: p for p in valid_paths if len(Path(p).name) >= 4
    }
    for basename, full_path in basenames.items():
        if basename in evidence:
            return full_path

    return None


def filter_grounded_threats(
    threats: list[dict],
    valid_paths: set[str],
    label: str = "",
    logger: logging.Logger | None = None,
) -> list[dict]:
    """
    Retain only threats that cite a real repo file in their evidence field.

    Mutates each kept threat to add 'threat_location' (the matched path).
    Discards threats with no valid citation and logs the discard rate.

    Args:
        threats:     List of threat dicts.
        valid_paths: Set of full relative paths from repo_surface.json.
        label:       Short label for log messages (e.g. component name).
        logger:      Logger instance; uses module logger if None.

    Returns:
        Filtered list of grounded threats (threat_location added in place).
    """
    log  = logger or get_logger("validator")
    pfx  = f"[{label}] " if label else ""
    kept, discarded = [], []

    for threat in threats:
        loc = extract_threat_location(threat, valid_paths)
        if loc:
            threat["threat_location"] = loc
            kept.append(threat)
        else:
            threat["threat_location"] = None
            discarded.append(threat)

    log.info("%sGrounded: %d  Discarded: %d", pfx, len(kept), len(discarded))
    if discarded:
        titles = [t.get("title", "?")[:40] for t in discarded[:3]]
        log.debug("%sDiscarded titles: %s", pfx, titles)

    return kept


# ── IAE Scoring Model ─────────────────────────────────────────────────────────

"""
IAE Scoring — Impact + Exploitability + Exposure

The LLM explicitly outputs structured factor fields as part of each threat
(see STRIDE_SYSTEM prompt in NB03). The scorer reads those structured fields
directly — it does NOT keyword-match LLM prose, which would let phrasing
control the score.

Each dimension is scored 1–3 per factor, summed 3–9 per dimension.

  Total_Raw   = Impact + Exploitability + Exposure   (range  9–27)
  Final_Score = (Total_Raw − 9) / 18 × 10            (range  0.0–10.0)

Severity thresholds (Total_Raw):
  CRITICAL ≥ 23  (Final ≥ 7.8)
  HIGH     ≥ 18  (Final ≥ 5.0)
  MEDIUM   ≥ 13  (Final ≥ 2.2)
  LOW       < 13
"""

_VALID_RANGE = {1, 2, 3}

def _validated_factor(value: Any, field_name: str, default: int = 2) -> int:
    """
    Coerce and range-check a structured factor value from the LLM output.

    The LLM is instructed to return integers 1–3. If it returns something
    else (null, string, out-of-range int), we clamp or default and log a
    warning rather than crashing.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        logging.getLogger("scorer").warning(
            "Factor '%s' has non-integer value %r — defaulting to %d",
            field_name, value, default
        )
        return default
    if v not in _VALID_RANGE:
        clamped = max(1, min(3, v))
        logging.getLogger("scorer").warning(
            "Factor '%s' value %d out of range [1,3] — clamping to %d",
            field_name, v, clamped
        )
        return clamped
    return v


def compute_iae_score(threat: dict) -> dict:
    """
    Compute the full IAE score from structured factor fields in the threat dict.

    Expects these keys (all integers 1–3, set by the LLM in NB03):
      Impact:          data_sensitivity, privilege_level, system_criticality
      Exploitability:  access_vector, exploit_input_control, attack_complexity
      Exposure:        endpoint_visibility, auth_barrier, data_flow_reach

    Returns a dict with: final_score, severity, impact_score, exploit_score,
    exposure_score, total_raw, factor_breakdown.
    """
    factors = threat.get("iae_factors", {})

    # ── Impact ────────────────────────────────────────────────────────────────
    ds  = _validated_factor(factors.get("data_sensitivity"),      "data_sensitivity")
    pl  = _validated_factor(factors.get("privilege_level"),       "privilege_level")
    sc  = _validated_factor(factors.get("system_criticality"),    "system_criticality")
    impact = ds + pl + sc  # 3–9

    # ── Exploitability ────────────────────────────────────────────────────────
    av  = _validated_factor(factors.get("access_vector"),         "access_vector")
    ic  = _validated_factor(factors.get("exploit_input_control"), "exploit_input_control")
    ac  = _validated_factor(factors.get("attack_complexity"),     "attack_complexity")
    exploit = av + ic + ac  # 3–9

    # ── Exposure ──────────────────────────────────────────────────────────────
    ev  = _validated_factor(factors.get("endpoint_visibility"),   "endpoint_visibility")
    ab  = _validated_factor(factors.get("auth_barrier"),          "auth_barrier")
    dr  = _validated_factor(factors.get("data_flow_reach"),       "data_flow_reach")
    exposure = ev + ab + dr  # 3–9

    total_raw   = impact + exploit + exposure  # 9–27
    final_score = round((total_raw - 9) / 18 * 10, 1)

    severity = (
        "CRITICAL" if total_raw >= 23 else
        "HIGH"     if total_raw >= 18 else
        "MEDIUM"   if total_raw >= 13 else
        "LOW"
    )

    return {
        "final_score":    final_score,
        "severity":       severity,
        "impact_score":   impact,
        "exploit_score":  exploit,
        "exposure_score": exposure,
        "total_raw":      total_raw,
        "factor_breakdown": {
            "data_sensitivity":    ds,
            "privilege_level":     pl,
            "system_criticality":  sc,
            "access_vector":       av,
            "exploit_input_control": ic,
            "attack_complexity":   ac,
            "endpoint_visibility": ev,
            "auth_barrier":        ab,
            "data_flow_reach":     dr,
        },
    }


# ── LLM call helpers ──────────────────────────────────────────────────────────

def parse_json_response(raw: str, context: str = "") -> dict | list:
    """
    Robustly parse a JSON string that may be wrapped in markdown fences.

    Raises json.JSONDecodeError with a helpful message on failure.
    """
    text = raw.strip()
    # Strip ```json ... ``` or ``` ... ``` fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Drop first line (``` or ```json) and last line (```)
        inner = "\n".join(lines[1:] if lines[-1].strip() == "```" else lines[1:])
        # If the stripping left a trailing ```, remove it
        inner = re.sub(r"\s*```\s*$", "", inner).strip()
        text = inner
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        prefix = f"[{context}] " if context else ""
        raise json.JSONDecodeError(
            f"{prefix}Could not parse JSON: {exc.msg}",
            exc.doc, exc.pos
        ) from exc


def call_with_retry(
    fn,
    *args,
    max_retries: int = 3,
    retry_prompt_suffix: str | None = None,
    logger: logging.Logger | None = None,
    **kwargs,
) -> Any:
    """
    Call fn(*args, **kwargs) with exponential back-off on any exception.

    If retry_prompt_suffix is provided and the failure is a JSONDecodeError,
    the suffix is appended to the 'content' of the last user message to
    request well-formed JSON on the next attempt.

    Returns the result of fn on success, raises RuntimeError after max_retries.
    """
    log = logger or get_logger("retry")
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except json.JSONDecodeError as exc:
            wait = 2 ** attempt
            log.warning("JSON parse error (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, exc, wait)
            # If messages are in kwargs, append a corrective turn
            if retry_prompt_suffix and "messages" in kwargs:
                kwargs["messages"] = list(kwargs["messages"]) + [
                    {"role": "assistant", "content": "I apologize, my previous response was not valid JSON."},
                    {"role": "user",      "content": retry_prompt_suffix},
                ]
            time.sleep(wait)
        except Exception as exc:
            wait = 2 ** attempt
            log.warning("API error (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, exc, wait)
            time.sleep(wait)
    raise RuntimeError(f"Call failed after {max_retries} attempts")


# ── Pipeline state I/O ────────────────────────────────────────────────────────

def load_json(path: str | Path, schema_keys: list[str] | None = None) -> dict:
    """
    Load a JSON file and optionally validate that required top-level keys exist.

    Raises FileNotFoundError or KeyError with a clear message on failure.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Pipeline artifact not found: {p}. "
            f"Run the preceding notebook first."
        )
    with p.open() as f:
        data = json.load(f)
    if schema_keys:
        missing = [k for k in schema_keys if k not in data]
        if missing:
            raise KeyError(
                f"Artifact {p.name} is missing required keys: {missing}. "
                f"It may be from a stale pipeline run."
            )
    return data


def save_json(data: dict | list, path: str | Path, run_id: str | None = None) -> Path:
    """
    Save data as pretty-printed JSON.

    If run_id is provided, also writes a timestamped copy to an 'outputs/'
    subdirectory for audit trail purposes.

    Returns the primary output path.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        json.dump(data, f, indent=2)
    size_kb = p.stat().st_size / 1024
    log = get_logger("io")
    log.info("Saved %s (%.1f KB)", p.name, size_kb)

    if run_id:
        archive = p.parent / "outputs" / run_id / p.name
        archive.parent.mkdir(parents=True, exist_ok=True)
        with archive.open("w") as f:
            json.dump(data, f, indent=2)
        log.debug("Archived to %s", archive)

    return p


def sanitise_markdown(text: str) -> str:
    """
    Escape Markdown-special characters in free-text strings before embedding
    them in a Markdown table or heading.
    """
    return text.replace("|", "\\|").replace("`", "'").replace("#", "\\#")
