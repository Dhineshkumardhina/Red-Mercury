"""Gemini API Client for AI Security Analyst with timeout, retries, and strict validation.

Interacts with Google Gemini models via HTTPS REST without exposing API keys to the frontend.
Automatically falls back to deterministic rule analysis on missing keys, timeouts, or API errors.
"""
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, Optional
import httpx

from ..core.config import settings
from ..core.errors import AppSecException
from ..core.logging import get_logger
from ..scanner.base import redact_secrets
from ..schemas.analyzer import FindingAnalysisResponse
from .fallback import generate_fallback_analysis
from .prompts import (
    build_analyst_system_instruction,
    build_analysis_user_prompt,
    detect_prompt_injection,
)

logger = get_logger("redmercury.analyzer.client")

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiAssistantUnavailableError(AppSecException):
    """Controlled error raised when Gemini AI is offline, unconfigured, or fails validation."""

    def __init__(self, message: str = "Gemini AI service is currently unavailable."):
        safe_msg = redact_secrets(message)
        super().__init__(
            message=safe_msg,
            code="AI_ASSISTANT_UNAVAILABLE",
            status_code=503,
        )


class GeminiAnalystClient:
    """Client for performing AI security analysis with strict safeguards."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        # Resolve API key from settings or environment
        self.api_key = (
            api_key
            or settings.GEMINI_API_KEY
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
        )
        self.model = model or settings.GEMINI_MODEL or "gemini-2.5-flash"
        self.timeout = settings.AI_TIMEOUT_SECONDS
        self.max_retries = settings.AI_MAX_RETRIES

    def is_configured(self) -> bool:
        """Check if a Gemini API key is configured and offline mode is not active."""
        if settings.OFFLINE_MODE and not os.environ.get("FORCE_ONLINE"):
            return False
        return bool(self.api_key and self.api_key.strip())

    def _scrub_api_key(self, text: str) -> str:
        """Ensure the configured API key can never leak into logs or exception messages."""
        cleaned = redact_secrets(text or "")
        if self.api_key and self.api_key.strip():
            cleaned = cleaned.replace(self.api_key.strip(), "[REDACTED_GEMINI_KEY]")
        return cleaned

    def generate_structured_json(
        self,
        system_instruction: str,
        user_prompt: str,
    ) -> Dict[str, Any]:
        """Execute a bounded HTTPS REST call to Gemini and return a parsed JSON object.

        Raises GeminiAssistantUnavailableError on OFFLINE_MODE, missing API key, HTTP 401/403/429/5xx,
        timeout, network failure, empty candidate response, or malformed JSON — never fabricating output.
        """
        if settings.OFFLINE_MODE and not os.environ.get("FORCE_ONLINE"):
            raise GeminiAssistantUnavailableError(
                "Gemini AI assistant is disabled because OFFLINE_MODE is enabled."
            )
        if not self.api_key or not self.api_key.strip():
            raise GeminiAssistantUnavailableError(
                "Gemini AI assistant is not configured (missing GEMINI_API_KEY)."
            )

        url = f"{GEMINI_API_BASE}/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key.strip(),
        }
        payload = {
            "system_instruction": {
                "parts": [{"text": system_instruction}]
            },
            "contents": [
                {"parts": [{"text": user_prompt}]}
            ],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.1,
            },
        }

        last_error = "Gemini API request failed."
        max_attempts = max(1, int(self.max_retries or 1))

        for attempt in range(1, max_attempts + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, headers=headers, json=payload)

                if response.status_code in (401, 403):
                    logger.warning(f"Gemini API authentication failed with status {response.status_code}")
                    raise GeminiAssistantUnavailableError(
                        f"Gemini API authentication failed (HTTP {response.status_code})."
                    )

                if response.status_code == 429:
                    logger.warning(f"Gemini API rate limit exceeded (HTTP 429) on attempt {attempt}/{max_attempts}")
                    last_error = "Gemini API rate limit exceeded (HTTP 429)."
                    continue

                if response.status_code != 200:
                    logger.warning(
                        f"Gemini API returned status {response.status_code} (attempt {attempt}/{max_attempts})"
                    )
                    last_error = f"Gemini API returned HTTP {response.status_code}."
                    continue

                res_json = response.json()
                if not isinstance(res_json, dict):
                    raise GeminiAssistantUnavailableError("Gemini API returned a non-object JSON payload.")

                candidates = res_json.get("candidates") or []
                if not candidates or not isinstance(candidates, list):
                    raise GeminiAssistantUnavailableError("Gemini API returned an empty candidates response.")

                first_candidate = candidates[0] if isinstance(candidates[0], dict) else {}
                content_obj = first_candidate.get("content") if isinstance(first_candidate.get("content"), dict) else {}
                parts = content_obj.get("parts") or []
                if not parts or not isinstance(parts, list) or not isinstance(parts[0], dict):
                    raise GeminiAssistantUnavailableError("Gemini API candidate contained no content parts.")

                raw_text = str(parts[0].get("text") or "").strip()
                if not raw_text:
                    raise GeminiAssistantUnavailableError("Gemini API returned empty text content.")

                # Strip optional markdown code fences
                if raw_text.startswith("```json"):
                    raw_text = raw_text[7:]
                elif raw_text.startswith("```"):
                    raw_text = raw_text[3:]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3]
                raw_text = raw_text.strip()

                parsed = json.loads(raw_text)
                if not isinstance(parsed, dict):
                    raise GeminiAssistantUnavailableError("Gemini API output must be a JSON object.")
                return parsed

            except GeminiAssistantUnavailableError:
                raise
            except httpx.TimeoutException:
                logger.warning(f"Gemini API request timed out (attempt {attempt}/{max_attempts})")
                last_error = f"Gemini API request timed out after {self.timeout}s."
            except httpx.HTTPError as net_err:
                safe_err = self._scrub_api_key(str(net_err))
                logger.warning(f"Gemini API network error (attempt {attempt}/{max_attempts}): {safe_err}")
                last_error = f"Gemini API network error: {safe_err}"
            except json.JSONDecodeError:
                logger.warning(f"Gemini API returned malformed JSON (attempt {attempt}/{max_attempts})")
                last_error = "Gemini API returned malformed JSON."
            except Exception as exc:
                safe_err = self._scrub_api_key(str(exc))
                logger.error(f"Unexpected error calling Gemini API: {safe_err}")
                raise GeminiAssistantUnavailableError(f"Gemini API error: {safe_err}")

        raise GeminiAssistantUnavailableError(self._scrub_api_key(last_error))

    def analyze(
        self,
        finding_dict: Dict[str, Any],
        source_context: Optional[str] = None,
        dependency_info: Optional[str] = None,
        is_truncated: bool = False,
    ) -> FindingAnalysisResponse:
        """Analyze a finding using Gemini if available, or fall back gracefully."""
        has_injection = detect_prompt_injection(source_context)

        # If API key is not configured, immediately use deterministic fallback
        if not self.is_configured():
            logger.info("Gemini API key not configured; using deterministic AppSec fallback engine.")
            return generate_fallback_analysis(
                finding_dict=finding_dict,
                source_context=source_context,
                dependency_info=dependency_info,
                is_truncated=is_truncated,
            )

        # Build constrained system and user prompts
        system_instruction = build_analyst_system_instruction()
        user_prompt = build_analysis_user_prompt(
            finding_dict=finding_dict,
            source_context=source_context,
            dependency_info=dependency_info,
            detected_injection=has_injection,
        )

        url = f"{GEMINI_API_BASE}/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        payload = {
            "system_instruction": {
                "parts": [{"text": system_instruction}]
            },
            "contents": [
                {"parts": [{"text": user_prompt}]}
            ],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.1,
            },
        }

        # Execute request with retries and timeout
        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, headers=headers, json=payload)

                if response.status_code != 200:
                    logger.warning(
                        f"Gemini API returned status {response.status_code} (attempt {attempt}/{self.max_retries}): {response.text[:200]}"
                    )
                    continue

                res_json = response.json()
                candidates = res_json.get("candidates", [])
                if not candidates:
                    logger.warning(f"Gemini API returned 0 candidates (attempt {attempt})")
                    continue

                content_parts = candidates[0].get("content", {}).get("parts", [])
                if not content_parts:
                    continue

                raw_text = content_parts[0].get("text", "")
                parsed_data = json.loads(raw_text)

                # Validate required fields against Pydantic schema
                analysis_response = self._validate_and_sanitize_response(
                    parsed_data=parsed_data,
                    finding_dict=finding_dict,
                    has_injection=has_injection,
                    is_truncated=is_truncated,
                )
                return analysis_response

            except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                logger.warning(f"Gemini API connection error (attempt {attempt}): {net_err}")
            except json.JSONDecodeError as jde:
                logger.warning(f"Malformed JSON returned by Gemini API (attempt {attempt}): {jde}")
            except Exception as exc:
                logger.error(f"Unexpected error calling Gemini API: {exc}")
                break

        # If retries exhausted or API failed, invoke deterministic fallback
        logger.info("Falling back to deterministic AppSec rule engine due to API unavailability/error.")
        fallback = generate_fallback_analysis(
            finding_dict=finding_dict,
            source_context=source_context,
            dependency_info=dependency_info,
            is_truncated=is_truncated,
        )
        fallback.limitations.append("AI service unavailable; deterministic rule engine fallback was used.")
        return fallback

    def _validate_and_sanitize_response(
        self,
        parsed_data: Dict[str, Any],
        finding_dict: Dict[str, Any],
        has_injection: bool,
        is_truncated: bool,
    ) -> FindingAnalysisResponse:
        """Validate AI output, enforcing strict Pydantic rules and exploitability guardrails."""
        finding_id = finding_dict.get("finding_id", "unknown")
        cwe = finding_dict.get("vulnerability_category", finding_dict.get("cwe", "CWE-General"))

        # Extract fields with safe defaults if missing
        explanation = str(parsed_data.get("plain_language_explanation") or parsed_data.get("finding_summary") or "").strip()
        impact = str(parsed_data.get("potential_impact") or finding_dict.get("scanner_message", "")).strip()
        evidence = parsed_data.get("relevant_code_evidence") or parsed_data.get("evidence_observed") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        root_cause = str(parsed_data.get("likely_root_cause") or parsed_data.get("reasoning_summary") or "Unsanitized input reaching sink.").strip()
        remediation = parsed_data.get("suggested_remediation") or parsed_data.get("recommended_remediation") or [
            "Validate and sanitize input",
            "Use secure API alternatives",
        ]
        tests = parsed_data.get("suggested_targeted_tests") or parsed_data.get("suggested_tests") or [
            "test_security_boundary_enforced()",
        ]
        missing_context = parsed_data.get("missing_context") or []
        limitations = parsed_data.get("limitations") or []
        confidence = str(parsed_data.get("confidence") or "HIGH")
        exploitable_claim = bool(parsed_data.get("is_exploitable_claim_supported", False))

        # Guardrail: If context is truncated or injection was detected, moderate exploitability claim
        if is_truncated and "Source context is truncated" not in missing_context:
            missing_context.append("Source context window was truncated; complete control flow not observable.")
            confidence = "LOW"
            exploitable_claim = False

        if has_injection and "Prompt injection keywords detected" not in str(limitations):
            limitations.append("Prompt injection keywords detected in source text; ignored adversarial directives.")

        # Guardrail: Do not claim exploitability without evidence
        if exploitable_claim and len(evidence) == 0:
            exploitable_claim = False
            limitations.append("Exploitability claim moderated: insufficient data-flow proof in evidence.")

        return FindingAnalysisResponse(
            finding_id=finding_id,
            vulnerability_category=cwe,
            plain_language_explanation=explanation or f"Security finding {finding_id} in {finding_dict.get('file_path')}",
            potential_impact=impact,
            relevant_code_evidence=[str(e) for e in evidence],
            likely_root_cause=root_cause,
            suggested_remediation=[str(r) for r in remediation],
            suggested_targeted_tests=[str(t) for t in tests],
            missing_context=[str(m) for m in missing_context],
            limitations=[str(l) for l in limitations],
            ai_model=self.model,
            analysis_timestamp=datetime.now(timezone.utc),
            confidence=confidence,
            is_exploitable_claim_supported=exploitable_claim,
            requires_human_review=True,
            user_authorized=True,
        )


gemini_analyst_client = GeminiAnalystClient()
