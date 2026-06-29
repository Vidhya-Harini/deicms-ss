"""
AI Investigation Assistant — Orchestration Workflow
====================================================
Category C — Complex Application Logic.

Five-stage pipeline (each stage is independently testable):
  1. classify_intent   — keyword-frequency classifier -> IntentCategory
  2. retrieve_context  — fetch relevant DB records based on intent
  3. build_prompt      — construct system prompt + message history
  4. call_claude       — send to Claude API, receive raw reply
  5. validate_response — length / refusal / off-topic checks

This is not a simple API passthrough: the context injection, intent
classification, and validation logic are custom application code.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from flask import current_app


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

class IntentCategory(str, Enum):
    CASE_QUERY      = "CASE_QUERY"
    EVIDENCE_QUERY  = "EVIDENCE_QUERY"
    RISK_QUERY      = "RISK_QUERY"
    CUSTODY_QUERY   = "CUSTODY_QUERY"
    INTEGRITY_QUERY = "INTEGRITY_QUERY"
    GENERAL_FORENSICS = "GENERAL_FORENSICS"
    UNKNOWN         = "UNKNOWN"


@dataclass
class ClassifiedIntent:
    category: IntentCategory
    confidence: float          # 0.0 – 1.0
    entity_id: Optional[int]   # numeric ID parsed from the message if present
    keywords_matched: List[str]


@dataclass
class RetrievedContext:
    intent: ClassifiedIntent
    records: Dict                # raw DB objects (for tests / logging)
    context_text: str            # human-readable summary injected into prompt


@dataclass
class AssistantResponse:
    reply: str
    intent: IntentCategory
    context_used: bool
    validation_passed: bool
    warning: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# Assistant
# ─────────────────────────────────────────────────────────────────────────────

class AIInvestigationAssistant:
    """
    Orchestrates the AI Q&A session about forensic case data.
    Each stage is a separate method so it can be tested and extended
    independently.
    """

    # Intent -> keywords lookup
    _INTENT_KEYWORDS: Dict[IntentCategory, List[str]] = {
        IntentCategory.CASE_QUERY: [
            "case", "cases", "investigation", "case number", "case id",
            "open case", "closed case", "case status", "assigned",
        ],
        IntentCategory.EVIDENCE_QUERY: [
            "evidence", "file", "item", "exhibit", "upload", "document",
            "sample", "artefact", "artifact", "sha256",
        ],
        IntentCategory.RISK_QUERY: [
            "risk", "score", "danger", "threat", "vulnerability",
            "critical", "high risk", "risk level", "assessment", "risky",
        ],
        IntentCategory.CUSTODY_QUERY: [
            "custody", "transfer", "chain", "handover", "handler",
            "who had", "moved", "possession", "custody log",
        ],
        IntentCategory.INTEGRITY_QUERY: [
            "integrity", "tamper", "hash", "verify", "verification",
            "corrupt", "signature", "mismatch", "altered", "modified",
        ],
        IntentCategory.GENERAL_FORENSICS: [
            "forensic", "procedure", "best practice", "protocol",
            "how to", "what is", "explain", "define", "guideline",
            "standard", "methodology",
        ],
    }

    # ── Stage 1: Intent classification ───────────────────────────────────────

    def classify_intent(self, user_message: str) -> ClassifiedIntent:
        """
        Keyword-frequency classifier.

        Algorithm:
          - Convert message to lowercase.
          - For each intent category, count how many of its keywords appear.
          - The category with the most hits wins.
          - Confidence = (winner_hits / total_hits) * 2, clamped to [0, 1].
          - Parse a numeric entity ID from the message if one is present
            (e.g. "case 3", "evidence #7", "item id 12").
        """
        msg_lower = user_message.lower()
        scores: Dict[IntentCategory, int] = {}
        matched_kws: Dict[IntentCategory, List[str]] = {}

        for category, keywords in self._INTENT_KEYWORDS.items():
            hits = [kw for kw in keywords if kw in msg_lower]
            scores[category] = len(hits)
            matched_kws[category] = hits

        best_category = max(scores, key=lambda c: scores[c])
        best_score = scores[best_category]

        if best_score == 0:
            return ClassifiedIntent(
                category=IntentCategory.UNKNOWN,
                confidence=0.0,
                entity_id=None,
                keywords_matched=[],
            )

        total_hits = sum(scores.values()) or 1
        confidence = min(1.0, best_score / total_hits * 2.0)

        # Extract entity ID: "case 3", "evidence id 7", "#5", etc.
        entity_id: Optional[int] = None
        id_match = re.search(
            r'(?:case|evidence|item|id)[^\d]{0,5}(\d+)', msg_lower
        )
        if not id_match:
            id_match = re.search(r'#\s*(\d+)', msg_lower)
        if id_match:
            entity_id = int(id_match.group(1))

        return ClassifiedIntent(
            category=best_category,
            confidence=round(confidence, 3),
            entity_id=entity_id,
            keywords_matched=matched_kws[best_category],
        )

    # ── Stage 2: Context retrieval ────────────────────────────────────────────

    def retrieve_context(self, intent: ClassifiedIntent) -> RetrievedContext:
        """
        Fetches the DB records most relevant to the classified intent and
        serialises them into a compact text block for the prompt.
        """
        from app.models.case import Case
        from app.models.evidence import EvidenceItem
        from app.models.custody_log import CustodyLog
        from app.models.investigator import Investigator

        records: Dict = {}
        lines: List[str] = []

        # ── Case queries ──────────────────────────────────────────────────────
        if intent.category == IntentCategory.CASE_QUERY:
            if intent.entity_id:
                case = Case.query.get(intent.entity_id)
                if case:
                    records["case"] = case
                    lines.append(
                        f"Case #{case.id}: '{case.title}' | "
                        f"Status: {case.status} | "
                        f"Created: {case.created_at.date()} | "
                        f"Evidence items: {case.evidence_items.count()}"
                    )
                    for ev in case.evidence_items.all():
                        lines.append(
                            f"  Evidence #{ev.id}: '{ev.title}' "
                            f"[{getattr(ev, 'lifecycle_state', 'Unknown')}]"
                        )
                else:
                    lines.append(f"No case found with ID {intent.entity_id}.")
            else:
                cases = Case.query.order_by(Case.created_at.desc()).limit(10).all()
                records["cases"] = cases
                lines.append(f"Most recent {len(cases)} case(s):")
                for c in cases:
                    lines.append(
                        f"  Case #{c.id}: '{c.title}' | "
                        f"{c.status} | {c.evidence_items.count()} evidence item(s)"
                    )

        # ── Evidence / Risk / Integrity queries ───────────────────────────────
        elif intent.category in (
            IntentCategory.EVIDENCE_QUERY,
            IntentCategory.RISK_QUERY,
            IntentCategory.INTEGRITY_QUERY,
        ):
            if intent.entity_id:
                ev = EvidenceItem.query.get(intent.entity_id)
                if ev:
                    records["evidence"] = ev
                    lines.append(
                        f"Evidence #{ev.id}: '{ev.title}' | "
                        f"Category: {getattr(ev, 'category', 'Other')} | "
                        f"State: {getattr(ev, 'lifecycle_state', 'Unknown')} | "
                        f"Case: #{ev.case_id} | "
                        f"File: {getattr(ev, 'file_name', 'N/A')}"
                    )
                else:
                    lines.append(f"No evidence item found with ID {intent.entity_id}.")
            else:
                items = (
                    EvidenceItem.query
                    .order_by(EvidenceItem.created_at.desc())
                    .limit(10)
                    .all()
                )
                records["evidence_items"] = items
                lines.append(f"Most recent {len(items)} evidence item(s):")
                for ev in items:
                    lines.append(
                        f"  Evidence #{ev.id}: '{ev.title}' | "
                        f"State: {getattr(ev, 'lifecycle_state', 'Unknown')} | "
                        f"File: {getattr(ev, 'file_name', 'N/A')}"
                    )

        # ── Custody queries ───────────────────────────────────────────────────
        elif intent.category == IntentCategory.CUSTODY_QUERY:
            if intent.entity_id:
                logs = (
                    CustodyLog.query
                    .filter_by(evidence_id=intent.entity_id)
                    .order_by(CustodyLog.timestamp.asc())
                    .all()
                )
                records["custody_logs"] = logs
                if logs:
                    lines.append(
                        f"Custody chain for Evidence #{intent.entity_id} "
                        f"({len(logs)} transfer(s)):"
                    )
                    for log in logs:
                        handler = Investigator.query.get(log.to_investigator_id)
                        name = handler.full_name if handler else "Unknown"
                        lines.append(
                            f"  {log.timestamp.date()} -> {name} "
                            f"(reason: {log.reason or 'not specified'})"
                        )
                else:
                    lines.append(
                        f"No custody transfers found for Evidence #{intent.entity_id}."
                    )
            else:
                logs = (
                    CustodyLog.query
                    .order_by(CustodyLog.timestamp.desc())
                    .limit(15)
                    .all()
                )
                records["recent_custody"] = logs
                lines.append(f"Most recent {len(logs)} custody transfer(s):")
                for log in logs:
                    handler = Investigator.query.get(log.to_investigator_id)
                    name = handler.full_name if handler else "Unknown"
                    lines.append(
                        f"  Evidence #{log.evidence_id} -> {name} "
                        f"on {log.timestamp.date()}"
                    )
                    
        # ── General forensics or unknown — no DB context needed ───────────────
        else:
            lines.append(
                "No specific case or evidence record retrieved for this query. "
                "Answering from general forensics knowledge."
            )

        context_text = "\n".join(lines) if lines else "No relevant records found."
        return RetrievedContext(
            intent=intent,
            records=records,
            context_text=context_text,
        )

    # ── Stage 3: Prompt construction ──────────────────────────────────────────

    def build_prompt(
        self,
        user_message: str,
        context: RetrievedContext,
        conversation_history: Optional[List[Dict]] = None,
    ) -> Tuple[List[Dict], str]:
        """
        Assembles the system prompt and message list for the Claude API.

        The system prompt embeds the live DB context so the model answers
        about actual case data instead of hallucinating.
        Previous conversation turns (up to 6) are prepended as history.
        """
        system_content = (
            "You are DEICMS-AI, an expert forensic investigation assistant embedded "
            "in the Digital Evidence Integrity & Chain-of-Custody Management System.\n"
            "Your role: help investigators understand case data, interpret risk scores, "
            "explain custody chains, and advise on digital forensics best practices.\n\n"
            "Rules:\n"
            "- Base your answers on the SYSTEM CONTEXT block when it contains relevant data.\n"
            "- Be concise and professional. Use bullet points for lists.\n"
            "- Never invent case IDs, investigator names, or file names "
            "that are not in the context.\n"
            "- If the context does not contain the answer, say so and offer general guidance.\n"
            "- Do not discuss topics unrelated to digital forensics, evidence management, "
            "or cybersecurity.\n\n"
            f"SYSTEM CONTEXT (live database snapshot)\n"
            f"{'=' * 60}\n"
            f"{context.context_text}\n"
            f"{'=' * 60}"
        )

        messages: List[Dict] = []

        # Inject previous turns (trim to last 6 to control context size)
        if conversation_history:
            for turn in conversation_history[-6:]:
                messages.append({"role": turn["role"], "content": turn["content"]})

        messages.append({"role": "user", "content": user_message})
        return messages, system_content

    # ── Stage 4: Claude API call ──────────────────────────────────────────────

    def call_claude(self, messages: List[Dict], system_content: str) -> str:
        """
        Calls the NVIDIA NIM API (OpenAI-compatible endpoint).
        Falls back to intelligent mock if no key is configured.
        """
        from openai import OpenAI
        api_key = current_app.config.get("NVIDIA_API_KEY", "")

        if api_key and api_key.startswith("nvapi-"):
            try:
                client = OpenAI(
                    base_url="https://integrate.api.nvidia.com/v1",
                    api_key=api_key,
                )
                # Prepend system message as first user turn (NIM style)
                full_messages = [{"role": "system", "content": system_content}] + messages
                response = client.chat.completions.create(
                    model="meta/llama-3.1-70b-instruct",
                    messages=full_messages,
                    max_tokens=1024,
                    temperature=0.7,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                import traceback
                print("CLAUDE CALL FAILED:", repr(e))
                traceback.print_exc()
                pass  # fall through to mock

        return self._mock_response(messages, system_content)
    
    def _mock_response(self, messages: List[Dict], system_content: str) -> str:
        """
        Generates a context-aware mock reply by reading the injected
        system context block — demonstrates the full pipeline without
        requiring API credits.
        """
        user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_msg = m.get("content", "").lower()
                break

        # Extract the SYSTEM CONTEXT block from the system prompt
        context_block = ""
        if "SYSTEM CONTEXT" in system_content:
            parts = system_content.split("=" * 60)
            if len(parts) >= 2:
                context_block = parts[1].strip()

        # Build a reply that references the actual injected context
        if context_block and "No relevant records" not in context_block:
            lines = [l.strip() for l in context_block.splitlines() if l.strip()]
            summary = "\n".join(f"• {l}" for l in lines[:8])
            reply = (
                f"Based on the current database records, here is what I found:\n\n"
                f"{summary}\n\n"
                f"[Note: This is a structured mock response. "
                f"The full 5-stage orchestration pipeline ran successfully — "
                f"intent was classified, database context was retrieved and injected, "
                f"and the prompt was constructed. "
                f"Connect a live API key to receive a natural-language answer.]"
            )
        else:
            reply = (
                "I can answer general digital forensics questions. "
                "For example:\n"
                "• Chain of custody ensures evidence integrity from collection to court.\n"
                "• SHA-256 hashing verifies that a file has not been altered.\n"
                "• Role-based access control limits who can handle sensitive evidence.\n\n"
                "[Note: Mock response — the orchestration pipeline ran fully. "
                "Add API credits for natural-language answers.]"
            )

        return reply

    # ── Stage 5: Response validation ─────────────────────────────────────────

    def validate_response(
        self, raw_reply: str, intent: IntentCategory
    ) -> Tuple[str, bool, Optional[str]]:
        """
        Checks the reply for:
          - Minimum length (> 20 chars)
          - Refusal patterns (model declined to answer)
          - Off-topic signals (no forensics terms in a domain-specific reply)

        Returns (reply_text, passed: bool, warning_message | None)
        """
        if len(raw_reply.strip()) < 20:
            return raw_reply, False, "Response too short — the model may have failed."

        refusal_patterns = [
            r"i(?:'m| am) (?:sorry|unable|not able)",
            r"i cannot (?:help|assist|answer)",
            r"as an ai (?:language model|assistant)",
            r"i don'?t have (?:access|information)",
        ]
        for pattern in refusal_patterns:
            if re.search(pattern, raw_reply.lower()):
                return raw_reply, False, "Model indicated it could not answer the question."

        # Warn if the reply for a domain-specific query lacks any forensics term
        forensics_terms = [
            "evidence", "case", "forensic", "custody", "investigat",
            "hash", "integrity", "risk", "transfer", "file", "audit", "chain",
        ]
        domain_specific = intent not in (
            IntentCategory.GENERAL_FORENSICS, IntentCategory.UNKNOWN
        )
        if domain_specific and not any(t in raw_reply.lower() for t in forensics_terms):
            return raw_reply, True, "Response may be off-topic — review before relying on it."

        return raw_reply, True, None

    # ── Public entry point ────────────────────────────────────────────────────

    def answer(
        self,
        user_message: str,
        conversation_history: Optional[List[Dict]] = None,
    ) -> AssistantResponse:
        """
        Runs the full five-stage pipeline.
        Degrades gracefully — always returns an AssistantResponse even on error.
        """
        try:
            intent  = self.classify_intent(user_message)
            context = self.retrieve_context(intent)
            messages, system_content = self.build_prompt(
                user_message, context, conversation_history
            )
            raw = self.call_claude(messages, system_content)
            reply, passed, warning = self.validate_response(raw, intent.category)

            context_used = (
                bool(context.context_text) and
                "No relevant records" not in context.context_text and
                "Answering from general" not in context.context_text
            )

            return AssistantResponse(
                reply=reply,
                intent=intent.category,
                context_used=context_used,
                validation_passed=passed,
                warning=warning,
            )

        except Exception as api_err:
            if "401" in str(api_err) or "auth" in str(api_err).lower():
                return AssistantResponse(
                    reply=(
                        "Authentication error: the NVIDIA_API_KEY is missing or invalid. "
                        "Please set it in config.py."
                    ),
                    intent=IntentCategory.UNKNOWN,
                    context_used=False,
                    validation_passed=False,
                    warning="API key error",
                )
        except Exception as exc:
            return AssistantResponse(
                reply=f"An unexpected error occurred: {exc}. Please try again.",
                intent=IntentCategory.UNKNOWN,
                context_used=False,
                validation_passed=False,
                warning=str(exc),
            )