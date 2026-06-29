"""
Custody Chain Reconstruction Algorithm
Section 2C — Complex Application Logic (Feature 3)

When the custody log has gaps — missing transfer records, deleted entries,
or inconsistent timestamps — this algorithm attempts to reconstruct the
most plausible complete custody chain using available partial evidence.

It uses a custom heuristic best-first search, scoring each candidate
record on four criteria:
    (a) Temporal proximity  — how close the candidate's timestamp is
                              to the expected transfer window
    (b) Role consistency    — whether the investigator's role permits
                              custody of this evidence category
    (c) Location consistency — whether the location is plausible given
                               surrounding custody locations
    (d) Behavioural consistency — whether the investigator had other
                                  interactions with the same case

Each gap is tagged as:
    Confirmed  — original verified record
    Inferred   — best candidate above the plausibility threshold
    Unresolved — no candidate scored above the threshold
"""
from datetime import timedelta
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional

# Minimum plausibility score (0.0 to 1.0) for a candidate to be accepted
PLAUSIBILITY_THRESHOLD = 0.40

# Role permission matrix: which roles can hold which evidence categories
ROLE_CUSTODY_PERMISSIONS = {
    'Admin':              ['Image', 'Video', 'Audio', 'Document', 'Database', 'Log File', 'Other'],
    'Lead Investigator':  ['Image', 'Video', 'Audio', 'Document', 'Database', 'Log File', 'Other'],
    'Analyst':            ['Image', 'Video', 'Audio', 'Document', 'Log File', 'Other'],
    'Read-Only':          []
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class CandidateRecord:
    """A potential filling record for a gap in the custody chain."""
    audit_record_id: int
    investigator_id: int
    investigator_name: str
    investigator_role: str
    timestamp: datetime
    location: Optional[str]
    plausibility_score: float = 0.0
    score_breakdown: dict = field(default_factory=dict)


@dataclass
class ChainLink:
    """A single link in the reconstructed custody chain."""
    position: int                    # index in the reconstructed chain
    custody_log_id: Optional[int]    # None if inferred
    event_type: str
    investigator_name: str
    timestamp: datetime
    location: Optional[str]
    label: str                       # 'Confirmed' | 'Inferred' | 'Unresolved'
    confidence: float                # 0.0 to 1.0
    inferred_reason: Optional[str] = None


@dataclass
class ReconstructionReport:
    """Full output of the Custody Chain Reconstruction Algorithm."""
    evidence_id: int
    total_expected_links: int
    confirmed_links: int
    inferred_links: int
    unresolved_gaps: int
    chain_confidence_score: float    # (confirmed + inferred) / total_expected * 100
    reconstructed_chain: List[ChainLink] = field(default_factory=list)
    ran_at: datetime = field(default_factory=lambda: (datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None))

    def to_dict(self) -> dict:
        return {
            'evidence_id': self.evidence_id,
            'total_expected_links': self.total_expected_links,
            'confirmed_links': self.confirmed_links,
            'inferred_links': self.inferred_links,
            'unresolved_gaps': self.unresolved_gaps,
            'chain_confidence_score': self.chain_confidence_score,
            'reconstructed_chain': [
                {
                    'position': link.position,
                    'event_type': link.event_type,
                    'investigator_name': link.investigator_name,
                    'timestamp': link.timestamp.isoformat(),
                    'location': link.location,
                    'label': link.label,
                    'confidence': link.confidence,
                    'inferred_reason': link.inferred_reason
                }
                for link in self.reconstructed_chain
            ],
            'ran_at': self.ran_at.isoformat()
        }


# ── Main algorithm class ──────────────────────────────────────────────────────

class ChainReconstructionEngine:
    """
    Implements the Custody Chain Reconstruction Algorithm.

    Usage:
        engine = ChainReconstructionEngine(evidence_item)
        report = engine.reconstruct()
    """

    def __init__(self, evidence_item):
        self.evidence = evidence_item

    def reconstruct(self) -> ReconstructionReport:
        """
        Main entry point. Full reconstruction workflow:
          1. Load all confirmed custody log entries (partial graph)
          2. Identify gaps between consecutive entries
          3. For each gap: generate candidates, score them, pick the best
          4. Assemble the reconstructed chain with confidence labels
          5. Compute the overall chain confidence score
        """
        from app.models.custody_log import CustodyLog

        # Step 1: Load confirmed custody records ordered by timestamp
        confirmed_logs = (CustodyLog.query
                          .filter_by(evidence_id=self.evidence.id)
                          .order_by(CustodyLog.timestamp.asc())
                          .all())

        if not confirmed_logs:
            return ReconstructionReport(
                evidence_id=self.evidence.id,
                total_expected_links=0,
                confirmed_links=0,
                inferred_links=0,
                unresolved_gaps=0,
                chain_confidence_score=0.0,
                reconstructed_chain=[]
            )

        # Step 2: Identify gaps
        gaps = self._identify_gaps(confirmed_logs)

        # Step 3: Build the reconstructed chain by filling gaps
        reconstructed_chain = []
        position = 0
        confirmed_count = 0
        inferred_count = 0
        unresolved_count = 0

        for i, log in enumerate(confirmed_logs):
            # Add the confirmed link
            reconstructed_chain.append(ChainLink(
                position=position,
                custody_log_id=log.id,
                event_type=log.event_type,
                investigator_name=self._get_investigator_name(
                    log.to_investigator_id or log.from_investigator_id),
                timestamp=log.timestamp,
                location=log.location,
                label='Confirmed',
                confidence=1.0
            ))
            confirmed_count += 1
            position += 1

            # Check if there is a gap after this confirmed record
            if i < len(confirmed_logs) - 1:
                next_log = confirmed_logs[i + 1]
                if (log.log_id, next_log.log_id) in gaps if hasattr(log, 'log_id') \
                        else self._is_gap(log, next_log):

                    # Step 3a: Generate candidates for this gap
                    candidates = self._generate_candidates(log, next_log)

                    # Step 3b: Score each candidate using the plausibility function
                    scored = [self._score_candidate(c, log, next_log)
                              for c in candidates]

                    # Step 3c: Best-first selection
                    scored.sort(key=lambda c: c.plausibility_score, reverse=True)
                    best = scored[0] if scored else None

                    if best and best.plausibility_score >= PLAUSIBILITY_THRESHOLD:
                        # Accept the best candidate as an inferred link
                        reconstructed_chain.append(ChainLink(
                            position=position,
                            custody_log_id=None,
                            event_type='Transfer (Inferred)',
                            investigator_name=best.investigator_name,
                            timestamp=best.timestamp,
                            location=best.location,
                            label='Inferred',
                            confidence=round(best.plausibility_score, 3),
                            inferred_reason=(
                                f"Inferred from access log. "
                                f"Score: {best.plausibility_score:.2f} "
                                f"(temporal={best.score_breakdown.get('temporal', 0):.2f}, "
                                f"role={best.score_breakdown.get('role', 0):.2f}, "
                                f"location={best.score_breakdown.get('location', 0):.2f}, "
                                f"behavioural={best.score_breakdown.get('behavioural', 0):.2f})"
                            )
                        ))
                        inferred_count += 1
                    else:
                        # No candidate passed the threshold — mark as unresolved
                        gap_start = log.timestamp
                        gap_end = next_log.timestamp
                        reconstructed_chain.append(ChainLink(
                            position=position,
                            custody_log_id=None,
                            event_type='Gap (Unresolved)',
                            investigator_name='Unknown',
                            timestamp=gap_start + (gap_end - gap_start) / 2,
                            location=None,
                            label='Unresolved',
                            confidence=0.0,
                            inferred_reason=(
                                f"Gap between {gap_start.strftime('%d %b %Y %H:%M')} "
                                f"and {gap_end.strftime('%d %b %Y %H:%M')}. "
                                f"No candidate scored above threshold "
                                f"({PLAUSIBILITY_THRESHOLD})."
                            )
                        ))
                        unresolved_count += 1

                    position += 1

        # Step 4: Compute chain confidence score
        total_expected = confirmed_count + inferred_count + unresolved_count
        if total_expected > 0:
            confidence_score = round(
                (confirmed_count + inferred_count) / total_expected * 100, 2
            )
        else:
            confidence_score = 100.0

        return ReconstructionReport(
            evidence_id=self.evidence.id,
            total_expected_links=total_expected,
            confirmed_links=confirmed_count,
            inferred_links=inferred_count,
            unresolved_gaps=unresolved_count,
            chain_confidence_score=confidence_score,
            reconstructed_chain=reconstructed_chain
        )

    def _identify_gaps(self, logs) -> set:
        """
        Identify gaps between consecutive custody records.
        A gap exists when the expected holder after a transfer
        does not match the from_investigator_id of the next record.
        Returns a set of (log_id_before, log_id_after) tuples.
        """
        gaps = set()
        for i in range(len(logs) - 1):
            curr = logs[i]
            nxt = logs[i + 1]
            if self._is_gap(curr, nxt):
                gaps.add((curr.id, nxt.id))
        return gaps

    def _is_gap(self, log_before, log_after) -> bool:
        """
        Determine if there is a gap between two consecutive custody records.
        A gap exists when:
        - The expected holder (to_investigator_id of log_before) does not
          match the actual holder (from_investigator_id of log_after)
        - AND both are non-null
        """
        expected_holder = log_before.to_investigator_id
        actual_from = log_after.from_investigator_id

        if expected_holder is None or actual_from is None:
            return False

        return expected_holder != actual_from

    def _generate_candidates(self, log_before, log_after) -> List[CandidateRecord]:
        """
        Generate candidate records for a gap by querying the audit log
        for access events that fall within the gap's time window and
        involve investigators with case permissions.
        """
        from app.models.audit_record import AuditRecord
        from app.models.investigator import Investigator

        gap_start = log_before.timestamp
        gap_end = log_after.timestamp

        # Query access events within the gap window
        access_records = (AuditRecord.query
                          .filter(
                              AuditRecord.evidence_id == self.evidence.id,
                              AuditRecord.event_type == 'File Access',
                              AuditRecord.timestamp > gap_start,
                              AuditRecord.timestamp < gap_end
                          )
                          .all())

        candidates = []
        for record in access_records:
            if not record.investigator_id:
                continue
            investigator = Investigator.query.get(record.investigator_id)
            if not investigator:
                continue

            candidates.append(CandidateRecord(
                audit_record_id=record.id,
                investigator_id=investigator.id,
                investigator_name=investigator.full_name,
                investigator_role=investigator.role,
                timestamp=record.timestamp,
                location=None  # Access logs don't record location
            ))

        return candidates

    def _score_candidate(self, candidate: CandidateRecord,
                         log_before, log_after) -> CandidateRecord:
        """
        Compute a plausibility score (0.0 to 1.0) for a candidate record.
        Combines four independent criteria with equal weighting (0.25 each).

        (a) Temporal proximity  — closer to the midpoint of the gap = higher score
        (b) Role consistency    — correct role for this evidence category
        (c) Location consistency — placeholder (no location in access logs)
        (d) Behavioural consistency — has the investigator accessed this case before?
        """
        scores = {}

        # (a) Temporal proximity
        gap_start = log_before.timestamp
        gap_end = log_after.timestamp
        gap_duration = (gap_end - gap_start).total_seconds()
        if gap_duration > 0:
            candidate_offset = (candidate.timestamp - gap_start).total_seconds()
            # Score highest near the midpoint, lower at the edges
            midpoint_ratio = abs(candidate_offset / gap_duration - 0.5)
            scores['temporal'] = round(1.0 - midpoint_ratio, 3)
        else:
            scores['temporal'] = 0.5

        # (b) Role consistency
        permitted = ROLE_CUSTODY_PERMISSIONS.get(candidate.investigator_role, [])
        scores['role'] = 1.0 if self.evidence.category in permitted else 0.0

        # (c) Location consistency
        # Since access log records don't include location, we give a neutral score
        scores['location'] = 0.5

        # (d) Behavioural consistency
        # Check if this investigator has accessed the same case in surrounding events
        scores['behavioural'] = self._check_behavioural_consistency(
            candidate.investigator_id, log_before, log_after
        )

        # Weighted sum (equal weights = simple average)
        total = sum(scores.values()) / len(scores)
        candidate.plausibility_score = round(total, 4)
        candidate.score_breakdown = scores
        return candidate

    def _check_behavioural_consistency(self, investigator_id: int,
                                        log_before, log_after) -> float:
        """
        Check whether the candidate investigator had other interactions
        with the same case within a reasonable time window around the gap.
        Returns 1.0 if consistent, 0.5 if no data, 0.0 if inconsistent.
        """
        from app.models.audit_record import AuditRecord

        window_start = log_before.timestamp - timedelta(hours=48)
        window_end = log_after.timestamp + timedelta(hours=48)

        related_activity = AuditRecord.query.filter(
            AuditRecord.case_id == self.evidence.case_id,
            AuditRecord.investigator_id == investigator_id,
            AuditRecord.timestamp >= window_start,
            AuditRecord.timestamp <= window_end
        ).count()

        if related_activity >= 2:
            return 1.0
        elif related_activity == 1:
            return 0.7
        else:
            return 0.3

    def _get_investigator_name(self, investigator_id: Optional[int]) -> str:
        """Helper to safely get an investigator's full name."""
        if not investigator_id:
            return 'Unknown'
        from app.models.investigator import Investigator
        inv = Investigator.query.get(investigator_id)
        return inv.full_name if inv else f'Investigator #{investigator_id}'