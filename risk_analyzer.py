"""Cloud Sentry — Security Misconfiguration & Educational Risk Analyzer.

Analyzes simulated cloud storage object configurations for common access-control
misconfigurations, assigns severity levels (CRITICAL, HIGH, MEDIUM, LOW),
computes an educational heuristic risk score (0-100), and produces clear
explanations and remediation recommendations.

IMPORTANT DISCLAIMER:
    The 0-100 risk score produced by this module is an educational heuristic
    created for university cybersecurity demonstrations. It is NOT an
    industry-standard cloud security metric (such as CIS Benchmarks, NIST,
    CVSS, or commercial CSPM scores).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import pandas as pd

from models import AccessPolicy, Classification, Role, StorageObject


EDUCATIONAL_RISK_DISCLAIMER: str = (
    "Educational Heuristic Notice: The 0-100 risk score in Cloud Sentry is a "
    "simplified educational heuristic designed for academic learning and viva "
    "demonstrations. It is not an industry-standard cloud security score."
)


class Severity(str, Enum):
    """Risk severity levels assigned to analyzed cloud storage objects."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@dataclass(frozen=True)
class RiskAssessment:
    """Structured security misconfiguration assessment for a storage object."""

    object_id: str
    object_name: str
    classification: str
    policy: str
    allowed_roles: list[str]
    detected_issue: str
    severity: Severity
    risk_score: int
    explanation: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the assessment to a dictionary suitable for Pandas / JSON."""
        return {
            "Object ID": self.object_id,
            "Object": self.object_name,
            "Classification": self.classification,
            "Policy": self.policy,
            "Allowed Roles": ", ".join(self.allowed_roles) if self.allowed_roles else "None",
            "Detected Issue": self.detected_issue,
            "Severity": self.severity.value,
            "Risk Score": self.risk_score,
            "Explanation": self.explanation,
            "Remediation": self.remediation,
        }


def analyze_object(cloud_object: StorageObject) -> RiskAssessment:
    """Analyze a single StorageObject for security misconfigurations.

    Evaluation proceeds from highest severity (CRITICAL) to lowest (LOW) so the
    most urgent security exposure is surfaced first with an educational
    heuristic risk score between 0 and 100.
    """
    classification = cloud_object.classification
    policy = cloud_object.policy
    allowed = set(cloud_object.allowed_roles)
    allowed_names = [role.value for role in cloud_object.allowed_roles]

    def build_result(
        detected_issue: str,
        severity: Severity,
        risk_score: int,
        explanation: str,
        remediation: str,
    ) -> RiskAssessment:
        bounded_score = max(0, min(100, risk_score))
        return RiskAssessment(
            object_id=cloud_object.id,
            object_name=cloud_object.name,
            classification=classification.value,
            policy=policy.value,
            allowed_roles=allowed_names,
            detected_issue=detected_issue,
            severity=severity,
            risk_score=bounded_score,
            explanation=explanation,
            remediation=remediation,
        )

    # ------------------------------------------------------------------
    # Rule 1 (CRITICAL — Score 100): Restricted object with public-read
    # ------------------------------------------------------------------
    if classification == Classification.RESTRICTED and policy == AccessPolicy.PUBLIC_READ:
        return build_result(
            detected_issue="Restricted object exposed with public-read policy",
            severity=Severity.CRITICAL,
            risk_score=100,
            explanation=(
                f"'{cloud_object.name}' is classified as Restricted (highest sensitivity) "
                f"but configured with 'public-read'. Any user, including unauthenticated "
                f"or Guest identities, can read highly sensitive assets such as backups or credentials."
            ),
            remediation=(
                "Immediately change the policy from 'public-read' to 'private' so only "
                "the owner and Admin can access this object, and clear any public ACLs."
            ),
        )

    # ------------------------------------------------------------------
    # Rule 2 (CRITICAL — Score 90): Confidential object with public-read
    # ------------------------------------------------------------------
    if classification == Classification.CONFIDENTIAL and policy == AccessPolicy.PUBLIC_READ:
        return build_result(
            detected_issue="Confidential object exposed with public-read policy",
            severity=Severity.CRITICAL,
            risk_score=90,
            explanation=(
                f"'{cloud_object.name}' is classified as Confidential but uses the "
                f"'public-read' policy. Confidential records (such as payroll or HR files) "
                f"are openly readable by Employees and external Guests, creating a severe data-leak risk."
            ),
            remediation=(
                "Change the policy from 'public-read' to 'role-restricted' with "
                "allowed_roles limited to ['Admin', 'Manager'], or set it to 'private'."
            ),
        )

    # ------------------------------------------------------------------
    # Rule 3 (HIGH — Score 80): Restricted object accessible by Employee or Guest
    # ------------------------------------------------------------------
    if (
        classification == Classification.RESTRICTED
        and policy == AccessPolicy.ROLE_RESTRICTED
        and (Role.EMPLOYEE in allowed or Role.GUEST in allowed)
    ):
        exposed_roles = [r.value for r in (Role.EMPLOYEE, Role.GUEST) if r in allowed]
        return build_result(
            detected_issue="Restricted object accessible by Employee or Guest",
            severity=Severity.HIGH,
            risk_score=80,
            explanation=(
                f"Restricted object '{cloud_object.name}' uses 'role-restricted' and grants "
                f"access to {', '.join(exposed_roles)}. Restricted assets must be strictly "
                f"isolated and should never be accessible to general Employees or Guests."
            ),
            remediation=(
                "Change policy to 'private' (Owner and Admin only) and remove Employee/Guest "
                "from allowed_roles to restore least-privilege protection."
            ),
        )

    # ------------------------------------------------------------------
    # Rule 4 (HIGH — Score 75): Confidential object accessible by Guest
    # ------------------------------------------------------------------
    if (
        classification == Classification.CONFIDENTIAL
        and policy == AccessPolicy.ROLE_RESTRICTED
        and Role.GUEST in allowed
    ):
        return build_result(
            detected_issue="Confidential object accessible by Guest",
            severity=Severity.HIGH,
            risk_score=75,
            explanation=(
                f"Confidential object '{cloud_object.name}' explicitly includes 'Guest' in "
                f"allowed_roles. External Guests should never have read access to confidential "
                f"organizational data."
            ),
            remediation=(
                "Remove 'Guest' from allowed_roles immediately and restrict access to "
                "['Admin', 'Manager']."
            ),
        )

    # ------------------------------------------------------------------
    # Rule 5 (MEDIUM — Score 50-55): Excessively broad allowed_roles / exposure
    # ------------------------------------------------------------------
    if classification == Classification.INTERNAL and policy == AccessPolicy.PUBLIC_READ:
        return build_result(
            detected_issue="Excessively broad access: Internal object set to public-read",
            severity=Severity.MEDIUM,
            risk_score=55,
            explanation=(
                f"Internal object '{cloud_object.name}' is configured as 'public-read', "
                f"exposing internal organizational documents to external Guests."
            ),
            remediation=(
                "Switch policy to 'role-restricted' with allowed_roles set to "
                "['Admin', 'Manager', 'Employee'] so Guests are denied."
            ),
        )

    if policy == AccessPolicy.ROLE_RESTRICTED:
        if (
            (classification == Classification.INTERNAL and Role.GUEST in allowed)
            or (classification == Classification.CONFIDENTIAL and Role.EMPLOYEE in allowed)
            or (classification == Classification.RESTRICTED and Role.MANAGER in allowed)
            or len(allowed) == len(Role)
        ):
            return build_result(
                detected_issue="Excessively broad allowed_roles configuration",
                severity=Severity.MEDIUM,
                risk_score=50,
                explanation=(
                    f"'{cloud_object.name}' ({classification.value}) grants access to an "
                    f"overly broad set of roles ({', '.join(allowed_names)}), violating the "
                    f"principle of least privilege."
                ),
                remediation=(
                    "Narrow allowed_roles to the minimum roles required by business need: "
                    "['Admin', 'Manager', 'Employee'] for Internal, ['Admin', 'Manager'] for "
                    "Confidential, or use 'private' for Restricted objects."
                ),
            )

        if not allowed:
            return build_result(
                detected_issue="Excessively vague policy: role-restricted with empty allowed_roles",
                severity=Severity.MEDIUM,
                risk_score=45,
                explanation=(
                    f"'{cloud_object.name}' uses 'role-restricted' but defines no allowed_roles, "
                    f"leaving access intent unclear and prone to ad-hoc misconfiguration."
                ),
                remediation=(
                    "Explicitly list the required roles in allowed_roles or switch the object "
                    "to the 'private' policy."
                ),
            )

    # ------------------------------------------------------------------
    # Rule 6 (LOW — Score 10): Correct least-privilege configuration
    # ------------------------------------------------------------------
    return build_result(
        detected_issue="Correct least-privilege configuration",
        severity=Severity.LOW,
        risk_score=10,
        explanation=(
            f"'{cloud_object.name}' ({classification.value}) is properly configured with the "
            f"'{policy.value}' policy matching least-privilege expectations (minimal residual risk)."
        ),
        remediation=(
            "No immediate change required. Periodically review ownership and role assignments "
            "as part of routine access governance."
        ),
    )


def analyze_all_objects(objects: list[StorageObject]) -> list[RiskAssessment]:
    """Analyze every storage object and sort assessments from highest to lowest risk."""
    assessments = [analyze_object(obj) for obj in objects]
    assessments.sort(
        key=lambda item: (SEVERITY_ORDER[item.severity], -item.risk_score, item.object_name)
    )
    return assessments


def calculate_overall_risk(assessments: list[RiskAssessment]) -> dict[str, Any]:
    """Compute an aggregate educational heuristic risk score (0-100) across all objects.

    Formula (Educational Heuristic):
        overall_score = round(0.8 * max_object_score + 0.2 * average_object_score)

    Weighting the worst finding at 80% reflects that a single critically exposed
    cloud object compromises security posture even if other objects are secure.
    """
    if not assessments:
        return {
            "overall_score": 0,
            "overall_severity": Severity.LOW.value,
            "counts": {sev.value: 0 for sev in Severity},
            "disclaimer": EDUCATIONAL_RISK_DISCLAIMER,
        }

    scores = [a.risk_score for a in assessments]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)
    overall_score = max(0, min(100, round(0.8 * max_score + 0.2 * avg_score)))

    if overall_score >= 80:
        overall_severity = Severity.CRITICAL.value
    elif overall_score >= 60:
        overall_severity = Severity.HIGH.value
    elif overall_score >= 35:
        overall_severity = Severity.MEDIUM.value
    else:
        overall_severity = Severity.LOW.value

    counts = {
        sev.value: sum(1 for a in assessments if a.severity == sev) for sev in Severity
    }

    return {
        "overall_score": overall_score,
        "overall_severity": overall_severity,
        "counts": counts,
        "disclaimer": EDUCATIONAL_RISK_DISCLAIMER,
    }


def assessments_to_dataframe(assessments: list[RiskAssessment]) -> pd.DataFrame:
    """Convert a list of RiskAssessment records into a Pandas DataFrame."""
    return pd.DataFrame([a.to_dict() for a in assessments])
