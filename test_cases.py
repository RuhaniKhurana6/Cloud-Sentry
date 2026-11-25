"""Cloud Sentry — Expected Access Matrix & Automated Verification Tests.

Stores the predefined Expected READ Access Matrix independently from the main
access-control engine (`access_control.py`) and provides functions to compare
expected access against actual `check_access()` results (returning PASS/FAIL).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

import pandas as pd

from access_control import check_access
from models import (
    AccessPolicy,
    Action,
    Classification,
    Role,
    StorageObject,
    User,
    load_objects,
    load_users,
)


# ---------------------------------------------------------------------------
# Independent Predefined Expected READ Access Matrix
# Stored outside access_control.py so verification never depends on the
# decision engine's internal logic.
# ---------------------------------------------------------------------------
MATRIX_ROLES: list[Role] = [Role.ADMIN, Role.MANAGER, Role.EMPLOYEE, Role.GUEST]

EXPECTED_READ_MATRIX: dict[str, dict[Role, bool]] = {
    "public_notice.pdf": {
        Role.ADMIN: True,
        Role.MANAGER: True,
        Role.EMPLOYEE: True,
        Role.GUEST: True,
    },
    "company_policy.pdf": {
        Role.ADMIN: True,
        Role.MANAGER: True,
        Role.EMPLOYEE: True,
        Role.GUEST: False,
    },
    "employee_records.csv": {
        Role.ADMIN: True,
        Role.MANAGER: True,
        Role.EMPLOYEE: False,
        Role.GUEST: False,
    },
    "salary_data.xlsx": {
        Role.ADMIN: True,
        Role.MANAGER: True,
        Role.EMPLOYEE: False,
        Role.GUEST: False,
    },
    "database_backup.zip": {
        Role.ADMIN: True,
        Role.MANAGER: False,
        Role.EMPLOYEE: False,
        Role.GUEST: False,
    },
}


@dataclass(frozen=True)
class MatrixVerificationResult:
    """Result of comparing expected READ access vs. actual access-control decision."""

    object_name: str
    user: str
    role: str
    expected_allowed: bool
    actual_allowed: bool
    status: str  # "PASS" or "FAIL"
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "Object": self.object_name,
            "User": self.user,
            "Role": self.role,
            "Expected READ": "YES" if self.expected_allowed else "NO",
            "Actual READ": "YES" if self.actual_allowed else "NO",
            "Status": self.status,
            "Reason": self.reason,
        }


def _lookup_expected_read(
    object_name: str,
    role: Role,
    expected_matrix: dict[str, dict[Role, bool]] = EXPECTED_READ_MATRIX,
) -> bool:
    """Look up expected READ access by full filename or base name (without extension)."""
    if object_name in expected_matrix:
        return expected_matrix[object_name][role]

    stem = object_name.rsplit(".", 1)[0]
    for key, role_map in expected_matrix.items():
        if key.rsplit(".", 1)[0] == stem:
            return role_map[role]

    raise KeyError(
        f"Object '{object_name}' is not defined in the predefined expected access matrix."
    )


def get_expected_read_matrix_df(
    expected_matrix: dict[str, dict[Role, bool]] = EXPECTED_READ_MATRIX,
) -> pd.DataFrame:
    """Return the predefined expected READ access matrix as a Pandas DataFrame."""
    rows: list[dict[str, str]] = []
    for object_name, permissions in expected_matrix.items():
        short_name = object_name.rsplit(".", 1)[0]
        row: dict[str, str] = {"Object": short_name}
        for role in MATRIX_ROLES:
            row[role.value] = "YES" if permissions[role] else "NO"
        rows.append(row)
    return pd.DataFrame(rows)


def format_expected_matrix(
    expected_matrix: dict[str, dict[Role, bool]] = EXPECTED_READ_MATRIX,
) -> str:
    """Render the predefined expected READ access matrix as a readable table."""
    lines = [
        f"{'':<18} {'Admin':<7} {'Manager':<8} {'Employee':<9} {'Guest':<6}",
        "-" * 52,
    ]
    for object_name, permissions in expected_matrix.items():
        short_name = object_name.rsplit(".", 1)[0]
        admin = "YES" if permissions[Role.ADMIN] else "NO"
        manager = "YES" if permissions[Role.MANAGER] else "NO"
        employee = "YES" if permissions[Role.EMPLOYEE] else "NO"
        guest = "YES" if permissions[Role.GUEST] else "NO"
        lines.append(
            f"{short_name:<18} {admin:<7} {manager:<8} {employee:<9} {guest:<6}"
        )
    return "\n".join(lines)


def compare_expected_vs_actual(
    user: User,
    cloud_object: StorageObject,
    expected_matrix: dict[str, dict[Role, bool]] = EXPECTED_READ_MATRIX,
) -> MatrixVerificationResult:
    """Compare expected READ access from the matrix against actual `check_access()`.

    Returns a MatrixVerificationResult with status='PASS' when expected and
    actual decisions match, or status='FAIL' when they do not.
    """
    expected_allowed = _lookup_expected_read(
        cloud_object.name, user.role, expected_matrix=expected_matrix
    )
    actual_decision = check_access(user, cloud_object, Action.READ)
    status = "PASS" if actual_decision.allowed == expected_allowed else "FAIL"

    return MatrixVerificationResult(
        object_name=cloud_object.name,
        user=user.name,
        role=user.role.value,
        expected_allowed=expected_allowed,
        actual_allowed=actual_decision.allowed,
        status=status,
        reason=actual_decision.reason,
    )


def verify_matrix_against_engine(
    users: list[User],
    objects: list[StorageObject],
    expected_matrix: dict[str, dict[Role, bool]] = EXPECTED_READ_MATRIX,
) -> list[MatrixVerificationResult]:
    """Verify every (object, user) pair defined in the expected READ access matrix."""
    results: list[MatrixVerificationResult] = []
    for obj in objects:
        if obj.name not in expected_matrix:
            continue
        for user in users:
            results.append(
                compare_expected_vs_actual(user, obj, expected_matrix=expected_matrix)
            )
    return results


def verify_matrix_dataframe(
    users: list[User],
    objects: list[StorageObject],
    expected_matrix: dict[str, dict[Role, bool]] = EXPECTED_READ_MATRIX,
) -> pd.DataFrame:
    """Return full expected-vs-actual READ matrix verification as a DataFrame."""
    results = verify_matrix_against_engine(
        users, objects, expected_matrix=expected_matrix
    )
    return pd.DataFrame([r.to_dict() for r in results])


def run_access_control_tests() -> bool:
    """Run deterministic access-control tests and expected-matrix verification."""
    users_list = load_users()
    objects_list = load_objects()
    users = {u.name: u for u in users_list}
    objects = {o.name: o for o in objects_list}

    # In-memory private object owned by Bob to verify non-Admin owner privileges
    bob_private_note = StorageObject(
        id="OBJ999",
        name="bob_private_notes.txt",
        owner="Bob",
        classification=Classification.CONFIDENTIAL,
        policy=AccessPolicy.PRIVATE,
        allowed_roles=[],
    )

    test_cases = [
        # --- Required Minimum Verification Cases ---
        ("TC-01", users["Alice"], objects["database_backup.zip"], Action.READ, True),
        ("TC-02", users["David"], objects["database_backup.zip"], Action.READ, False),
        ("TC-03", users["David"], objects["public_notice.pdf"], Action.READ, True),
        ("TC-04", users["Charlie"], objects["salary_data.xlsx"], Action.READ, False),
        ("TC-05", users["Bob"], objects["salary_data.xlsx"], Action.READ, True),
        ("TC-06", users["Charlie"], objects["company_policy.pdf"], Action.READ, True),
        ("TC-07", users["David"], objects["public_notice.pdf"], Action.DELETE, False),
        ("TC-08", users["Alice"], objects["public_notice.pdf"], Action.DELETE, True),
        # --- Additional Policy & Role Boundary Cases ---
        ("TC-09", users["Charlie"], objects["public_notice.pdf"], Action.WRITE, False),
        ("TC-10", users["Bob"], objects["public_notice.pdf"], Action.DELETE, False),
        ("TC-11", users["Alice"], objects["public_notice.pdf"], Action.WRITE, True),
        ("TC-12", users["Bob"], objects["database_backup.zip"], Action.READ, False),
        ("TC-13", users["Bob"], bob_private_note, Action.DELETE, True),
        ("TC-14", users["Alice"], bob_private_note, Action.READ, True),
        ("TC-15", users["Charlie"], bob_private_note, Action.READ, False),
        ("TC-16", users["Charlie"], objects["company_policy.pdf"], Action.WRITE, False),
        ("TC-17", users["David"], objects["company_policy.pdf"], Action.READ, False),
        ("TC-18", users["Bob"], objects["salary_data.xlsx"], Action.WRITE, True),
        ("TC-19", users["Bob"], objects["salary_data.xlsx"], Action.DELETE, False),
        ("TC-20", users["Charlie"], objects["employee_records.csv"], Action.READ, False),
        ("TC-21", users["Alice"], objects["salary_data.xlsx"], Action.DELETE, True),
    ]

    passed = 0
    print("=" * 102)
    print("Predefined Expected READ Access Matrix")
    print("=" * 102)
    print(format_expected_matrix())

    print("\n" + "=" * 102)
    print("Expected Matrix vs. Actual Access-Control Verification (20 checks)")
    print("=" * 102)
    matrix_results = verify_matrix_against_engine(users_list, objects_list)
    matrix_passed = sum(1 for r in matrix_results if r.status == "PASS")
    print(
        f"{'Object':<22} | {'User':<8} | {'Role':<8} | {'Expected':<8} | {'Actual':<8} | {'Status':<6}"
    )
    print("-" * 102)
    for r in matrix_results:
        exp_str = "YES" if r.expected_allowed else "NO"
        act_str = "YES" if r.actual_allowed else "NO"
        print(
            f"{r.object_name:<22} | {r.user:<8} | {r.role:<8} | {exp_str:<8} | {act_str:<8} | {r.status:<6}"
        )
    print(f"Matrix Verification Summary: {matrix_passed}/{len(matrix_results)} PASS")

    print("\n" + "=" * 102)
    print("Action-Level Access-Control Unit Tests (21 checks)")
    print("=" * 102)
    for test_id, user, obj, action, expected_allowed in test_cases:
        result = check_access(user, obj, action)
        expected_label = "ALLOW" if expected_allowed else "DENY"
        ok = result.allowed == expected_allowed
        if ok:
            passed += 1
        status = "PASS" if ok else "FAIL"
        print(
            f"{test_id:<6} | {result.role:<8} | {result.object:<22} | {result.action:<6} | "
            f"{expected_label:<8} | {result.decision:<8} | {status:<6}"
        )

    print("=" * 102)
    print(
        f"Overall Summary: Matrix {matrix_passed}/{len(matrix_results)} PASS | "
        f"Unit Tests {passed}/{len(test_cases)} PASS"
    )
    print("=" * 102)
    return (matrix_passed == len(matrix_results)) and (passed == len(test_cases))


if __name__ == "__main__":
    all_passed = run_access_control_tests()
    sys.exit(0 if all_passed else 1)
