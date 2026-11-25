"""Cloud Sentry — Deterministic Access Control Engine.

Evaluates user access requests (READ, WRITE, DELETE) against simulated cloud
storage object policies (public-read, private, role-restricted) using clear,
deterministic rules suitable for educational demonstration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models import AccessPolicy, Action, Role, StorageObject, User


@dataclass(frozen=True)
class AccessDecision:
    """Structured outcome of an access-control evaluation."""

    allowed: bool
    reason: str
    user: str
    role: str
    object: str
    action: str

    @property
    def decision(self) -> str:
        """Return the standard ALLOW / DENY label for this result."""
        return "ALLOW" if self.allowed else "DENY"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the access decision into a dictionary."""
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "reason": self.reason,
            "user": self.user,
            "role": self.role,
            "object": self.object,
            "action": self.action,
        }


def _normalize_action(action: Action | str) -> Action:
    """Convert a string or Action enum into a validated Action enum value."""
    if isinstance(action, Action):
        return action
    if isinstance(action, str):
        try:
            return Action(action.strip().upper())
        except ValueError as exc:
            valid = ", ".join(a.value for a in Action)
            raise ValueError(
                f"Unsupported action '{action}'. Must be one of: {valid}."
            ) from exc
    raise TypeError(f"Expected Action or str, got {type(action).__name__}.")


def _evaluate_public_read(user: User, action: Action) -> tuple[bool, str]:
    """Evaluate rules for the 'public-read' policy.

    - All roles can READ.
    - Only Admin can WRITE or DELETE.
    """
    if action == Action.READ:
        return (
            True,
            f"Policy 'public-read' allows all roles ({user.role.value}) to READ.",
        )

    if user.role == Role.ADMIN:
        return (
            True,
            f"Policy 'public-read' allows Admin to {action.value}.",
        )

    return (
        False,
        f"Policy 'public-read' denies {user.role.value} from {action.value} (Admin only).",
    )


def _evaluate_private(
    user: User,
    cloud_object: StorageObject,
    action: Action,
) -> tuple[bool, str]:
    """Evaluate rules for the 'private' policy.

    - Owner can READ, WRITE, and DELETE.
    - Admin can READ, WRITE, and DELETE.
    - Everyone else is denied.
    """
    is_owner = user.name == cloud_object.owner or user.id == cloud_object.owner

    if is_owner:
        return (
            True,
            f"Policy 'private' allows object owner '{user.name}' to {action.value}.",
        )

    if user.role == Role.ADMIN:
        return (
            True,
            f"Policy 'private' allows Admin to {action.value}.",
        )

    return (
        False,
        f"Policy 'private' denies {user.name} ({user.role.value}) from {action.value} "
        f"(only owner '{cloud_object.owner}' or Admin permitted).",
    )


def _evaluate_role_restricted(
    user: User,
    cloud_object: StorageObject,
    action: Action,
) -> tuple[bool, str]:
    """Evaluate rules for the 'role-restricted' policy.

    - READ is allowed only when the user's role exists in allowed_roles.
    - WRITE is allowed only for Admin and Manager if their role is also allowed.
    - DELETE is Admin only.
    """
    role_is_allowed = user.role in cloud_object.allowed_roles

    if action == Action.READ:
        if role_is_allowed:
            return (
                True,
                f"Policy 'role-restricted' allows {user.role.value} to READ "
                f"(role is in allowed_roles).",
            )
        return (
            False,
            f"Policy 'role-restricted' denies {user.role.value} from READ "
            f"(role not in allowed_roles).",
        )

    if action == Action.WRITE:
        if user.role in (Role.ADMIN, Role.MANAGER) and role_is_allowed:
            return (
                True,
                f"Policy 'role-restricted' allows {user.role.value} to WRITE "
                f"(permitted writer role present in allowed_roles).",
            )
        if user.role not in (Role.ADMIN, Role.MANAGER):
            return (
                False,
                f"Policy 'role-restricted' denies {user.role.value} from WRITE "
                f"(only Admin and Manager may WRITE).",
            )
        return (
            False,
            f"Policy 'role-restricted' denies {user.role.value} from WRITE "
            f"(role not in allowed_roles).",
        )

    if action == Action.DELETE:
        if user.role == Role.ADMIN:
            return (
                True,
                "Policy 'role-restricted' allows Admin to DELETE.",
            )
        return (
            False,
            f"Policy 'role-restricted' denies {user.role.value} from DELETE (Admin only).",
        )

    return False, "Denied by default fallback rule."


def check_access(
    user: User,
    cloud_object: StorageObject,
    action: Action | str,
) -> AccessDecision:
    """Evaluate whether a user is allowed to perform an action on a cloud object.

    Args:
        user: The simulated User requesting access.
        cloud_object: The target StorageObject being accessed.
        action: The requested operation ('READ', 'WRITE', or 'DELETE').

    Returns:
        An AccessDecision dataclass containing allowed, reason, user, role,
        object, and action.
    """
    normalized_action = _normalize_action(action)

    if cloud_object.policy == AccessPolicy.PUBLIC_READ:
        allowed, reason = _evaluate_public_read(user, normalized_action)
    elif cloud_object.policy == AccessPolicy.PRIVATE:
        allowed, reason = _evaluate_private(user, cloud_object, normalized_action)
    elif cloud_object.policy == AccessPolicy.ROLE_RESTRICTED:
        allowed, reason = _evaluate_role_restricted(user, cloud_object, normalized_action)
    else:
        allowed, reason = False, f"Unknown policy '{cloud_object.policy}' — access denied."

    return AccessDecision(
        allowed=allowed,
        reason=reason,
        user=user.name,
        role=user.role.value,
        object=cloud_object.name,
        action=normalized_action.value,
    )
