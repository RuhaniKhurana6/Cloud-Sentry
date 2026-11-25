"""Cloud Sentry — Core Data Models (Users, Roles, and Cloud Storage Objects).

Defines typed enums, data classes, and local JSON persistence helpers for
simulated users and cloud storage objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


DATA_DIR: Path = Path(__file__).resolve().parent / "data"
DEFAULT_USERS_PATH: Path = DATA_DIR / "users.json"
DEFAULT_OBJECTS_PATH: Path = DATA_DIR / "objects.json"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
class Role(str, Enum):
    """Supported user roles in the Cloud Sentry simulator."""

    ADMIN = "Admin"
    MANAGER = "Manager"
    EMPLOYEE = "Employee"
    GUEST = "Guest"


class Classification(str, Enum):
    """Data sensitivity classifications for simulated cloud storage objects."""

    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class AccessPolicy(str, Enum):
    """Supported cloud storage access control policies."""

    PUBLIC_READ = "public-read"
    PRIVATE = "private"
    ROLE_RESTRICTED = "role-restricted"


class Action(str, Enum):
    """Supported actions that a user can request on a storage object."""

    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"


# ---------------------------------------------------------------------------
# User Data Model & Helpers
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class User:
    """Represents a simulated cloud user and their assigned RBAC role."""

    id: str
    name: str
    role: Role

    def to_dict(self) -> dict[str, str]:
        """Serialize the User instance to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "User":
        """Create and validate a User instance from a dictionary."""
        missing_fields = [key for key in ("id", "name", "role") if key not in data]
        if missing_fields:
            raise ValueError(f"User record missing required fields: {missing_fields}")

        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            role=Role(data["role"]),
        )


def load_users(file_path: Path | str = DEFAULT_USERS_PATH) -> list[User]:
    """Load and validate all simulated users from a local JSON file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Users data file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        raw_users: list[dict[str, Any]] = json.load(handle)

    if not isinstance(raw_users, list):
        raise ValueError("Expected a JSON array of user objects in users.json.")

    return [User.from_dict(item) for item in raw_users]


def save_users(
    users: list[User],
    file_path: Path | str = DEFAULT_USERS_PATH,
) -> None:
    """Persist simulated users to a local JSON file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump([user.to_dict() for user in users], handle, indent=2)


def get_user_by_id(users: list[User], user_id: str) -> Optional[User]:
    """Find a user by their unique ID, or return None if not found."""
    for user in users:
        if user.id == user_id:
            return user
    return None


def get_users_by_role(users: list[User], role: Role) -> list[User]:
    """Filter users matching a specific Role."""
    return [user for user in users if user.role == role]


# ---------------------------------------------------------------------------
# Cloud Storage Object Data Model & Helpers
# ---------------------------------------------------------------------------
@dataclass
class StorageObject:
    """Represents a simulated cloud storage object and its access configuration."""

    id: str
    name: str
    owner: str
    classification: Classification
    policy: AccessPolicy
    allowed_roles: list[Role] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the StorageObject instance to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner,
            "classification": self.classification.value,
            "policy": self.policy.value,
            "allowed_roles": [role.value for role in self.allowed_roles],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StorageObject":
        """Create and validate a StorageObject instance from a dictionary."""
        required_fields = ("id", "name", "owner", "classification", "policy", "allowed_roles")
        missing_fields = [key for key in required_fields if key not in data]
        if missing_fields:
            raise ValueError(
                f"StorageObject record missing required fields: {missing_fields}"
            )

        raw_allowed_roles = data["allowed_roles"]
        if not isinstance(raw_allowed_roles, list):
            raise ValueError("'allowed_roles' must be a list of valid role names.")

        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            owner=str(data["owner"]),
            classification=Classification(data["classification"]),
            policy=AccessPolicy(data["policy"]),
            allowed_roles=[Role(role_name) for role_name in raw_allowed_roles],
        )


def load_objects(file_path: Path | str = DEFAULT_OBJECTS_PATH) -> list[StorageObject]:
    """Load and validate all simulated storage objects from a local JSON file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Objects data file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        raw_objects: list[dict[str, Any]] = json.load(handle)

    if not isinstance(raw_objects, list):
        raise ValueError("Expected a JSON array of storage objects in objects.json.")

    return [StorageObject.from_dict(item) for item in raw_objects]


def save_objects(
    objects: list[StorageObject],
    file_path: Path | str = DEFAULT_OBJECTS_PATH,
) -> None:
    """Persist simulated storage objects to a local JSON file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump([obj.to_dict() for obj in objects], handle, indent=2)


def get_object_by_id(
    objects: list[StorageObject],
    object_id: str,
) -> Optional[StorageObject]:
    """Find a storage object by its unique ID, or return None if not found."""
    for obj in objects:
        if obj.id == object_id:
            return obj
    return None


def get_object_by_name(
    objects: list[StorageObject],
    name: str,
) -> Optional[StorageObject]:
    """Find a storage object by its file name, or return None if not found."""
    for obj in objects:
        if obj.name == name:
            return obj
    return None
