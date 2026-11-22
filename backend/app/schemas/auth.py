"""Pydantic schemas for authentication and user accounts."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"


class UserRole(str, Enum):
    """Strict enumeration of valid application roles."""
    ADMIN = "admin"
    MAINTAINER = "maintainer"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDITOR = "auditor"


DEFAULT_REGISTERED_ROLE = UserRole.ANALYST

PRIVILEGED_REGISTRATION_FIELDS = {"role", "roles", "is_admin", "is_superuser"}


class UserRegister(BaseModel):
    model_config = ConfigDict(extra="ignore")

    email: str = Field(..., pattern=EMAIL_REGEX, description="Valid email address", examples=["practitioner@xerova.com"])
    password: str = Field(..., min_length=8, max_length=128, description="Minimum 8 characters")

    @model_validator(mode="before")
    @classmethod
    def reject_privileged_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            forbidden = [k for k in data.keys() if str(k).lower() in PRIVILEGED_REGISTRATION_FIELDS]
            if forbidden:
                raise ValueError(
                    f"Privileged field(s) {forbidden} cannot be supplied during public registration."
                )
        return data


class UserLogin(BaseModel):
    email: str = Field(..., pattern=EMAIL_REGEX, description="Valid email address", examples=["practitioner@xerova.com"])
    password: str = Field(..., min_length=1, description="Account password")


class UserRead(BaseModel):
    id: str
    email: str
    account_status: str
    role: UserRole = DEFAULT_REGISTERED_ROLE
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead


class LogoutResponse(BaseModel):
    success: bool = True
    message: str = "Successfully logged out."
