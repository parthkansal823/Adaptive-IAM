"""Strict API input contracts; identity is always supplied by a session."""
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Context(StrictInput):
    known_device: bool = True
    known_location: bool = True
    vpn: bool = False
    failed_attempts: int = Field(0, ge=0, le=20)
    hour: int = Field(10, ge=0, le=23)
    login_velocity: int = Field(1, ge=0, le=30)
    account_age_days: int = Field(365, ge=0, le=3650)
    travel_distance_km: float = Field(0, ge=0, le=20000)
    sensitivity: float = Field(0.5, ge=0, le=1)
    prior_risk: float = Field(0.1, ge=0, le=1)


class AssessmentInput(StrictInput):
    context: Context = Field(default_factory=Context)


class LoginInput(StrictInput):
    user_id: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    context: Context = Field(default_factory=Context)


class VerifyInput(StrictInput):
    challenge_id: str = Field(min_length=1, max_length=128)
    code: str | None = Field(None, min_length=6, max_length=6, pattern=r"^[0-9]{6}$")
    recovery_code: str | None = Field(None, min_length=8, max_length=80)

    @model_validator(mode="after")
    def one_factor(self):
        if bool(self.code) == bool(self.recovery_code):
            raise ValueError("Supply exactly one verification code or recovery code")
        return self


class RequestInput(StrictInput):
    resource_id: str = Field(min_length=1, max_length=80)
    justification: str = Field(min_length=20, max_length=2000)
    duration_hours: float = Field(4, gt=0, le=72)


class VoteInput(StrictInput):
    approve: bool
    comment: str = Field("", max_length=500)
