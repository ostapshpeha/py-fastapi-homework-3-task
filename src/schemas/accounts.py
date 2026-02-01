from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

class UserResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    pass


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteSchema(UserBase):
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    pass


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass