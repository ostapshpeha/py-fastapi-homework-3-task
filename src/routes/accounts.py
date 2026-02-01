import secrets
from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.accounts import get_user_by_email
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError

from schemas import UserRegistrationRequestSchema
from schemas.accounts import UserResponseSchema, UserActivationRequestSchema, PasswordResetRequestSchema, \
    PasswordResetCompleteRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, pwd_context

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

router = APIRouter()


@router.post("/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    existing_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        group_query = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_query)
        user_group = group_result.scalar_one_or_none()

        if not user_group:
            raise Exception("Default user group not found in database.")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )
        db.add(new_user)

        await db.flush()

        token_str = secrets.token_urlsafe(32)
        new_token = ActivationTokenModel(
            user_id=cast(int, new_user.id),
            token=token_str
        )
        db.add(new_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        await db.rollback()
        print(f"Registration Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):

    user_query = get_user_by_email(db, data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_query = select(ActivationTokenModel).where(
        ActivationTokenModel.token == data.token,
        ActivationTokenModel.user_id == cast(int, user.id)
    )
    token_record = await db.execute(token_query)

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    db_expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if db_expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True

        await db.delete(token_record)

        await db.commit()
        return {"message": "User account activated successfully."}

    except Exception as e:
        await db.rollback()
        print(f"Activation Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )

@router.post("/login", response_model=Token)
async def login(email: str, password: str, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, email)
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}





async def require_admin(current_user: UserRead = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden: admins only")
    return current_user



