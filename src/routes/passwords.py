from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status
from typing import cast

from crud.accounts import get_user_by_email
from database import get_db, PasswordResetTokenModel, UserModel

from schemas.accounts import PasswordResetCompleteSchema, PasswordResetRequestSchema

router = APIRouter()

@router.post("/request", status_code=status.HTTP_200_OK)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    success_message = {"message": "If you are registered, you will receive an email with instructions."}

    query = get_user_by_email(db, data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        try:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == cast(int, user.id)
                )
            )

            new_reset_token = PasswordResetTokenModel(
                user_id=cast(int, user.id)
            )
            db.add(new_reset_token)

            await db.commit()


        except Exception as e:
            await db.rollback()
            print(f"Error creating reset token: {e}")
            return success_message

    return success_message


@router.post("/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
        data: PasswordResetCompleteSchema,
        db: AsyncSession = Depends(get_db)
):
    user_query = get_user_by_email(db, data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == cast(int, user.id)
    )
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    async def invalidate_and_raise():
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if not token_record or token_record.token != data.token:
        await invalidate_and_raise()

    db_expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if db_expires_at < datetime.now(datetime.timezone.utc):
        await invalidate_and_raise()

    try:
        user.password = data.password

        await db.delete(token_record)

        await db.commit()
        return {"message": "Password reset successfully."}

    except ValueError as ve:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        await db.rollback()
        print(f"Password reset error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )