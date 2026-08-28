from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Literal

import models
from database import get_db
from core.deps import require_admin
from core.security import get_password_hash

router = APIRouter(prefix="/api/users", tags=["Users"])


class UserCreateRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=8, max_length=255)
    role: Literal["ADMIN", "USER"] = "USER"


class UserOut(BaseModel):
    user_id: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: models.User = Depends(require_admin)):
    """SFR-005 프로젝트 권한 할당 시 대상 사용자 조회. 관리자 전용(SEC-003)."""
    return db.query(models.User).order_by(models.User.user_id).all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    request: UserCreateRequest,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    existing = db.query(models.User).filter(models.User.user_id == request.user_id).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="이미 존재하는 계정입니다.")

    user = models.User(
        user_id=request.user_id,
        password_hash=get_password_hash(request.password),
        role=request.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
