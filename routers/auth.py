from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
import models
from database import get_db
from core.security import verify_password, create_access_token
from core.deps import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# 요청 Body 데이터 검증을 위한 스키마
class LoginRequest(BaseModel):
    user_id: str
    password: str

@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    # 1. 사용자 계정 조회
    user = db.query(models.User).filter(models.User.user_id == request.user_id).first()
    
    # 2. 계정 존재 여부 및 비밀번호 검증
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 일치하지 않습니다."
        )
    
    # 3. 비활성 계정 차단
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="비활성화된 계정입니다."
        )

    # 4. JWT 인증 토큰 발급 (SFR-002 대응)
    access_token = create_access_token(data={"sub": user.user_id, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
def read_current_user(current_user: models.User = Depends(get_current_user)):
    return {
        "user_id": current_user.user_id,
        "role": current_user.role,
        "is_active": current_user.is_active,
    }