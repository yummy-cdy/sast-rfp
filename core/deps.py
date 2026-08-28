from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

import models
from database import get_db
from core.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """SEC-002: 유효한 인증 정보가 없는 요청은 차단한다."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증이 필요합니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if payload is None or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않거나 만료된 인증 수단입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(models.User).filter(models.User.user_id == payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="계정을 확인할 수 없습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    """SEC-003: 관리자 전용 기능 통제."""
    if user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="관리자 권한이 필요합니다."
        )
    return user


def require_project_access(
    project_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> models.Project:
    """SEC-005/006: 요청 식별자만 신뢰하지 않고 저장된 권한 관계로 접근을 검증한다.
    권한 없는 경우 프로젝트 존재 여부가 드러나지 않도록 404로 응답한다."""
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="프로젝트를 찾을 수 없습니다.")

    if user.role == "ADMIN":
        return project

    has_permission = (
        db.query(models.ProjectPermission)
        .filter(
            models.ProjectPermission.project_id == project_id,
            models.ProjectPermission.user_id == user.user_id,
        )
        .first()
    )
    if not has_permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="프로젝트를 찾을 수 없습니다.")
    return project
