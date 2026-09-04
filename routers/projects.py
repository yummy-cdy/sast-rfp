import os
import shutil
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from database import get_db
from core.deps import get_current_user, require_admin, require_project_access

router = APIRouter(prefix="/api/projects", tags=["Projects"])

SUPPORTED_LANGUAGES = Literal["Python", "Java", "Javascript"]


class ProjectCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = None
    target_language: SUPPORTED_LANGUAGES


class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = None
    target_language: Optional[SUPPORTED_LANGUAGES] = None


class ProjectOut(BaseModel):
    project_id: int
    name: str
    description: Optional[str]
    source_type: str
    target_language: str
    source_path: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PermissionGrantRequest(BaseModel):
    user_id: str


# SFR-004: 시스템 관리자는 분석 대상 프로젝트의 기본 정보를 등록할 수 있어야 한다.
@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    request: ProjectCreateRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    project = models.Project(
        name=request.name,
        description=request.description,
        source_type="NONE",
        target_language=request.target_language,
        source_path="",
        created_by=current_user.user_id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


# SFR-006: 일반 사용자는 권한이 부여된 프로젝트만, 관리자는 전체를 조회.
@router.get("", response_model=list[ProjectOut])
def list_projects(
    db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)
):
    if current_user.role == "ADMIN":
        return db.query(models.Project).order_by(models.Project.project_id).all()

    return (
        db.query(models.Project)
        .join(
            models.ProjectPermission,
            models.ProjectPermission.project_id == models.Project.project_id,
        )
        .filter(models.ProjectPermission.user_id == current_user.user_id)
        .order_by(models.Project.project_id)
        .all()
    )


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project: models.Project = Depends(require_project_access)):
    return project


# SFR-004: 시스템 관리자는 프로젝트 기본 정보를 수정할 수 있어야 한다.
@router.put("/{project_id}", response_model=ProjectOut)
def update_project(
    request: ProjectUpdateRequest,
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="프로젝트를 찾을 수 없습니다.")

    if request.name is not None:
        project.name = request.name
    if request.description is not None:
        project.description = request.description
    if request.target_language is not None:
        project.target_language = request.target_language
    db.commit()
    db.refresh(project)
    return project


# SFR-004: 시스템 관리자는 프로젝트를 삭제할 수 있어야 한다.
@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="프로젝트를 찾을 수 없습니다.")

    execution_ids = [
        row.execution_id
        for row in db.query(models.AnalysisExecution.execution_id)
        .filter(models.AnalysisExecution.project_id == project_id)
        .all()
    ]
    if execution_ids:
        db.query(models.DiagnosticResult).filter(
            models.DiagnosticResult.execution_id.in_(execution_ids)
        ).delete(synchronize_session=False)
    db.query(models.AnalysisExecution).filter(
        models.AnalysisExecution.project_id == project_id
    ).delete(synchronize_session=False)
    db.query(models.ProjectPermission).filter(
        models.ProjectPermission.project_id == project_id
    ).delete(synchronize_session=False)

    source_path = project.source_path
    db.delete(project)
    db.commit()

    if source_path and os.path.isdir(source_path):
        try:
            shutil.rmtree(source_path)
        except OSError:
            # 동기화 클라이언트(OneDrive 등)의 파일 잠금 등으로 삭제가 실패해도
            # DB 상 프로젝트 삭제는 이미 완료된 상태이므로 그대로 둔다.
            pass

    return None


# SFR-005/DAR-004: 프로젝트별 사용자 접근 권한 부여/해제/조회 (관리자 전용, SEC-003)
@router.get("/{project_id}/permissions", response_model=list[str])
def list_project_permissions(
    project_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="프로젝트를 찾을 수 없습니다.")

    rows = (
        db.query(models.ProjectPermission)
        .filter(models.ProjectPermission.project_id == project_id)
        .all()
    )
    return [row.user_id for row in rows]


@router.post("/{project_id}/permissions", status_code=status.HTTP_201_CREATED)
def grant_project_permission(
    project_id: int,
    request: PermissionGrantRequest,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="프로젝트를 찾을 수 없습니다.")

    target_user = db.query(models.User).filter(models.User.user_id == request.user_id).first()
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다.")

    existing = (
        db.query(models.ProjectPermission)
        .filter(
            models.ProjectPermission.project_id == project_id,
            models.ProjectPermission.user_id == request.user_id,
        )
        .first()
    )
    if existing:
        return {"message": "이미 권한이 부여되어 있습니다."}

    db.add(models.ProjectPermission(project_id=project_id, user_id=request.user_id))
    db.commit()
    return {"message": "권한이 부여되었습니다."}


@router.delete("/{project_id}/permissions/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_project_permission(
    project_id: int,
    user_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    row = (
        db.query(models.ProjectPermission)
        .filter(
            models.ProjectPermission.project_id == project_id,
            models.ProjectPermission.user_id == user_id,
        )
        .first()
    )
    if row:
        db.delete(row)
        db.commit()
    return None
