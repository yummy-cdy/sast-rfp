import os
import shutil
import stat
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

import models
from database import get_db
from engine.scanner import run_analysis, AnalysisTimeoutError
from core.deps import get_current_user, require_admin, require_project_access
from core.config import (
    ANALYSIS_TIMEOUT_SECONDS,
    MAX_ZIP_MEMBER_COUNT,
    MAX_UNCOMPRESSED_TOTAL_BYTES,
    MAX_UNCOMPRESSED_FILE_BYTES,
    MAX_COMPRESSION_RATIO,
)

router = APIRouter(prefix="/api/projects", tags=["Analysis"])
executions_router = APIRouter(prefix="/api/executions", tags=["Analysis"])

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

_analysis_executor = ThreadPoolExecutor(max_workers=2)


def _is_symlink_entry(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _validate_and_extract_zip(zip_path: str, project_dir: str) -> None:
    """SEC-007/008: 경로 조작, 심볼릭 링크, zip bomb을 방지하며 안전하게 압축을 해제한다."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            infolist = zip_ref.infolist()

            if len(infolist) > MAX_ZIP_MEMBER_COUNT:
                raise HTTPException(status_code=400, detail="압축 파일 내 항목 개수가 허용 한도를 초과합니다.")

            total_uncompressed = 0
            for info in infolist:
                member = info.filename

                if os.path.isabs(member) or ":" in member:
                    raise HTTPException(status_code=400, detail="경로 조작이 의심되는 파일이 포함되어 있습니다.")

                normalized = os.path.normpath(member)
                if normalized.startswith("..") or normalized.startswith(os.sep):
                    raise HTTPException(status_code=400, detail="경로 조작이 의심되는 파일이 포함되어 있습니다.")

                if _is_symlink_entry(info):
                    raise HTTPException(status_code=400, detail="심볼릭 링크 항목은 허용되지 않습니다.")

                member_path = os.path.abspath(os.path.join(project_dir, member))
                try:
                    if os.path.commonpath([project_dir, member_path]) != project_dir:
                        raise HTTPException(status_code=400, detail="경로 조작이 의심되는 파일이 포함되어 있습니다.")
                except ValueError:
                    raise HTTPException(status_code=400, detail="경로 조작이 의심되는 파일이 포함되어 있습니다.")

                if info.file_size > MAX_UNCOMPRESSED_FILE_BYTES:
                    raise HTTPException(status_code=400, detail="개별 파일 크기가 허용 한도를 초과합니다.")

                if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    raise HTTPException(status_code=400, detail="비정상적으로 높은 압축률이 감지되었습니다(zip bomb 의심).")

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_TOTAL_BYTES:
                    raise HTTPException(status_code=400, detail="압축 해제 총 용량이 허용 한도를 초과합니다.")

            for info in infolist:
                zip_ref.extract(info, project_dir)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="유효하지 않은 압축 파일입니다.")


# SFR-007/008: 관리자만 분석 대상 소스를 등록/실행할 수 있다 (SEC-003).
@router.post("/{project_id}/source")
def upload_source(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="프로젝트를 찾을 수 없습니다.")

    # 분석 작업 영역 격리 (SEC-007)
    project_dir = os.path.abspath(os.path.join(UPLOAD_DIR, f"project_{project_id}"))
    if os.path.exists(project_dir):
        try:
            shutil.rmtree(project_dir)
        except OSError:
            # 동기화 클라이언트(OneDrive 등)의 파일 잠금 등으로 삭제가 실패하면
            # 기존 디렉터리는 그대로 두고 새로운 격리 디렉터리를 사용한다.
            project_dir = f"{project_dir}_{int(time.time())}"
    os.makedirs(project_dir, exist_ok=True)

    zip_path = os.path.join(project_dir, file.filename)
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        _validate_and_extract_zip(zip_path, project_dir)
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)

    project.source_path = project_dir
    project.source_type = "ZIP_UPLOAD"
    db.commit()

    return {"message": "소스코드 업로드 및 격리 해제가 완료되었습니다.", "source_path": project_dir}


@router.post("/{project_id}/analyze")
def execute_analysis(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
    if not project or not project.source_path:
        raise HTTPException(status_code=400, detail="소스코드가 등록되지 않았습니다.")

    # SFR-015: 대기(WAIT) 상태로 실행 건 생성
    execution = models.AnalysisExecution(
        project_id=project.project_id,
        engine_type="TREE_SITTER_AST_v1",
        target_language=project.target_language,
        status="WAIT",
        executed_by=current_user.user_id,
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    # 진행(PROG) 상태로 전환 후 엔진 호출 (SFR-009)
    execution.status = "PROG"
    execution.start_time = datetime.utcnow()
    db.commit()

    try:
        future = _analysis_executor.submit(
            run_analysis, project.source_path, project.target_language, ANALYSIS_TIMEOUT_SECONDS
        )
        try:
            scan_results = future.result(timeout=ANALYSIS_TIMEOUT_SECONDS + 5)
        except FutureTimeoutError:
            raise AnalysisTimeoutError(f"분석 시간이 {ANALYSIS_TIMEOUT_SECONDS}초를 초과했습니다.")

        severity_counts: dict[str, int] = {}
        for res in scan_results:
            db_result = models.DiagnosticResult(
                execution_id=execution.execution_id,
                criteria_id=res["criteria_id"],
                criteria_name=res["criteria_name"],
                standard_id="KISA-SW-SEC-GUIDE",
                target_language=project.target_language,
                severity=res["severity"],
                confidence="CERTAIN",
                file_path=res["file_path"],
                message=res["message"],
                evidence=res["evidence"],
                recommendation=res.get("recommendation"),
                raw_result=res.get("raw_result"),
            )
            db.add(db_result)
            severity_counts[res["severity"]] = severity_counts.get(res["severity"], 0) + 1

        execution.status = "COMP"
        execution.end_time = datetime.utcnow()
        execution.summary = {"findings_count": len(scan_results), "by_severity": severity_counts}
        db.commit()

        return {
            "message": "정적 분석이 완료되었습니다.",
            "execution_id": execution.execution_id,
            "findings_count": len(scan_results),
        }

    except Exception as e:
        execution.status = "FAIL"
        execution.error_info = str(e)
        execution.end_time = datetime.utcnow()
        db.commit()
        raise HTTPException(status_code=500, detail=f"분석 중 오류 발생: {str(e)}")


# SFR-016: 프로젝트별 분석 이력 조회 (권한 있는 사용자, SEC-004/005)
@router.get("/{project_id}/executions")
def list_executions(
    project: models.Project = Depends(require_project_access),
    db: Session = Depends(get_db),
):
    executions = (
        db.query(models.AnalysisExecution)
        .filter(models.AnalysisExecution.project_id == project.project_id)
        .order_by(models.AnalysisExecution.execution_id.desc())
        .all()
    )
    return executions


@router.get("/{project_id}/results")
def get_analysis_results(
    project: models.Project = Depends(require_project_access),
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    execution = (
        db.query(models.AnalysisExecution)
        .filter(
            models.AnalysisExecution.project_id == project.project_id,
            models.AnalysisExecution.status == "COMP",
        )
        .order_by(models.AnalysisExecution.execution_id.desc())
        .first()
    )

    if not execution:
        return []

    query = db.query(models.DiagnosticResult).filter(
        models.DiagnosticResult.execution_id == execution.execution_id
    )

    # SFR-017: 심각도 등 주요 속성 필터
    if severity:
        query = query.filter(models.DiagnosticResult.severity == severity)

    return query.all()


# SFR-016: 실행 건 상세 조회 (상태/오류정보 등). 권한 있는 사용자만 조회 가능 (SEC-009).
@executions_router.get("/{execution_id}")
def get_execution_detail(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    execution = (
        db.query(models.AnalysisExecution)
        .filter(models.AnalysisExecution.execution_id == execution_id)
        .first()
    )
    if not execution:
        raise HTTPException(status_code=404, detail="분석 실행 건을 찾을 수 없습니다.")

    # SEC-005/006: 프로젝트 소속 검증 (요청 식별자만 신뢰하지 않음)
    require_project_access(project_id=execution.project_id, db=db, user=current_user)
    return execution


@executions_router.get("/{execution_id}/results")
def get_execution_results(
    execution_id: int,
    severity: Optional[str] = None,
    criteria_id: Optional[str] = None,
    confidence: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    execution = (
        db.query(models.AnalysisExecution)
        .filter(models.AnalysisExecution.execution_id == execution_id)
        .first()
    )
    if not execution:
        raise HTTPException(status_code=404, detail="분석 실행 건을 찾을 수 없습니다.")

    require_project_access(project_id=execution.project_id, db=db, user=current_user)

    query = db.query(models.DiagnosticResult).filter(
        models.DiagnosticResult.execution_id == execution_id
    )
    if severity:
        query = query.filter(models.DiagnosticResult.severity == severity)
    if criteria_id:
        query = query.filter(models.DiagnosticResult.criteria_id == criteria_id)
    if confidence:
        query = query.filter(models.DiagnosticResult.confidence == confidence)

    return query.all()
