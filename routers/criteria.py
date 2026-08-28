from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

import models
from database import get_db
from core.deps import get_current_user

router = APIRouter(prefix="/api/criteria", tags=["Criteria"])


# SFR-013/TST-006: KISA 49개 진단 기준 카탈로그 조회 (인증된 사용자 누구나 조회 가능)
@router.get("")
def list_criteria(
    category: Optional[str] = None,
    implementation_status: Optional[str] = None,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    query = db.query(models.DiagnosticCriteria)
    if category:
        query = query.filter(models.DiagnosticCriteria.category == category)
    if implementation_status:
        query = query.filter(
            models.DiagnosticCriteria.implementation_status == implementation_status
        )
    return query.order_by(models.DiagnosticCriteria.criteria_id).all()
