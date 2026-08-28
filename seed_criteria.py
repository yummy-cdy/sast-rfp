import models
from database import SessionLocal
from engine.kisa_catalog import catalog_rows


def seed_criteria():
    db = SessionLocal()
    try:
        for row in catalog_rows():
            existing = (
                db.query(models.DiagnosticCriteria)
                .filter(models.DiagnosticCriteria.criteria_id == row["criteria_id"])
                .first()
            )
            if existing:
                for key, value in row.items():
                    setattr(existing, key, value)
            else:
                db.add(models.DiagnosticCriteria(**row))
        db.commit()
        print(f"KISA 진단 기준 카탈로그 {len(catalog_rows())}개 항목이 등록/갱신되었습니다.")
    finally:
        db.close()


if __name__ == "__main__":
    seed_criteria()
