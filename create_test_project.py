import models
from database import SessionLocal
from datetime import datetime

db = SessionLocal()
try:
    if not db.query(models.Project).filter_by(project_id=1).first():
        test_project = models.Project(
            project_id=1,
            name="토이프로젝트 테스트 대상",
            description="초기 분석 대상 시스템 테스트",
            source_type="NONE",
            target_language="Python", # Python 코드를 테스트로 업로드 가정
            source_path=""
        )
        db.add(test_project)
        db.commit()
        print("테스트용 프로젝트(ID: 1, 언어: Python)가 생성되었습니다.")
finally:
    db.close()