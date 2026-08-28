import models
from database import SessionLocal
from core.security import get_password_hash

def create_admin():
    db = SessionLocal()
    try:
        # 기존 admin 계정 존재 여부 확인
        existing_user = db.query(models.User).filter(models.User.user_id == "admin").first()
        if existing_user:
            print("관리자 계정이 이미 존재합니다.")
            return

        # 단방향 암호화된 비밀번호 생성
        hashed_pw = get_password_hash("admin1234!")
        
        # 신규 계정 객체 생성
        admin_user = models.User(
            user_id="admin",
            password_hash=hashed_pw,
            role="ADMIN",
            is_active=True
        )
        
        # DB에 저장
        db.add(admin_user)
        db.commit()
        print("테스트용 관리자 계정(ID: admin, PW: admin1234!)이 생성되었습니다.")
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()