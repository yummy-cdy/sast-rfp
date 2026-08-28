import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get(
    "SAST_DATABASE_URL", "mysql+pymysql://root:root@127.0.0.1:3306/sast_db"
)

JWT_SECRET_KEY = os.environ.get(
    "SAST_JWT_SECRET_KEY", "dev-only-insecure-secret-set-SAST_JWT_SECRET_KEY-env-var"
)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# SEC-009: 분석 실행 자원 고갈 방지
ANALYSIS_TIMEOUT_SECONDS = int(os.environ.get("SAST_ANALYSIS_TIMEOUT_SECONDS", "120"))

# SEC-007/008: 업로드 압축 해제 한도 (zip bomb 방지)
MAX_ZIP_MEMBER_COUNT = int(os.environ.get("SAST_MAX_ZIP_MEMBER_COUNT", "5000"))
MAX_UNCOMPRESSED_TOTAL_BYTES = int(
    os.environ.get("SAST_MAX_UNCOMPRESSED_TOTAL_BYTES", str(200 * 1024 * 1024))
)
MAX_UNCOMPRESSED_FILE_BYTES = int(
    os.environ.get("SAST_MAX_UNCOMPRESSED_FILE_BYTES", str(20 * 1024 * 1024))
)
MAX_COMPRESSION_RATIO = int(os.environ.get("SAST_MAX_COMPRESSION_RATIO", "100"))
