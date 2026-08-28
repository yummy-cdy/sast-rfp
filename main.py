from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import os

from routers import auth, analysis, projects, users, criteria

# DAR-001: 스키마는 Alembic 마이그레이션으로 관리한다 (alembic upgrade head).
# 최초 구동 전 반드시 `alembic upgrade head`를 실행할 것.

app = FastAPI(title="SAST Program API")

# 라우터 등록
app.include_router(auth.router)
app.include_router(analysis.router)
app.include_router(analysis.executions_router)
app.include_router(projects.router)
app.include_router(users.router)
app.include_router(criteria.router)

os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# 루트 접속 시 index.html 반환
@app.get("/")
def read_root():
    return FileResponse("static/index.html")