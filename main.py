from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response

import os

from routers import auth, analysis, projects, users, criteria

# DAR-001: 스키마는 Alembic 마이그레이션으로 관리한다 (alembic upgrade head).
# 최초 구동 전 반드시 `alembic upgrade head`를 실행할 것.


class NoCacheStaticFiles(StaticFiles):
    """정적 자산(html/js/css)을 수정할 때마다 브라우저가 옛 버전을 계속 쓰는
    문제를 막기 위해 캐시를 비활성화한다. 매 요청 디스크 조회 비용은 이
    프로젝트 규모에서는 무시할 수준이다."""

    def file_response(self, *args, **kwargs) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-store"
        return response


app = FastAPI(title="SAST Program API")

# 라우터 등록
app.include_router(auth.router)
app.include_router(analysis.router)
app.include_router(analysis.executions_router)
app.include_router(projects.router)
app.include_router(users.router)
app.include_router(criteria.router)

os.makedirs("static", exist_ok=True)
app.mount("/static", NoCacheStaticFiles(directory="static"), name="static")

# 루트 접속 시 index.html 반환
@app.get("/")
def read_root():
    return FileResponse("static/index.html")