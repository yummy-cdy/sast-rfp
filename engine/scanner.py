import os
import time

from engine.parser import language_for_extension, parse_source, read_source_bytes
from engine.registry import get_rules_for_language


class AnalysisTimeoutError(Exception):
    """SEC-009: 분석 실행 시간이 허용 한도를 초과했다."""


# 압축/번들링(minify)된 코드로 보이는 파일을 걸러내기 위한 임계값.
# 이런 파일은 사람이 작성한 소스가 아니라 서드파티 라이브러리 산출물(예: Monaco
# Editor, webpack/vite 번들)인 경우가 대부분이라, 구조 분석 결과가 무의미하고
# (단일 문자로 축약된 변수명 등) 근거에 읽을 수 있는 코드 맥락을 담을 수 없다.
_MINIFIED_MAX_LINE_LEN = 2000
_MINIFIED_AVG_LINE_LEN = 500


def _looks_minified(source_bytes: bytes) -> bool:
    if not source_bytes:
        return False
    text = source_bytes.decode("utf-8", errors="replace")
    lines = text.split("\n")
    if not lines:
        return False
    max_line_len = max(len(line) for line in lines)
    avg_line_len = len(text) / len(lines)
    return max_line_len > _MINIFIED_MAX_LINE_LEN or avg_line_len > _MINIFIED_AVG_LINE_LEN


# 널리 쓰이는 서드파티/빌드 산출물 디렉터리 이름 — 대부분의 린터/SAST 도구가
# 기본적으로 제외하는 관례를 따른다. 사용자가 작성하지 않은 코드를 진단 대상에서
# 뺀다 (예: 프런트엔드 프로젝트에 그대로 커밋된 라이브러리 번들).
_VENDOR_DIR_NAMES = {"node_modules", "vendor", "vendors", "dist", "build", "third_party", "thirdparty"}


def _is_vendor_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    if any(part.lower() in _VENDOR_DIR_NAMES for part in parts[:-1]):
        return True
    filename = parts[-1].lower()
    return ".min." in filename


def scan_file(file_path: str, language: str, display_path: str | None = None) -> list[dict]:
    source_bytes = read_source_bytes(file_path)
    if source_bytes is None:
        return []
    if _looks_minified(source_bytes):
        return []

    tree = parse_source(source_bytes, language)
    rules = get_rules_for_language(language)
    reported_path = display_path if display_path is not None else file_path

    results: list[dict] = []
    for rule in rules:
        for finding in rule.find(tree, source_bytes, reported_path, language):
            results.append(
                {
                    "criteria_id": finding.criteria_id,
                    "criteria_name": finding.criteria_name,
                    "severity": finding.severity,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "message": finding.message,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                    "raw_result": finding.raw_result,
                }
            )
    return results


def run_analysis(source_dir: str, target_language: str, timeout_seconds: float | None = None) -> list[dict]:
    """SFR-009: 소스 수집 -> 코드 구조 분석(tree-sitter AST) -> 진단 항목 실행 -> 결과 정규화.
    SFR-011: target_language(Python/Java/Javascript)에 해당하는 확장자 파일만 구조 기반으로 분석한다.
    SEC-009: timeout_seconds 초과 시 AnalysisTimeoutError를 발생시켜 장기 실행을 방지한다."""
    deadline = time.monotonic() + timeout_seconds if timeout_seconds else None
    all_results: list[dict] = []

    # 분석 작업 영역 격리(SEC-007): 지정된 폴더 하위만 순회
    for root, _, files in os.walk(source_dir):
        for file in files:
            if deadline is not None and time.monotonic() > deadline:
                raise AnalysisTimeoutError(f"분석 시간이 {timeout_seconds}초를 초과했습니다.")

            file_path = os.path.join(root, file)
            extension = os.path.splitext(file)[1]
            language = language_for_extension(extension)
            if language != target_language:
                continue

            # 결과 화면/DB에 로컬 서버의 절대 경로가 그대로 노출되지 않도록,
            # 업로드 소스 루트 기준 상대 경로로 저장한다.
            display_path = os.path.relpath(file_path, source_dir)
            if _is_vendor_path(display_path):
                continue
            all_results.extend(scan_file(file_path, language, display_path))

    return all_results
