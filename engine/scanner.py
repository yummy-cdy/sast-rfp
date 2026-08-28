import os
import time

from engine.parser import language_for_extension, parse_source, read_source_bytes
from engine.registry import get_rules_for_language


class AnalysisTimeoutError(Exception):
    """SEC-009: 분석 실행 시간이 허용 한도를 초과했다."""


def scan_file(file_path: str, language: str) -> list[dict]:
    source_bytes = read_source_bytes(file_path)
    if source_bytes is None:
        return []

    tree = parse_source(source_bytes, language)
    rules = get_rules_for_language(language)

    results: list[dict] = []
    for rule in rules:
        for finding in rule.find(tree, source_bytes, file_path, language):
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

            all_results.extend(scan_file(file_path, language))

    return all_results
