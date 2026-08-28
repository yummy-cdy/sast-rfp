from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Tree

from engine.parser import get_language


@dataclass
class Finding:
    criteria_id: str
    criteria_name: str
    severity: str
    file_path: str
    line_number: int
    column: int
    message: str
    evidence: str
    recommendation: str
    raw_result: dict = field(default_factory=dict)


class Rule:
    """진단 항목 1개 = 서브클래스 1개 (QLT-002: 독립적 추가/수정/시험).

    쿼리 기반 룰은 QUERIES 딕셔너리(언어별 tree-sitter S-expression 쿼리)만 정의하면
    match()가 자동으로 실행된다. 매칭 방식이 특수한 룰은 find()를 직접 오버라이드한다.
    캡처 이름이 "target"인 노드를 탐지 위치/근거로 사용한다.
    """

    criteria_id: str = ""
    criteria_name: str = ""
    category: str = ""
    languages: list[str] = []
    severity: str = "Medium"
    message: str = ""
    recommendation: str = ""

    # {language: tree-sitter query string}
    QUERIES: dict[str, str] = {}

    def _run_query(self, tree: Tree, language: str):
        query_str = self.QUERIES.get(language)
        if not query_str:
            return []
        ts_language = get_language(language)
        query = ts_language.query(query_str)
        return query.matches(tree.root_node)

    def _build_finding(self, node, source: bytes, file_path: str, language: str) -> Finding:
        evidence = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
        return Finding(
            criteria_id=self.criteria_id,
            criteria_name=self.criteria_name,
            severity=self.severity,
            file_path=file_path,
            line_number=node.start_point[0] + 1,
            column=node.start_point[1],
            message=self.message,
            evidence=evidence.strip()[:500],
            recommendation=self.recommendation,
            raw_result={
                "node_type": node.type,
                "start_point": list(node.start_point),
                "end_point": list(node.end_point),
                "language": language,
            },
        )

    def find(self, tree: Tree, source: bytes, file_path: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            if not target_nodes:
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings


# 외부 입력으로 추정되는 식별자명 (경로조작/SSRF/Open Redirect 등 유사 패턴에서 공통 사용)
DEFAULT_TAINT_SOURCES = {"request", "req", "params"}


def _contains_identifier(node, names: set[str]) -> bool:
    if node.type == "identifier" and node.text.decode("utf-8", errors="replace") in names:
        return True
    return any(_contains_identifier(child, names) for child in node.children)


class TaintedArgumentRule(Rule):
    """QUERIES가 "target"(호출식 전체)과 "args"(인자 목록) 캡처를 갖는 룰 전용.
    인자 서브트리에 외부 입력으로 추정되는 식별자가 포함된 경우에만 탐지한다."""

    taint_sources: set[str] = DEFAULT_TAINT_SOURCES

    def find(self, tree: Tree, source: bytes, file_path: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            args_nodes = captures.get("args")
            if not target_nodes or not args_nodes:
                continue
            if not any(_contains_identifier(n, self.taint_sources) for n in args_nodes):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings
