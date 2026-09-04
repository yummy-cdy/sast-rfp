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
        evidence, context_start_line = _extract_context(node, source)
        return Finding(
            criteria_id=self.criteria_id,
            criteria_name=self.criteria_name,
            severity=self.severity,
            file_path=file_path,
            line_number=node.start_point[0] + 1,
            column=node.start_point[1],
            message=self.message,
            evidence=evidence[:3000],
            recommendation=self.recommendation,
            raw_result={
                "node_type": node.type,
                "start_point": list(node.start_point),
                "end_point": list(node.end_point),
                "language": language,
                # 근거(evidence)에서 실제 탐지 줄이 몇 번째 줄인지 프론트에서
                # 강조 표시할 수 있도록, 근거 텍스트의 시작 줄 번호를 같이 내려준다.
                "context_start_line": context_start_line,
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
# 프레임워크별 요청 객체(req/request/params)뿐 아니라 환경변수/커맨드라인 등
# 자주 쓰이는 신뢰 경계 진입점도 함께 취급한다.
DEFAULT_TAINT_SOURCES = {
    "request", "req", "params", "environ", "argv",
}

_FUNCTION_LIKE_TYPES = {
    "function_definition",  # Python
    "function_declaration", "method_definition", "arrow_function", "function_expression",  # Javascript
    "method_declaration", "constructor_declaration",  # Java
}
_ASSIGNMENT_LIKE_TYPES = {"assignment", "variable_declarator", "assignment_expression"}


def _contains_identifier(node, names: set[str]) -> bool:
    if node.type == "identifier" and node.text.decode("utf-8", errors="replace") in names:
        return True
    return any(_contains_identifier(child, names) for child in node.children)


# 언어별 "{}"/들여쓰기 블록 노드 타입 — 근거(evidence)를 한 줄이 아니라
# 탐지된 지점을 감싸는 블록 단위로 보여주기 위해 사용한다.
_BLOCK_TYPES = {"block", "statement_block"}  # Python(들여쓰기)/Java/Javascript 전부 이 이름을 씀
_MAX_CONTEXT_LINES = 25


def _find_enclosing_block(node):
    current = node.parent
    while current is not None:
        if current.type in _BLOCK_TYPES:
            return current
        current = current.parent
    return None


def _extract_context(node, source: bytes) -> tuple[str, int]:
    """탐지된 노드를 감싸는 블록 단위로 근거를 추출한다. 블록을 찾을 수 없으면(예:
    모듈 최상위 문장) 노드 자체의 텍스트를 사용한다. 블록이 너무 크면 탐지된 줄
    주변으로 잘라낸다. (근거 텍스트, 그 첫 줄의 1-indexed 줄 번호)를 반환한다."""
    block = _find_enclosing_block(node)
    if block is None:
        text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
        return text.strip(), node.start_point[0] + 1

    start_line = block.start_point[0]
    end_line = block.end_point[0]
    node_line = node.start_point[0]

    if end_line - start_line + 1 > _MAX_CONTEXT_LINES:
        half = _MAX_CONTEXT_LINES // 2
        start_line = max(start_line, node_line - half)
        end_line = min(end_line, node_line + half)

    lines = source.decode("utf-8", errors="replace").splitlines()
    snippet = "\n".join(lines[start_line : end_line + 1])
    return snippet.strip("\n"), start_line + 1


def _find_enclosing_scope(node):
    """node를 감싸는 가장 가까운 함수/메서드 노드. 없으면 최상위(root) 노드."""
    current = node.parent
    while current is not None:
        if current.type in _FUNCTION_LIKE_TYPES:
            return current
        if current.parent is None:
            return current
        current = current.parent
    return node


def _last_assigned_value(scope_node, name: str):
    """scope_node 서브트리 안에서 식별자 name에 마지막으로 대입된 우변 노드를 찾는다.
    (같은 스코프 내 단순 재대입만 추적하는 얕은 분석: 조건/루프에 따른 실제 실행
    순서는 고려하지 않고, 트리 순회 순서상 마지막 대입을 사용한다.)"""
    result = None

    def walk(node):
        nonlocal result
        if node.type in _ASSIGNMENT_LIKE_TYPES:
            left = node.child_by_field_name("left") or node.child_by_field_name("name")
            right = node.child_by_field_name("right") or node.child_by_field_name("value")
            if left is not None and right is not None and left.type == "identifier":
                if left.text.decode("utf-8", errors="replace") == name:
                    result = right
        for child in node.children:
            walk(child)

    walk(scope_node)
    return result


def _collect_identifier_names(node) -> set[str]:
    names: set[str] = set()

    def walk(n):
        if n.type == "identifier":
            names.add(n.text.decode("utf-8", errors="replace"))
        for child in n.children:
            walk(child)

    walk(node)
    return names


# Spring MVC 등에서 파라미터를 요청값으로 바인딩하는 대표적 어노테이션
_REQUEST_PARAM_ANNOTATIONS = {
    "RequestParam", "PathVariable", "RequestBody", "ModelAttribute", "CookieValue", "RequestHeader",
}


def _is_annotated_request_param(scope_node, name: str) -> bool:
    """scope_node(Java 메서드)의 파라미터 중 name과 이름이 같고 @RequestParam 등
    요청 바인딩 어노테이션이 붙은 것이 있는지 확인한다."""
    if scope_node is None or scope_node.type != "method_declaration":
        return False
    params = scope_node.child_by_field_name("parameters")
    if params is None:
        return False
    for param in params.children:
        if param.type != "formal_parameter":
            continue
        pname = param.child_by_field_name("name")
        if pname is None or pname.text.decode("utf-8", errors="replace") != name:
            continue
        modifiers = next((c for c in param.children if c.type == "modifiers"), None)
        if modifiers is None:
            continue
        for mod in modifiers.children:
            if mod.type not in ("annotation", "marker_annotation"):
                continue
            ann_name = mod.child_by_field_name("name")
            if ann_name is not None and ann_name.text.decode("utf-8", errors="replace") in _REQUEST_PARAM_ANNOTATIONS:
                return True
    return False


def _is_tainted(node, names: set[str], _depth: int = 0, _resolving: set[str] | None = None) -> bool:
    """node 서브트리가 taint source를 직접 포함하거나, 같은 함수 스코프 내에서
    taint source로부터 대입된 지역 변수를 거쳐 오염되는 경우까지 탐지한다
    (최대 3단계 변수 대입 추적). Java의 경우 @RequestParam 등으로 요청값이
    바인딩된 메서드 파라미터도 taint source로 취급한다."""
    if _contains_identifier(node, names):
        return True
    if _depth >= 3:
        return False
    resolving = _resolving if _resolving is not None else set()
    scope = _find_enclosing_scope(node)
    for ident in _collect_identifier_names(node):
        if ident in names or ident in resolving:
            continue
        if _is_annotated_request_param(scope, ident):
            return True
        resolved = _last_assigned_value(scope, ident)
        if resolved is None:
            continue
        resolving.add(ident)
        if _is_tainted(resolved, names, _depth + 1, resolving):
            return True
    return False


class TaintedArgumentRule(Rule):
    """QUERIES가 "target"(호출식 전체)과 "args"(인자 목록) 캡처를 갖는 룰 전용.
    인자 서브트리에 외부 입력으로 추정되는 식별자가 직접 있거나, 같은 함수 스코프
    내에서 그런 값을 대입받은 지역 변수를 거쳐 전달되는 경우에도 탐지한다."""

    taint_sources: set[str] = DEFAULT_TAINT_SOURCES

    def find(self, tree: Tree, source: bytes, file_path: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            args_nodes = captures.get("args")
            if not target_nodes or not args_nodes:
                continue
            if not any(_is_tainted(n, self.taint_sources) for n in args_nodes):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings


_CONCAT_EXPR_TYPES = {"Python": "binary_operator", "Java": "binary_expression", "Javascript": "binary_expression"}
_TEMPLATE_STRING_TYPES = {
    "Python": ("string", "interpolation"),
    "Javascript": ("template_string", "template_substitution"),
}


def _is_risky_string_build(node, language: str) -> bool:
    """문자열 결합(+ 연산) 또는 보간 문자열(f-string/template literal)인지 확인한다."""
    if node.type == _CONCAT_EXPR_TYPES.get(language):
        return True
    template = _TEMPLATE_STRING_TYPES.get(language)
    if template and node.type == template[0]:
        return any(child.type == template[1] for child in node.children)
    return False


class ConcatenatedArgumentRule(Rule):
    """QUERIES의 "target" 캡처가 문자열 결합/보간식 자체이거나, 같은 함수 스코프
    내에서 마지막으로 그런 값을 대입받은 지역 변수(단일 identifier)인 경우에만
    탐지한다. SQL/XQuery/LDAP 인젝션처럼 "쿼리를 변수에 먼저 만들고 나중에
    실행 함수에 넘기는" 간접 패턴까지 잡기 위한 것으로, 대입값이 결합/보간식이
    아닌 경우(바인딩 변수 등 안전한 패턴)는 매칭하지 않는다."""

    def find(self, tree: Tree, source: bytes, file_path: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            if not target_nodes:
                continue
            node = target_nodes[0]
            check_node = node
            if node.type == "identifier":
                scope = _find_enclosing_scope(node)
                resolved = _last_assigned_value(scope, node.text.decode("utf-8", errors="replace"))
                if resolved is None:
                    continue
                check_node = resolved
            if not _is_risky_string_build(check_node, language):
                continue
            findings.append(self._build_finding(node, source, file_path, language))
        return findings
