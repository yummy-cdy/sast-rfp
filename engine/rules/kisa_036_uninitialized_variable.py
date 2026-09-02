import re

from engine.base_rule import Rule

_ASSIGN_RE = re.compile(r"^\s*(\w+)\s*=[^=]")


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class UninitializedVariableJsRule(Rule):
    """초기값 없이 선언된 변수를 대입 없이 바로 다음 문장에서 사용하는 패턴을 탐지한다."""

    criteria_id = "KISA-036"
    criteria_name = "초기화되지 않은 변수 사용"
    category = "코드오류"
    languages = ["Javascript"]
    severity = "Low"
    message = "초기값 없이 선언된 변수가 대입되기 전에 곧바로 사용되고 있어 undefined 값을 참조할 수 있습니다."
    recommendation = "변수 선언 시 초기값을 지정하거나, 사용하기 전에 반드시 값을 대입하십시오."
    QUERIES = {}

    def find(self, tree, source, file_path, language):
        findings = []
        self._scan(tree.root_node, source, file_path, findings)
        return findings

    def _scan(self, node, source, file_path, findings):
        if node.type in ("program", "statement_block"):
            children = [c for c in node.children if c.is_named]
            for i, child in enumerate(children):
                if child.type != "lexical_declaration":
                    continue
                for declarator in child.named_children:
                    if declarator.type != "variable_declarator":
                        continue
                    if declarator.child_by_field_name("value") is not None:
                        continue
                    name_node = declarator.child_by_field_name("name")
                    if name_node is None or i + 1 >= len(children):
                        continue
                    name = source[name_node.start_byte : name_node.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                    next_stmt = children[i + 1]
                    next_text = source[next_stmt.start_byte : next_stmt.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                    assign_match = _ASSIGN_RE.match(next_text.strip())
                    if assign_match and assign_match.group(1) == name:
                        continue
                    if re.search(rf"\b{re.escape(name)}\b", next_text):
                        findings.append(
                            self._build_finding(next_stmt, source, file_path, "Javascript")
                        )
        for child in node.children:
            self._scan(child, source, file_path, findings)
