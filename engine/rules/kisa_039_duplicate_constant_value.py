import re

from engine.base_rule import Rule

_CONST_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_TRIVIAL_NUMBERS = {"0", "1"}
_TRIVIAL_STRINGS = {""}


def _quoted_string_value(node, source):
    text = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    if len(text) < 2 or text[0] not in "\"'" or text[-1] != text[0]:
        return None
    return text[1:-1]


def _detect_duplicates(constants):
    """같은 스코프 내에서 값은 같지만 이름이 다른 상수 선언을 찾는다.
    constants: (name, value_key, node) 목록 (선언 순서)."""
    first_name_for_value: dict[str, str] = {}
    targets = []
    for name, value_key, node in constants:
        prior_name = first_name_for_value.get(value_key)
        if prior_name is None:
            first_name_for_value[value_key] = name
        elif prior_name != name:
            targets.append(node)
    return targets


def _python_scope_constants(children, source):
    constants = []
    for child in children:
        if child.type != "expression_statement" or not child.named_children:
            continue
        assign = child.named_children[0]
        if assign.type != "assignment":
            continue
        left = assign.child_by_field_name("left")
        right = assign.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            continue
        name = source[left.start_byte : left.end_byte].decode("utf-8", errors="replace")
        if not _CONST_NAME_RE.match(name):
            continue
        if right.type == "integer":
            text = source[right.start_byte : right.end_byte].decode("utf-8", errors="replace")
            if text in _TRIVIAL_NUMBERS:
                continue
            constants.append((name, f"int:{text}", assign))
        elif right.type == "string":
            if any(c.type == "interpolation" for c in right.children):
                continue
            value = _quoted_string_value(right, source)
            if value is None or value in _TRIVIAL_STRINGS:
                continue
            constants.append((name, f"str:{value}", assign))
    return constants


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class DuplicateConstantValuePythonRule(Rule):
    """모듈/클래스 스코프에서 이름은 다르지만 값이 같은 상수(대문자 관례)를 탐지한다."""

    criteria_id = "KISA-039"
    criteria_name = "동일한 상수 사용에 의한 잘못된 값 참조"
    category = "코드오류"
    languages = ["Python"]
    severity = "Low"
    message = "이름이 다른 상수가 동일한 값을 재사용하고 있어, 한쪽 값만 변경될 경우 의도치 않은 값이 참조될 수 있습니다."
    recommendation = "서로 다른 의미의 상수는 값이 우연히 같더라도 구분해 선언하거나, 공통 상수를 하나로 통합해 재사용하십시오."
    QUERIES = {}

    def find(self, tree, source, file_path, language):
        targets = list(_detect_duplicates(_python_scope_constants(tree.root_node.named_children, source)))

        def walk(node):
            if node.type == "class_definition":
                body = node.child_by_field_name("body")
                if body is not None:
                    targets.extend(_detect_duplicates(_python_scope_constants(body.named_children, source)))
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return [self._build_finding(node, source, file_path, language) for node in targets]


def _java_modifiers_text(node, source) -> str:
    for child in node.children:
        if child.type == "modifiers":
            return source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
    return ""


def _java_scope_constants(class_body, source):
    constants = []
    for field in class_body.named_children:
        if field.type != "field_declaration":
            continue
        if "final" not in _java_modifiers_text(field, source):
            continue
        for declarator in field.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value_node = declarator.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            name = source[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")
            if not _CONST_NAME_RE.match(name):
                continue
            if value_node.type == "decimal_integer_literal":
                text = source[value_node.start_byte : value_node.end_byte].decode(
                    "utf-8", errors="replace"
                )
                if text in _TRIVIAL_NUMBERS:
                    continue
                constants.append((name, f"int:{text}", declarator))
            elif value_node.type == "string_literal":
                value = _quoted_string_value(value_node, source)
                if value is None or value in _TRIVIAL_STRINGS:
                    continue
                constants.append((name, f"str:{value}", declarator))
    return constants


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class DuplicateConstantValueJavaRule(Rule):
    """클래스 스코프에서 이름은 다르지만 값이 같은 final 상수 필드를 탐지한다."""

    criteria_id = "KISA-039"
    criteria_name = "동일한 상수 사용에 의한 잘못된 값 참조"
    category = "코드오류"
    languages = ["Java"]
    severity = "Low"
    message = "이름이 다른 상수가 동일한 값을 재사용하고 있어, 한쪽 값만 변경될 경우 의도치 않은 값이 참조될 수 있습니다."
    recommendation = "서로 다른 의미의 상수는 값이 우연히 같더라도 구분해 선언하거나, 공통 상수를 하나로 통합해 재사용하십시오."
    QUERIES = {"Java": "(class_declaration body: (class_body) @cbody) @target"}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            cbody_nodes = captures.get("cbody")
            if not cbody_nodes:
                continue
            for node in _detect_duplicates(_java_scope_constants(cbody_nodes[0], source)):
                findings.append(self._build_finding(node, source, file_path, language))
        return findings


def _js_scope_constants(children, source):
    constants = []
    for child in children:
        if child.type != "lexical_declaration":
            continue
        if not any(c.type == "const" for c in child.children):
            continue
        for declarator in child.named_children:
            if declarator.type != "variable_declarator":
                continue
            name_node = declarator.child_by_field_name("name")
            value_node = declarator.child_by_field_name("value")
            if name_node is None or value_node is None or name_node.type != "identifier":
                continue
            name = source[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")
            if not _CONST_NAME_RE.match(name):
                continue
            if value_node.type == "number":
                text = source[value_node.start_byte : value_node.end_byte].decode(
                    "utf-8", errors="replace"
                )
                if text in _TRIVIAL_NUMBERS:
                    continue
                constants.append((name, f"num:{text}", declarator))
            elif value_node.type == "string":
                value = _quoted_string_value(value_node, source)
                if value is None or value in _TRIVIAL_STRINGS:
                    continue
                constants.append((name, f"str:{value}", declarator))
    return constants


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class DuplicateConstantValueJsRule(Rule):
    """모듈 스코프에서 이름은 다르지만 값이 같은 const 상수(대문자 관례)를 탐지한다."""

    criteria_id = "KISA-039"
    criteria_name = "동일한 상수 사용에 의한 잘못된 값 참조"
    category = "코드오류"
    languages = ["Javascript"]
    severity = "Low"
    message = "이름이 다른 상수가 동일한 값을 재사용하고 있어, 한쪽 값만 변경될 경우 의도치 않은 값이 참조될 수 있습니다."
    recommendation = "서로 다른 의미의 상수는 값이 우연히 같더라도 구분해 선언하거나, 공통 상수를 하나로 통합해 재사용하십시오."
    QUERIES = {}

    def find(self, tree, source, file_path, language):
        targets = _detect_duplicates(_js_scope_constants(tree.root_node.named_children, source))
        return [self._build_finding(node, source, file_path, language) for node in targets]
