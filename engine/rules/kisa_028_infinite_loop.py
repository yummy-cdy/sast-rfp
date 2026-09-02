from engine.base_rule import Rule

_LOOP_TYPES = {
    "Python": {"while_statement", "for_statement"},
    "Javascript": {"while_statement", "for_statement", "for_in_statement", "do_statement"},
    "Java": {"while_statement", "for_statement", "enhanced_for_statement", "do_statement"},
}

_MESSAGE = "종료 조건이 상수 참(true)으로 고정되어 있고 내부에 break가 없어 무한 루프가 발생할 수 있습니다."
_RECOMMENDATION = "루프 내부에 명확한 종료 조건 또는 break 문을 두어 반복이 항상 종료되도록 하십시오."


def _contains_break(node, loop_types: set) -> bool:
    for child in node.children:
        if child.type == "break_statement":
            return True
        if child.type in loop_types:
            continue
        if _contains_break(child, loop_types):
            return True
    return False


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class InfiniteLoopPythonRule(Rule):
    criteria_id = "KISA-028"
    criteria_name = "종료되지 않는 반복문 또는 재귀함수"
    category = "시간 및 상태"
    languages = ["Python"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {"Python": "(while_statement condition: (true) body: (block) @body) @target"}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            body_nodes = captures.get("body")
            if not target_nodes or not body_nodes:
                continue
            if _contains_break(body_nodes[0], _LOOP_TYPES[language]):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class InfiniteLoopJsRule(InfiniteLoopPythonRule):
    languages = ["Javascript"]
    QUERIES = {
        "Javascript": "(while_statement condition: (parenthesized_expression (true)) body: (statement_block) @body) @target"
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class InfiniteLoopJavaRule(InfiniteLoopPythonRule):
    languages = ["Java"]
    QUERIES = {
        "Java": "(while_statement condition: (parenthesized_expression (true)) body: (block) @body) @target"
    }
