from engine.base_rule import Rule

_MESSAGE = "실패할 수 있는 외부 자원 접근/변환 호출이 예외 처리 없이 사용되어, 오류 상황에 대한 대응이 누락되어 있습니다."
_RECOMMENDATION = "예상 가능한 오류 상황(파일 없음, 잘못된 형식 등)에 대해 try/catch로 명시적으로 처리하십시오."


def _has_try_ancestor(node) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "try_statement":
            return True
        current = current.parent
    return False


class MissingErrorHandlingPythonRule(Rule):
    criteria_id = "KISA-030"
    criteria_name = "오류 상황 대응 부재"
    category = "에러처리"
    languages = ["Python"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {"Python": '(call function: (identifier) @fn (#eq? @fn "open")) @target'}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            if not target_nodes or _has_try_ancestor(target_nodes[0]):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings


class MissingErrorHandlingJsRule(MissingErrorHandlingPythonRule):
    languages = ["Javascript"]
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression object: (identifier) @mod (#eq? @mod "JSON") property: (property_identifier) @fn (#eq? @fn "parse"))) @target
        """
    }


class MissingErrorHandlingJavaRule(MissingErrorHandlingPythonRule):
    languages = ["Java"]
    QUERIES = {
        "Java": """
        (method_invocation
          object: (identifier) @mod (#eq? @mod "Integer")
          name: (identifier) @fn (#eq? @fn "parseInt")) @target
        """
    }
