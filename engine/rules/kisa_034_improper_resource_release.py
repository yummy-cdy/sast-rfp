from engine.base_rule import Rule


def _ancestor_types(node):
    current = node.parent
    while current is not None:
        yield current.type
        current = current.parent


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class ImproperResourceReleasePythonRule(Rule):
    """open()을 with 문(컨텍스트 매니저) 없이 사용하여 자원 해제가 보장되지 않는 패턴을 탐지한다."""

    criteria_id = "KISA-034"
    criteria_name = "부적절한 자원 해제"
    category = "코드오류"
    languages = ["Python"]
    severity = "Medium"
    message = "open()으로 연 파일 자원이 with 문(컨텍스트 매니저) 없이 사용되어, 예외 발생 시 자원이 해제되지 않을 수 있습니다."
    recommendation = "파일/소켓 등 자원은 with 문을 사용해 블록 종료 시 자동으로 해제되도록 하십시오."
    QUERIES = {"Python": '(call function: (identifier) @fn (#eq? @fn "open")) @target'}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            if not target_nodes:
                continue
            if "with_item" in _ancestor_types(target_nodes[0]):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class ImproperResourceReleaseJavaRule(Rule):
    """FileInputStream 등 자원을 try-with-resources 없이 생성하는 패턴을 탐지한다."""

    criteria_id = "KISA-034"
    criteria_name = "부적절한 자원 해제"
    category = "코드오류"
    languages = ["Java"]
    severity = "Medium"
    message = "파일/소켓 자원을 try-with-resources 없이 생성하여, 예외 발생 시 자원이 해제되지 않을 수 있습니다."
    recommendation = "자원은 try-with-resources 구문을 사용해 블록 종료 시 자동으로 close()되도록 하십시오."
    QUERIES = {
        "Java": """
        (object_creation_expression
          type: (type_identifier) @t (#match? @t "^(FileInputStream|FileOutputStream|FileReader|FileWriter|Socket)$")) @target
        """
    }

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            if not target_nodes:
                continue
            if "resource_specification" in _ancestor_types(target_nodes[0]):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings
