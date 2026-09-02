from engine.base_rule import Rule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class VulnerableApiUsageJavaRule(Rule):
    """문자 인코딩을 지정하지 않는 String.getBytes()/new String(byte[]) 호출을 탐지한다.

    인코딩을 지정하지 않으면 플랫폼 기본 인코딩에 의존하게 되어, 실행 환경에 따라
    결과가 달라지는 취약한 API 사용 문제(FindBugs DM_DEFAULT_ENCODING 계열)가 발생한다."""

    criteria_id = "KISA-048"
    criteria_name = "취약한 API 사용"
    category = "API 오용"
    languages = ["Java"]
    severity = "Low"
    message = "문자 인코딩을 명시하지 않는 API를 사용하고 있어, 플랫폼 기본 인코딩에 따라 동작이 달라질 수 있습니다."
    recommendation = "getBytes()/new String() 사용 시 반드시 문자셋(StandardCharsets.UTF_8 등)을 명시하십시오."
    QUERIES = {
        "Java": '(method_invocation name: (identifier) @m (#eq? @m "getBytes") arguments: (argument_list) @args) @target'
    }

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            args_nodes = captures.get("args")
            if not target_nodes or not args_nodes:
                continue
            if args_nodes[0].named_child_count != 0:
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings
