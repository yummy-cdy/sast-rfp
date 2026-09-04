from engine.base_rule import ConcatenatedArgumentRule, Rule

_MESSAGE = "외부 입력값이 결합된 문자열이 운영체제 명령 실행에 사용되어 커맨드 인젝션이 발생할 수 있습니다."
_RECOMMENDATION = "셸을 경유하지 않는 배열 인자 실행 방식을 사용하고, 외부 입력값은 허용 목록으로 검증하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OsCommandInjectionPythonRule(ConcatenatedArgumentRule):
    """os.system("..." + x)처럼 직접 결합하는 경우뿐 아니라, cmd = "..." + x 로
    미리 만든 변수를 넘기는 간접 패턴도 탐지한다."""

    criteria_id = "KISA-004"
    criteria_name = "운영체제 명령어 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (attribute object: (identifier) @mod (#eq? @mod "os") attribute: (identifier) @fn (#eq? @fn "system"))
          arguments: (argument_list [(binary_operator) (string (interpolation)) (identifier)] @target))
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OsCommandInjectionSubprocessPythonRule(Rule):
    """subprocess.run/call/Popen(cmd_str) 또는 shell=True 옵션을 문자열 인자와 함께
    사용하는 패턴을 탐지한다 (문자열 인자는 셸을 경유하므로 위험, 배열 인자는 안전)."""

    criteria_id = "KISA-004"
    criteria_name = "운영체제 명령어 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: [(identifier) @fn (attribute attribute: (identifier) @fn)]
          (#match? @fn "^(run|call|Popen|check_call|check_output)$")
          arguments: (argument_list . [(identifier) (binary_operator)] @target)) @call
        """
    }

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            call_nodes = captures.get("call")
            if not target_nodes or not call_nodes:
                continue
            findings.append(self._build_finding(call_nodes[0], source, file_path, language))
        return findings


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OsCommandInjectionJsRule(Rule):
    criteria_id = "KISA-004"
    criteria_name = "운영체제 명령어 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression object: (identifier) @mod (#eq? @mod "child_process") property: (property_identifier) @fn (#match? @fn "^(exec|execSync)$"))
          arguments: (arguments [(binary_expression) (template_string (template_substitution))] @target))
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OsCommandInjectionJavaRule(Rule):
    criteria_id = "KISA-004"
    criteria_name = "운영체제 명령어 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          object: (method_invocation name: (identifier) @g (#eq? @g "getRuntime"))
          name: (identifier) @m (#eq? @m "exec")
          arguments: (argument_list (binary_expression) @target))
        """
    }
