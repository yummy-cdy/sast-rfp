from engine.base_rule import Rule

_MESSAGE = "외부 입력값이 결합된 문자열이 운영체제 명령 실행에 사용되어 커맨드 인젝션이 발생할 수 있습니다."
_RECOMMENDATION = "셸을 경유하지 않는 배열 인자 실행 방식을 사용하고, 외부 입력값은 허용 목록으로 검증하십시오."


class OsCommandInjectionPythonRule(Rule):
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
          arguments: (argument_list [(binary_operator) (string (interpolation))] @target))
        """
    }


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
