from engine.base_rule import Rule

_MESSAGE = "검증되지 않은 외부 입력값이 XPath 표현식에 직접 결합되어 인증 우회/데이터 노출이 가능합니다."
_RECOMMENDATION = "XPath 표현식에는 외부 입력값을 직접 결합하지 말고, 변수 바인딩 방식을 사용하십시오."


class XpathInjectionPythonRule(Rule):
    criteria_id = "KISA-008"
    criteria_name = "XPath 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @m (#eq? @m "xpath"))
          arguments: (argument_list [(binary_operator) (string (interpolation))] @target))
        """
    }


class XpathInjectionJavaRule(Rule):
    criteria_id = "KISA-008"
    criteria_name = "XPath 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          object: (identifier) @o (#match? @o "(?i)xpath")
          name: (identifier) @m (#eq? @m "evaluate")
          arguments: (argument_list (binary_expression) @target))
        """
    }
