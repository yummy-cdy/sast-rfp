from engine.base_rule import TaintedArgumentRule

_MESSAGE = "검증되지 않은 외부 입력값으로 리다이렉트되어 오픈 리다이렉트/피싱에 악용될 수 있습니다."
_RECOMMENDATION = "리다이렉트 대상 URL을 사전에 등록된 허용 목록과 대조 후 사용하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OpenRedirectPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-006"
    criteria_name = "신뢰되지 않는 URL 주소로의 자동접속 연결"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (identifier) @fn (#eq? @fn "redirect")
          arguments: (argument_list) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OpenRedirectJsRule(TaintedArgumentRule):
    criteria_id = "KISA-006"
    criteria_name = "신뢰되지 않는 URL 주소로의 자동접속 연결"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression property: (property_identifier) @m (#eq? @m "redirect"))
          arguments: (arguments) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class OpenRedirectJavaRule(TaintedArgumentRule):
    criteria_id = "KISA-006"
    criteria_name = "신뢰되지 않는 URL 주소로의 자동접속 연결"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          name: (identifier) @m (#eq? @m "sendRedirect")
          arguments: (argument_list) @args) @target
        """
    }
