from engine.base_rule import TaintedArgumentRule

_MESSAGE = "검증되지 않은 외부 입력값이 HTTP 응답 헤더 값으로 사용되어 헤더/응답 분할, 캐시 오염 등에 악용될 수 있습니다."
_RECOMMENDATION = "헤더 값으로 사용하는 외부 입력값에서 개행 문자(CR/LF)를 제거하거나 허용 목록으로 검증하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HttpResponseSplittingPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-012"
    criteria_name = "HTTP 응답분할"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (assignment
          left: (subscript value: (attribute attribute: (identifier) @h (#eq? @h "headers")))
          right: (_) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HttpResponseSplittingJsRule(TaintedArgumentRule):
    criteria_id = "KISA-012"
    criteria_name = "HTTP 응답분할"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression property: (property_identifier) @m (#eq? @m "setHeader"))
          arguments: (arguments) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HttpResponseSplittingJavaRule(TaintedArgumentRule):
    criteria_id = "KISA-012"
    criteria_name = "HTTP 응답분할"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          name: (identifier) @m (#match? @m "^(setHeader|addHeader)$")
          arguments: (argument_list) @args) @target
        """
    }
