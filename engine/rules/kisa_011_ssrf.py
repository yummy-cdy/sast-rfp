from engine.base_rule import TaintedArgumentRule

_MESSAGE = "검증되지 않은 외부 입력값이 서버 측 HTTP 요청의 대상 주소로 사용되어 SSRF가 발생할 수 있습니다."
_RECOMMENDATION = "요청 대상 호스트를 허용 목록으로 제한하고, 내부망 대역(사설 IP 등)으로의 요청을 차단하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SsrfPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-011"
    criteria_name = "서버사이드 요청 위조(SSRF)"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (attribute object: (identifier) @mod (#match? @mod "^(requests|urllib)$"))
          arguments: (argument_list) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SsrfUrlopenPythonRule(TaintedArgumentRule):
    """from urllib.request import urlopen 처럼 모듈 접두사 없이 바로 호출되는 형태를 탐지한다.
    (SsrfPythonRule의 requests.*/urllib.* 속성 접근 패턴과는 별도 클래스로 분리 —
    같은 필드에 서로 다른 캡처명을 쓰는 alternation은 tree-sitter 술어 필터링이
    깨지는 문제가 있어, 캡처명이 겹치지 않는 단순 쿼리로 분리했다.)"""

    criteria_id = "KISA-011"
    criteria_name = "서버사이드 요청 위조(SSRF)"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (identifier) @fn (#match? @fn "^(urlopen|urlretrieve)$")
          arguments: (argument_list) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SsrfJsRule(TaintedArgumentRule):
    criteria_id = "KISA-011"
    criteria_name = "서버사이드 요청 위조(SSRF)"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression object: (identifier) @mod (#match? @mod "^(axios|http|https)$"))
          arguments: (arguments) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SsrfJavaRule(TaintedArgumentRule):
    criteria_id = "KISA-011"
    criteria_name = "서버사이드 요청 위조(SSRF)"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (object_creation_expression
          type: (type_identifier) @t (#eq? @t "URL")
          arguments: (argument_list) @args) @target
        """
    }
