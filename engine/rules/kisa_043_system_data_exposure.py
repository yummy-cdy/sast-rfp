from engine.base_rule import Rule

_MESSAGE = "서버/프레임워크 배너 정보를 응답 헤더로 노출하고 있어, 공격자가 기술 스택과 버전 정보를 파악할 수 있습니다."
_RECOMMENDATION = "Server/X-Powered-By 등 배너성 헤더는 제거하거나 일반화된 값으로 대체하십시오."
_HEADER_PATTERN = "(?i)(Server|X-Powered-By)"


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SystemDataExposurePythonRule(Rule):
    criteria_id = "KISA-043"
    criteria_name = "시스템 데이터 정보노출"
    category = "캡슐화"
    languages = ["Python"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": f"""
        (assignment
          left: (subscript
            value: (attribute attribute: (identifier) @h (#eq? @h "headers"))
            subscript: (string) @key (#match? @key "{_HEADER_PATTERN}"))
          right: (_)) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SystemDataExposureJsRule(Rule):
    criteria_id = "KISA-043"
    criteria_name = "시스템 데이터 정보노출"
    category = "캡슐화"
    languages = ["Javascript"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": f"""
        (call_expression
          function: (member_expression property: (property_identifier) @m (#eq? @m "setHeader"))
          arguments: (arguments (string) @key (#match? @key "{_HEADER_PATTERN}"))) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SystemDataExposureJavaRule(Rule):
    criteria_id = "KISA-043"
    criteria_name = "시스템 데이터 정보노출"
    category = "캡슐화"
    languages = ["Java"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": f"""
        (method_invocation
          name: (identifier) @m (#match? @m "^(setHeader|addHeader)$")
          arguments: (argument_list (string_literal) @key (#match? @key "{_HEADER_PATTERN}"))) @target
        """
    }
