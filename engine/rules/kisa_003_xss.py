from engine.base_rule import Rule, TaintedArgumentRule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class XssInnerHtmlJsRule(Rule):
    criteria_id = "KISA-003"
    criteria_name = "크로스사이트 스크립트(XSS)"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "High"
    message = "검증/이스케이프 없는 값이 innerHTML에 직접 할당되어 XSS가 발생할 수 있습니다."
    recommendation = "innerHTML 대신 textContent를 사용하거나, DOMPurify 등으로 값을 이스케이프/살균 후 사용하십시오."
    QUERIES = {
        "Javascript": """
        (assignment_expression
          left: (member_expression property: (property_identifier) @p (#eq? @p "innerHTML"))
          right: [(identifier) (member_expression) (call_expression)] @target)
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class XssMarkupPythonRule(Rule):
    """Markup()/mark_safe()로 감싼 값은 템플릿 자동 이스케이프를 우회하므로,
    호출 자체를 XSS 위험 신호로 탐지한다 (Flask MarkupSafe / Django mark_safe)."""

    criteria_id = "KISA-003"
    criteria_name = "크로스사이트 스크립트(XSS)"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = "Markup()/mark_safe()로 값이 자동 이스케이프 없이 그대로 렌더링되어 XSS가 발생할 수 있습니다."
    recommendation = "신뢰할 수 없는 값은 Markup()/mark_safe()로 감싸지 말고, 템플릿 엔진의 기본 자동 이스케이프를 사용하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (identifier) @fn (#match? @fn "^(Markup|mark_safe)$")
          arguments: (argument_list) @target)
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class XssJavaRule(TaintedArgumentRule):
    criteria_id = "KISA-003"
    criteria_name = "크로스사이트 스크립트(XSS)"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "High"
    message = "검증/이스케이프 없는 외부 입력값이 HTTP 응답 본문에 직접 출력되어 XSS가 발생할 수 있습니다."
    recommendation = "출력 전 HTML 특수문자를 이스케이프하거나 OWASP Java Encoder 등 검증된 라이브러리를 사용하십시오."
    QUERIES = {
        "Java": """
        (method_invocation
          name: (identifier) @m (#match? @m "^(print|println|write)$")
          arguments: (argument_list) @args) @target
        """
    }
