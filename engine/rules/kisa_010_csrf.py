from engine.base_rule import Rule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class CsrfExemptPythonRule(Rule):
    """CSRF 보호를 명시적으로 해제하는 데코레이터(csrf_exempt) 사용을 탐지한다."""

    criteria_id = "KISA-010"
    criteria_name = "크로스사이트 요청 위조(CSRF)"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = "상태를 변경하는 요청 처리에 CSRF 보호가 명시적으로 해제되어 있어 CSRF 공격에 노출될 수 있습니다."
    recommendation = "CSRF 보호를 해제하지 말고, 요청마다 CSRF 토큰을 검증하는 프레임워크 기본 보호 기능을 사용하십시오."
    QUERIES = {
        "Python": """
        (decorator [(identifier) @d (attribute attribute: (identifier) @d)] (#eq? @d "csrf_exempt")) @target
        """
    }
