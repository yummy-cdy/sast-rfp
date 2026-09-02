from engine.base_rule import Rule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class NullDereferenceJavaRule(Rule):
    """Map.get() 등 null을 반환할 수 있는 호출의 결과를 변수에 저장/검증하지 않고 곧바로 역참조하는 패턴을 탐지한다."""

    criteria_id = "KISA-033"
    criteria_name = "널 포인터 역참조"
    category = "코드오류"
    languages = ["Java"]
    severity = "Medium"
    message = "get() 호출 결과가 null일 수 있음에도 검증 없이 곧바로 메소드를 호출하고 있어 NullPointerException이 발생할 수 있습니다."
    recommendation = "get() 결과를 변수에 저장한 뒤 null 여부를 검증하고 나서 사용하십시오."
    QUERIES = {
        "Java": """
        (method_invocation
          object: (method_invocation name: (identifier) @g (#eq? @g "get"))) @target
        """
    }
