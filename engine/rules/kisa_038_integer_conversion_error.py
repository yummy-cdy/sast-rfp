from engine.base_rule import Rule


class IntegerConversionErrorJavaRule(Rule):
    """long 값을 반환하는 System.currentTimeMillis()를 int로 강제 형변환하여 값 손실이 발생하는 패턴을 탐지한다."""

    criteria_id = "KISA-038"
    criteria_name = "정수형 변환 오류"
    category = "코드오류"
    languages = ["Java"]
    severity = "Low"
    message = "long 값을 int로 강제 형변환하고 있어 값 손실(오버플로우/절삭)이 발생할 수 있습니다."
    recommendation = "형변환이 꼭 필요한지 검토하고, 필요하다면 값의 범위를 사전에 검증하십시오."
    QUERIES = {
        "Java": """
        (cast_expression
          type: (integral_type) @t (#eq? @t "int")
          value: (method_invocation name: (identifier) @m (#eq? @m "currentTimeMillis"))) @target
        """
    }
