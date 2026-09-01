from engine.base_rule import TaintedArgumentRule


class IntegerOverflowJavaRule(TaintedArgumentRule):
    """외부 입력을 정수로 변환한 값을 검증 없이 곧바로 산술 연산에 사용하는 패턴.

    파싱 결과를 별도 변수에 대입해 검증하는 코드는 매칭되지 않으며,
    파싱 결과를 즉시 산술식에 사용하는 경우만 탐지한다."""

    criteria_id = "KISA-013"
    criteria_name = "정수형 오버플로우"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "Medium"
    message = "외부 입력값을 정수로 변환한 직후 범위 검증 없이 산술 연산에 사용하여 정수형 오버플로우가 발생할 수 있습니다."
    recommendation = "정수 변환 후 연산 전에 예상 범위 내의 값인지 검증하거나, long 등 더 넓은 자료형으로 연산하십시오."
    QUERIES = {
        "Java": """
        (binary_expression
          left: (method_invocation
            name: (identifier) @fn (#eq? @fn "parseInt")
            arguments: (argument_list) @args)) @target
        """
    }
