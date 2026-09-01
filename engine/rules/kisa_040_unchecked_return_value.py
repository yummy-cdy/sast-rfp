from engine.base_rule import Rule


class UncheckedReturnValueJavaRule(Rule):
    """File.delete()/mkdir() 등 성공 여부를 boolean으로 반환하는 호출의 반환값을 버리는 패턴을 탐지한다."""

    criteria_id = "KISA-040"
    criteria_name = "할당 후 미검사 반환값"
    category = "코드오류"
    languages = ["Java"]
    severity = "Low"
    message = "성공/실패 여부를 반환하는 호출의 반환값을 검사하지 않고 있어, 작업 실패를 인지하지 못할 수 있습니다."
    recommendation = "반환값을 변수에 저장해 성공 여부를 확인하고, 실패 시 적절히 처리하십시오."
    QUERIES = {
        "Java": """
        (expression_statement
          (method_invocation name: (identifier) @m (#match? @m "^(delete|mkdir|mkdirs|renameTo)$"))) @target
        """
    }
