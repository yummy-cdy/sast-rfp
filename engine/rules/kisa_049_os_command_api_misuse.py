from engine.base_rule import Rule


class OsCommandApiMisuseJavaRule(Rule):
    """Runtime.exec()의 단일 문자열 오버로드를 사용하는 패턴을 탐지한다.

    단일 문자열 형태는 내부적으로 단순 공백 분리로 명령을 나누기 때문에
    인자에 공백/특수문자가 포함된 경우 의도와 다르게 파싱되는 API 오용이다.
    외부 입력 결합 여부와 무관하게, 이 오버로드 자체의 사용을 문제로 본다
    (외부 입력이 결합된 경우는 KISA-004에서 별도로 다룬다)."""

    criteria_id = "KISA-049"
    criteria_name = "운영체제 명령 실행 API 오용"
    category = "API 오용"
    languages = ["Java"]
    severity = "Medium"
    message = "Runtime.exec()의 단일 문자열 오버로드를 사용하고 있어, 인자 파싱이 의도와 다르게 동작할 수 있습니다."
    recommendation = "명령과 인자를 배열(String[])로 분리하여 exec()에 전달하십시오."
    QUERIES = {
        "Java": """
        (method_invocation
          object: (method_invocation name: (identifier) @g (#eq? @g "getRuntime"))
          name: (identifier) @m (#eq? @m "exec")
          arguments: (argument_list (string_literal) @arg)) @target
        """
    }
