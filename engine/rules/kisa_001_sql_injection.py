from engine.base_rule import Rule

_MESSAGE = "사용자 입력값이 SQL 쿼리 문자열에 직접 결합되어 SQL Injection이 발생할 수 있습니다."
_RECOMMENDATION = "문자열 결합 대신 파라미터 바인딩(Prepared Statement)을 사용하십시오."


class SqlInjectionPythonRule(Rule):
    criteria_id = "KISA-001"
    criteria_name = "SQL 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @m (#match? @m "^(execute|executemany)$"))
          arguments: (argument_list [(binary_operator) (string (interpolation))] @target))
        """
    }


class SqlInjectionJsRule(Rule):
    criteria_id = "KISA-001"
    criteria_name = "SQL 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression property: (property_identifier) @m (#match? @m "^(query|execute)$"))
          arguments: (arguments [(binary_expression) (template_string (template_substitution))] @target))
        """
    }


class SqlInjectionJavaRule(Rule):
    criteria_id = "KISA-001"
    criteria_name = "SQL 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          name: (identifier) @m (#match? @m "^(executeQuery|executeUpdate|execute)$")
          arguments: (argument_list (binary_expression) @target))
        """
    }
