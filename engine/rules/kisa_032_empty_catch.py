from engine.base_rule import Rule

_MESSAGE = "예외를 포착하고도 아무 처리 없이 무시하고 있어 오류 상황이 은폐될 수 있습니다."
_RECOMMENDATION = "예외를 최소한 로그로 기록하거나, 상위로 재전파하거나, 명확한 복구 로직을 구현하십시오."


class EmptyExceptionPythonRule(Rule):
    criteria_id = "KISA-032"
    criteria_name = "빈 Catch 블록"
    category = "에러처리"
    languages = ["Python"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (except_clause (block (pass_statement)) @target)
        """
    }


class EmptyCatchJsRule(Rule):
    criteria_id = "KISA-032"
    criteria_name = "빈 Catch 블록"
    category = "에러처리"
    languages = ["Javascript"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (catch_clause body: (statement_block) @body (#eq? @body "{}")) @target
        """
    }


class EmptyCatchJavaRule(Rule):
    criteria_id = "KISA-032"
    criteria_name = "빈 Catch 블록"
    category = "에러처리"
    languages = ["Java"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (catch_clause body: (block) @body (#eq? @body "{}")) @target
        """
    }
