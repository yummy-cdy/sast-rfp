from engine.base_rule import Rule

_MESSAGE = "외부 입력값이 동적 코드 실행 함수에 전달되어 임의 코드가 실행될 수 있습니다."
_RECOMMENDATION = "eval/동적 코드 실행 대신 안전한 파서(json.loads 등) 또는 명시적 분기 처리를 사용하십시오."


class CodeInjectionEvalPythonRule(Rule):
    criteria_id = "KISA-014"
    criteria_name = "코드 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call function: (identifier) @fn (#match? @fn "^(eval|exec)$")) @target
        """
    }


class CodeInjectionEvalJsRule(Rule):
    criteria_id = "KISA-014"
    criteria_name = "코드 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (call_expression function: (identifier) @fn (#eq? @fn "eval")) @target
        """
    }
