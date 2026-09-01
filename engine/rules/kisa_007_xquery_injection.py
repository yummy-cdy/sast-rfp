from engine.base_rule import Rule


class XqueryInjectionPythonRule(Rule):
    criteria_id = "KISA-007"
    criteria_name = "XQuery 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "Medium"
    message = "검증되지 않은 외부 입력값이 XQuery 쿼리 문자열에 직접 결합되어 데이터 조작/노출이 가능합니다."
    recommendation = "XQuery 실행 시 외부 입력값을 바인딩 변수로 전달하고, 쿼리 문자열에 직접 결합하지 마십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @m (#eq? @m "xquery"))
          arguments: (argument_list [(binary_operator) (string (interpolation))] @target))
        """
    }
