from engine.base_rule import TaintedArgumentRule


class OpenRedirectPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-006"
    criteria_name = "신뢰되지 않는 URL 주소로의 자동접속 연결"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "Medium"
    message = "검증되지 않은 외부 입력값으로 리다이렉트되어 오픈 리다이렉트/피싱에 악용될 수 있습니다."
    recommendation = "리다이렉트 대상 URL을 사전에 등록된 허용 목록과 대조 후 사용하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (identifier) @fn (#eq? @fn "redirect")
          arguments: (argument_list) @args) @target
        """
    }
