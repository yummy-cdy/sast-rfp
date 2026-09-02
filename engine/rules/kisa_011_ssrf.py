from engine.base_rule import TaintedArgumentRule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class SsrfPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-011"
    criteria_name = "서버사이드 요청 위조(SSRF)"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = "검증되지 않은 외부 입력값이 서버 측 HTTP 요청의 대상 주소로 사용되어 SSRF가 발생할 수 있습니다."
    recommendation = "요청 대상 호스트를 허용 목록으로 제한하고, 내부망 대역(사설 IP 등)으로의 요청을 차단하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute object: (identifier) @mod (#match? @mod "^(requests|urllib)$"))
          arguments: (argument_list) @args) @target
        """
    }
