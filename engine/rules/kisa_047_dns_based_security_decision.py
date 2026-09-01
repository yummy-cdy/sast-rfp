from engine.base_rule import Rule


class DnsBasedSecurityDecisionJavaRule(Rule):
    """역방향 DNS 조회 결과(호스트명)를 보안 판단에 사용할 수 있는 지점을 탐지한다."""

    criteria_id = "KISA-047"
    criteria_name = "DNS Lookup에 의존한 보안 결정"
    category = "API 오용"
    languages = ["Java"]
    severity = "Low"
    message = "DNS 조회로 얻은 호스트명은 위조가 가능하므로, 이를 근거로 보안 결정을 내리면 우회당할 수 있습니다."
    recommendation = "호스트명 대신 IP 주소 자체를 검증하거나, 별도의 강한 인증 수단을 사용하십시오."
    QUERIES = {
        "Java": '(method_invocation name: (identifier) @m (#match? @m "^(getHostName|getCanonicalHostName)$")) @target'
    }
