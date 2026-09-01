from engine.base_rule import Rule


class LdapInjectionPythonRule(Rule):
    criteria_id = "KISA-009"
    criteria_name = "LDAP 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "Medium"
    message = "검증되지 않은 외부 입력값이 LDAP 검색 필터 문자열에 직접 결합되어 인증 우회/정보노출이 가능합니다."
    recommendation = "LDAP 필터에 사용되는 외부 입력값은 특수문자를 이스케이프하거나 안전한 필터 빌더를 사용하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @m (#match? @m "^(search_s|search_ext_s)$"))
          arguments: (argument_list [(binary_operator) (string (interpolation))] @target))
        """
    }
