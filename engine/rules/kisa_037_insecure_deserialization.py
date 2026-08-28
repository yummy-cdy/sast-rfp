from engine.base_rule import Rule


class InsecureDeserializationPythonRule(Rule):
    criteria_id = "KISA-037"
    criteria_name = "신뢰할 수 없는 데이터의 역직렬화"
    category = "코드오류"
    languages = ["Python"]
    severity = "High"
    message = "신뢰할 수 없는 데이터를 pickle로 역직렬화하면 임의 코드 실행으로 이어질 수 있습니다."
    recommendation = "외부 입력에는 pickle 대신 json 등 안전한 직렬화 포맷을 사용하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute object: (identifier) @mod (#eq? @mod "pickle") attribute: (identifier) @fn (#match? @fn "^(loads|load)$"))) @target
        """
    }
