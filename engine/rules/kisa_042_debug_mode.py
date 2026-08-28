from engine.base_rule import Rule


class DebugModeExposurePythonRule(Rule):
    criteria_id = "KISA-042"
    criteria_name = "제거되지 않고 남은 디버그 코드"
    category = "캡슐화"
    languages = ["Python"]
    severity = "Medium"
    message = "디버그 모드가 활성화된 상태로 배포될 경우 상세 오류/내부 정보가 노출될 수 있습니다."
    recommendation = "운영 환경에서는 debug=False로 설정하고, 디버그 모드는 환경변수로 분리 관리하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @m (#eq? @m "run"))
          arguments: (argument_list (keyword_argument name: (identifier) @kw (#eq? @kw "debug") value: (true)) @target))
        """
    }
