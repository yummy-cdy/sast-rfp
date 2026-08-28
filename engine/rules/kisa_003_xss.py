from engine.base_rule import Rule


class XssInnerHtmlJsRule(Rule):
    criteria_id = "KISA-003"
    criteria_name = "크로스사이트 스크립트(XSS)"
    category = "입력데이터 검증 및 표현"
    languages = ["Javascript"]
    severity = "High"
    message = "검증/이스케이프 없는 값이 innerHTML에 직접 할당되어 XSS가 발생할 수 있습니다."
    recommendation = "innerHTML 대신 textContent를 사용하거나, DOMPurify 등으로 값을 이스케이프/살균 후 사용하십시오."
    QUERIES = {
        "Javascript": """
        (assignment_expression
          left: (member_expression property: (property_identifier) @p (#eq? @p "innerHTML"))
          right: [(identifier) (member_expression) (call_expression)] @target)
        """
    }
