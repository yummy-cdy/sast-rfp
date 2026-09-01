from engine.base_rule import TaintedArgumentRule

_MESSAGE = "권한/역할을 나타내는 필드가 검증 없이 외부 입력값으로 직접 설정되어(mass assignment), 사용자가 자신의 권한을 임의로 상승시킬 수 있습니다."
_RECOMMENDATION = "권한/역할 필드는 외부 입력값으로 직접 설정하지 말고, 서버 측 권한 검증 로직을 통해서만 변경하십시오."
_FIELD_PATTERN = "(?i)^(is_admin|isadmin|role|is_staff|permission)$"


class ImproperAuthorizationPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-016"
    criteria_name = "부적절한 인가"
    category = "보안기능"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": f"""
        (assignment
          left: (attribute attribute: (identifier) @f (#match? @f "{_FIELD_PATTERN}"))
          right: (_) @args) @target
        """
    }


class ImproperAuthorizationJsRule(TaintedArgumentRule):
    criteria_id = "KISA-016"
    criteria_name = "부적절한 인가"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": f"""
        (assignment_expression
          left: (member_expression property: (property_identifier) @f (#match? @f "{_FIELD_PATTERN}"))
          right: (_) @args) @target
        """
    }


class ImproperAuthorizationJavaRule(TaintedArgumentRule):
    criteria_id = "KISA-016"
    criteria_name = "부적절한 인가"
    category = "보안기능"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          name: (identifier) @m (#match? @m "^(setRole|setIsAdmin|setAdmin|setPermission)$")
          arguments: (argument_list) @args) @target
        """
    }
