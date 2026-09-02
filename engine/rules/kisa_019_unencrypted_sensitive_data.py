from engine.base_rule import TaintedArgumentRule

_MESSAGE = "주민등록번호/카드번호 등 중요정보로 추정되는 필드에 외부 입력값이 암호화 없이 그대로 저장됩니다."
_RECOMMENDATION = "중요정보는 저장/전송 전에 반드시 암호화하십시오."
_FIELD_PATTERN = "(?i)^(ssn|credit_card|card_number|social_security)$"


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class UnencryptedSensitiveDataPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-019"
    criteria_name = "암호화되지 않은 중요정보"
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


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class UnencryptedSensitiveDataJsRule(TaintedArgumentRule):
    criteria_id = "KISA-019"
    criteria_name = "암호화되지 않은 중요정보"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (assignment_expression
          left: (member_expression property: (property_identifier) @f (#match? @f "(?i)^(ssn|creditcard|cardnumber|socialsecurity)$"))
          right: (_) @args) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class UnencryptedSensitiveDataJavaRule(TaintedArgumentRule):
    criteria_id = "KISA-019"
    criteria_name = "암호화되지 않은 중요정보"
    category = "보안기능"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (method_invocation
          name: (identifier) @m (#match? @m "^(setSsn|setCreditCard|setCardNumber|setSocialSecurityNumber)$")
          arguments: (argument_list) @args) @target
        """
    }
