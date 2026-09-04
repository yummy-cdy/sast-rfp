from engine.base_rule import Rule

_NAME_PATTERN = "(?i)^(secret[_-]?key|encryption[_-]?key|crypto[_-]?key|salt|iv)$"
_MESSAGE = "암호화 키/salt/IV로 추정되는 값이 소스코드에 평문으로 고정되어 있습니다."
_RECOMMENDATION = "암호화 키는 환경변수 또는 KMS/Vault 등 별도 키 관리 체계에서 로드하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HardcodedCryptoKeyPythonRule(Rule):
    criteria_id = "KISA-022"
    criteria_name = "하드코드된 암호화 키"
    category = "보안기능"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": f"""
        (assignment
          left: (identifier) @varname (#match? @varname "{_NAME_PATTERN}")
          right: (string) @target)
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HardcodedCryptoKeyJsRule(Rule):
    criteria_id = "KISA-022"
    criteria_name = "하드코드된 암호화 키"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": f"""
        (variable_declarator
          name: (identifier) @varname (#match? @varname "{_NAME_PATTERN}")
          value: (string) @target)
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HardcodedCryptoKeyJavaRule(Rule):
    criteria_id = "KISA-022"
    criteria_name = "하드코드된 암호화 키"
    category = "보안기능"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": f"""
        (variable_declarator
          name: (identifier) @varname (#match? @varname "{_NAME_PATTERN}")
          value: (string_literal) @target)
        """
    }
