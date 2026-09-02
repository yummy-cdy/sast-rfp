from engine.base_rule import Rule

_NAME_PATTERN = "(?i)^(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)$"
_MESSAGE = "비밀번호/토큰으로 추정되는 값이 소스코드에 평문으로 고정되어 있습니다."
_RECOMMENDATION = "비밀정보는 환경변수 또는 별도의 시크릿 관리 저장소(Vault 등)에서 로드하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HardcodedPasswordPythonRule(Rule):
    criteria_id = "KISA-020"
    criteria_name = "하드코드된 비밀번호"
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
class HardcodedPasswordJsRule(Rule):
    criteria_id = "KISA-020"
    criteria_name = "하드코드된 비밀번호"
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
class HardcodedPasswordJavaRule(Rule):
    criteria_id = "KISA-020"
    criteria_name = "하드코드된 비밀번호"
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
