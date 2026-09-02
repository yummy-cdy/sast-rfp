from engine.base_rule import Rule

_MESSAGE = "암호학적으로 안전하지 않은 난수 생성기를 사용하고 있습니다. 보안 토큰/세션ID 등에 사용 시 예측이 가능할 수 있습니다."
_RECOMMENDATION = "보안 목적에는 secrets 모듈, java.security.SecureRandom, crypto.randomBytes 등 암호학적으로 안전한 난수 생성기를 사용하십시오."


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class InsecureRandomPythonRule(Rule):
    criteria_id = "KISA-021"
    criteria_name = "적절하지 않은 난수 값 사용"
    category = "보안기능"
    languages = ["Python"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call function: (attribute object: (identifier) @mod (#eq? @mod "random"))) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class InsecureRandomJsRule(Rule):
    criteria_id = "KISA-021"
    criteria_name = "적절하지 않은 난수 값 사용"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": """
        (member_expression object: (identifier) @o (#eq? @o "Math") property: (property_identifier) @p (#eq? @p "random")) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class InsecureRandomJavaRule(Rule):
    criteria_id = "KISA-021"
    criteria_name = "적절하지 않은 난수 값 사용"
    category = "보안기능"
    languages = ["Java"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (object_creation_expression type: (type_identifier) @t (#eq? @t "Random")) @target
        """
    }
