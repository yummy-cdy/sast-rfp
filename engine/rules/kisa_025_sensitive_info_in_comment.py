from engine.base_rule import Rule

_MESSAGE = "소스코드 주석에 계정/비밀번호/API 키 등으로 추정되는 시스템 주요정보가 노출되어 있습니다."
_RECOMMENDATION = "주석에 실제 계정정보/키 값을 남기지 말고, 별도의 시크릿 관리 저장소를 사용하십시오."
_REGEX = "(?i)(password|passwd|secret|api[_-]?key).*[:=]"


class SensitiveInfoInCommentPythonRule(Rule):
    criteria_id = "KISA-025"
    criteria_name = "주석문 안에 포함된 시스템 주요정보"
    category = "보안기능"
    languages = ["Python"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": f'((comment) @target (#match? @target "{_REGEX}"))'
    }


class SensitiveInfoInCommentJsRule(Rule):
    criteria_id = "KISA-025"
    criteria_name = "주석문 안에 포함된 시스템 주요정보"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": f'((comment) @target (#match? @target "{_REGEX}"))'
    }


class SensitiveInfoInCommentJavaRule(Rule):
    criteria_id = "KISA-025"
    criteria_name = "주석문 안에 포함된 시스템 주요정보"
    category = "보안기능"
    languages = ["Java"]
    severity = "Low"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": f'([(line_comment) (block_comment)] @target (#match? @target "{_REGEX}"))'
    }
