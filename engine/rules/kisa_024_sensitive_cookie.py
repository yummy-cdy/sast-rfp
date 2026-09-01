from engine.base_rule import Rule

_MESSAGE = "비밀번호/토큰 등 중요정보로 추정되는 값이 사용자 하드디스크에 저장되는 쿠키의 키 이름으로 사용되어 정보노출이 발생할 수 있습니다."
_RECOMMENDATION = "중요정보는 쿠키에 평문으로 저장하지 말고, 서버 측 세션에 저장한 뒤 세션 식별자만 쿠키로 전달하십시오."
_KEY_PATTERN = "(?i)(password|ssn|card|token|secret)"


class SensitiveCookiePythonRule(Rule):
    criteria_id = "KISA-024"
    criteria_name = "사용자 하드디스크에 저장되는 쿠키를 통한 정보노출"
    category = "보안기능"
    languages = ["Python"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": f"""
        (call
          function: (attribute attribute: (identifier) @m (#eq? @m "set_cookie"))
          arguments: (argument_list (string) @key (#match? @key "{_KEY_PATTERN}"))) @target
        """
    }


class SensitiveCookieJsRule(Rule):
    criteria_id = "KISA-024"
    criteria_name = "사용자 하드디스크에 저장되는 쿠키를 통한 정보노출"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Javascript": f"""
        (call_expression
          function: (member_expression property: (property_identifier) @m (#eq? @m "cookie"))
          arguments: (arguments (string) @key (#match? @key "{_KEY_PATTERN}"))) @target
        """
    }


class SensitiveCookieJavaRule(Rule):
    criteria_id = "KISA-024"
    criteria_name = "사용자 하드디스크에 저장되는 쿠키를 통한 정보노출"
    category = "보안기능"
    languages = ["Java"]
    severity = "Medium"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": f"""
        (object_creation_expression
          type: (type_identifier) @t (#eq? @t "Cookie")
          arguments: (argument_list (string_literal) @key (#match? @key "{_KEY_PATTERN}"))) @target
        """
    }
