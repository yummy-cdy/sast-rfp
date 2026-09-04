from engine.base_rule import Rule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HashWithoutSaltPythonRule(Rule):
    """비밀번호로 추정되는 값을 salt 없이 곧바로 해시하는 패턴을 탐지한다.

    hashlib.sha256(password.encode())처럼 인자가 다른 값과 결합되지 않은
    단독 식별자인 경우만 매칭되며, hashlib.sha256((password + salt).encode())처럼
    다른 값과 결합된 경우(자료형이 identifier가 아님)는 매칭되지 않는다."""

    criteria_id = "KISA-026"
    criteria_name = "솔트 없이 일방향 해시함수 사용"
    category = "보안기능"
    languages = ["Python"]
    severity = "Medium"
    message = "비밀번호를 salt 없이 단방향 해시하고 있어 레인보우 테이블 공격에 취약할 수 있습니다."
    recommendation = "비밀번호 해시 시에는 사용자별로 무작위 생성된 salt를 함께 사용하거나 bcrypt/scrypt/argon2 등 salt 내장 알고리즘을 사용하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute
            object: (identifier) @mod (#eq? @mod "hashlib")
            attribute: (identifier) @fn (#eq? @fn "sha256"))
          arguments: (argument_list (call
            function: (attribute
              object: (identifier) @var (#match? @var "(?i)(password|passwd|pwd)")
              attribute: (identifier) @enc (#eq? @enc "encode"))))) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HashWithoutSaltJsRule(Rule):
    """crypto.createHash(...).update(password)처럼 update() 인자가 다른 값과
    결합되지 않은 단독 식별자인 경우만 매칭된다."""

    criteria_id = "KISA-026"
    criteria_name = "솔트 없이 일방향 해시함수 사용"
    category = "보안기능"
    languages = ["Javascript"]
    severity = "Medium"
    message = "비밀번호를 salt 없이 단방향 해시하고 있어 레인보우 테이블 공격에 취약할 수 있습니다."
    recommendation = "비밀번호 해시 시에는 사용자별로 무작위 생성된 salt를 함께 사용하거나 bcrypt/scrypt/argon2 등 salt 내장 알고리즘을 사용하십시오."
    QUERIES = {
        "Javascript": """
        (call_expression
          function: (member_expression
            object: (call_expression
              function: (member_expression
                object: (identifier) @mod (#eq? @mod "crypto")
                property: (property_identifier) @ch (#eq? @ch "createHash")))
            property: (property_identifier) @upd (#eq? @upd "update"))
          arguments: (arguments (identifier) @var (#match? @var "(?i)(password|passwd|pwd)"))) @target
        """
    }


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class HashWithoutSaltJavaRule(Rule):
    """MessageDigest.digest(password.getBytes())처럼 digest() 인자가 다른 값과
    결합되지 않은 단독 identifier.getBytes() 호출인 경우만 매칭된다."""

    criteria_id = "KISA-026"
    criteria_name = "솔트 없이 일방향 해시함수 사용"
    category = "보안기능"
    languages = ["Java"]
    severity = "Medium"
    message = "비밀번호를 salt 없이 단방향 해시하고 있어 레인보우 테이블 공격에 취약할 수 있습니다."
    recommendation = "비밀번호 해시 시에는 사용자별로 무작위 생성된 salt를 함께 사용하거나 bcrypt/scrypt/argon2 등 salt 내장 알고리즘을 사용하십시오."
    QUERIES = {
        "Java": """
        (method_invocation
          object: (method_invocation
            name: (identifier) @get (#eq? @get "getInstance"))
          name: (identifier) @digest (#eq? @digest "digest")
          arguments: (argument_list (method_invocation
            object: (identifier) @var (#match? @var "(?i)(password|passwd|pwd)")
            name: (identifier) @getbytes (#eq? @getbytes "getBytes")))) @target
        """
    }
