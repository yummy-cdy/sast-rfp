from engine.base_rule import Rule


class HardcodedCryptoKeyPythonRule(Rule):
    criteria_id = "KISA-022"
    criteria_name = "하드코드된 암호화 키"
    category = "보안기능"
    languages = ["Python"]
    severity = "High"
    message = "암호화 키/salt/IV로 추정되는 값이 소스코드에 평문으로 고정되어 있습니다."
    recommendation = "암호화 키는 환경변수 또는 KMS/Vault 등 별도 키 관리 체계에서 로드하십시오."
    QUERIES = {
        "Python": """
        (assignment
          left: (identifier) @varname (#match? @varname "(?i)^(secret[_-]?key|encryption[_-]?key|crypto[_-]?key|salt|iv)$")
          right: (string) @target)
        """
    }
