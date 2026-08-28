from engine.base_rule import Rule


class WeakHashPythonRule(Rule):
    criteria_id = "KISA-018"
    criteria_name = "취약한 암호화 알고리즘 사용"
    category = "보안기능"
    languages = ["Python"]
    severity = "Medium"
    message = "안전성이 검증되지 않은 취약한 해시 알고리즘(MD5/SHA1)을 사용하고 있습니다."
    recommendation = "SHA-256 이상의 안전한 해시 알고리즘으로 대체하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute object: (identifier) @mod (#eq? @mod "hashlib") attribute: (identifier) @fn (#match? @fn "^(md5|sha1)$"))) @target
        """
    }


class WeakCryptoJavaRule(Rule):
    criteria_id = "KISA-018"
    criteria_name = "취약한 암호화 알고리즘 사용"
    category = "보안기능"
    languages = ["Java"]
    severity = "Medium"
    message = "안전성이 검증되지 않은 취약한 암호화/해시 알고리즘(MD5/SHA1/DES)을 사용하고 있습니다."
    recommendation = "SHA-256 이상의 해시 또는 AES-256 등 안전한 암호화 알고리즘으로 대체하십시오."
    QUERIES = {
        "Java": """
        (method_invocation
          object: (identifier) @o (#match? @o "^(MessageDigest|Cipher)$")
          name: (identifier) @m (#eq? @m "getInstance")
          arguments: (argument_list (string_literal) @alg (#match? @alg "(?i)(md5|sha-?1|\\\\bdes\\\\b)"))) @target
        """
    }
