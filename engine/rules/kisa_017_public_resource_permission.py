from engine.base_rule import Rule


class PublicResourcePermissionPythonRule(Rule):
    """클라우드 스토리지 등 중요 자원에 공개 접근 권한(ACL)을 부여하는 패턴을 탐지한다."""

    criteria_id = "KISA-017"
    criteria_name = "중요한 자원에 대한 잘못된 권한 설정"
    category = "보안기능"
    languages = ["Python"]
    severity = "Medium"
    message = "중요 자원(스토리지 등)에 공개 접근 권한(public-read/public-read-write)이 설정되어 누구나 접근할 수 있습니다."
    recommendation = "자원 접근 권한은 필요한 최소 범위로 제한하고, 공개 ACL 대신 명시적인 접근 정책을 사용하십시오."
    QUERIES = {
        "Python": """
        (call
          arguments: (argument_list
            (keyword_argument
              name: (identifier) @k (#eq? @k "ACL")
              value: (string) @v (#match? @v "(?i)public")))) @target
        """
    }
