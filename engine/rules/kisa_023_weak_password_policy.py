from engine.base_rule import Rule


class WeakPasswordPolicyPythonRule(Rule):
    """비밀번호 길이 검증 기준이 지나치게 짧은(8자 미만) 정책을 탐지한다."""

    criteria_id = "KISA-023"
    criteria_name = "취약한 비밀번호 허용"
    category = "보안기능"
    languages = ["Python"]
    severity = "Medium"
    message = "비밀번호 길이 검증 기준이 지나치게 짧아 취약한 비밀번호가 허용될 수 있습니다."
    recommendation = "비밀번호는 최소 8자 이상이면서 문자/숫자/특수문자를 조합하도록 복잡도 정책을 강제하십시오."
    QUERIES = {
        "Python": """
        (comparison_operator
          (call
            function: (identifier) @lenfn (#eq? @lenfn "len")
            arguments: (argument_list (identifier) @var (#match? @var "(?i)(password|passwd|pwd)")))
          (integer) @threshold (#match? @threshold "^[0-7]$")) @target
        """
    }
