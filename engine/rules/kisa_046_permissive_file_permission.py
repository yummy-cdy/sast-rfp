from engine.base_rule import Rule


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class PermissiveFilePermissionPythonRule(Rule):
    criteria_id = "KISA-046"
    criteria_name = "잘못된 파일 업로드 권한 부여(파일 권한 설정 오류)"
    category = "캡슐화"
    languages = ["Python"]
    severity = "Medium"
    message = "파일/디렉터리에 과도하게 허용적인 권한이 부여되고 있습니다."
    recommendation = "필요한 최소 권한만 부여하십시오 (예: 0o644/0o750)."
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @fn (#eq? @fn "chmod"))
          arguments: (argument_list (_) (integer) @target (#match? @target "^0[oO]?(7[0-7][0-7]|6[6-7][6-7])$")))
        """
    }
