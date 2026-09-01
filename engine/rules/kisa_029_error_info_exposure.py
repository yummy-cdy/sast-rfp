from engine.base_rule import Rule


class ErrorInfoExposurePythonRule(Rule):
    criteria_id = "KISA-029"
    criteria_name = "오류 메시지를 통한 정보노출"
    category = "에러처리"
    languages = ["Python"]
    severity = "Medium"
    message = "예외의 상세 트레이스백을 조회/전송하고 있어 시스템 내부 정보가 노출될 수 있습니다."
    recommendation = "사용자에게는 일반화된 오류 메시지만 전달하고, 상세 트레이스백은 서버 내부 로그로만 기록하십시오."
    QUERIES = {
        "Python": """
        (call
          function: (attribute
            object: (identifier) @mod (#eq? @mod "traceback")
            attribute: (identifier) @fn (#match? @fn "^(format_exc|print_exc)$"))) @target
        """
    }


class ErrorInfoExposureJavaRule(Rule):
    criteria_id = "KISA-029"
    criteria_name = "오류 메시지를 통한 정보노출"
    category = "에러처리"
    languages = ["Java"]
    severity = "Medium"
    message = "예외의 스택 트레이스를 직접 출력하고 있어 시스템 내부 정보가 노출될 수 있습니다."
    recommendation = "printStackTrace() 대신 로깅 프레임워크로 내부 로그에만 기록하고, 사용자에게는 일반화된 오류 메시지를 전달하십시오."
    QUERIES = {
        "Java": '(method_invocation name: (identifier) @m (#eq? @m "printStackTrace")) @target'
    }
