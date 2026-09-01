from engine.base_rule import TaintedArgumentRule, Rule

_MESSAGE = "업로드된 파일을 원본 파일명 그대로 저장하여 실행 가능한 스크립트 파일 등이 업로드될 수 있습니다."
_RECOMMENDATION = "저장 파일명은 서버에서 새로 생성(UUID 등)하고, 확장자를 허용 목록으로 검증하십시오."


class DangerousFileUploadPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-005"
    criteria_name = "위험한 형식 파일 업로드"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    taint_sources = {"filename"}
    QUERIES = {
        "Python": """
        (call
          function: (attribute attribute: (identifier) @m (#eq? @m "save"))
          arguments: (argument_list) @args) @target
        """
    }


class DangerousFileUploadJavaRule(Rule):
    """MultipartFile의 원본 파일명(getOriginalFilename)을 그대로 저장 경로에 사용하는 패턴."""

    criteria_id = "KISA-005"
    criteria_name = "위험한 형식 파일 업로드"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Java": """
        (object_creation_expression
          type: (type_identifier) @t (#eq? @t "File")
          arguments: (argument_list (_) (method_invocation name: (identifier) @m (#eq? @m "getOriginalFilename")))) @target
        """
    }
