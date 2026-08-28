from engine.base_rule import TaintedArgumentRule, Rule

_MESSAGE = "외부 입력값이 검증 없이 파일 경로에 사용되어 시스템 파일에 접근할 수 있습니다."
_RECOMMENDATION = "경로를 화이트리스트로 검증하거나 정규화(normpath) 후 허용된 디렉터리 하위인지 확인하십시오."


class PathTraversalOpenPythonRule(TaintedArgumentRule):
    criteria_id = "KISA-002"
    criteria_name = "경로 조작 및 자원 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Python"]
    severity = "High"
    message = _MESSAGE
    recommendation = _RECOMMENDATION
    QUERIES = {
        "Python": """
        (call
          function: (identifier) @fn (#eq? @fn "open")
          arguments: (argument_list) @args) @target
        """
    }


class ZipSlipJavaRule(Rule):
    """압축 해제 시 엔트리 이름을 검증 없이 File 경로에 그대로 사용하는 Zip Slip 패턴."""

    criteria_id = "KISA-002"
    criteria_name = "경로 조작 및 자원 삽입"
    category = "입력데이터 검증 및 표현"
    languages = ["Java"]
    severity = "High"
    message = "압축 파일 엔트리 이름이 검증 없이 파일 경로 생성에 사용되어 Zip Slip 취약점이 발생할 수 있습니다."
    recommendation = "압축 해제 대상 경로가 지정된 작업 디렉터리 하위인지 정규화 후 검증하십시오."
    QUERIES = {
        "Java": """
        (object_creation_expression
          type: (type_identifier) @t (#eq? @t "File")
          arguments: (argument_list (_) (method_invocation name: (identifier) @m (#eq? @m "getName")))) @target
        """
    }
