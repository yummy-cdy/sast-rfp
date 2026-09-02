import re

from engine.base_rule import Rule

_BROAD_TYPE_RE = re.compile(r"(?i)\b(Exception|BaseException)\b")


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class ImproperExceptionHandlingPythonRule(Rule):
    """bare except: 또는 except Exception(/BaseException)처럼 지나치게 광범위한 예외 타입을 잡는 경우를 탐지한다.
    (비어 있는 catch 블록은 KISA-032에서 별도로 다룬다.)"""

    criteria_id = "KISA-031"
    criteria_name = "부적절한 예외처리"
    category = "에러처리"
    languages = ["Python"]
    severity = "Low"
    message = "예외 타입을 지정하지 않거나 최상위 Exception으로 뭉뚱그려 처리하고 있어, 서로 다른 오류 상황이 구분 없이 처리됩니다."
    recommendation = "예상되는 구체적인 예외 타입별로 나누어 처리하십시오."
    QUERIES = {"Python": "(except_clause) @target"}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            if not target_nodes:
                continue
            target = target_nodes[0]
            value_node = target.child_by_field_name("value")
            if value_node is not None:
                text = source[value_node.start_byte : value_node.end_byte].decode(
                    "utf-8", errors="replace"
                )
                if not _BROAD_TYPE_RE.search(text):
                    continue
            findings.append(self._build_finding(target, source, file_path, language))
        return findings


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class ImproperExceptionHandlingJavaRule(Rule):
    criteria_id = "KISA-031"
    criteria_name = "부적절한 예외처리"
    category = "에러처리"
    languages = ["Java"]
    severity = "Low"
    message = "구체적인 예외 타입 대신 Exception/Throwable/RuntimeException처럼 지나치게 광범위한 타입을 잡고 있어, 서로 다른 오류 상황이 구분 없이 처리됩니다."
    recommendation = "예상되는 구체적인 예외 타입별로 나누어 처리하십시오."
    QUERIES = {
        "Java": """
        (catch_clause
          (catch_formal_parameter
            (catch_type (type_identifier) @t (#match? @t "^(Exception|Throwable|RuntimeException)$")))) @target
        """
    }
