import re

from engine.base_rule import Rule

_CONDITION_RE = re.compile(r"os\.path\.(exists|isfile)")
_RISKY_CALL_RE = re.compile(r"\bopen\s*\(")


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class ToctouPythonRule(Rule):
    """os.path.exists()로 존재 여부를 검사한 직후 같은 블록에서 open()하는 TOCTOU 패턴을 탐지한다."""

    criteria_id = "KISA-027"
    criteria_name = "경쟁조건: 검사 시점과 사용 시점(TOCTOU)"
    category = "시간 및 상태"
    languages = ["Python"]
    severity = "Medium"
    message = "파일 존재 여부를 검사한 시점과 실제로 파일을 여는 시점 사이에 경쟁조건(TOCTOU)이 발생할 수 있습니다."
    recommendation = "검사와 사용을 분리하지 말고, 파일을 열 때 발생하는 예외를 직접 처리하는 방식을 사용하십시오."
    QUERIES = {
        "Python": """
        (if_statement
          condition: (call function: (attribute) @cond_fn)
          consequence: (block) @body) @target
        """
    }

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            cond_nodes = captures.get("cond_fn")
            body_nodes = captures.get("body")
            if not target_nodes or not cond_nodes or not body_nodes:
                continue
            cond_text = source[cond_nodes[0].start_byte : cond_nodes[0].end_byte].decode(
                "utf-8", errors="replace"
            )
            if not _CONDITION_RE.search(cond_text):
                continue
            body_text = source[body_nodes[0].start_byte : body_nodes[0].end_byte].decode(
                "utf-8", errors="replace"
            )
            if not _RISKY_CALL_RE.search(body_text):
                continue
            findings.append(self._build_finding(target_nodes[0], source, file_path, language))
        return findings
