import re

from engine.base_rule import Rule

_CLOSE_RE = re.compile(r"^(\w+)\.close\(\)$")


# SFR-011: 초기 대상 언어(Java/Javascript/Python) 소스코드에 대한 구조화된 코드 분석 기반 보안 취약점 진단 항목 구현
class UseAfterCloseePythonRule(Rule):
    """같은 블록 안에서 f.close() 호출 이후 동일 변수의 메소드를 다시 호출하는(해제된 자원 재사용) 패턴을 탐지한다."""

    criteria_id = "KISA-035"
    criteria_name = "해제된 자원 사용"
    category = "코드오류"
    languages = ["Python"]
    severity = "Medium"
    message = "close()로 이미 해제한 자원을 같은 블록에서 다시 사용하고 있습니다."
    recommendation = "자원을 닫은 이후에는 재사용하지 말고, with 문으로 수명주기를 관리하십시오."
    QUERIES = {}

    def find(self, tree, source, file_path, language):
        findings = []
        self._scan_block(tree.root_node, source, file_path, language, findings)
        return findings

    def _scan_block(self, node, source, file_path, language, findings):
        if node.type in ("block", "module"):
            closed = set()
            for child in node.children:
                if not child.is_named:
                    continue
                text = source[child.start_byte : child.end_byte].decode(
                    "utf-8", errors="replace"
                ).strip()
                match = _CLOSE_RE.match(text)
                if match:
                    closed.add(match.group(1))
                    continue
                for name in closed:
                    if re.search(rf"\b{re.escape(name)}\.\w+\(", text):
                        findings.append(self._build_finding(child, source, file_path, language))
                        break
        for child in node.children:
            self._scan_block(child, source, file_path, language, findings)
