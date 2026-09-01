import re

from engine.base_rule import Rule

_SENSITIVE_PATH_RE = re.compile(r"(admin|delete|manage)", re.IGNORECASE)
_AUTH_DECORATOR_RE = re.compile(r"(login_required|admin_required|permission_required|authenticated)", re.IGNORECASE)


class MissingAuthenticationPythonRule(Rule):
    """관리자/삭제 등 민감한 경로로 추정되는 Flask 라우트에 인증 데코레이터가 없는 경우를 탐지한다."""

    criteria_id = "KISA-015"
    criteria_name = "적절한 인증 없는 중요 기능 허용"
    category = "보안기능"
    languages = ["Python"]
    severity = "High"
    message = "관리자 기능 등 민감한 라우트로 추정되나 인증을 검증하는 데코레이터가 없어 인증 없이 접근이 가능할 수 있습니다."
    recommendation = "민감한 기능을 처리하는 라우트에는 로그인/권한 검증 데코레이터(login_required 등)를 적용하십시오."
    QUERIES = {
        "Python": """
        (decorated_definition
          (decorator (call
            function: (attribute attribute: (identifier) @fn (#eq? @fn "route"))
            arguments: (argument_list (string) @path)))) @target
        """
    }

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            target_nodes = captures.get("target")
            path_nodes = captures.get("path")
            if not target_nodes or not path_nodes:
                continue
            path_text = source[path_nodes[0].start_byte : path_nodes[0].end_byte].decode(
                "utf-8", errors="replace"
            )
            if not _SENSITIVE_PATH_RE.search(path_text):
                continue
            decorated = target_nodes[0]
            decorator_texts = [
                source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
                for child in decorated.children
                if child.type == "decorator"
            ]
            if any(_AUTH_DECORATOR_RE.search(text) for text in decorator_texts):
                continue
            findings.append(self._build_finding(decorated, source, file_path, language))
        return findings
