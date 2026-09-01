from engine.base_rule import Rule, _contains_identifier


class SessionDataExposurePythonRule(Rule):
    """요청별로 달라야 할 데이터를 세션이 아닌 전역(global) 변수에 저장하는 패턴을 탐지한다.
    여러 사용자의 요청이 하나의 전역 상태를 공유하게 되어, 다른 사용자의 데이터가 노출될 수 있다."""

    criteria_id = "KISA-041"
    criteria_name = "잘못된 세션에 의한 데이터 정보노출"
    category = "캡슐화"
    languages = ["Python"]
    severity = "High"
    message = "요청별 데이터를 세션이 아닌 전역 변수에 저장하고 있어, 동시 요청 시 다른 사용자의 데이터가 노출될 수 있습니다."
    recommendation = "요청별 데이터는 전역 변수 대신 세션(session) 객체 또는 요청 컨텍스트에 저장하십시오."
    QUERIES = {"Python": "(function_definition body: (block) @body) @target"}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            body_nodes = captures.get("body")
            if not body_nodes:
                continue
            body = body_nodes[0]
            global_names = set()
            for child in body.children:
                if child.type == "global_statement":
                    for n in child.named_children:
                        if n.type == "identifier":
                            global_names.add(
                                source[n.start_byte : n.end_byte].decode("utf-8", errors="replace")
                            )
            if not global_names:
                continue
            for child in body.children:
                if child.type != "expression_statement" or not child.named_children:
                    continue
                assign = child.named_children[0]
                if assign.type != "assignment":
                    continue
                left = assign.child_by_field_name("left")
                right = assign.child_by_field_name("right")
                if left is None or right is None or left.type != "identifier":
                    continue
                left_name = source[left.start_byte : left.end_byte].decode(
                    "utf-8", errors="replace"
                )
                if left_name not in global_names:
                    continue
                if _contains_identifier(right, {"request", "req", "params"}):
                    findings.append(self._build_finding(child, source, file_path, language))
        return findings
