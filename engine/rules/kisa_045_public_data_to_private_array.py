from engine.base_rule import Rule


def _modifiers_text(node, source) -> str:
    for child in node.children:
        if child.type == "modifiers":
            return source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
    return ""


class PublicDataToPrivateArrayJavaRule(Rule):
    """생성자/메소드 파라미터로 받은 배열을 clone() 없이 곧바로 private 배열 필드에 저장하는 패턴을 탐지한다."""

    criteria_id = "KISA-045"
    criteria_name = "Private 배열에 Public 데이터 할당"
    category = "캡슐화"
    languages = ["Java"]
    severity = "Low"
    message = "외부에서 전달받은 배열 참조를 그대로 private 필드에 저장하고 있어, 호출자가 내부 상태를 임의로 변경할 수 있습니다."
    recommendation = "배열 파라미터는 clone()으로 복사한 뒤 필드에 저장하십시오."
    QUERIES = {"Java": "(class_declaration body: (class_body) @cbody) @target"}

    def find(self, tree, source, file_path, language):
        findings = []
        for _pattern_index, captures in self._run_query(tree, language):
            cbody_nodes = captures.get("cbody")
            if not cbody_nodes:
                continue
            cbody = cbody_nodes[0]
            private_array_fields = set()
            for child in cbody.named_children:
                if child.type != "field_declaration":
                    continue
                type_node = child.child_by_field_name("type")
                if type_node is None or type_node.type != "array_type":
                    continue
                if "private" not in _modifiers_text(child, source):
                    continue
                declarator = child.child_by_field_name("declarator")
                name_node = declarator.child_by_field_name("name") if declarator else None
                if name_node is not None:
                    private_array_fields.add(
                        source[name_node.start_byte : name_node.end_byte].decode(
                            "utf-8", errors="replace"
                        )
                    )
            if not private_array_fields:
                continue

            for child in cbody.named_children:
                if child.type not in ("constructor_declaration", "method_declaration"):
                    continue
                body = child.child_by_field_name("body")
                if body is None:
                    continue
                for stmt in body.named_children:
                    if stmt.type != "expression_statement" or not stmt.named_children:
                        continue
                    assign = stmt.named_children[0]
                    if assign.type != "assignment_expression":
                        continue
                    left = assign.child_by_field_name("left")
                    right = assign.child_by_field_name("right")
                    if left is None or right is None or left.type != "field_access":
                        continue
                    field_node = left.child_by_field_name("field")
                    if field_node is None or right.type != "identifier":
                        continue
                    field_name = source[field_node.start_byte : field_node.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                    if field_name in private_array_fields:
                        findings.append(self._build_finding(stmt, source, file_path, language))
        return findings
