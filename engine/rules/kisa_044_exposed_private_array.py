from engine.base_rule import Rule


def _modifiers_text(node, source) -> str:
    for child in node.children:
        if child.type == "modifiers":
            return source[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
    return ""


class ExposedPrivateArrayJavaRule(Rule):
    """private 배열 필드를 public 메소드가 clone() 없이 그대로 반환(참조 노출)하는 패턴을 탐지한다."""

    criteria_id = "KISA-044"
    criteria_name = "Public 메소드로부터 반환된 Private 배열"
    category = "캡슐화"
    languages = ["Java"]
    severity = "Low"
    message = "private 배열 필드를 참조 그대로 반환하고 있어, 호출자가 내부 상태를 임의로 변경할 수 있습니다."
    recommendation = "배열을 반환할 때는 clone()으로 복사본을 반환하십시오."
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
                if child.type != "method_declaration":
                    continue
                if "public" not in _modifiers_text(child, source):
                    continue
                ret_type = child.child_by_field_name("type")
                if ret_type is None or ret_type.type != "array_type":
                    continue
                body = child.child_by_field_name("body")
                if body is None:
                    continue
                for stmt in body.named_children:
                    if stmt.type != "return_statement" or not stmt.named_children:
                        continue
                    value = stmt.named_children[0]
                    if value.type != "identifier":
                        continue
                    name = source[value.start_byte : value.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                    if name in private_array_fields:
                        findings.append(self._build_finding(stmt, source, file_path, language))
        return findings
