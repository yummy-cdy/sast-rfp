import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser, Tree

# SFR-010/QLT-003: 언어 확장은 여기에 문법 패키지 1개만 추가하면 된다.
_LANGUAGES: dict[str, Language] = {
    "Python": Language(tspython.language()),
    "Javascript": Language(tsjavascript.language()),
    "Java": Language(tsjava.language()),
}

_EXTENSION_TO_LANGUAGE = {
    ".py": "Python",
    ".js": "Javascript",
    ".jsx": "Javascript",
    ".java": "Java",
}

_PARSERS: dict[str, Parser] = {
    language: Parser(grammar) for language, grammar in _LANGUAGES.items()
}


def language_for_extension(extension: str) -> str | None:
    return _EXTENSION_TO_LANGUAGE.get(extension.lower())


def get_language(language: str) -> Language:
    return _LANGUAGES[language]


def parse_source(source_bytes: bytes, language: str) -> Tree:
    return _PARSERS[language].parse(source_bytes)


def read_source_bytes(file_path: str) -> bytes | None:
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except OSError:
        return None
