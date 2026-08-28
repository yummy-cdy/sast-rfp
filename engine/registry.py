import importlib
import inspect
import pkgutil

from engine.base_rule import Rule
import engine.rules as rules_package


def _discover_rules() -> list[Rule]:
    """engine/rules/ 하위 모든 모듈을 스캔해 Rule 서브클래스를 자동 등록한다.
    신규 진단 항목은 이 패키지에 파일 1개만 추가하면 되며 registry.py 수정이 불필요하다 (SFR-012)."""
    discovered: list[Rule] = []
    for module_info in pkgutil.iter_modules(rules_package.__path__):
        module = importlib.import_module(f"{rules_package.__name__}.{module_info.name}")
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Rule) and obj is not Rule and obj.__module__ == module.__name__:
                discovered.append(obj())
    return discovered


ALL_RULES: list[Rule] = _discover_rules()


def get_rules_for_language(language: str) -> list[Rule]:
    return [rule for rule in ALL_RULES if language in rule.languages]
