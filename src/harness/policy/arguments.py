"""Do these arguments match what the provider said it accepts?

Every adapter declares an ``input_schema`` and nothing read it (R2-07): a proposal could carry
``{"ports": "1-65535", "totally_unknown_arg": "junk"}`` and the policy answered ``allow``, so the one
place that knows what a tool accepts was the tool itself, after the call had already been decided.
Checking the declaration before the verdict moves that failure to where it can be recorded as a
policy reason instead of as a provider error.

What this is not: a JSON Schema implementation. It enforces the keywords the shipped adapters use -
``type``, ``properties``, ``required``, ``additionalProperties``, ``items`` and ``enum`` - and
ignores any other keyword rather than guessing at it. That is a deliberate limit, stated here because
the alternative is worse in both directions: refusing a schema that carries a keyword this does not
know would break an MCP server for declaring something extra, and pretending to enforce it would let
a provider author believe a constraint that nothing checks. A provider that needs more than these
keywords enforced needs a validator, not a schema.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "array": (list, tuple),
    "object": (dict,),
    "null": (type(None),),
}


def schema_violation(schema: Mapping[str, Any] | None, args: Mapping[str, Any]) -> str | None:
    """The first reason these arguments do not match the schema, or ``None`` when they do.

    Returns a sentence rather than a bool because it is recorded as a policy reason, and "the
    arguments were invalid" is not actionable to whoever reads the decision later.
    """
    if not schema:
        return None
    return _check(schema, args, path="args")


def _check(schema: Any, value: Any, *, path: str) -> str | None:
    if not isinstance(schema, Mapping):
        return None

    expected = schema.get("type")
    if isinstance(expected, list):
        candidates = [str(item) for item in expected]
    elif isinstance(expected, str):
        candidates = [expected]
    else:
        candidates = []
    if candidates and not any(_is_type(value, name) for name in candidates):
        # bool is an int in Python, so the integer/number checks below are order-sensitive; naming the
        # declared type in the message is what makes this readable in a decision record.
        return f"{path} is {type(value).__name__}, and the provider accepts {', '.join(candidates)}"

    declared_values = schema.get("enum")
    if isinstance(declared_values, Sequence) and not isinstance(declared_values, (str, bytes)):
        if value not in declared_values:
            return f"{path} is {value!r}, which is not one of {list(declared_values)}"

    properties = schema.get("properties")
    if isinstance(value, Mapping):
        required = schema.get("required")
        if isinstance(required, Sequence) and not isinstance(required, (str, bytes)):
            missing = sorted(str(name) for name in required if name not in value)
            if missing:
                return f"{path} is missing required argument(s) {missing}"
        if isinstance(properties, Mapping):
            for name, sub in properties.items():
                if name in value:
                    problem = _check(sub, value[name], path=f"{path}.{name}")
                    if problem is not None:
                        return problem
        if schema.get("additionalProperties") is False:
            # No `properties` at all still means "nothing else is accepted": a schema that declares
            # `additionalProperties: false` and forgets to list its properties is a provider saying
            # it takes no arguments, not one saying it takes anything.
            declared_names = properties if isinstance(properties, Mapping) else {}
            unknown = sorted(str(name) for name in value if name not in declared_names)
            if unknown:
                accepts = sorted(str(name) for name in declared_names)
                return (
                    f"{path} carries argument(s) {unknown} that the provider does not declare "
                    f"(it accepts {accepts or 'no arguments'})"
                )

    items = schema.get("items")
    if isinstance(value, (list, tuple)) and items is not None:
        for index, entry in enumerate(value):
            problem = _check(items, entry, path=f"{path}[{index}]")
            if problem is not None:
                return problem
    return None


def _is_type(value: Any, name: str) -> bool:
    if name == "integer":
        # A bool is an int in Python; a provider asking for an integer is not asking for `true`.
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    expected = _JSON_TYPES.get(name)
    if expected is None:
        # An unknown type name is a schema this does not understand, not a value that is wrong.
        return True
    return isinstance(value, expected)
