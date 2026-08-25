"""Lightweight, comment-aware Rust source-shape checks.

This is intentionally a lexer, not a Rust parser. It is suitable for CI checks that
must tolerate rustfmt whitespace while continuing to compare literal and code tokens
exactly. Call matching also tolerates rustfmt's optional outer trailing comma.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
import re


class RustLexError(ValueError):
    """Raised when a string literal or block comment is unterminated."""


_MULTI_PUNCTUATION = tuple(
    sorted(
        ("<<=", ">>=", "..=", "...", "::", "->", "=>", "==", "!=", "<=", ">=",
         "&&", "||", "<<", ">>", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", ".."),
        key=len,
        reverse=True,
    )
)
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
_JSON_KEY = re.compile(r'^"([A-Za-z_][A-Za-z0-9_]*)"$')


@dataclass(frozen=True)
class RustFunction:
    """Token-bounded Rust function declaration and its body."""

    name: str
    tokens: tuple[str, ...]
    body: tuple[str, ...]


def _identifier_start(character: str) -> bool:
    return character == "_" or character.isalpha() or ord(character) >= 128


def _identifier_continue(character: str) -> bool:
    return character == "_" or character.isalnum() or ord(character) >= 128


def _quoted_end(source: str, quote: int) -> int:
    index = quote + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == '"':
            return index + 1
        else:
            index += 1
    raise RustLexError("unterminated Rust string literal")


def _raw_string_end(source: str, start: int) -> int | None:
    for prefix in ("br", "cr", "r"):
        if not source.startswith(prefix, start):
            continue
        index = start + len(prefix)
        while index < len(source) and source[index] == "#":
            index += 1
        if index >= len(source) or source[index] != '"':
            continue
        hashes = source[start + len(prefix):index]
        closing = '"' + hashes
        end = source.find(closing, index + 1)
        if end < 0:
            raise RustLexError("unterminated Rust raw string literal")
        return end + len(closing)
    return None


def _character_end(source: str, quote: int) -> int | None:
    index = quote + 1
    if index >= len(source) or source[index] in "'\r\n":
        return None
    if source[index] == "\\":
        index += 1
        if index >= len(source):
            raise RustLexError("unterminated Rust character literal")
        if source[index] == "u" and index + 1 < len(source) and source[index + 1] == "{":
            index = source.find("}", index + 2)
            if index < 0:
                raise RustLexError("unterminated Rust Unicode escape")
            index += 1
        elif source[index] == "x":
            index += 3
        else:
            index += 1
    else:
        index += 1
    return index + 1 if index < len(source) and source[index] == "'" else None


def _numeric_end(source: str, start: int) -> int:
    """Return the end of one Rust numeric literal without consuming operators."""
    index = start
    if source.startswith(("0b", "0B"), start):
        index = start + 2
        valid_digits = "01_"
    elif source.startswith(("0o", "0O"), start):
        index = start + 2
        valid_digits = "01234567_"
    elif source.startswith(("0x", "0X"), start):
        index = start + 2
        valid_digits = "0123456789abcdefABCDEF_"
    else:
        valid_digits = "0123456789_"
    while index < len(source) and source[index] in valid_digits:
        index += 1

    decimal = valid_digits == "0123456789_"
    if (
        decimal
        and index < len(source)
        and source[index] == "."
        and not source.startswith("..", index)
        and (
            index + 1 == len(source)
            or source[index + 1].isdigit()
            or source[index + 1] in "_eE"
            or not _identifier_start(source[index + 1])
        )
    ):
        index += 1
        while index < len(source) and (source[index].isdigit() or source[index] == "_"):
            index += 1

    if decimal and index < len(source) and source[index] in "eE":
        exponent = index
        cursor = index + 1
        if cursor < len(source) and source[cursor] in "+-":
            cursor += 1
        digit_start = cursor
        while cursor < len(source) and (source[cursor].isdigit() or source[cursor] == "_"):
            cursor += 1
        if cursor > digit_start:
            index = cursor
        else:
            index = exponent

    if index < len(source) and _identifier_start(source[index]):
        index += 1
        while index < len(source) and _identifier_continue(source[index]):
            index += 1
    return index


@lru_cache(maxsize=256)
def tokenize_rust(source: str) -> tuple[str, ...]:
    """Return Rust lexical tokens, discarding whitespace and nested comments."""
    tokens: list[str] = []
    index = 0
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < len(source) and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise RustLexError("unterminated Rust block comment")
            index = cursor
            continue

        raw_end = _raw_string_end(source, index)
        if raw_end is not None:
            tokens.append(source[index:raw_end])
            index = raw_end
            continue
        if source[index] == '"' or (
            source[index] in "bc" and index + 1 < len(source) and source[index + 1] == '"'
        ):
            quote = index if source[index] == '"' else index + 1
            end = _quoted_end(source, quote)
            tokens.append(source[index:end])
            index = end
            continue
        quote = index + 1 if source.startswith("b'", index) else index
        if quote < len(source) and source[quote] == "'":
            end = _character_end(source, quote)
            if end is not None:
                tokens.append(source[index:end])
                index = end
                continue
        if source.startswith("r#", index) and index + 2 < len(source) and _identifier_start(source[index + 2]):
            end = index + 3
            while end < len(source) and _identifier_continue(source[end]):
                end += 1
            tokens.append(source[index:end])
            index = end
            continue
        if _identifier_start(source[index]):
            end = index + 1
            while end < len(source) and _identifier_continue(source[end]):
                end += 1
            tokens.append(source[index:end])
            index = end
            continue
        if source[index].isdigit():
            end = _numeric_end(source, index)
            tokens.append(source[index:end])
            index = end
            continue
        punctuation = next((item for item in _MULTI_PUNCTUATION if source.startswith(item, index)), None)
        if punctuation is not None:
            tokens.append(punctuation)
            index += len(punctuation)
        else:
            tokens.append(source[index])
            index += 1
    return tuple(tokens)


def rust_code_contains(source: str, marker: str) -> bool:
    """Return whether ``marker`` occurs as one contiguous Rust token sequence."""
    expected = tokenize_rust(marker)
    if not expected:
        raise ValueError("Rust marker must contain at least one code token")
    actual = tokenize_rust(source)
    return _tokens_contain(actual, expected)


def _tokens_contain(actual: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    width = len(expected)
    return any(actual[index:index + width] == expected for index in range(len(actual) - width + 1))


def _matching_delimiter(tokens: tuple[str, ...], opening: int) -> int | None:
    expected_close = _OPEN_TO_CLOSE.get(tokens[opening])
    if expected_close is None:
        raise ValueError("opening token is not a Rust delimiter")
    stack = [expected_close]
    for index in range(opening + 1, len(tokens)):
        token = tokens[index]
        if token in _OPEN_TO_CLOSE:
            stack.append(_OPEN_TO_CLOSE[token])
        elif token in _OPEN_TO_CLOSE.values():
            if not stack or token != stack.pop():
                return None
            if not stack:
                return index
    return None


def rust_json_object_key_sets(
    source: str,
    required_keys: Sequence[str] = ("schema_version", "ready"),
) -> tuple[frozenset[str], ...]:
    """Return top-level key sets for balanced JSON-like Rust objects.

    String keys must be simple quoted identifiers followed by ``:``. Nested object
    keys are deliberately excluded from their parent and may form their own result.
    """
    if isinstance(required_keys, str):
        raise TypeError("required_keys must be a sequence of key names")
    required = frozenset(required_keys)
    if not required or any(_JSON_KEY.fullmatch(f'"{key}"') is None for key in required):
        raise ValueError("required_keys must contain simple JSON key names")
    tokens = tokenize_rust(source)
    candidates: list[frozenset[str]] = []
    for opening, token in enumerate(tokens):
        if token != "{":
            continue
        closing = _matching_delimiter(tokens, opening)
        if closing is None:
            continue
        keys: set[str] = set()
        index = opening + 1
        while index < closing:
            nested = tokens[index]
            if nested in _OPEN_TO_CLOSE:
                nested_close = _matching_delimiter(tokens, index)
                if nested_close is None or nested_close > closing:
                    break
                index = nested_close + 1
                continue
            key = _JSON_KEY.fullmatch(nested)
            if key is not None and index + 1 < closing and tokens[index + 1] == ":":
                keys.add(key.group(1))
            index += 1
        frozen = frozenset(keys)
        if required <= frozen:
            candidates.append(frozen)
    return tuple(candidates)


def extract_rust_functions(source: str, function_name: str) -> tuple[RustFunction, ...]:
    """Extract token-balanced definitions named ``function_name`` from Rust source."""
    name_tokens = tokenize_rust(function_name)
    if len(name_tokens) != 1 or not _identifier_start(name_tokens[0][0]):
        raise ValueError("function_name must be one Rust identifier")
    name = name_tokens[0]
    tokens = tokenize_rust(source)
    functions: list[RustFunction] = []
    for start in range(len(tokens) - 2):
        if tokens[start:start + 2] != ("fn", name):
            continue
        parameters = start + 2
        if tokens[parameters] != "(":
            continue
        parameter_end = _matching_delimiter(tokens, parameters)
        if parameter_end is None:
            continue
        body_start: int | None = None
        cursor = parameter_end + 1
        while cursor < len(tokens):
            if tokens[cursor] == ";":
                break
            if tokens[cursor] == "{":
                body_start = cursor
                break
            if tokens[cursor] in ("(", "["):
                nested_end = _matching_delimiter(tokens, cursor)
                if nested_end is None:
                    break
                cursor = nested_end
            cursor += 1
        if body_start is None:
            continue
        body_end = _matching_delimiter(tokens, body_start)
        if body_end is None:
            continue
        functions.append(RustFunction(
            name=name,
            tokens=tokens[start:body_end + 1],
            body=tokens[body_start + 1:body_end],
        ))
    return tuple(functions)


def rust_function_code_contains(source: str, function_name: str, marker: str) -> bool:
    """Check for a real token sequence inside a named function body only."""
    expected = tokenize_rust(marker)
    if not expected:
        raise ValueError("Rust marker must contain at least one code token")
    return any(_tokens_contain(function.body, expected) for function in extract_rust_functions(source, function_name))


def rust_call_contains(source: str, callee: str, arguments: Sequence[str]) -> bool:
    """Match a Rust call with exact ordered argument tokens and optional trailing comma."""
    return _rust_call_tokens_contain(tokenize_rust(source), callee, arguments)


def _rust_call_tokens_contain(
    tokens: tuple[str, ...], callee: str, arguments: Sequence[str]
) -> bool:
    if isinstance(arguments, str):
        raise TypeError("arguments must be a sequence of Rust argument fragments")
    callee_tokens = tokenize_rust(callee)
    if not callee_tokens or any(token in _OPEN_TO_CLOSE or token in _OPEN_TO_CLOSE.values() for token in callee_tokens):
        raise ValueError("callee must be a non-empty Rust path or method expression")
    argument_tokens = [tokenize_rust(argument) for argument in arguments]
    if any(not argument for argument in argument_tokens):
        raise ValueError("Rust call arguments cannot be empty")
    expected_body: tuple[str, ...] = tuple(
        token
        for argument_index, argument in enumerate(argument_tokens)
        for token in ((",",) if argument_index else ()) + argument
    )
    width = len(callee_tokens)
    for index in range(len(tokens) - width):
        if tokens[index:index + width] != callee_tokens:
            continue
        if index and tokens[index - 1] in (".", "::"):
            continue
        opening = index + width
        if tokens[opening] != "(":
            continue
        closing = _matching_delimiter(tokens, opening)
        if closing is None:
            continue
        body = tokens[opening + 1:closing]
        if body[-1:] == (",",):
            body = body[:-1]
        if body == expected_body:
            return True
    return False


def rust_function_call_contains(
    source: str,
    function_name: str,
    callee: str,
    arguments: Sequence[str],
) -> bool:
    """Check for an exact call inside a named function body only."""
    return any(
        _rust_call_tokens_contain(function.body, callee, arguments)
        for function in extract_rust_functions(source, function_name)
    )
