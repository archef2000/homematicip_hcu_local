# pyright: reportMissingTypeStubs=false, reportDeprecated=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAny=false, reportExplicitAny=false
import functools
import inspect
import logging
import time
import types
from typing import (
    Any,
    Callable,
    Literal,
    ParamSpec,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)
import warnings


def _is_typed_dict(tp: object) -> bool:
    if not isinstance(tp, type):  # not a class
        return False
    if not hasattr(tp, "__annotations__"):
        return False
    return hasattr(tp, "__total__") or hasattr(tp, "__required_keys__")


def _validate_typed_dict(
    name: str,
    spec: type,
    value: object,
    issues: list[str],
    *,
    allow_extra: bool = False,
    record_unexpected: bool = True,
) -> None:
    """Validate a TypedDict-like object.

    allow_extra controls whether unexpected keys raise (False) or are just
    collected as issues (True). Used with union probing to avoid premature
    failure before picking the best variant.
    """
    if not isinstance(value, dict):
        issues.append(
            f"{name}: expected dict (TypedDict {spec.__name__}), got {type(value).__name__}"
        )
        return
    annotations: dict[str, object] = getattr(spec, "__annotations__", {})  # type: ignore[reportExplicitAny]
    for k, tp in annotations.items():
        if k not in value:  # type: ignore[reportUnknownArgumentType]
            # Suppress missing-key report when the field is Optional (i.e. Union[..., None])
            is_optional = False
            try:
                if _is_union_type(tp):
                    args = get_args(tp)
                    # Optional if a NoneType member exists
                    if any(a is type(None) for a in args):  # noqa: E721
                        is_optional = True
                elif tp is None or tp is type(None):  # direct None annotation
                    is_optional = True
            except Exception:  # pragma: no cover - defensive
                pass
            if not is_optional:
                issues.append(f"{name}.{k}: missing key")
            continue
        # Use full runtime checker (handles unions & nested TypedDicts)
        _runtime_type_check(tp, value[k], f"{name}.{k}", issues)
    if record_unexpected:
        extras = [str(k) for k in value.keys() if k not in annotations]
        if extras:
            if not allow_extra:
                raise KeyError(f"{name}: unexpected key(s) {extras}")


def _is_union_type(tp: object) -> bool:
    """Return True if tp is a typing / PEP 604 union construct."""
    origin = get_origin(tp)
    if origin is Union:
        return True
    return origin is types.UnionType


_UNION_DISCRIMINATOR_KEYS: tuple[str, ...] = (
    "type",
    "pushEventType",
    "functionalChannelType",
    "channelRole",
)


def _literal_values(tp: object) -> set[object]:
    if get_origin(tp) is Literal:
        return set(get_args(tp))
    return set()


def _pick_typed_dict_union_variant(
    variants: tuple[object, ...], value: object
) -> object | None:
    if not isinstance(value, dict):
        return None
    best: object | None = None
    best_score = -10
    for variant in variants:
        if not _is_typed_dict(variant):
            continue
        ann = getattr(variant, "__annotations__", {})
        score = 0
        matched = False
        for key in _UNION_DISCRIMINATOR_KEYS:
            if key in value and key in ann:
                tp = ann[key]
                lits = _literal_values(tp)
                # Literal discriminator = strongest signal
                if lits:
                    if value[key] in lits:
                        score += 50
                        matched = True
                    else:
                        # Hard mismatch -> invalidate this variant completely
                        score = -100
                        matched = False
                        break
                else:
                    # Non-literal discriminator: soft signal if runtime value type matches annotation base
                    base = _unwrap_optional(tp)
                    try:
                        if isinstance(base, type) and isinstance(value[key], base):
                            score += 5
                            matched = True
                        else:
                            score += 1  # weak hint due to key presence
                    except TypeError:
                        score += 1
        if score < 0:
            continue
        required_keys = set(getattr(variant, "__annotations__", {}).keys())
        present = required_keys.intersection(value.keys())
        missing = required_keys - value.keys()
        score += len(present) * 0.05
        score -= len(missing) * 0.02
        if matched and score > best_score:
            best_score = score
            best = variant
    return best


def _variant_literal_mismatch(variant: object, value: object) -> bool:
    """Return True if any literal discriminator key on variant mismatches value.

    Only considers keys in _UNION_DISCRIMINATOR_KEYS that are annotated as Literal[...] on the variant.
    Missing discriminator key on value is treated as mismatch (can't positively identify variant).
    """
    if not isinstance(value, dict) or not _is_typed_dict(variant):
        return True
    ann = getattr(variant, "__annotations__", {})
    for key in _UNION_DISCRIMINATOR_KEYS:
        if key not in ann:
            continue
        tp = ann[key]
        if get_origin(tp) is Literal:
            lits = set(get_args(tp))
            if key not in value:
                return True
            if value[key] not in lits:
                return True
    return False


def _validate_value(path: str, tp: object, value: object, issues: list[str]) -> None:
    origin = get_origin(tp)
    if origin is None:
        # Simple type or TypedDict
        if _is_typed_dict(tp):
            _validate_typed_dict(path, tp, value, issues)  # pyright: ignore[reportArgumentType]
        else:
            try:
                if (tp is None and (value is not None)) or (not isinstance(value, tp)):  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
                    issues.append(
                        f"{path}: expected {getattr(tp, '__name__', tp)}, got {type(value).__name__}"
                    )
            except TypeError:
                # TypedDict or non-instantiable target; treat as non-fatal
                pass
    elif origin is dict:
        if not isinstance(value, dict):
            issues.append(f"{path}: expected dict, got {type(value).__name__}")
    elif origin is list:
        if not isinstance(value, list):
            issues.append(f"{path}: expected list, got {type(value).__name__}")
        else:
            (elem_type,) = get_args(tp) or (Any,)
            for i, elem in enumerate(value):
                _validate_value(f"{path}[{i}]", elem_type, elem, issues)
    elif origin is tuple:
        args = get_args(tp)
        if not isinstance(value, tuple):
            issues.append(f"{path}: expected tuple, got {type(value).__name__}")
        else:
            for i, (elem, elem_type) in enumerate(zip(value, args)):
                _validate_value(f"{path}[{i}]", elem_type, elem, issues)
    elif origin is set:
        if not isinstance(value, set):
            issues.append(f"{path}: expected set, got {type(value).__name__}")
    elif origin is types.UnionType or _is_union_type(tp):  # union (typing | PEP604)
        variants = get_args(tp)
        matched = False
        for v in variants:
            # TypedDict variant: match if value is a dict
            if _is_typed_dict(v):
                if isinstance(value, dict):
                    matched = True
                    break
                continue
            # Simple class type
            if isinstance(v, type):
                if isinstance(value, v):
                    matched = True
                    break
                continue
            # Fallback: accept (cannot precisely check at runtime)
            matched = True
            break
        if not matched:
            issues.append(
                f"{path}: value {value!r} not compatible with union variants (count={len(variants)})"
            )


P = ParamSpec("P")
R = TypeVar("R")


def _unwrap_optional(tp: Any) -> Any:
    """Return the inner type for Optional / PEP 604 union with None.

    Supports both typing.Optional[T] / Union[T, None] and PEP 604 syntax (T | None).
    If multiple non-None members remain (e.g. int | str | None) we keep the
    original union because it isn't a simple Optional.
    """
    try:
        if _is_union_type(tp):
            args = get_args(tp)
            non_none = tuple(a for a in args if a is not type(None))  # noqa: E721
            if len(non_none) == 1:
                return non_none[0]
    except Exception:  # pragma: no cover - defensive
        pass
    return tp


def _is_any(tp: Any) -> bool:
    try:
        return tp is Any or getattr(tp, "__origin__", None) is Any
    except Exception:  # pragma: no cover - defensive
        return False


def _validate_literal(tp: Any, value: Any) -> bool:
    if get_origin(tp) is Literal:
        return value in get_args(tp)
    return True


def _validate_generic(
    origin: Any,
    args: tuple[Any, ...],
    value: Any,
    path: str,
    issues: list[str],
    depth: int,
) -> None:
    if origin in (list, tuple, set):
        if not isinstance(value, origin):
            issues.append(
                f"{path}: expected {origin.__name__}, got {type(value).__name__}"
            )
            return
        elem_types: tuple[Any, ...]
        if not args:
            return
        if origin is tuple and len(args) != 2 and args and args[-1] is Ellipsis:
            # Homogenous tuple like Tuple[T, ...]
            elem_types = (args[0],)
        else:
            elem_types = args
        for i, elem in enumerate(value):
            check_tp = elem_types[min(i, len(elem_types) - 1)]
            _runtime_type_check(check_tp, elem, f"{path}[{i}]", issues, depth + 1)
    elif origin is dict:
        if not isinstance(value, dict):
            issues.append(f"{path}: expected dict, got {type(value).__name__}")
            return
        if len(args) == 2:
            kt, vt = args
            for i, (k, v) in enumerate(value.items()):
                if i >= 50:  # limit to avoid huge cost
                    break
                _runtime_type_check(kt, k, f"{path}.<key>", issues, depth + 1)
                _runtime_type_check(vt, v, f"{path}[{repr(k)}]", issues, depth + 1)
    else:
        # Fallback: basic instance check
        if not isinstance(value, origin):
            issues.append(
                f"{path}: expected {getattr(origin, '__name__', origin)}, got {type(value).__name__}"
            )


def _runtime_type_check(
    tp: Any,
    value: Any,
    path: str,
    issues: list[str],
    depth: int = 0,
    max_depth: int = 6,
) -> None:
    if depth > max_depth:
        return
    if _is_any(tp):  # Any accepts everything
        return
    if tp is object:
        return
    # Fast-path: accept None when annotation explicitly allows it (before Optional unwrapping).
    # Without this guard, we unwrap Optional[T] to T and then incorrectly flag None values.
    if value is None:
        try:
            if tp is None or tp is type(None):  # direct None annotation
                return
            if _is_union_type(tp):
                args = get_args(tp)
                # If any variant is exactly NoneType we accept None immediately
                if any(a is type(None) for a in args):  # noqa: E721
                    return
        except Exception:  # pragma: no cover - defensive
            pass
    # Handle optionals
    base = _unwrap_optional(tp)
    origin = get_origin(base)
    # Early guard: if 'base' is not a type / TypedDict / union / literal container we skip.
    if not (
        isinstance(base, type)
        or _is_typed_dict(base)
        or _is_union_type(base)
        or origin is not None
        or base is None
    ):
        # Prevent messages like 'expected UnionType, got dict' when a runtime value
        # (e.g. already a dict) was accidentally passed as the spec.
        return
    if origin is Literal:
        if not _validate_literal(tp, value):
            issues.append(f"{path}: value {value!r} not in {get_args(base)!r}")
        return
    if _is_typed_dict(base):
        try:
            _validate_typed_dict(path, base, value, issues)
        except KeyError as ke:
            issues.append(str(ke))
        return
    if _is_union_type(base):  # handle Union / PEP604
        union_args = get_args(base)
        # Fast discriminant-based selection for TypedDict unions
        chosen = _pick_typed_dict_union_variant(union_args, value)
        if chosen is not None:
            _runtime_type_check(chosen, value, path, issues, depth + 1, max_depth)
            return
        # Fallback: sequential attempt until one yields no new issues
        best_variant: object | None = None
        best_variant_missing = 10**9
        # Track whether any variant matched strictly (zero issues) for early exit
        for variant in union_args:  # type: ignore[reportExplicitAny]
            # Skip early if literal discriminator mismatch
            if _is_typed_dict(variant) and isinstance(value, dict):  # type: ignore[reportExplicitAny]
                try:
                    if _variant_literal_mismatch(variant, value):
                        continue
                except Exception:
                    # defensive: skip on unexpected errors
                    continue
            trial_issues: list[str] = []
            if _is_typed_dict(variant) and isinstance(value, dict):  # type: ignore[reportExplicitAny]
                # Probe with allow_extra to focus on missing keys first
                try:
                    _validate_typed_dict(
                        path,
                        variant,
                        value,
                        trial_issues,
                        allow_extra=True,
                        record_unexpected=False,
                    )  # type: ignore[reportExplicitAny]
                except KeyError:
                    # Should not raise with allow_extra=True, but ignore if it does
                    pass
                missing_count = sum(
                    1 for m in trial_issues if m.endswith("missing key")
                )
                if missing_count < best_variant_missing:
                    best_variant_missing = missing_count
                    best_variant = variant
                if missing_count == 0:
                    # Re-run strictly to record any unexpected keys / nested issues
                    strict_issues: list[str] = []
                    try:
                        _validate_typed_dict(
                            path,
                            variant,
                            value,
                            strict_issues,
                            allow_extra=False,
                            record_unexpected=True,
                        )  # type: ignore[reportExplicitAny]
                    except KeyError as ke:
                        strict_issues.append(str(ke))
                    issues.extend(strict_issues)
                    return
            else:
                _runtime_type_check(
                    variant, value, path, trial_issues, depth + 1, max_depth
                )  # type: ignore[reportExplicitAny]
                if not trial_issues:
                    return

        # No variant matched perfectly. Produce detailed diagnostics explaining why.
        def _variant_name(v: object) -> str:
            return getattr(v, "__name__", repr(v))

        if isinstance(value, dict):
            diagnostics: list[str] = []
            MAX_VARIANTS = 12
            shown = 0
            for variant in union_args:  # type: ignore[reportExplicitAny]
                if shown >= MAX_VARIANTS:
                    diagnostics.append(
                        f"... ({len(union_args) - shown} more variants omitted)"
                    )
                    break
                if not _is_typed_dict(variant):  # type: ignore[reportExplicitAny]
                    continue
                shown += 1
                v_issues: list[str] = []
                try:
                    _validate_typed_dict(
                        path,
                        variant,
                        value,
                        v_issues,
                        allow_extra=False,
                        record_unexpected=True,
                    )  # type: ignore[reportExplicitAny]
                except KeyError as ke:
                    v_issues.append(str(ke))
                missing: list[str] = []
                unexpected: list[str] = []
                nested: list[str] = []
                for msg in v_issues:
                    if msg.endswith("missing key"):
                        comp = msg.split(":", 1)[0].removeprefix(f"{path}.")
                        missing.append(comp)
                    elif msg.endswith("unexpected key"):
                        comp = msg.split(":", 1)[0].removeprefix(f"{path}.")
                        unexpected.append(comp)
                    else:
                        nested.append(msg)
                literal_mismatches: list[str] = []
                ann = getattr(variant, "__annotations__", {})  # type: ignore[reportExplicitAny]
                for k in _UNION_DISCRIMINATOR_KEYS:
                    if k in ann and get_origin(ann[k]) is Literal:  # type: ignore[reportExplicitAny]
                        allowed = set(get_args(ann[k]))
                        if k not in value:
                            literal_mismatches.append(
                                f"{k}=<missing> expected one of {sorted(allowed)!r}"
                            )
                        elif value[k] not in allowed:
                            literal_mismatches.append(
                                f"{k}={value[k]!r} not in {sorted(allowed)!r}"
                            )
                parts: list[str] = []
                if missing:
                    parts.append(f"missing={missing}")
                if unexpected:
                    parts.append(f"unexpected={unexpected}")
                if literal_mismatches:
                    parts.append(f"literal={literal_mismatches}")
                if nested and len(nested) < 4:
                    parts.append(f"nested={nested}")
                elif nested:
                    parts.append(f"nestedIssues={len(nested)}")
                if not parts:
                    parts.append("(no direct key issues – likely nested mismatch)")
                diagnostics.append(f"{_variant_name(variant)} -> " + ", ".join(parts))  # type: ignore[reportExplicitAny]
            if best_variant is not None:
                best_name = _variant_name(best_variant)
                diagnostics.sort(
                    key=lambda d: 0 if d.startswith(best_name + " ->") else 1
                )
            issues.append(
                f"{path}: dict not compatible with any of {len(union_args)} union variants. Details: "
                + " | ".join(diagnostics)
            )
            return
        else:
            issues.append(
                f"{path}: value {type(value).__name__} not compatible with any union variant ({len(union_args)})"
            )
        return
    if origin is not None:
        _validate_generic(origin, get_args(base), value, path, issues, depth)
        return
    # Primitive / class check
    if base is None:
        if value is not None:
            issues.append(f"{path}: expected None, got {type(value).__name__}")
        return
    if not isinstance(value, base):
        # Improve union residual case readability (should rarely happen)
        if _is_union_type(base):
            issues.append(f"{path}: value {value!r} not in union {get_args(base)!r}")
        else:
            issues.append(
                f"{path}: expected {getattr(base, '__name__', base)}, got {type(value).__name__}"
            )


def _quick_match(tp: Any, value: Any) -> bool:
    """Fast, shallow compatibility check used during Union / overload filtering."""
    try:
        if _is_any(tp) or tp is object:
            return True
        base = _unwrap_optional(tp)
        origin = get_origin(base)
        if origin is Literal:
            return value in get_args(base)
        if _is_typed_dict(base):
            return isinstance(value, dict)
        if _is_union_type(base):
            return any(_quick_match(a, value) for a in get_args(base))
        if origin in (list, tuple, set):
            return isinstance(value, origin)
        if origin is dict:
            return isinstance(value, dict)
        if base is None:
            return value is None
        try:
            return isinstance(value, base)
        except TypeError:
            return False
    except Exception:
        return True  # Be permissive on unexpected forms


def _format_issues(label: str, issues: list[str], duration: float) -> None:
    for msg in issues:
        warnings.warn(f"{label}: {msg}")
    if issues:
        logging.getLogger("type_checker").debug(
            "%s: %d issue(s) validated in %.4fs", label, len(issues), duration
        )


TYPE_CHECKING_ENABLED = True


def type_checker(func: Callable[P, R]) -> Callable[P, R]:
    """Universal runtime type checker decorator with overload support.

    Features:
    - Resolves which overload (if any) matches the provided runtime arguments.
    - Validates annotated argument types (except *args/**kwargs contents) for the
      selected overload (or the implementation as a fallback).
    - Validates the return type (including nested containers & TypedDicts).
    - Gracefully degrades on unsupported / complex typing constructs (skips).
    - Bounded recursion depth to avoid excessive cost.
    - Designed to work on bound methods (ignores 'self' / 'cls').
    """
    import inspect
    from typing import get_overloads

    logger = logging.getLogger("type_checker")

    try:
        overload_defs = list(get_overloads(func))  # type: ignore[arg-type]
    except Exception:  # pragma: no cover - defensive
        overload_defs = []

    # Precompute metadata for overloads
    overload_meta: list[tuple[inspect.Signature, dict[str, Any]]] = []
    for ov in overload_defs:
        try:
            sig = inspect.signature(ov)
            hints = get_type_hints(ov)  # type: ignore[arg-type]
            overload_meta.append((sig, hints))
        except Exception:  # pragma: no cover - skip malformed
            continue

    impl_sig = None
    try:
        impl_sig = inspect.signature(func)
    except Exception:  # pragma: no cover
        pass
    impl_hints: dict[str, Any] = {}
    try:
        impl_hints = get_type_hints(func)  # type: ignore[arg-type]
    except Exception:  # pragma: no cover
        pass

    def _select_overload(
        call_args: tuple[Any, ...], call_kwargs: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not overload_meta or impl_sig is None:
            return impl_hints, {}
        matches: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
        for idx, (sig, hints) in enumerate(overload_meta):
            try:
                bound = sig.bind_partial(*call_args, **call_kwargs)
            except TypeError:
                continue
            # Build mapping excluding self/cls
            param_issues: list[str] = []
            for name, val in bound.arguments.items():
                if name in ("self", "cls"):
                    continue
                ann = hints.get(name)
                if ann is None:
                    continue
                if not _quick_match(ann, val):
                    param_issues.append(name)
                    break
            if not param_issues:
                matches.append((idx, hints, dict(bound.arguments)))
        if not matches:
            return impl_hints, {}
        # Pick first (defined order) match
        _idx, hints, bargs = matches[0]
        return hints, bargs

    @functools.wraps(func)
    def wrapper(*call_args: P.args, **call_kwargs: P.kwargs) -> R:
        if not TYPE_CHECKING_ENABLED:
            return func(*call_args, **call_kwargs)
        selected_hints, bound_args = _select_overload(call_args, call_kwargs)
        # Validate arguments
        arg_issues: list[str] = []
        start = time.perf_counter()
        for name, ann in selected_hints.items():
            if name == "return":
                continue
            if name in ("self", "cls"):
                continue
            if name in bound_args:
                _runtime_type_check(
                    ann, bound_args[name], f"param '{name}'", arg_issues
                )
        arg_duration = time.perf_counter() - start
        _format_issues(f"{func.__name__} arguments", arg_issues, arg_duration)
        result = func(*call_args, **call_kwargs)
        # Validate return
        if "return" in selected_hints and result is not None:
            ret_ann = selected_hints["return"]
            ret_issues: list[str] = []
            rstart = time.perf_counter()
            _runtime_type_check(ret_ann, result, "return", ret_issues)
            rdur = time.perf_counter() - rstart
            if ret_issues:
                print(result)
            _format_issues(f"{func.__name__} return", ret_issues, rdur)
        return result

    logger.debug(
        "type_checker applied to %s with %d overload(s)",
        getattr(func, "__qualname__", func),
        len(overload_meta),
    )
    return wrapper


def validate_annotated(
    value: object,
    name: str | None = None,
    *,
    raise_on_error: bool = False,
    max_depth: int = 6,
) -> list[str]:
    """Validate a variable against its annotated type in the caller's function.

    Usage inside a function or method with annotated parameters:
        def f(data: MyTypedDict):
            validate_annotated(data)   # picks 'data' automatically

    You can also specify the parameter name explicitly:
        validate_annotated(data, name='data')

    Returns a list of issue strings. If raise_on_error=True, raises TypeError
    if any issues are found. Best-effort: if the function or annotation can't
    be resolved, it returns an empty list silently.
    """
    try:
        frame = inspect.currentframe()
        if frame is None or frame.f_back is None:  # pragma: no cover - defensive
            return []
        caller = frame.f_back
        code = caller.f_code
        locs = caller.f_locals
        globs = caller.f_globals

        # Attempt to locate the callable object for better get_type_hints handling
        func_obj: object | None = None

        # Method: search on self / cls first
        self_obj = locs.get("self") or locs.get("cls")
        if self_obj is not None:
            for attr_name in dir(self_obj):
                try:
                    attr = getattr(self_obj, attr_name)
                except Exception:  # pragma: no cover
                    continue
                if callable(attr) and getattr(attr, "__code__", None) is code:
                    func_obj = attr
                    break
        # Fallback: scan globals
        if func_obj is None:
            for gval in globs.values():
                if callable(gval) and getattr(gval, "__code__", None) is code:
                    func_obj = gval
                    break
        if func_obj is None:
            return []  # Can't resolve function

        try:
            hints = get_type_hints(func_obj)  # type: ignore[arg-type]
        except Exception:
            return []

        # Infer parameter name if not explicitly provided
        target_name: str | None = name
        if target_name is None:
            for var_name, var_val in locs.items():
                if id(var_val) == id(value) and var_name in hints:
                    target_name = var_name
                    break
        if target_name is None:
            return []  # No matching annotated name

        expected = hints.get(target_name)
        if expected is None:
            return []
        issues: list[str] = []
        _runtime_type_check(expected, value, target_name, issues, 0, max_depth)
        if issues:
            for msg in issues:
                warnings.warn(f"validate_annotated: {msg}")
            if raise_on_error:
                raise TypeError(
                    f"{target_name} failed runtime validation with {len(issues)} issue(s): {issues[:3]}..."
                )
        return issues
    finally:
        try:
            del frame  # pyright: ignore[reportPossiblyUnboundVariable]
        except Exception:
            pass
