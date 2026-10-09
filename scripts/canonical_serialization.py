"""Versioned canonical bytes. The active model is RFC 8785 restricted to safe integers."""
from __future__ import annotations
import copy
import hashlib
import json
import math
import re
from decimal import Decimal

SCHEME = 'e2eesa-jcs-integer-v1'
SAFE_INTEGER = 2**53 - 1
LEGACY_SCHEMES = {'legacy-python-ascii-v0', 'legacy-python-utf8-v0'}


def _string(value):
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError('invalid Unicode surrogate')
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def canonical_bytes(value):
    def normalize(item):
        if item is None or isinstance(item, bool): return item
        if isinstance(item, int):
            if abs(item) > SAFE_INTEGER: raise ValueError('integer exceeds safe interoperable range')
            return item
        if isinstance(item, str):
            if re.search('[\ud800-\udfff]', item): raise ValueError('invalid Unicode surrogate')
            return item
        if isinstance(item, list): return [normalize(x) for x in item]
        if isinstance(item, dict):
            if not all(isinstance(k, str) for k in item): raise ValueError('object keys must be strings')
            for k in item: normalize(k)
            keys = sorted(item, key=lambda k: k.encode('utf-16be'))
            return {k: normalize(item[k]) for k in keys}
        raise ValueError('active canonical model rejects floating point and unsupported types')
    return json.dumps(normalize(value),ensure_ascii=False,separators=(',', ':'),allow_nan=False).encode('utf-8')


def legacy_bytes(value, *, scheme):
    if scheme not in LEGACY_SCHEMES: raise ValueError('unknown historical serialization scheme')
    return json.dumps(value, ensure_ascii=scheme == 'legacy-python-ascii-v0', sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def bytes_for_scheme(value, *, scheme):
    if scheme == SCHEME: return canonical_bytes(value)
    return legacy_bytes(value, scheme=scheme)


def canonical_digest(value):
    return 'sha256:' + hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate JSON object key: ' + key)
            result[key] = value
        return result
    def reject(value): raise ValueError('floating point/nonfinite JSON number prohibited: ' + value)
    result = json.loads(text, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    canonical_bytes(result)
    return result


def preprocess_sets(value, *, paths):
    """Only the exact schema-declared paths are unordered; all other arrays keep order."""
    result = copy.deepcopy(value)
    for path in paths:
        target = result
        for key in path[:-1]: target = target[key]
        items = target[path[-1]]
        if not isinstance(items, list): raise ValueError('declared set must be an array')
        keyed = [(canonical_bytes(item), item) for item in items]
        if len({key for key, _ in keyed}) != len(keyed): raise ValueError('duplicate set element')
        target[path[-1]] = [item for _, item in sorted(keyed, key=lambda x: x[0])]
    return result


def external_decimal_model(value):
    """Explicit adapter: exact retained binary64 values become tagged decimal strings.

    New imports must retain original decimal strings. This legacy adapter never rounds,
    and does not claim to recover precision already lost by an external JSON parser.
    """
    if isinstance(value, float):
        if not math.isfinite(value): raise ValueError('nonfinite external value')
        return {'decimal_encoding': 'exact-binary64-v1', 'value': str(Decimal.from_float(value))}
    if isinstance(value, dict): return {k: external_decimal_model(v) for k, v in value.items()}
    if isinstance(value, list): return [external_decimal_model(v) for v in value]
    return value
