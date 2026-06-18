# -*- coding: utf-8 -*-
"""
Regression tests for the generic.py parsing-limit / cycle-guard backports:

- CVE-2026-27024 : TreeObject.children cyclic /Next infinite loop.
- CVE-2026-31826 : unbounded declared stream /Length allocation.
- CVE-2026-33123 : array-based ContentStream resource exhaustion.
"""
import pytest

try:
    from io import BytesIO
except ImportError:  # pragma: no cover
    from cStringIO import StringIO as BytesIO
try:
    from unittest.mock import Mock
except ImportError:  # Python 2
    from mock import Mock

from PyPDF2 import generic
from PyPDF2.errors import PdfReadError
from PyPDF2.generic import (
    ArrayObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    TreeObject,
)


def _stream(data):
    so = DecodedStreamObject()
    so._data = data
    return so


def _node(**kv):
    d = DictionaryObject()
    for k, v in kv.items():
        d[NameObject(k)] = v
    return d


# --- CVE-2026-27024: TreeObject.children cycle ----------------------------

def test_children_linear_ok():
    a = DictionaryObject()
    b = DictionaryObject()
    a[NameObject("/Next")] = b
    t = TreeObject()
    t[NameObject("/First")] = a
    t[NameObject("/Last")] = b
    assert list(t.children()) == [a, b]


def test_children_cycle_terminates():
    a = DictionaryObject()
    b = DictionaryObject()
    a[NameObject("/Next")] = b
    b[NameObject("/Next")] = a  # cycle that never reaches /Last
    t = TreeObject()
    t[NameObject("/First")] = a
    t[NameObject("/Last")] = DictionaryObject()  # unreachable sentinel
    kids = list(t.children())  # must terminate rather than hang
    assert kids == [a, b]


# --- CVE-2026-31826: declared stream /Length cap --------------------------

def test_declared_stream_length_capped():
    pdf = Mock(strict=False)
    data = b"<< /Length 999999999 >>\nstream\n"
    with pytest.raises(PdfReadError):
        generic.DictionaryObject.read_from_stream(BytesIO(data), pdf)


def test_small_stream_length_ok():
    pdf = Mock(strict=False)
    data = b"<< /Length 3 >>\nstream\nabc\nendstream"
    obj = generic.DictionaryObject.read_from_stream(BytesIO(data), pdf)
    assert obj.get_data() in (b"abc", "abc")


# --- CVE-2026-33123: array-based ContentStream caps -----------------------

def test_content_stream_array_element_cap(monkeypatch):
    monkeypatch.setattr(generic, "CONTENT_STREAM_ARRAY_MAX_LENGTH", 2)
    arr = ArrayObject([_stream(b"q\n"), _stream(b"Q\n"), _stream(b"q\n")])
    with pytest.raises(PdfReadError):
        ContentStream(arr, Mock())


def test_content_stream_array_output_cap(monkeypatch):
    monkeypatch.setattr(generic, "MAX_ARRAY_BASED_STREAM_OUTPUT_LENGTH", 3)
    arr = ArrayObject([_stream(b"q\n"), _stream(b"Q\n")])  # 4 bytes > 3
    with pytest.raises(PdfReadError):
        ContentStream(arr, Mock())


def test_content_stream_array_ok():
    arr = ArrayObject([_stream(b"q\n"), _stream(b"Q\n")])
    cs = ContentStream(arr, Mock())
    assert len(cs.operations) == 2

