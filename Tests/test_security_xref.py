# -*- coding: utf-8 -*-
"""
Regression tests for the _reader.py xref-parsing hardening backports:

- CVE-2026-22691 : regex-based xref rebuild -> manual scan (ReDoS).
- CVE-2026-27628 : circular xref /Prev chain infinite loop.
- CVE-2026-41168 : oversized /N (object stream) and /Index/Size iteration.
"""
import warnings

import pytest

try:
    from io import BytesIO
except ImportError:  # pragma: no cover
    from cStringIO import StringIO as BytesIO

from PyPDF2._reader import PdfReader


def _bare_reader():
    # Build a PdfReader without running __init__ (we only test small helpers).
    return PdfReader.__new__(PdfReader)


# --- CVE-2026-22691: manual object scan -----------------------------------

def test_find_pdf_objects_basic():
    data = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n12 5 obj\n<<>>\nendobj\n"
    found = list(PdfReader._find_pdf_objects(data))
    ids = [(idnum, gen) for idnum, gen, _ in found]
    assert (1, 0) in ids
    assert (12, 5) in ids
    # the recorded position points at the start of the object number
    for idnum, gen, pos in found:
        assert data[pos : pos + 1].isdigit()


def test_find_pdf_objects_ignores_bare_obj():
    # "obj" not preceded by "<id> <gen>" must not be reported.
    assert list(PdfReader._find_pdf_objects(b"the object is here obj\n")) == []


def test_find_pdf_objects_terminates_on_whitespace_runs():
    # CVE-2026-22691: long whitespace runs must not cause pathological time.
    data = b" " * 200000 + b"3 0 obj"
    found = list(PdfReader._find_pdf_objects(data))
    assert (3, 0) in [(i, g) for i, g, _ in found]


# --- CVE-2026-27628: circular xref /Prev chain ----------------------------

def _build_cyclic_xref_pdf():
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += ("%d 0 obj\n" % i).encode("latin-1") + body + b"\nendobj\n"
    xref_off = len(out)
    out += b"xref\n0 4\n0000000000 65535 f \n"
    for off in offsets:
        out += ("%010d 00000 n \n" % off).encode("latin-1")
    # /Prev points back at this same xref offset -> cycle.
    out += ("trailer\n<< /Size 4 /Root 1 0 R /Prev %d >>\n" % xref_off).encode(
        "latin-1"
    )
    out += ("startxref\n%d\n%%%%EOF" % xref_off).encode("latin-1")
    return out


def test_cyclic_xref_prev_terminates():
    pdf = _build_cyclic_xref_pdf()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        reader = PdfReader(BytesIO(pdf))  # must not hang on the /Prev cycle
        assert len(reader.pages) == 1


# --- CVE-2026-41168: oversized object-stream /N ---------------------------

class _FakeIndirect(object):
    def __init__(self, obj):
        self._obj = obj

    def get_object(self):
        return self._obj


class _Ref(object):
    idnum = 5
    generation = 0


def test_objstm_N_is_clamped(monkeypatch):
    from PyPDF2 import _reader as reader_mod
    from PyPDF2.generic import (
        DecodedStreamObject,
        NameObject,
        NumberObject,
    )

    reader = PdfReader.__new__(PdfReader)
    reader.strict = False
    reader.xref_objStm = {5: (7, 0)}

    objstm = DecodedStreamObject()
    objstm[NameObject("/Type")] = NameObject("/ObjStm")
    objstm[NameObject("/N")] = NumberObject(10 ** 9)  # absurd /N
    objstm[NameObject("/First")] = NumberObject(4)
    # entry table "5 0 " then object 5's body (the integer 42) at /First,
    # with a trailing delimiter so the number parses cleanly.
    objstm._data = b"5 0 42 "

    # Intercept the IndirectObject(...).get_object() lookup for the ObjStm.
    monkeypatch.setattr(
        reader_mod, "IndirectObject", lambda num, gen, pdf: _FakeIndirect(objstm)
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # The /N clamp must not break resolution of a valid object even when
        # /N is absurd: object 5 is found and returned.
        result = reader._get_object_from_stream(_Ref())
    assert int(result) == 42
