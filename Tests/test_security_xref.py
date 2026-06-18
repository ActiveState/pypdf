# -*- coding: utf-8 -*-
"""
Regression tests for the _reader.py xref-parsing hardening backports:

- CVE-2026-22691 : regex-based xref rebuild -> manual scan (ReDoS).
- CVE-2026-27628 : circular xref /Prev chain infinite loop.
- CVE-2026-41168 : oversized /N (object stream) and /Index/Size iteration.
"""
import pytest

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
