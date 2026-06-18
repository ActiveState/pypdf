# -*- coding: utf-8 -*-
"""Regression test for CVE-2026-24688: cyclic document outline /Next loop."""
import warnings

from PyPDF2._reader import PdfReader
from PyPDF2.generic import DictionaryObject, NameObject


def test_get_outlines_cycle_terminates():
    reader = PdfReader.__new__(PdfReader)
    reader._build_outline = lambda node: None  # isolate the walk
    a = DictionaryObject()
    b = DictionaryObject()
    a[NameObject("/Next")] = b
    b[NameObject("/Next")] = a  # cycle that never ends
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = reader._get_outlines(a, [])  # must terminate, not hang
    assert result == []
