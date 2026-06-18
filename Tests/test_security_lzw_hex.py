# -*- coding: utf-8 -*-
"""
Regression tests for the LZW and ASCIIHex decoder hardening backports:

- CVE-2026-28804          : ASCIIHexDecode quadratic decoding -> bulk decode.
- CVE-2025-62708/66019    : bound LZWDecode output (decompression bomb).
"""
import pytest

from PyPDF2 import filters
from PyPDF2.errors import PdfReadError, PdfStreamError


# --- CVE-2026-28804: ASCIIHexDecode ---------------------------------------

def test_asciihex_basic():
    assert filters.ASCIIHexDecode.decode("48656c6c6f>") == b"Hello"


def test_asciihex_ignores_whitespace():
    assert filters.ASCIIHexDecode.decode("48 65 6c\n6c\t6f >") == b"Hello"


def test_asciihex_odd_length_padded():
    # ISO 32000 §7.4.2: a trailing odd digit is treated as followed by "0".
    assert filters.ASCIIHexDecode.decode("4>") == b"@"  # 0x40


def test_asciihex_missing_eod_raises():
    with pytest.raises(PdfStreamError):
        filters.ASCIIHexDecode.decode("48656c6c6f")  # no '>'
