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


# --- CVE-2025-62708 / CVE-2025-66019: LZWDecode output cap -----------------

def _pack_lzw(codes, width=9):
    """Pack a list of fixed-width LZW codes MSB-first into bytes.

    Kept small so the code width stays at the initial 9 bits (dictlen < 511).
    """
    bits = "".join(format(c, "0%db" % width) for c in codes)
    while len(bits) % 8:
        bits += "0"
    return bytes(bytearray(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)))


def test_lzw_decodes_normally():
    # Three literal 'A' (65) codes then STOP (257) -> "AAA".
    data = _pack_lzw([65, 65, 65, 257])
    assert filters.LZWDecode.Decoder(data).decode() == b"AAA"


def test_lzw_output_is_capped():
    # Many literal codes with no STOP; a tiny cap must abort before exhaustion.
    data = _pack_lzw([65] * 200)
    with pytest.raises(PdfReadError):
        filters.LZWDecode.Decoder(data, max_output_length=5).decode()
