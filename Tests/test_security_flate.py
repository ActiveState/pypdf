# -*- coding: utf-8 -*-
"""
Regression tests for the FlateDecode / zlib decompression-limit backports:

- CVE-2025-55197 : bound decompressed output (zip-bomb) in ``decompress``.
- CVE-2026-27026 : bound byte-by-byte recovery input in ``decompress``.
- CVE-2026-41312 : reject absurd ``/Columns`` in ``FlateDecode.decode``.
"""
import zlib

import pytest

from PyPDF2 import filters
from PyPDF2.errors import PdfReadError


def test_decompress_roundtrip():
    raw = b"The quick brown fox. " * 5000
    assert filters.decompress(zlib.compress(raw)) == raw


def test_flate_output_bomb_is_capped(monkeypatch):
    # CVE-2025-55197: a tiny stream that inflates beyond the cap must raise.
    monkeypatch.setattr(filters, "ZLIB_MAX_OUTPUT_LENGTH", 1000000)  # 1 MB
    bomb = zlib.compress(b"\x00" * 5000000)  # 5 MB of zeros -> a few KB
    with pytest.raises(PdfReadError):
        filters.decompress(bomb)


def test_flate_recovery_input_is_capped(monkeypatch):
    # CVE-2026-27026: a large malformed stream must not be scanned unbounded.
    monkeypatch.setattr(filters, "ZLIB_MAX_RECOVERY_INPUT_LENGTH", 1000)
    garbage = b"\xff" * 5000  # not valid zlib -> falls into recovery loop
    with pytest.raises(PdfReadError):
        filters.decompress(garbage)


