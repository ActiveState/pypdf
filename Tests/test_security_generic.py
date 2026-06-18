# -*- coding: utf-8 -*-
"""
Regression tests for the generic.py parsing-limit / cycle-guard backports:

- CVE-2026-27024 : TreeObject.children cyclic /Next infinite loop.
- CVE-2026-31826 : unbounded declared stream /Length allocation.
- CVE-2026-33123 : array-based ContentStream resource exhaustion.
"""
import pytest

from PyPDF2.generic import DictionaryObject, NameObject, TreeObject


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
