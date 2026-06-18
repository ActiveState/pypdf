# -*- coding: utf-8 -*-
"""Regression test for CVE-2026-40260: XMP XML entity expansion."""
import pytest

from xml.parsers.expat import ExpatError

from PyPDF2.xmp import XmpInformation


class _FakeStream(object):
    def __init__(self, data):
        self._data = data

    def get_data(self):
        return self._data


_RDF = (
    b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b"<rdf:Description/></rdf:RDF>"
)


def test_xmp_normal_parses():
    xml = (
        b'<?xml version="1.0"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">' + _RDF + b"</x:xmpmeta>"
    )
    xmp = XmpInformation(_FakeStream(xml))
    assert xmp.rdfRoot is not None


def test_xmp_entity_declaration_rejected():
    xml = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE x [ <!ENTITY boom "AAAA"> ]>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">' + _RDF + b"</x:xmpmeta>"
    )
    with pytest.raises(ExpatError):
        XmpInformation(_FakeStream(xml))
