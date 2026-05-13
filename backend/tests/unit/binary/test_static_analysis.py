"""Tests for Binary Static Analysis and Clustering."""

import pytest
from pathlib import Path
import tempfile

from src.workers.binary.static.analyser import (
    BinaryFormat, BinaryMetadata, BinaryAnalysisResult,
    _detect_binary_format, _extract_strings, _detect_packer_hints,
    _calc_entropy, _classify_capabilities,
)


class TestDetectBinaryFormat:
    def test_detects_elf(self):
        data = b"\x7fELF\x02\x01\x01" + b"\x00" * 64
        assert _detect_binary_format(data) == BinaryFormat.ELF

    def test_detects_pe(self):
        data = bytearray(128)
        data[0:2] = b"MZ"
        assert _detect_binary_format(bytes(data)) == BinaryFormat.PE

    def test_detects_mach_o(self):
        import struct
        data = struct.pack(">I", 0xFEEDFACE) + b"\x00" * 60
        assert _detect_binary_format(data) == BinaryFormat.MACH_O

    def test_unknown_format(self):
        data = b"Hello World"
        assert _detect_binary_format(data) == BinaryFormat.UNKNOWN


class TestExtractStrings:
    def test_extracts_ascii_strings(self):
        data = b"hello world\x00test\x00\x00abc"
        strings = _extract_strings(data, min_length=4)
        assert "hello world" in strings
        assert "test" in strings

    def test_min_length_filter(self):
        data = b"hi\x00hello\x00a"
        strings = _extract_strings(data, min_length=4)
        assert "hello" in strings
        assert "hi" not in strings


class TestEntropy:
    def test_zero_entropy(self):
        assert _calc_entropy(b"\x00" * 100) == 0.0

    def test_max_entropy(self):
        data = bytes(range(256)) * 10
        entropy = _calc_entropy(data)
        assert entropy > 7.0

    def test_empty_data(self):
        assert _calc_entropy(b"") == 0.0


class TestPackerDetection:
    def test_detects_upx(self):
        strings = ["UPX0", "UPX1", "hello"]
        hints = _detect_packer_hints(strings, b"\x00" * 100)
        assert any("UPX" in h for h in hints)

    def test_no_packer(self):
        strings = ["hello", "world", "just normal strings"]
        hints = _detect_packer_hints(strings, b"normal binary data")
        assert len(hints) == 0


class TestCapabilityClassification:
    def test_network_communication(self):
        strings = ["http://evil.com/malware", "socket connect"]
        caps = _classify_capabilities(strings)
        assert "network_communication" in caps

    def test_credential_access(self):
        strings = ["lsass.exe", "password dump", "credential theft"]
        caps = _classify_capabilities(strings)
        assert "credential_access" in caps

    def test_clean_binary(self):
        strings = ["hello world", "version 1.0", "copyright 2026"]
        caps = _classify_capabilities(strings)
        assert len(caps) == 0


class TestBinaryMetadata:
    def test_default_values(self):
        m = BinaryMetadata()
        assert m.format == BinaryFormat.UNKNOWN
        assert m.obfuscation_score == 0.0
        assert len(m.packer_hints) == 0


class TestBinaryAnalysisResult:
    def test_default_values(self):
        r = BinaryAnalysisResult()
        assert r.verdict == ""
        assert r.risk_score == 0.0
