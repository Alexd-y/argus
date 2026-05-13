"""Tests for Binary Dynamic Lab and Custody."""

import pytest
from unittest.mock import patch, AsyncMock

from src.workers.binary.dynamic.lab import (
    DynamicResult, CustodyRecord,
    run_dynamic_analysis, quarantine_sample,
    request_export_approval, _classify_dynamic_output,
)


class TestDynamicResult:
    def test_default_values(self):
        r = DynamicResult()
        assert r.exit_code == -1
        assert r.execution_time_ms == 0


class TestDynamicClassification:
    def test_reverse_shell_detected(self):
        output = "reverse shell established\nconnected to 10.0.0.1"
        assert _classify_dynamic_output(output, 0) == "malicious"

    def test_password_dump_detected(self):
        output = "password found: admin / admin123"
        assert _classify_dynamic_output(output, 0) == "malicious"

    def test_clean_exit(self):
        output = "Process completed successfully"
        assert _classify_dynamic_output(output, 0) == "executed_successfully"

    def test_error_exit(self):
        assert _classify_dynamic_output("", 1) == "exit_code_1"


class TestCustody:
    def test_default_record(self):
        r = CustodyRecord()
        assert r.status == "received"
        assert len(r.custody_chain) == 0

    def test_request_export_first_approval(self):
        record = CustodyRecord()
        assert request_export_approval(record, "approver1") is False
        assert len([e for e in record.custody_chain if e["action"] == "approve"]) == 1

    def test_request_export_second_approval(self):
        record = CustodyRecord()
        record.custody_chain.append({"action": "approve", "by": "approver1"})
        assert request_export_approval(record, "approver2") is True
        assert any(e["action"] == "export_approved" for e in record.custody_chain)

    def test_duplicate_approval_rejected(self):
        record = CustodyRecord()
        record.custody_chain.append({"action": "approve", "by": "approver1"})
        assert request_export_approval(record, "approver1") is False
        assert any(e["action"] == "duplicate_approval_rejected" for e in record.custody_chain)
