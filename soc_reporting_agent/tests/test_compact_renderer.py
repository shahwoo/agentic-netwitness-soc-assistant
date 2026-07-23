from __future__ import annotations

import pytest

from reporting.compact_renderer import (
    build_approval_summary,
    build_chain_of_custody_note,
    build_data_impact_summary,
    build_evidence_register_summary,
    count_placeholders,
    filter_empty_columns,
    filter_empty_rows,
    is_placeholder,
    table_placeholder_ratio,
)
from reporting.structured_report import blocks_from_text, markdown_to_blocks


class TestIsPlaceholder:
    def test_none_is_placeholder(self):
        assert is_placeholder(None) is True

    def test_empty_string_is_placeholder(self):
        assert is_placeholder("") is True

    def test_known_placeholder_strings(self):
        for value in ["Not Provided", "To Be Validated", "Pending", "Not linked", "To Be Assigned"]:
            assert is_placeholder(value) is True

    def test_real_value_is_not_placeholder(self):
        assert is_placeholder("FINANCE-WKS-017") is False
        assert is_placeholder("Soong Yang") is False
        assert is_placeholder("approved") is False

    def test_empty_list_is_placeholder(self):
        assert is_placeholder([]) is True

    def test_non_empty_list_is_not_placeholder(self):
        assert is_placeholder(["EV-001"]) is False


class TestCountPlaceholders:
    def test_empty_dict(self):
        assert count_placeholders({}) == 0

    def test_nested_placeholders(self):
        assert count_placeholders({"a": "Not Provided", "b": "real"}) == 1

    def test_list_placeholders(self):
        assert count_placeholders(["Not Provided", "real"]) == 1

    def test_deep_nesting(self):
        assert count_placeholders({"outer": {"inner": "To Be Validated"}}) == 1


class TestFilterEmptyColumns:
    def test_hides_all_placeholder_column(self):
        columns = ["A", "B"]
        rows = [["x", "Not Provided"], ["y", "Pending"]]
        kept, kept_rows, hidden = filter_empty_columns(columns, rows)
        assert kept == ["A"]
        assert hidden == [1]

    def test_keeps_real_column(self):
        columns = ["A", "B"]
        rows = [["x", "real"]]
        kept, kept_rows, hidden = filter_empty_columns(columns, rows)
        assert kept == ["A", "B"]
        assert hidden == []

    def test_empty_inputs(self):
        kept, kept_rows, hidden = filter_empty_columns([], [])
        assert kept == []
        assert hidden == []


class TestFilterEmptyRows:
    def test_removes_all_placeholder_row(self):
        columns = ["A", "B"]
        rows = [["Not Provided", "Pending"], ["real", "value"]]
        kept_cols, kept_rows = filter_empty_rows(columns, rows)
        assert len(kept_rows) == 1
        assert kept_rows[0] == ["real", "value"]

    def test_keeps_partial_row(self):
        columns = ["A", "B"]
        rows = [["real", "Pending"]]
        kept_cols, kept_rows = filter_empty_rows(columns, rows)
        assert len(kept_rows) == 1


class TestTablePlaceholderRatio:
    def test_no_placeholders(self):
        columns = ["A", "B"]
        rows = [["x", "y"]]
        ratio = table_placeholder_ratio(rows, columns)
        assert ratio == 0.0

    def test_all_placeholders(self):
        columns = ["A", "B"]
        rows = [["Not Provided", "Pending"]]
        ratio = table_placeholder_ratio(rows, columns)
        assert ratio == 1.0

    def test_mixed(self):
        columns = ["A", "B"]
        rows = [["real", "Not Provided"]]
        ratio = table_placeholder_ratio(rows, columns)
        assert ratio == 0.5


class TestBuildEvidenceRegisterSummary:
    def test_compact_when_many_placeholders(self):
        evidence = [
            {"id": "EV-001", "source": None, "type": "Evidence", "description": "alert", "timestamp": None, "confidence": None, "raw_reference": None},
            {"id": "EV-002", "source": None, "type": "Evidence", "description": "log", "timestamp": None, "confidence": None, "raw_reference": None},
        ]
        result = build_evidence_register_summary(evidence)
        assert result["compact"] is True
        assert result["summary"] is not None
        assert "Evidence register summary:" in result["summary"]
        assert len(result["hidden_columns"]) >= 1

    def test_full_when_few_placeholders(self):
        evidence = [
            {"id": "EV-001", "source": "NetWitness", "type": "SIEM", "description": "alert", "timestamp": "2025-01-01T00:00:00Z", "confidence": "High", "raw_reference": "NW-123"},
        ]
        result = build_evidence_register_summary(evidence)
        assert result["compact"] is False
        assert result["summary"] is None
        assert "Timestamp" in result["columns"]

    def test_notes_when_timestamp_missing(self):
        evidence = [
            {"id": "EV-001", "source": None, "type": None, "description": None, "timestamp": None, "confidence": None, "raw_reference": None},
        ]
        result = build_evidence_register_summary(evidence)
        assert any("Timestamps were not supplied" in n for n in result["notes"])
        assert "hidden_rows" in result

    def test_notes_when_raw_reference_missing(self):
        evidence = [
            {"id": "EV-001", "source": None, "type": None, "description": None, "timestamp": None, "confidence": None, "raw_reference": None},
        ]
        result = build_evidence_register_summary(evidence)
        assert any("Raw event references were not supplied" in n for n in result["notes"])


class TestBuildDataImpactSummary:
    def test_returns_compact_summary(self):
        summary = build_data_impact_summary({})
        assert "Data impact assessment:" in summary
        assert "No evidence of data access" in summary
        assert "Personal data involvement: Cannot determine from current evidence" in summary

    def test_includes_impact_context(self):
        context = {
            "impact_assessment": {
                "business": "Limited to FINANCE-WKS-017.",
                "security": "Potential malware execution.",
            }
        }
        summary = build_data_impact_summary(context)
        assert "Limited to FINANCE-WKS-017." in summary
        assert "Potential malware execution." in summary


class TestBuildChainOfCustodyNote:
    def test_note_when_no_real_custody(self):
        evidence = [
            {"id": "EV-001", "timestamp": None, "source": None},
        ]
        note = build_chain_of_custody_note(evidence)
        assert "Formal chain-of-custody metadata was not supplied" in note

    def test_empty_note_when_real_custody_exists(self):
        evidence = [
            {"id": "EV-001", "collection_time": "2025-01-01T00:00:00Z", "collector": "SOC Analyst", "storage_location": "case-folder", "hash": "abc123", "integrity": "verified"},
        ]
        note = build_chain_of_custody_note(evidence)
        assert note == ""

    def test_empty_note_when_no_evidence(self):
        note = build_chain_of_custody_note([])
        assert "Formal chain-of-custody metadata was not supplied" in note


class TestBuildApprovalSummary:
    def test_approved_report_summary(self):
        approval = {"approval_status": "approved", "analyst_decision": "approved", "approved_by": "Soong Yang"}
        containment = {}
        summary = build_approval_summary(approval, containment)
        assert summary["report"].startswith("Report generation approval status: Approved by Soong Yang.")

    def test_containment_summary(self):
        approval = {}
        containment = {"status": "approved_pending_execution", "recommended_action": "Isolate FINANCE-WKS-017"}
        summary = build_approval_summary(approval, containment)
        assert "Containment approval status: Approved Pending Execution." in summary["containment"]
        assert "Recommended containment action: Isolate FINANCE-WKS-017." in summary["recommended"]

    def test_unknown_note_when_both_unknown(self):
        summary = build_approval_summary({}, {})
        assert "Approval record exists, but approval type requires analyst validation." in summary["note"]


class TestMarkdownTableParsing:
    def test_compact_markdown_separator_becomes_table_block(self):
        blocks = markdown_to_blocks("| Field | Value |\n|---|---|\n| A | B |\n")
        assert blocks[0]["type"] == "table"
        assert blocks[0]["columns"] == ["Field", "Value"]
        assert blocks[0]["rows"] == [["A", "B"]]

    def test_plain_text_pipe_table_fallback_becomes_table_block(self):
        blocks = blocks_from_text("Field | Value\nA | B\nC | D\n")
        assert blocks[0]["type"] == "table"
        assert blocks[0]["columns"] == ["Field", "Value"]
        assert blocks[0]["rows"] == [["A", "B"], ["C", "D"]]
