"""
Compliance report generator — produces PDF + JSON reports for auditors.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ComplianceReportMeta:
    generated_at: str
    framework: str
    organization: str
    assessor: str
    version: str = "1.0"


class ComplianceReporter:
    """
    Generates compliance reports in JSON and PDF formats.

    PDF generation uses reportlab if available, otherwise falls back to HTML.

    Usage::

        reporter = ComplianceReporter(organization="Acme Corp", assessor="Security Team")
        reporter.add_section("GDPR", gdpr_report)
        reporter.add_section("HIPAA", hipaa_report)
        reporter.save_json("/output/compliance-2024.json")
        reporter.save_pdf("/output/compliance-2024.pdf")
    """

    def __init__(self, organization: str = "", assessor: str = "") -> None:
        self.organization = organization
        self.assessor = assessor
        self._sections: List[Dict[str, Any]] = []

    def add_section(self, framework: str, report: Any) -> None:
        """Add a compliance framework section to the report."""
        if hasattr(report, "__dataclass_fields__"):
            data = asdict(report)  # type: ignore[call-overload]
        elif hasattr(report, "to_dict"):
            data = report.to_dict()
        elif isinstance(report, dict):
            data = report
        else:
            data = {"raw": str(report)}

        # Convert enums to strings
        data = _serialize_enums(data)

        self._sections.append({"framework": framework, "data": data})

    def save_json(self, path: str) -> str:
        """Write the full compliance report as JSON. Returns the path."""
        report = self._build_report()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(report, indent=2, default=str))
        return str(p)

    def save_pdf(self, path: str) -> str:
        """
        Write the compliance report as PDF.
        Requires 'reportlab'. Falls back to HTML if unavailable.
        """
        try:
            return self._save_pdf_reportlab(path)
        except ImportError:
            return self._save_pdf_html_fallback(path)

    def get_summary(self) -> Dict[str, Any]:
        """Return a dict summary with overall compliance status per framework."""
        summary: Dict[str, Any] = {}
        for section in self._sections:
            fw = section["framework"]
            data = section["data"]
            summary[fw] = {
                "compliant": data.get("compliant", False),
                "score": data.get("score", 0),
                "findings_count": len(data.get("findings", data.get("controls", []))),
            }
        return summary

    # ------------------------------------------------------------------

    def _build_report(self) -> Dict[str, Any]:
        import datetime
        return {
            "meta": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "organization": self.organization,
                "assessor": self.assessor,
                "version": "1.0",
            },
            "summary": self.get_summary(),
            "sections": self._sections,
        }

    def _save_pdf_reportlab(self, path: str) -> str:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        )
        import datetime

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(p), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph("AgentShield Compliance Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
        story.append(Paragraph(f"Organization: {self.organization}", styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))

        # Summary table
        summary = self.get_summary()
        table_data = [["Framework", "Compliant", "Score", "Findings"]]
        for fw, s in summary.items():
            table_data.append([
                fw,
                "✓" if s["compliant"] else "✗",
                f"{s['score']:.1f}%",
                str(s["findings_count"]),
            ])

        t = Table(table_data, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * inch))

        # Sections
        for section in self._sections:
            story.append(Paragraph(section["framework"], styles["Heading2"]))
            data = section["data"]
            findings = data.get("findings", data.get("controls", data.get("requirements", [])))
            for finding in findings:
                if isinstance(finding, dict):
                    severity = finding.get("severity", finding.get("status", ""))
                    desc = finding.get("description", "")
                    rec = finding.get("recommendation", "")
                    story.append(Paragraph(f"<b>[{severity.upper()}]</b> {desc}", styles["Normal"]))
                    if rec:
                        story.append(Paragraph(f"→ {rec}", styles["Italic"]))
                    story.append(Spacer(1, 0.1 * inch))

        doc.build(story)
        return str(p)

    def _save_pdf_html_fallback(self, path: str) -> str:
        """Save as HTML when reportlab is not available."""
        html_path = path.replace(".pdf", ".html")
        report = self._build_report()
        html = f"""<!DOCTYPE html>
<html><head><title>AgentShield Compliance Report</title>
<style>body{{font-family:sans-serif;margin:40px}} h1{{color:#1a3a5c}} .pass{{color:green}} .fail{{color:red}}</style>
</head><body>
<h1>AgentShield Compliance Report</h1>
<p>Generated: {report['meta']['generated_at']}</p>
<p>Organization: {self.organization}</p>
<h2>Summary</h2><table border='1' cellpadding='6'><tr><th>Framework</th><th>Compliant</th><th>Score</th></tr>
"""
        for fw, s in report["summary"].items():
            cls = "pass" if s["compliant"] else "fail"
            html += f"<tr><td>{fw}</td><td class='{cls}'>{'Yes' if s['compliant'] else 'No'}</td><td>{s['score']:.1f}%</td></tr>"
        html += "</table></body></html>"
        Path(html_path).write_text(html)
        return html_path


def _serialize_enums(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _serialize_enums(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_enums(i) for i in obj]
    if hasattr(obj, "value"):  # Enum
        return obj.value
    return obj
