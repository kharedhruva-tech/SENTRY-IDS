import io
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ReportGenerator:
    @staticmethod
    def generate_csv_report(alerts):
        """Compile a list of alerts into a CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow([
            "Alert ID", "Timestamp", "Category", "Severity", 
            "Source IP", "Destination IP", "Message", 
            "Machine Learning", "Confidence Score", "Status"
        ])
        
        for a in alerts:
            writer.writerow([
                a.id,
                a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                a.category,
                a.severity,
                a.src_ip,
                a.dst_ip,
                a.message,
                "Yes" if a.is_ml else "No",
                f"{a.confidence:.2f}",
                a.status
            ])
            
        output.seek(0)
        return output.getvalue()

    @staticmethod
    def generate_pdf_report(alerts, stats):
        """Compile a list of alerts and summary statistics into a premium PDF file buffer."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=40,
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        
        # Custom styles for cybersecurity audit report
        title_style = ParagraphStyle(
            name='AuditTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),  # Deep Slate
            spaceAfter=15
        )
        
        subtitle_style = ParagraphStyle(
            name='AuditSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#64748b'),  # Cool grey
            spaceAfter=25
        )
        
        heading_style = ParagraphStyle(
            name='SectionHeading',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=15,
            spaceAfter=10
        )
        
        cell_style = ParagraphStyle(
            name='TableCell',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#334155')
        )
        
        cell_header_style = ParagraphStyle(
            name='TableHeaderCell',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            textColor=colors.white,
            fontName='Helvetica-Bold'
        )

        story = []
        
        # 1. Header
        story.append(Paragraph("INTRUSION DETECTION SYSTEM (IDS) SECURITY AUDIT", title_style))
        gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        story.append(Paragraph(f"Generated On: {gen_time} | Scope: Network Forensics & Threat Mitigation Data Log", subtitle_style))
        story.append(Spacer(1, 10))
        
        # 2. Executive Summary / Stats Cards
        story.append(Paragraph("Executive Threat Summary", heading_style))
        
        summary_data = [
            [
                Paragraph("<b>Total Alerts</b>", cell_style),
                Paragraph("<b>Critical Severity</b>", cell_style),
                Paragraph("<b>High Severity</b>", cell_style),
                Paragraph("<b>Medium/Low Severity</b>", cell_style)
            ],
            [
                Paragraph(f"<font size=14><b>{stats['total_alerts']}</b></font>", cell_style),
                Paragraph(f"<font size=14 color='#ef4444'><b>{stats['critical_alerts']}</b></font>", cell_style),
                Paragraph(f"<font size=14 color='#f97316'><b>{stats['high_alerts']}</b></font>", cell_style),
                Paragraph(f"<font size=14 color='#3b82f6'><b>{stats['other_alerts']}</b></font>", cell_style)
            ]
        ]
        
        summary_table = Table(summary_data, colWidths=[130, 130, 130, 130])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # 3. Alerts Table
        story.append(Paragraph("Detailed Incident Report", heading_style))
        
        # Table Headers: [ID, Time, Category, Severity, Source IP, Message]
        table_headers = [
            Paragraph("ID", cell_header_style),
            Paragraph("Time", cell_header_style),
            Paragraph("Category", cell_header_style),
            Paragraph("Severity", cell_header_style),
            Paragraph("Source IP", cell_header_style),
            Paragraph("Alert Message Detail", cell_header_style)
        ]
        
        table_data = [table_headers]
        
        for idx, alert in enumerate(alerts):
            # Map severity color indicators
            sev_color = '#ef4444' if alert.severity == 'Critical' else ('#f97316' if alert.severity == 'High' else '#3b82f6')
            
            row = [
                Paragraph(str(alert.id), cell_style),
                Paragraph(alert.timestamp.strftime('%m-%d %H:%M:%S'), cell_style),
                Paragraph(alert.category, cell_style),
                Paragraph(f"<font color='{sev_color}'><b>{alert.severity}</b></font>", cell_style),
                Paragraph(alert.src_ip, cell_style),
                Paragraph(alert.message, cell_style)
            ]
            table_data.append(row)
            
        # Total page width is 540 (612 - 72 margins)
        # Column allocations: ID(25), Time(65), Category(80), Severity(50), Source IP(85), Message(235)
        report_table = Table(table_data, colWidths=[25, 65, 80, 50, 85, 235])
        
        # Style table elements
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')), # Dark table header
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ])
        
        # Alternating row colors
        for i in range(1, len(table_data)):
            bg_color = colors.HexColor('#f8fafc') if i % 2 == 0 else colors.white
            table_style.add('BACKGROUND', (0, i), (-1, i), bg_color)
            
        report_table.setStyle(table_style)
        story.append(report_table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
