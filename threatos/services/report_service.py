from __future__ import annotations
import io
from datetime import UTC, datetime, timedelta
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from threatos.models.alert import Alert
from threatos.models.attack_chain import AttackChain
from threatos.models.coverage_matrix import CoverageMatrix
from threatos.models.detection_rule import DetectionRule
from threatos.models.raw_event import RawEvent
from threatos.models.audit_log import AuditLog
from threatos.models.ti_enrichment import TIEnrichment
from threatos.models.rule_metrics import RuleMetrics
from threatos.models.asset import Asset

async def gather_report_data(db: AsyncSession, days: int = 7) -> dict:
    cutoff = datetime.now(UTC) - timedelta(days=days)
    now    = datetime.now(UTC)

    # ── Alert stats ───────────────────────────────────────────────────────────
    alert_row = (await db.execute(
        select(func.count(Alert.id).label("total"),
               func.avg(Alert.risk_score).label("avg_risk"),
               func.max(Alert.risk_score).label("max_risk"))
        .where(Alert.created_at >= cutoff)
    )).one()

    alerts_by_status = {r.status: r.cnt for r in (await db.execute(
        select(Alert.status, func.count(Alert.id).label("cnt"))
        .where(Alert.created_at >= cutoff)
        .group_by(Alert.status)
        .order_by(func.count(Alert.id).desc())
    ))}

    top_techniques = [
        {"technique_id": r.technique_id, "tactic": r.tactic,
         "count": r.cnt, "avg_risk": round(float(r.avg_risk or 0), 1)}
        for r in (await db.execute(
            select(Alert.technique_id, Alert.tactic,
                   func.count(Alert.id).label("cnt"),
                   func.avg(Alert.risk_score).label("avg_risk"))
            .where(Alert.created_at >= cutoff)
            .group_by(Alert.technique_id, Alert.tactic)
            .order_by(func.count(Alert.id).desc()).limit(10)
        ))
    ]

    top_hosts = [
        {"host": r.entity_host, "count": r.cnt,
         "max_risk": round(float(r.max_risk or 0), 1)}
        for r in (await db.execute(
            select(Alert.entity_host, func.count(Alert.id).label("cnt"),
                   func.max(Alert.risk_score).label("max_risk"))
            .where(Alert.created_at >= cutoff, Alert.entity_host.isnot(None))
            .group_by(Alert.entity_host)
            .order_by(func.count(Alert.id).desc()).limit(10)
        ))
    ]

    high_risk_alerts = [
        {"id": str(a.id), "technique_id": a.technique_id,
         "tactic": a.tactic, "risk_score": a.risk_score,
         "host": a.entity_host, "status": a.status,
         "created_at": a.created_at.strftime("%Y-%m-%d %H:%M")}
        for a in (await db.execute(
            select(Alert).where(Alert.created_at >= cutoff, Alert.risk_score >= 70)
            .order_by(Alert.risk_score.desc()).limit(10)
        )).scalars().all()
    ]

    # ── Coverage ──────────────────────────────────────────────────────────────
    total_cov = int((await db.execute(
        select(func.count(CoverageMatrix.technique_id)))).scalar() or 0)
    covered   = int((await db.execute(
        select(func.count(CoverageMatrix.technique_id))
        .where(CoverageMatrix.covered.is_(True)))).scalar() or 0)
    coverage_pct = round(covered / total_cov * 100, 1) if total_cov else 0

    # ── Rules ─────────────────────────────────────────────────────────────────
    rules_total   = int((await db.execute(
        select(func.count(DetectionRule.id)))).scalar() or 0)
    rules_enabled = int((await db.execute(
        select(func.count(DetectionRule.id))
        .where(DetectionRule.enabled.is_(True)))).scalar() or 0)

    # ── Events ────────────────────────────────────────────────────────────────
    events_period = int((await db.execute(
        select(func.count(RawEvent.id))
        .where(RawEvent.received_at >= cutoff))).scalar() or 0)
    events_total  = int((await db.execute(
        select(func.count(RawEvent.id)))).scalar() or 0)

    # ── Chains ────────────────────────────────────────────────────────────────
    chain_rows = (await db.execute(
        select(AttackChain)
        .where(AttackChain.first_seen >= cutoff)
        .order_by(AttackChain.risk_score.desc()).limit(5)
    )).scalars().all()
    chains = [
        {"id": str(c.id)[:8], "host": c.host,
         "tactic_count": c.tactic_count, "risk_score": c.risk_score,
         "is_multi_stage": c.is_multi_stage, "status": c.status}
        for c in chain_rows
    ]
    multi_stage_count = int((await db.execute(
        select(func.count(AttackChain.id))
        .where(AttackChain.is_multi_stage.is_(True),
               AttackChain.first_seen >= cutoff)
    )).scalar() or 0)

    # ── MTTD — Mean Time to Detect ────────────────────────────────────────────
    # MTTD = average time between event ingestion and alert creation
    # Approximate: avg time between cutoff and alert created_at
    # Real MTTD needs event timestamps — using alert processing time as proxy
    mttd_seconds = None
    try:
        mttd_result = await db.execute(text("""
            SELECT AVG(EXTRACT(EPOCH FROM (a.created_at - r.received_at))) as mttd
            FROM alerts a
            JOIN raw_events r ON r.normalized->>'host' = a.entity_host
            WHERE a.created_at >= :cutoff
            AND r.received_at >= :cutoff
            AND r.received_at <= a.created_at
        """), {"cutoff": cutoff})
        row = mttd_result.one_or_none()
        if row and row.mttd:
            mttd_seconds = round(float(row.mttd), 1)
    except Exception:
        pass

    # ── MTTR — Mean Time to Respond ───────────────────────────────────────────
    mttr_seconds = None
    try:
        mttr_result = await db.execute(
            select(func.avg(
                func.extract('epoch', Alert.updated_at) -
                func.extract('epoch', Alert.created_at)
            ).label("mttr"))
            .where(Alert.created_at >= cutoff,
                   Alert.status.in_(["closed", "false_positive"]))
        )
        mttr_row = mttr_result.one_or_none()
        if mttr_row and mttr_row.mttr:
            mttr_seconds = round(float(mttr_row.mttr), 1)
    except Exception:
        pass

    # ── False Positive Rate ───────────────────────────────────────────────────
    total_closed = int((await db.execute(
        select(func.count(Alert.id))
        .where(Alert.created_at >= cutoff,
               Alert.status.in_(["closed", "false_positive"]))
    )).scalar() or 0)
    total_fp = int((await db.execute(
        select(func.count(Alert.id))
        .where(Alert.created_at >= cutoff,
               Alert.status == "false_positive")
    )).scalar() or 0)
    fp_rate = round(total_fp / total_closed * 100, 1) if total_closed > 0 else 0.0

    # ── TI Enrichment Summary ─────────────────────────────────────────────────
    ti_total = int((await db.execute(
        select(func.count(TIEnrichment.id))
        .where(TIEnrichment.enriched_at >= cutoff)
    )).scalar() or 0)
    ti_malicious = int((await db.execute(
        select(func.count(TIEnrichment.id))
        .where(TIEnrichment.enriched_at >= cutoff,
               TIEnrichment.verdict == "malicious")
    )).scalar() or 0)
    ti_suspicious = int((await db.execute(
        select(func.count(TIEnrichment.id))
        .where(TIEnrichment.enriched_at >= cutoff,
               TIEnrichment.verdict == "suspicious")
    )).scalar() or 0)

    ti_malicious_iocs = [
        {"ioc_type": r.ioc_type, "ioc_value": r.ioc_value,
         "source": r.source, "score": r.score, "country": r.country}
        for r in (await db.execute(
            select(TIEnrichment)
            .where(TIEnrichment.enriched_at >= cutoff,
                   TIEnrichment.verdict == "malicious")
            .order_by(TIEnrichment.score.desc()).limit(5)
        )).scalars().all()
    ]

    # ── Noisy Rules (FP > 50%) ────────────────────────────────────────────────
    noisy_rules = [
        {"name": r.DetectionRule.name[:55] if r.DetectionRule else "?",
         "technique_id": r.RuleMetrics.rule_id[:8],
         "fp_rate": round(float(r.RuleMetrics.fp_rate or 0) * 100, 1),
         "total_evals": r.RuleMetrics.total_evals}
        for r in (await db.execute(
            select(RuleMetrics, DetectionRule)
            .join(DetectionRule, DetectionRule.id == RuleMetrics.rule_id, isouter=True)
            .where(RuleMetrics.fp_rate >= 0.5,
                   RuleMetrics.total_evals >= 10)
            .order_by(RuleMetrics.fp_rate.desc()).limit(5)
        ))
    ]

    # ── Top Critical Assets at Risk ───────────────────────────────────────────
    critical_assets = []
    try:
        asset_rows = (await db.execute(
            select(Alert.entity_host,
                   func.count(Alert.id).label("alert_count"),
                   func.max(Alert.risk_score).label("max_risk"),
                   Asset.criticality)
            .join(Asset, Asset.hostname == Alert.entity_host, isouter=True)
            .where(Alert.created_at >= cutoff,
                   Alert.status.in_(["open", "investigating"]))
            .group_by(Alert.entity_host, Asset.criticality)
            .order_by(Asset.criticality.desc().nullslast(),
                      func.max(Alert.risk_score).desc())
            .limit(5)
        ))
        critical_assets = [
            {"host": r.entity_host,
             "alert_count": r.alert_count,
             "max_risk": round(float(r.max_risk or 0), 1),
             "criticality": r.criticality or 2}
            for r in asset_rows
        ]
    except Exception:
        pass

    # ── Compliance ────────────────────────────────────────────────────────────
    audit_entries = int((await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.timestamp >= cutoff)
    )).scalar() or 0)
    failed_logins = int((await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.timestamp >= cutoff,
               AuditLog.action == "login_failed")
    )).scalar() or 0)

    # ── Coverage trend (compare to previous period) ───────────────────────────
    prev_cutoff = cutoff - timedelta(days=days)
    # We don't store historical coverage, so show current vs gaps
    coverage_gap = total_cov - covered

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations = []
    open_alerts = alerts_by_status.get("open", 0)
    if open_alerts > 0:
        recommendations.append(f"Investigate {open_alerts} open alert(s) — prioritise by risk score")
    if multi_stage_count > 0:
        recommendations.append(f"Review {multi_stage_count} multi-stage attack chain(s) — potential active intrusion")
    if ti_malicious > 0:
        recommendations.append(f"{ti_malicious} confirmed malicious IOC(s) found — block at firewall immediately")
    if noisy_rules:
        recommendations.append(f"{len(noisy_rules)} rule(s) have FP rate > 50% — tune or disable to reduce noise")
    if coverage_gap > 0:
        recommendations.append(f"{coverage_gap} ATT&CK technique(s) have no detection — review coverage page")
    if fp_rate > 30:
        recommendations.append(f"False positive rate is {fp_rate}% — review and tune detection rules")
    if not recommendations:
        recommendations.append("No critical issues found — maintain regular review cadence")

    return {
        "period_days":        days,
        "generated_at":       now.strftime("%Y-%m-%d %H:%M UTC"),
        "cutoff":             cutoff.strftime("%Y-%m-%d %H:%M UTC"),
        # Alerts
        "total_alerts":       int(alert_row.total or 0),
        "avg_risk":           round(float(alert_row.avg_risk or 0), 1),
        "max_risk":           round(float(alert_row.max_risk or 0), 1),
        "alerts_by_status":   alerts_by_status,
        "top_techniques":     top_techniques,
        "top_hosts":          top_hosts,
        "high_risk_alerts":   high_risk_alerts,
        # Chains
        "chains":             chains,
        "multi_stage_chains": multi_stage_count,
        # Coverage
        "coverage_pct":       coverage_pct,
        "covered_techniques": covered,
        "total_techniques":   total_cov,
        "coverage_gap":       coverage_gap,
        "rules_total":        rules_total,
        "rules_enabled":      rules_enabled,
        # Events
        "events_period":      events_period,
        "events_total":       events_total,
        # MTTD / MTTR
        "mttd_seconds":       mttd_seconds,
        "mttr_seconds":       mttr_seconds,
        # FP rate
        "fp_rate":            fp_rate,
        "total_fp":           total_fp,
        "total_closed":       total_closed,
        # TI
        "ti_total":           ti_total,
        "ti_malicious":       ti_malicious,
        "ti_suspicious":      ti_suspicious,
        "ti_malicious_iocs":  ti_malicious_iocs,
        # Assets
        "critical_assets":    critical_assets,
        # Compliance
        "audit_entries":      audit_entries,
        "failed_logins":      failed_logins,
        # Rules quality
        "noisy_rules":        noisy_rules,
        # Recommendations
        "recommendations":    recommendations,
    }

def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    if seconds < 86400:
        return f"{seconds/3600:.1f}h"
    return f"{seconds/86400:.1f}d"

async def generate_pdf_report(data: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER
    from reportlab.pdfgen import canvas as pdfcanvas

    d = data

    PAGE_W, PAGE_H = A4
    CW = PAGE_W - 4*cm
    C_BG   = colors.HexColor('#1e1e2e')
    C_CODE = colors.HexColor('#cdd6f4')
    C_HEAD = colors.HexColor('#11111b')
    C_BLUE = colors.HexColor('#89b4fa')
    C_GREEN= colors.HexColor('#a6e3a1')
    C_RED  = colors.HexColor('#f38ba8')
    C_WARN = colors.HexColor('#fab387')
    C_YELL = colors.HexColor('#f9e2af')
    C_MUTE = colors.HexColor('#888899')
    C_ALT  = colors.HexColor('#f8f8fc')
    C_RULE = colors.HexColor('#cba6f7')

    S_TITLE = ParagraphStyle('T', fontName='Helvetica-Bold', fontSize=24,
                              textColor=C_HEAD, alignment=TA_CENTER, spaceAfter=4)
    S_SUB   = ParagraphStyle('S', fontName='Helvetica', fontSize=11,
                              textColor=C_MUTE, alignment=TA_CENTER, spaceAfter=4)
    S_H1    = ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=15,
                              textColor=C_HEAD, spaceBefore=10, spaceAfter=4)
    S_H2    = ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=11,
                              textColor=C_BLUE, spaceBefore=8, spaceAfter=3)
    S_BODY  = ParagraphStyle('B', fontName='Helvetica', fontSize=9,
                              textColor=C_HEAD, leading=13, spaceAfter=3)
    S_NOTE  = ParagraphStyle('N', fontName='Helvetica-Oblique', fontSize=8,
                              textColor=C_MUTE, leading=12)

    def section(title):
        return [Spacer(1, 4),
                Paragraph(title, S_H2),
                HRFlowable(width='100%', thickness=0.5, color=C_RULE, spaceAfter=4)]

    def kv_table(rows, col1=5*cm):
        data = [[
            Paragraph(k, ParagraphStyle('k', fontName='Helvetica-Bold',
                       fontSize=9, textColor=C_BLUE)),
            Paragraph(str(v), ParagraphStyle('v', fontName='Helvetica',
                       fontSize=9, textColor=C_HEAD))
        ] for k, v in rows]
        tbl = Table(data, colWidths=[col1, CW-col1])
        tbl.setStyle(TableStyle([
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, C_ALT]),
            ('TOPPADDING',    (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
            ('LINEBELOW',  (0,-1), (-1,-1), 0.5, C_RULE),
            ('LINEABOVE',  (0, 0), (-1, 0), 0.5, C_RULE),
        ]))
        return [tbl, Spacer(1, 6)]

    def grid_table(headers, rows, col_colors=None):
        data = [[Paragraph(h, ParagraphStyle('th', fontName='Helvetica-Bold',
                    fontSize=8, textColor=C_MUTE)) for h in headers]]
        for row in rows:
            data.append([Paragraph(str(c), ParagraphStyle('td',
                fontName='Helvetica', fontSize=8, textColor=C_HEAD))
                for c in row])
        col_w = CW / len(headers)
        tbl = Table(data, colWidths=[col_w]*len(headers))
        tbl.setStyle(TableStyle([
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, C_ALT]),
            ('LINEBELOW', (0,0), (-1,0), 1, C_RULE),
            ('TOPPADDING',    (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ]))
        return [tbl, Spacer(1, 6)]

    def stat_row(stats):
        """Horizontal stat cards row."""
        cells = []
        for label, value, color in stats:
            cell = Table([[
                Paragraph(str(value), ParagraphStyle('sv', fontName='Helvetica-Bold',
                    fontSize=18, textColor=color, alignment=TA_CENTER)),
                Paragraph(label, ParagraphStyle('sl', fontName='Helvetica',
                    fontSize=8, textColor=C_MUTE, alignment=TA_CENTER)),
            ]], colWidths=[CW/len(stats)])
            cell.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), C_ALT),
                ('BOX',        (0,0), (-1,-1), 0.5, C_RULE),
                ('TOPPADDING',   (0,0), (-1,-1), 8),
                ('BOTTOMPADDING',(0,0), (-1,-1), 8),
            ]))
            cells.append(cell)
        row = Table([cells], colWidths=[CW/len(stats)]*len(stats))
        return [row, Spacer(1, 8)]

    class NumCanvas(pdfcanvas.Canvas):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._pages = []
        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()
        def save(self):
            n = len(self._pages)
            for i, p in enumerate(self._pages, 1):
                self.__dict__.update(p)
                if i > 1:
                    self.saveState()
                    self.setFont('Helvetica', 7)
                    self.setFillColor(colors.HexColor('#888'))
                    self.drawRightString(PAGE_W-1.5*cm, 1.1*cm,
                        f'ThreatOS Security Report  |  Page {i} of {n}')
                    self.drawString(1.5*cm, 1.1*cm, f'Generated {d["generated_at"]}  —  Confidential')
                    self.setStrokeColor(colors.HexColor('#ddd'))
                    self.setLineWidth(0.3)
                    self.line(1.5*cm, 1.4*cm, PAGE_W-1.5*cm, 1.4*cm)
                    self.restoreState()
                super().showPage()
            super().save()

    buf   = io.BytesIO()
    doc   = SimpleDocTemplate(buf, pagesize=A4,
                leftMargin=2*cm, rightMargin=2*cm,
                topMargin=2*cm, bottomMargin=2.5*cm)
    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 2*cm),
        Paragraph('ThreatOS', S_TITLE),
        Paragraph('Security Operations Report', S_SUB),
        Spacer(1, 0.3*cm),
        HRFlowable(width='100%', thickness=2.5, color=C_RULE, spaceAfter=10),
        Paragraph(f'{d["period_days"]}-Day Period  ·  {d["generated_at"]}', S_NOTE),
        Spacer(1, 1*cm),
    ]

    # Verdict banner
    open_c   = d['alerts_by_status'].get('open', 0)
    verdict  = 'CRITICAL' if d['multi_stage_chains'] > 0 or d['ti_malicious'] > 0 \
               else 'WARNING' if open_c > 5 else 'NORMAL'
    v_color  = C_RED if verdict=='CRITICAL' else C_WARN if verdict=='WARNING' else C_GREEN
    v_banner = Table([[
        Paragraph(f'Security Status: {verdict}', ParagraphStyle('vb',
            fontName='Helvetica-Bold', fontSize=14,
            textColor=v_color, alignment=TA_CENTER))
    ]], colWidths=[CW])
    v_banner.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), colors.HexColor('#f8f8fc')),
        ('BOX',          (0,0), (-1,-1), 2, v_color),
        ('TOPPADDING',   (0,0), (-1,-1), 12),
        ('BOTTOMPADDING',(0,0), (-1,-1), 12),
    ]))
    story += [v_banner, Spacer(1, 1*cm)]

    # KPI row
    story += stat_row([
        ('Total Alerts',        d['total_alerts'],        C_BLUE),
        ('Open Alerts',         open_c,                   C_RED if open_c > 0 else C_GREEN),
        ('Multi-Stage Chains',  d['multi_stage_chains'],  C_RED if d['multi_stage_chains'] else C_GREEN),
        ('ATT&CK Coverage',     f"{d['coverage_pct']}%",  C_GREEN),
        ('Malicious IOCs',      d['ti_malicious'],        C_RED if d['ti_malicious'] else C_GREEN),
        ('FP Rate',             f"{d['fp_rate']}%",       C_WARN if d['fp_rate'] > 20 else C_GREEN),
    ])
    story.append(PageBreak())

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    story += [Paragraph('1. Executive Summary', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    story += kv_table([
        ('Report Period',        f"{d['period_days']} days  ({d['cutoff']} → {d['generated_at']})"),
        ('Total Alerts',         f"{d['total_alerts']}  (avg risk: {d['avg_risk']}  max risk: {d['max_risk']})"),
        ('Open / Investigating', f"{d['alerts_by_status'].get('open',0)} open  /  {d['alerts_by_status'].get('investigating',0)} investigating"),
        ('Closed / FP',          f"{d['alerts_by_status'].get('closed',0)} closed  /  {d['alerts_by_status'].get('false_positive',0)} false positive"),
        ('Multi-Stage Chains',   f"{d['multi_stage_chains']} detected — {'URGENT: investigate immediately' if d['multi_stage_chains'] else 'none'}"),
        ('ATT&CK Coverage',      f"{d['coverage_pct']}%  ({d['covered_techniques']}/{d['total_techniques']} techniques)"),
        ('Events Ingested',      f"{d['events_period']} this period  /  {d['events_total']} total"),
        ('Detection Rules',      f"{d['rules_enabled']} enabled  /  {d['rules_total']} total"),
    ])

    # ── 2. MTTD / MTTR / FP ──────────────────────────────────────────────────
    story += [Paragraph('2. Detection & Response Metrics', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    story += stat_row([
        ('Mean Time to Detect',   fmt_duration(d['mttd_seconds']), C_BLUE),
        ('Mean Time to Respond',  fmt_duration(d['mttr_seconds']), C_BLUE),
        ('False Positive Rate',   f"{d['fp_rate']}%",              C_WARN if d['fp_rate']>20 else C_GREEN),
        ('FPs this period',       d['total_fp'],                    C_WARN if d['total_fp']>5 else C_GREEN),
    ])
    story += kv_table([
        ('MTTD',          f"{fmt_duration(d['mttd_seconds'])}  — time from event ingestion to alert creation"),
        ('MTTR',          f"{fmt_duration(d['mttr_seconds'])}  — time from alert creation to resolution"),
        ('FP Rate',       f"{d['fp_rate']}%  ({d['total_fp']} FPs out of {d['total_closed']} closed alerts)"),
        ('Target MTTD',   '< 60 seconds for critical techniques'),
        ('Target MTTR',   '< 4 hours for high-risk alerts'),
        ('Target FP Rate','< 20%'),
    ])

    # ── 3. TI Enrichment ─────────────────────────────────────────────────────
    story += [Paragraph('3. Threat Intelligence Enrichment', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    story += stat_row([
        ('IOCs Checked',   d['ti_total'],      C_BLUE),
        ('Malicious',      d['ti_malicious'],  C_RED if d['ti_malicious'] else C_GREEN),
        ('Suspicious',     d['ti_suspicious'], C_WARN if d['ti_suspicious'] else C_GREEN),
    ])
    if d['ti_malicious_iocs']:
        story += section('Confirmed Malicious IOCs')
        story += grid_table(
            ['Type', 'IOC Value', 'Source', 'Score', 'Country'],
            [(i['ioc_type'], i['ioc_value'][:35], i['source'],
              f"{i['score']}%" if i['score'] else 'N/A', i['country'] or '?')
             for i in d['ti_malicious_iocs']]
        )
        story.append(Paragraph(
            '⚠ Action required: Block malicious IPs at perimeter firewall. '
            'Investigate all alerts from these sources immediately.', S_NOTE))
    else:
        story.append(Paragraph('No malicious IOCs confirmed this period.', S_BODY))

    # ── 4. Top Critical Assets at Risk ────────────────────────────────────────
    story += [Paragraph('4. Top Critical Assets at Risk', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    if d['critical_assets']:
        story += grid_table(
            ['Host', 'Open Alerts', 'Max Risk Score', 'Criticality'],
            [(a['host'], a['alert_count'], a['max_risk'],
              '★'*a['criticality'] + f" ({a['criticality']})")
             for a in d['critical_assets']]
        )
    else:
        story.append(Paragraph('No open alerts on registered assets.', S_BODY))

    # ── 5. Top Detected Techniques ────────────────────────────────────────────
    story += [Paragraph('5. Top Detected Techniques', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    if d['top_techniques']:
        story += grid_table(
            ['Technique', 'Tactic', 'Alert Count', 'Avg Risk'],
            [(t['technique_id'], t['tactic'], t['count'], t['avg_risk'])
             for t in d['top_techniques']]
        )
    else:
        story.append(Paragraph('No alerts this period.', S_BODY))

    # ── 6. High Risk Alerts ───────────────────────────────────────────────────
    story += [Paragraph('6. High Risk Alerts  (score ≥ 70)', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    if d['high_risk_alerts']:
        story += grid_table(
            ['Technique', 'Tactic', 'Host', 'Risk Score', 'Status', 'Time'],
            [(a['technique_id'], a['tactic'], a['host'] or '?',
              a['risk_score'], a['status'], a['created_at'])
             for a in d['high_risk_alerts']]
        )
    else:
        story.append(Paragraph('No high-risk alerts this period.', S_BODY))

    # ── 7. Attack Chains ─────────────────────────────────────────────────────
    story += [Paragraph('7. Attack Chain Correlation', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    story += kv_table([
        ('Multi-stage chains', f"{d['multi_stage_chains']} detected this period"),
        ('Risk threshold',     'Multi-stage = 3+ tactics — treat as confirmed intrusion'),
    ])
    if d['chains']:
        story += grid_table(
            ['Chain ID', 'Host', 'Tactics', 'Risk Score', 'Multi-Stage', 'Status'],
            [(c['id'], c['host'], c['tactic_count'],
              c['risk_score'], '✓' if c['is_multi_stage'] else '', c['status'])
             for c in d['chains']]
        )

    # ── 8. Coverage Trend ─────────────────────────────────────────────────────
    story += [Paragraph('8. ATT&CK Coverage', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    story += kv_table([
        ('Current Coverage',    f"{d['coverage_pct']}%  ({d['covered_techniques']}/{d['total_techniques']} techniques)"),
        ('Coverage Gap',        f"{d['coverage_gap']} techniques with no detection rule"),
        ('Detection Rules',     f"{d['rules_enabled']} enabled  /  {d['rules_total']} total"),
        ('Target',              '100% coverage across all 14 ATT&CK tactics'),
    ])

    # ── 9. Detection Quality ─────────────────────────────────────────────────
    story += [Paragraph('9. Detection Quality', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    if d['noisy_rules']:
        story += section('Rules Requiring Attention  (FP rate > 50%)')
        story += grid_table(
            ['Rule Name', 'Technique', 'FP Rate', 'Total Evals'],
            [(r['name'], r['technique_id'], f"{r['fp_rate']}%", r['total_evals'])
             for r in d['noisy_rules']]
        )
        story.append(Paragraph(
            'Recommendation: Disable or tune rules with FP rate > 80%. '
            'Use the Rules page → toggle off. Coverage is maintained even with some rules disabled.', S_NOTE))
    else:
        story.append(Paragraph('No rules with excessive false positive rates.', S_BODY))

    # ── 10. Compliance ────────────────────────────────────────────────────────
    story += [Paragraph('10. Compliance & Governance', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    story += kv_table([
        ('Audit log entries',  f"{d['audit_entries']} actions recorded this period"),
        ('Failed login attempts', f"{d['failed_logins']} failed logins"),
        ('Audit integrity',    'Verify at: GET /api/compliance/audit-integrity'),
        ('Data retention',     'Raw events: 90d  |  Audit: 365d  |  Closed alerts: 365d'),
    ])

    # ── 11. Recommendations ───────────────────────────────────────────────────
    story += [Paragraph('11. Recommendations', S_H1),
              HRFlowable(width='100%', thickness=1.5, color=C_RULE, spaceAfter=6)]
    for i, rec in enumerate(d['recommendations'], 1):
        story.append(Paragraph(f'{i}.  {rec}', S_BODY))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        'This report was automatically generated by ThreatOS. '
        'For questions contact the security operations team.', S_NOTE))

    doc.build(story, canvasmaker=NumCanvas)
    return buf.getvalue()
