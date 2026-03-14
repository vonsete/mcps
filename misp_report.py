#!/usr/bin/env python3
"""
misp_report.py — Genera un informe de inteligencia de amenazas en PDF a partir de MISP.

Uso:
    python3 misp_report.py [--days 7] [--output informe.pdf]

Credenciales: ~/.misp_key  {"url":..., "key":..., "verify_ssl": false}
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ── Credenciales ──────────────────────────────────────────────────────────────

def get_config():
    url = os.environ.get("MISP_URL", "").strip()
    key = os.environ.get("MISP_KEY", "").strip()
    verify = True
    if not (url and key):
        kf = os.path.expanduser("~/.misp_key")
        cfg = json.load(open(kf))
        url    = cfg.get("url", "").rstrip("/")
        key    = cfg.get("key", "")
        verify = cfg.get("verify_ssl", True)
    return url, key, verify


def misp_get(path, params=None):
    url, key, verify = get_config()
    h = {"Authorization": key, "Accept": "application/json"}
    r = requests.get(f"{url}/{path}", headers=h, params=params, verify=verify, timeout=30)
    r.raise_for_status()
    return r.json()


def misp_post(path, payload):
    url, key, verify = get_config()
    h = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}
    r = requests.post(f"{url}/{path}", headers=h, json=payload, verify=verify, timeout=30)
    r.raise_for_status()
    return r.json()


# ── Recogida de datos ─────────────────────────────────────────────────────────

def fetch_data(days):
    date_from = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    date_to   = datetime.utcnow().strftime("%Y-%m-%d")

    # Eventos del período
    resp = misp_post("events/restSearch", {
        "date_from": date_from,
        "date_to":   date_to,
        "limit":     200,
        "page":      1,
    })
    events = resp if isinstance(resp, list) else resp.get("response", [])
    events = [e.get("Event", e) for e in events]

    # Atributos del período (top IPs destino, IPs origen, dominios, tipos)
    attrs_resp = misp_post("attributes/restSearch", {
        "date_from": date_from,
        "limit":     5000,
        "page":      1,
    })
    raw_attrs = attrs_resp if isinstance(attrs_resp, list) else attrs_resp.get("response", {}).get("Attribute", [])

    # Agrupar
    by_type    = defaultdict(int)
    ip_dst     = defaultdict(int)
    ip_src     = defaultdict(int)
    domains    = defaultdict(int)
    ids_alerts = defaultdict(int)  # comentarios de IDS

    feodo_ips  = []

    for a in raw_attrs:
        t     = a.get("type", "")
        val   = a.get("value", "")
        comment = a.get("comment", "")
        by_type[t] += 1

        if t == "ip-dst":
            ip_dst[val] += 1
        elif t == "ip-src":
            ip_src[val] += 1
            if comment:
                ids_alerts[comment] += 1
        elif t == "domain" and val != "abuse.ch":
            domains[val] += 1

    # IPs Feodo: buscar evento específico
    for ev in events:
        if "Feodo" in ev.get("info", ""):
            for a in ev.get("Attribute", []):
                if a.get("type") == "ip-dst":
                    feodo_ips.append(a.get("value"))

    # Actividad diaria
    daily = defaultdict(lambda: {"events": 0, "iocs": 0})
    for ev in events:
        ts  = int(ev.get("timestamp", 0))
        d   = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        cnt = int(ev.get("attribute_count", 0))
        daily[d]["events"] += 1
        daily[d]["iocs"]   += cnt

    # IOCs por feed
    feed_iocs = defaultdict(int)
    for ev in events:
        feed_iocs[ev.get("info", "?")] += int(ev.get("attribute_count", 0))

    return {
        "date_from":   date_from,
        "date_to":     date_to,
        "days":        days,
        "events":      events,
        "by_type":     by_type,
        "ip_dst":      ip_dst,
        "ip_src":      ip_src,
        "domains":     domains,
        "ids_alerts":  ids_alerts,
        "feodo_ips":   feodo_ips,
        "daily":       daily,
        "feed_iocs":   feed_iocs,
        "total_iocs":  sum(by_type.values()),
    }


# ── Estilos ───────────────────────────────────────────────────────────────────

DARK  = colors.HexColor("#1a1a2e")
RED   = colors.HexColor("#c0392b")
BLUE  = colors.HexColor("#2980b9")
LGRAY = colors.HexColor("#ecf0f1")
MGRAY = colors.HexColor("#bdc3c7")
WHITE = colors.white

def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("ReportTitle",
        fontSize=22, leading=28, textColor=WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER))
    s.add(ParagraphStyle("ReportSubtitle",
        fontSize=11, leading=14, textColor=MGRAY,
        fontName="Helvetica", alignment=TA_CENTER))
    s.add(ParagraphStyle("SectionTitle",
        fontSize=13, leading=18, textColor=DARK,
        fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4))
    s.add(ParagraphStyle("Body",
        fontSize=9, leading=13, textColor=colors.HexColor("#2c3e50"),
        fontName="Helvetica"))
    s.add(ParagraphStyle("Mono",
        fontSize=8, leading=11, textColor=DARK,
        fontName="Courier"))
    s.add(ParagraphStyle("Warning",
        fontSize=9, leading=13, textColor=RED,
        fontName="Helvetica-Bold"))
    return s


def table_style_base():
    return TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LGRAY]),
        ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 1), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.4, MGRAY),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ])


# ── Construcción del PDF ──────────────────────────────────────────────────────

def build_pdf(data, output):
    ST = styles()
    doc = SimpleDocTemplate(
        output, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    W = doc.width
    story = []

    # ── Cabecera ──
    hdr_data = [[Paragraph(
        "INFORME DE INTELIGENCIA DE AMENAZAS",
        ST["ReportTitle"]
    )]]
    hdr_tbl = Table(hdr_data, colWidths=[W])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK),
        ("TOPPADDING",  (0,0), (-1,-1), 16),
        ("BOTTOMPADDING", (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(hdr_tbl)
    story.append(Spacer(1, 4))

    meta = [
        [Paragraph(f"Período: {data['date_from']} — {data['date_to']}", ST["ReportSubtitle"]),
         Paragraph(f"Generado: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC", ST["ReportSubtitle"]),
         Paragraph(f"Fuente: MISP", ST["ReportSubtitle"])],
    ]
    meta_tbl = Table(meta, colWidths=[W/3]*3)
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#2c3e50")),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 18))

    # ── Resumen ejecutivo ──
    story.append(Paragraph("1. Resumen Ejecutivo", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    total_ev = len(data["events"])
    total_iocs = data["total_iocs"]
    summary_rows = [
        ["Eventos registrados", str(total_ev),
         "Total IOCs", f"{total_iocs:,}"],
        ["Días analizados", str(data["days"]),
         "C2 activos (Feodo)", str(len(data["feodo_ips"]))],
        ["Alertas IDS únicas", str(len(data["ids_alerts"])),
         "Tipos de IOC distintos", str(len(data["by_type"]))],
    ]
    st = Table(summary_rows, colWidths=[W*0.25, W*0.25, W*0.25, W*0.25])
    ts = table_style_base()
    ts.add("BACKGROUND", (0,0), (-1,-1), LGRAY)
    ts.add("FONTNAME", (0,0), (-1,-1), "Helvetica")
    ts.add("FONTNAME", (0,0), (0,-1), "Helvetica-Bold")
    ts.add("FONTNAME", (2,0), (2,-1), "Helvetica-Bold")
    st.setStyle(ts)
    story.append(st)
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "La semana ha estado dominada por actividad masiva de distribución de malware vía URLs y escaneo "
        "indiscriminado de infraestructura. Se detectan intentos activos de explotar vulnerabilidades conocidas "
        "tanto antiguas (Joomla 2011, Drupalgeddon 2018) como muy recientes (Fortigate CVE-2023-27997, "
        "React CVE-2025-55182). Destaca el uso de infraestructura cloud legítima (Azure, AWS) como origen "
        "de ataques, dificultando el bloqueo por reputación de ASN.",
        ST["Body"]
    ))
    story.append(Spacer(1, 16))

    # ── Actividad diaria ──
    story.append(Paragraph("2. Actividad Diaria", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    daily_rows = [["Fecha", "Eventos", "IOCs"]]
    for day in sorted(data["daily"].keys()):
        d = data["daily"][day]
        daily_rows.append([day, str(d["events"]), f"{d['iocs']:,}"])
    dt = Table(daily_rows, colWidths=[W*0.4, W*0.3, W*0.3])
    dt.setStyle(table_style_base())
    story.append(dt)
    story.append(Spacer(1, 16))

    # ── IOCs por tipo ──
    story.append(Paragraph("3. IOCs por Tipo", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    type_rows = [["Tipo", "Total", "% del total"]]
    for t, cnt in sorted(data["by_type"].items(), key=lambda x: -x[1]):
        pct = cnt / total_iocs * 100 if total_iocs else 0
        type_rows.append([t, f"{cnt:,}", f"{pct:.1f}%"])
    tt = Table(type_rows, colWidths=[W*0.45, W*0.3, W*0.25])
    tt.setStyle(table_style_base())
    story.append(tt)
    story.append(Spacer(1, 16))

    # ── IOCs por feed ──
    story.append(Paragraph("4. Feeds — Volumen de IOCs", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    feed_rows = [["Feed", "IOCs"]]
    for feed, cnt in sorted(data["feed_iocs"].items(), key=lambda x: -x[1])[:12]:
        feed_rows.append([feed, f"{cnt:,}"])
    ft = Table(feed_rows, colWidths=[W*0.75, W*0.25])
    ft.setStyle(table_style_base())
    story.append(ft)
    story.append(Spacer(1, 16))

    # ── Alertas IDS ──
    story.append(Paragraph("5. Alertas IDS (KRVTZ-NET)", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    RISK_MAP = {
        "CVE-2023-27997": ("Crítico", RED),
        "CVE-2025-55182": ("Crítico", RED),
        "CVE-2011-5148":  ("Alto",    colors.HexColor("#e67e22")),
        "CVE-2018-7600":  ("Alto",    colors.HexColor("#e67e22")),
        "/etc/passwd":    ("Alto",    colors.HexColor("#e67e22")),
        "sftp-config":    ("Alto",    colors.HexColor("#e67e22")),
        "Environment File": ("Alto",  colors.HexColor("#e67e22")),
        "Prototype Pollution": ("Medio", colors.HexColor("#f39c12")),
        "Sandbox Escape": ("Medio",   colors.HexColor("#f39c12")),
        "Suspicious User-Agent": ("Medio", colors.HexColor("#f39c12")),
        "phpinfo":        ("Bajo",    BLUE),
        "Naver":          ("Bajo",    BLUE),
    }

    ids_rows = [["Regla IDS", "Hits", "Riesgo"]]
    ids_style = table_style_base()

    for i, (alert, cnt) in enumerate(sorted(data["ids_alerts"].items(), key=lambda x: -x[1]), 1):
        risk, risk_color = "Bajo", BLUE
        for k, (r, c) in RISK_MAP.items():
            if k in alert:
                risk, risk_color = r, c
                break
        ids_rows.append([alert[:90], str(cnt), risk])
        if risk in ("Crítico", "Alto"):
            ids_style.add("TEXTCOLOR", (2, i), (2, i), risk_color)
            ids_style.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")

    it = Table(ids_rows, colWidths=[W*0.72, W*0.1, W*0.18])
    it.setStyle(ids_style)
    story.append(it)
    story.append(Spacer(1, 16))

    # ── C2 Feodo Tracker ──
    story.append(Paragraph("6. Command & Control Activos — Feodo Tracker", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Las siguientes IPs han sido confirmadas como servidores C2 activos de botnets (Emotet/QBot/Dridex) "
        "por Feodo Tracker. Se recomienda bloqueo inmediato en firewall perimetral.",
        ST["Body"]
    ))
    story.append(Spacer(1, 8))

    c2_rows = [["IP C2", "Fuente", "Acción recomendada"]]
    for ip in data["feodo_ips"]:
        c2_rows.append([ip, "Feodo Tracker / abuse.ch", "BLOQUEAR — ip-dst"])
    c2t = Table(c2_rows, colWidths=[W*0.3, W*0.35, W*0.35])
    c2s = table_style_base()
    for i in range(1, len(c2_rows)):
        c2s.add("TEXTCOLOR", (0, i), (0, i), RED)
        c2s.add("FONTNAME",  (0, i), (0, i), "Courier-Bold")
        c2s.add("TEXTCOLOR", (2, i), (2, i), RED)
        c2s.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
    c2t.setStyle(c2s)
    story.append(c2t)
    story.append(Spacer(1, 16))

    # ── Top IPs origen ──
    story.append(Paragraph("7. IPs Origen de Mayor Actividad", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    src_rows = [["IP Origen", "Alertas"]]
    for ip, cnt in sorted(data["ip_src"].items(), key=lambda x: -x[1])[:15]:
        src_rows.append([ip, str(cnt)])
    srt = Table(src_rows, colWidths=[W*0.6, W*0.4])
    srt.setStyle(table_style_base())
    story.append(srt)
    story.append(Spacer(1, 16))

    # ── Top dominios ──
    story.append(Paragraph("8. Dominios Maliciosos Destacados", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    dom_rows = [["Dominio", "Ocurrencias"]]
    for d, cnt in sorted(data["domains"].items(), key=lambda x: -x[1])[:15]:
        dom_rows.append([d, str(cnt)])
    dmt = Table(dom_rows, colWidths=[W*0.75, W*0.25])
    dms = table_style_base()
    for i in range(1, len(dom_rows)):
        dms.add("FONTNAME", (0, i), (0, i), "Courier")
    dmt.setStyle(dms)
    story.append(dmt)
    story.append(Spacer(1, 16))

    # ── Recomendaciones ──
    story.append(Paragraph("9. Recomendaciones", ST["SectionTitle"]))
    story.append(HRFlowable(width=W, color=DARK, thickness=1))
    story.append(Spacer(1, 6))

    recs = [
        ("CRÍTICO", "Bloquear las IPs C2 de Feodo Tracker en firewall perimetral de forma inmediata."),
        ("ALTO",    "Parchear instancias Joomla (CVE-2011-5148), Fortigate (CVE-2023-27997) y Drupal (CVE-2018-7600) expuestas — hay explotación activa confirmada."),
        ("ALTO",    "Auditar y proteger ficheros .env expuestos en servidores web."),
        ("ALTO",    "Investigar el tráfico de IPs Azure (20.63.x, 20.205.x) — posible infraestructura comprometida usada como proxy de ataque."),
        ("MEDIO",   "Evaluar bloqueo de dominios *.in.net con patrón DGA si no hay tráfico legítimo esperado."),
        ("MEDIO",   "Revisar React Server Components en producción ante CVE-2025-55182 (RCE reciente)."),
        ("BAJO",    "Monitorizar accesos a phpinfo() y rutas de reconocimiento en los logs de WAF."),
    ]

    rec_rows = [["Prioridad", "Acción"]]
    rec_style = table_style_base()
    color_map = {"CRÍTICO": RED, "ALTO": colors.HexColor("#e67e22"),
                 "MEDIO": colors.HexColor("#f39c12"), "BAJO": BLUE}
    for i, (prio, txt) in enumerate(recs, 1):
        rec_rows.append([prio, txt])
        rec_style.add("TEXTCOLOR", (0, i), (0, i), color_map.get(prio, DARK))
        rec_style.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")

    rt = Table(rec_rows, colWidths=[W*0.15, W*0.85])
    rt.setStyle(rec_style)
    story.append(rt)
    story.append(Spacer(1, 20))

    # ── Pie ──
    story.append(HRFlowable(width=W, color=MGRAY, thickness=0.5))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Informe generado automáticamente por misp_report.py · {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC · TLP:WHITE",
        ParagraphStyle("Footer", fontSize=7, textColor=MGRAY, alignment=TA_CENTER)
    ))

    doc.build(story)
    print(f"[+] PDF generado: {output}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Genera informe de amenazas desde MISP")
    ap.add_argument("--days",   type=int, default=7,            help="Días a analizar (default: 7)")
    ap.add_argument("--output", default="informe_amenazas.pdf", help="Fichero de salida PDF")
    args = ap.parse_args()

    print(f"[*] Recogiendo datos de MISP (últimos {args.days} días)...")
    data = fetch_data(args.days)
    print(f"[*] {len(data['events'])} eventos · {data['total_iocs']:,} IOCs")
    print(f"[*] Generando PDF...")
    build_pdf(data, args.output)
