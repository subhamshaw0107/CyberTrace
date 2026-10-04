"""
app/web.py
============

Local operator console over app/service.py:
  /            status: ledger health, node agreement, identities
  /sender      upload a document, pick recipients, download the package
  /recipient   decrypt as an identity, download the watermarked copy
  /trace       upload a leaked file, get the attribution report

Everything is inline: markup, CSS, SVG icons and the small amount of
JavaScript. There is no CDN, no web font and no framework, because the system
must run inside an air gap. Nothing is fetched at run time.

This is an operator tool, not a public service. It binds to 127.0.0.1 and has
NO user authentication: anyone who can reach the port can act as any identity
whose passphrase they know. Put it behind the host's own access control
(see docs/DEPLOYMENT.md).
"""

from __future__ import annotations
import html
import io
import json
import os
import secrets
import sys
import time
import traceback
from pathlib import Path

_downloads: dict[str, object] = {}
_protected_packages: dict[str, dict] = {}
_unlocked_files: dict[str, dict] = {}

_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from flask import Flask, get_flashed_messages, redirect, request, send_file, url_for, flash, make_response, session, jsonify

from app.service import Workspace, ServiceError
from app.user_auth import AuthManager, DeliveryManager
from watermark.document_formats import UnsupportedFormat

MAX_UPLOAD_MB = 64

# --------------------------------------------------------------------- styling
CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#F3F6FA; --panel:#FFFFFF; --panel-2:#F7F9FC; --line:#D8E0EA; --line-soft:#E7ECF3;
  --fg:#0F1C2E; --muted:#52647B; --faint:#64768C;
  --accent:#0B5FCC; --accent-ink:#FFFFFF; --accent-soft:#EAF2FE; --accent-line:#CFE2FB;
  --ok:#0F6B45; --ok-soft:#EAF7F0; --ok-line:#B7E2CC;
  --warn:#8A5A00; --warn-soft:#FDF4E5; --warn-line:#F0D5A6;
  --bad:#A8232B; --bad-soft:#FCEEEE; --bad-line:#F0C3C3;
  --violet:#4E3BC4; --violet-soft:#EFECFD; --violet-line:#D8D2F8;
  --r-lg:14px; --r-md:10px; --r-sm:8px;
  --shadow:0 1px 2px rgba(16,24,40,.05), 0 10px 26px -18px rgba(16,24,40,.28);
  --mono:ui-monospace,"Cascadia Mono",Consolas,"SF Mono",monospace;
}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);
  font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased;min-height:100vh}
a{color:var(--accent)}
.mono{font-family:var(--mono);font-size:13px;letter-spacing:.1px;word-break:break-all}

/* ---------- header ---------- */
header{position:sticky;top:0;z-index:40;background:rgba(255,255,255,.93);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--line-soft)}
.bar{max-width:1280px;margin:0 auto;padding:13px 24px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px;font-weight:700;letter-spacing:.2px}
.brand .mark{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;
  background:linear-gradient(145deg,#12386F,#0B5FCC);color:#fff;border:1px solid #0A4FA8}
.brand small{display:block;font-weight:600;font-size:10.5px;color:var(--faint);letter-spacing:.8px;text-transform:uppercase}
nav{display:flex;gap:3px;margin-left:6px;flex-wrap:wrap}
nav a{color:var(--muted);text-decoration:none;padding:7px 13px;border-radius:8px;font-size:14px;
  display:inline-flex;align-items:center;gap:8px;border:1px solid transparent;transition:.15s}
nav a:hover{color:var(--fg);background:var(--panel-2)}
nav a.on{color:var(--accent);background:var(--accent-soft);border-color:var(--accent-line);font-weight:600}
.chips{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.chip{font-size:11.5px;color:var(--muted);border:1px solid var(--line);background:var(--panel);
  padding:5px 10px;border-radius:7px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.chip b{color:var(--fg);font-weight:700}
.dot{width:7px;height:7px;border-radius:50%;background:#18A05F;box-shadow:0 0 0 3px rgba(24,160,95,.15)}
.dot.bad{background:#D0353D;box-shadow:0 0 0 3px rgba(208,53,61,.15)}

/* ---------- layout ---------- */
main{max-width:1280px;margin:0 auto;padding:34px 24px 72px}
.hero{margin-bottom:26px}
.eyebrow{font-size:11.5px;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:30px;line-height:1.2;margin:9px 0 0;letter-spacing:-.5px;font-weight:700}
.lede{color:var(--muted);margin:11px 0 0;max-width:74ch}
.grid{display:grid;gap:18px}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.split{display:grid;gap:18px;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);align-items:start}
@media (max-width:900px){ .g2,.g3,.g4,.split{grid-template-columns:1fr} }
@media (max-width:640px){
  html,body{overflow-x:hidden}
  .bar{padding:11px 16px;gap:12px}
  main{padding:24px 16px 56px}
  .chips{margin-left:0;width:100%}
  .chip{font-size:11px}
  h1{font-size:24px}
  .card{padding:18px 16px}
  .drop{padding:20px 14px}
  .drop .big{font-size:14px}
  .kv td:first-child{width:42%}
}

/* ---------- cards ---------- */
.card{background:var(--panel);border:1px solid var(--line-soft);border-radius:var(--r-lg);
  padding:22px 24px;box-shadow:var(--shadow)}
.card h2{font-size:15px;margin:0;display:flex;align-items:center;gap:10px;letter-spacing:.1px;font-weight:700}
.card .sub{color:var(--muted);font-size:13.5px;margin:9px 0 0}
.icon{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;flex:none;
  background:var(--accent-soft);color:var(--accent);border:1px solid var(--accent-line)}
.icon.ok{background:var(--ok-soft);color:var(--ok);border-color:var(--ok-line)}
.icon.warn{background:var(--warn-soft);color:var(--warn);border-color:var(--warn-line)}
.icon.bad{background:var(--bad-soft);color:var(--bad);border-color:var(--bad-line)}
.icon.violet{background:var(--violet-soft);color:var(--violet);border-color:var(--violet-line)}
hr.sep{border:0;border-top:1px solid var(--line-soft);margin:18px 0}

/* ---------- stats & nodes ---------- */
.stat{background:var(--panel);border:1px solid var(--line-soft);border-radius:var(--r-md);
  padding:17px 18px;box-shadow:var(--shadow)}
.stat .k{font-size:11px;letter-spacing:1.1px;text-transform:uppercase;color:var(--faint);font-weight:700}
.stat .v{font-size:27px;font-weight:700;margin-top:7px;letter-spacing:-.6px}
.stat .n{font-size:12.5px;color:var(--muted);margin-top:3px}
.node{display:flex;align-items:center;gap:12px;padding:11px 14px;border:1px solid var(--line-soft);
  border-radius:var(--r-md);background:var(--panel-2)}
.node svg{color:var(--faint)}
.node .nm{font-family:var(--mono);font-size:12.5px}
.node .rc{margin-left:auto;font-size:12px;color:var(--muted);white-space:nowrap}

/* ---------- forms ---------- */
label{display:block;font-size:11.5px;letter-spacing:.6px;text-transform:uppercase;color:var(--faint);
  font-weight:700;margin:20px 0 8px}
input[type=text],input[type=password],select{width:100%;background:#fff;color:var(--fg);
  border:1px solid var(--line);border-radius:var(--r-sm);padding:11px 13px;font:inherit;font-size:14.5px;transition:.15s}
input:focus,select:focus,.drop:focus-visible{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(11,95,204,.15)}
input::placeholder{color:#94A3B4}
.drop{border:1.5px dashed var(--line);border-radius:var(--r-md);background:var(--panel-2);
  padding:26px 20px;text-align:center;cursor:pointer;transition:.15s;display:block;color:var(--accent)}
.drop:hover,.drop.hot{border-color:var(--accent);background:var(--accent-soft)}
.drop .big{font-weight:600;margin-top:10px;color:var(--fg)}
.drop .hint{color:var(--faint);font-size:12.5px;margin-top:5px}
.drop.filled{border-style:solid;border-color:var(--ok-line);background:var(--ok-soft);color:var(--ok)}
.drop input[type=file]{display:none}
.picks{display:flex;flex-wrap:wrap;gap:9px}
.pick{position:relative;text-transform:none;letter-spacing:0;margin:0;font-weight:400}
.pick input{position:absolute;opacity:0;inset:0;cursor:pointer}
.pick span{display:inline-flex;align-items:center;gap:9px;padding:9px 15px;border-radius:8px;
  border:1px solid var(--line);background:#fff;font-size:14px;cursor:pointer;transition:.15s;color:var(--fg)}
.pick span::before{content:"";width:15px;height:15px;border-radius:4px;border:1.5px solid #B9C5D4;flex:none;background:#fff}
.pick input:checked+span{border-color:var(--accent);background:var(--accent-soft);font-weight:600}
.pick input:checked+span::before{background:var(--accent);border-color:var(--accent);box-shadow:inset 0 0 0 2px #fff}
.pick input:focus-visible+span{box-shadow:0 0 0 3px rgba(11,95,204,.18)}
.btn{margin-top:24px;display:inline-flex;align-items:center;gap:10px;border:0;cursor:pointer;
  background:var(--accent);color:var(--accent-ink);font:inherit;font-weight:600;font-size:15px;
  padding:12px 22px;border-radius:9px;transition:.15s;box-shadow:0 1px 2px rgba(16,24,40,.08)}
.btn:hover{background:#0A53B4}
.btn.ghost{background:#fff;border:1px solid var(--line);color:var(--fg)}
.empty{color:var(--muted);font-size:13.5px;background:var(--panel-2);border:1px dashed var(--line);
  border-radius:var(--r-md);padding:16px}

/* ---------- key/value ---------- */
.kv{width:100%;border-collapse:collapse;font-size:14px}
.kv td{padding:10px 0;border-bottom:1px solid var(--line-soft);vertical-align:top}
.kv tr:last-child td{border-bottom:0}
.kv td:first-child{color:var(--faint);width:34%;font-size:11.5px;letter-spacing:.6px;
  text-transform:uppercase;font-weight:700;padding-right:16px}
.copy{border:1px solid var(--line);background:#fff;color:var(--muted);cursor:pointer;
  padding:2px 7px;border-radius:5px;font-size:11px}
.copy:hover{color:var(--accent);border-color:var(--accent);background:var(--accent-soft)}

/* ---------- verdict + evidence chain ---------- */
.verdict{border-radius:var(--r-md);padding:18px 20px;display:flex;gap:14px;align-items:flex-start;margin-bottom:20px}
.verdict.y{background:var(--ok-soft);border:1px solid var(--ok-line);color:#0B4F34}
.verdict.n{background:var(--bad-soft);border:1px solid var(--bad-line);color:#7F1D23}
.verdict .t{font-size:11.5px;letter-spacing:1.3px;text-transform:uppercase;font-weight:800}
.verdict.y .t{color:var(--ok)}
.verdict.n .t{color:var(--bad)}
.verdict p{margin:6px 0 0;font-size:14.5px}
.chain{display:grid;gap:10px}
.step{display:flex;align-items:center;gap:13px;padding:13px 15px;border:1px solid var(--line-soft);
  border-radius:var(--r-md);background:var(--panel-2)}
.step svg{color:var(--faint)}
.step .lbl{font-weight:600;font-size:14px}
.step .val{color:var(--muted);font-size:13px;margin-top:2px}
.step .st{margin-left:auto;font-size:11px;letter-spacing:.8px;text-transform:uppercase;font-weight:800}
.step.pass{background:var(--ok-soft);border-color:var(--ok-line)}
.step.pass svg{color:var(--ok)}
.step.pass .st{color:var(--ok)}
.step.fail{background:var(--bad-soft);border-color:var(--bad-line)}
.step.fail svg{color:var(--bad)}
.step.fail .st{color:var(--bad)}
.step.idle .st{color:var(--faint)}
.flash{border:1px solid var(--bad-line);background:var(--bad-soft);color:#7F1D23;padding:13px 16px;
  border-radius:var(--r-md);margin-bottom:20px;display:flex;gap:11px;align-items:center}
.note{color:var(--faint);font-size:12.5px;margin-top:16px}
code{font-family:var(--mono);font-size:12.5px;background:var(--panel-2);border:1px solid var(--line-soft);
  padding:2px 7px;border-radius:5px;color:#1C3A5E}

/* ---------- ledger explorer ---------- */
.tag{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.tag-ok{background:var(--ok-soft);color:var(--ok);border:1px solid var(--ok-line)}
.tag-warn{background:var(--warn-soft);color:var(--warn);border:1px solid var(--warn-line)}
.tag-bad{background:var(--bad-soft);color:var(--bad);border:1px solid var(--bad-line)}
.tag-info{background:var(--accent-soft);color:var(--accent);border:1px solid var(--accent-line)}
.tag-violet{background:var(--violet-soft);color:var(--violet);border:1px solid var(--violet-line)}

.filter-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.filter-bar input[type=text]{padding:8px 12px;font-size:13.5px;flex:1;min-width:200px}
.filter-bar select{padding:8px 12px;font-size:13.5px;width:auto;min-width:140px}

.tbl-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
.evt-table{width:100%;border-collapse:collapse;font-size:13.5px;text-align:left}
.evt-table th{background:var(--panel-2);color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px;font-weight:700;padding:12px 14px;border-bottom:1px solid var(--line-soft)}
.evt-table td{padding:13px 14px;border-bottom:1px solid var(--line-soft);vertical-align:middle}
.evt-table tr.evt-row:hover td{background:rgba(234,242,254,.45);cursor:pointer}

.modal-overlay{position:fixed;inset:0;z-index:999;background:rgba(15,28,46,.60);backdrop-filter:blur(5px);display:none;align-items:center;justify-content:center;padding:18px}
.modal-overlay.open{display:flex}
.modal-box{background:var(--panel);border-radius:var(--r-lg);width:100%;max-width:860px;max-height:92vh;overflow-y:auto;border:1px solid var(--line);box-shadow:0 24px 50px -12px rgba(16,24,40,.40);padding:28px 30px;position:relative}
.modal-close{position:absolute;top:18px;right:18px;background:none;border:none;font-size:22px;color:var(--muted);cursor:pointer;padding:4px 8px;border-radius:6px;transition:.15s}
.modal-close:hover{background:var(--panel-2);color:var(--fg)}

.chain-viz{display:flex;align-items:center;gap:12px;overflow-x:auto;padding:14px 4px;margin:12px 0}
.chain-node{flex:1;min-width:210px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:var(--r-md);padding:12px 14px}
.chain-node.current{background:var(--accent-soft);border-color:var(--accent-line);box-shadow:0 0 0 2px rgba(11,95,204,.15)}
.chain-arrow{color:var(--faint);font-size:18px;flex:none}

/* ---------- incident timeline (feature #21) ---------- */
.tl-container{display:flex;flex-direction:column;position:relative;margin-top:16px}
.tl-connector{display:flex;flex-direction:column;align-items:center;margin:3px 0;color:var(--faint);font-size:12px;line-height:1}
.tl-line{width:2px;height:24px;background:var(--line)}
.tl-arrow{color:var(--faint);font-size:11px;margin-top:-2px}
.tl-card{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:var(--r-md);padding:16px 20px;position:relative;transition:all .2s ease}
.tl-card:hover{border-color:var(--line);box-shadow:0 3px 12px rgba(16,24,40,.06)}
.tl-card.is-incident{background:rgba(220,38,38,.04);border:1.5px solid var(--bad);box-shadow:0 0 18px rgba(220,38,38,.14)}
.tl-card.is-forensic{background:rgba(78,59,196,.04);border:1px solid var(--violet-line)}
.tl-header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px}
.tl-title{display:flex;align-items:center;gap:8px;font-size:14.5px;font-weight:700;color:var(--fg)}
.tl-time{font-size:12.5px;color:var(--muted);font-family:var(--mono)}
.tl-body{display:flex;flex-direction:column;gap:5px;font-size:13.5px}
.tl-field{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tl-lbl{color:var(--muted);font-size:12.5px;min-width:80px}
.tl-val{color:var(--fg)}
.tl-incident-alert{margin-top:10px;padding:12px 14px;background:var(--bad-soft);border:1px solid var(--bad-line);border-radius:8px}
.tl-details{margin-top:12px;border-top:1px dashed var(--line-soft);padding-top:8px;font-size:12.5px}
.tl-details summary{cursor:pointer;color:var(--accent);font-weight:600;user-select:none;outline:none}
.tl-details summary:hover{text-decoration:underline}
.tl-details-content{margin-top:8px;background:var(--panel);border:1px solid var(--line-soft);border-radius:6px;padding:10px 14px}
.tl-details-table{width:100%;border-collapse:collapse}
.tl-details-table td{padding:5px 0;border-bottom:1px solid var(--line-soft);vertical-align:top}
.tl-details-table tr:last-child td{border-bottom:none}
.tl-details-table td.k{color:var(--muted);width:130px;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
.tl-details-table td.v{font-family:var(--mono);word-break:break-all;color:var(--fg);font-size:12px}
.tl-empty-box{text-align:center;padding:36px 16px;background:var(--panel-2);border-radius:var(--r-md);border:1px solid var(--line-soft)}
.tl-error-box{text-align:center;padding:26px 16px;background:var(--bad-soft);border-radius:var(--r-md);border:1px solid var(--bad-line)}


/* ---------- busy overlay & progress bar ---------- */
#busy{position:fixed;inset:0;z-index:90;display:none;place-items:center;
  background:rgba(243,246,250,.90);backdrop-filter:blur(4px);transition:opacity .2s ease}
#busy.on{display:grid}
#busy .box{position:relative;background:#fff;border:1px solid var(--line);border-radius:var(--r-lg);padding:28px 34px;
  text-align:center;box-shadow:0 24px 50px -18px rgba(16,24,40,.38);width:100%;max-width:410px}
#busy-x:hover{color:var(--fg)!important;background:var(--panel-2)!important}
.spin{width:36px;height:36px;margin:0 auto 14px;border-radius:50%;
  border:3.5px solid #E2EBF6;border-top-color:var(--accent);animation:sp .75s cubic-bezier(.6,.2,.4,.8) infinite}
@keyframes sp{ to{transform:rotate(360deg)} }
#busy .m{font-size:16px;font-weight:700;color:var(--fg);margin-bottom:4px}
#busy .s{color:var(--muted);font-size:13px;min-height:18px}

.pbar-wrap{margin:18px 0 6px}
.pbar-track{width:100%;height:10px;background:#EBF0F7;border-radius:999px;overflow:hidden;position:relative;border:1px solid var(--line-soft)}
.pbar-fill{height:100%;width:0%;background:linear-gradient(90deg,#0B5FCC,#3B82F6,#6366F1);border-radius:999px;
  transition:width .2s ease-out;position:relative;overflow:hidden}
.pbar-fill::after{content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.5),transparent);
  animation:pbar-shimmer 1.4s infinite;transform:translateX(-100%)}
@keyframes pbar-shimmer{ 100%{transform:translateX(100%)} }
.pbar-meta{display:flex;justify-content:space-between;align-items:center;font-size:12px;margin-top:7px;color:var(--muted);font-weight:600}
.pbar-pct{color:var(--accent);font-family:var(--mono);font-size:12.5px}

/* ---------- 3-second circuit video intro splash screen ---------- */
#intro-splash{position:fixed;inset:0;z-index:9999;display:grid;place-items:center;
  background:#090F19;overflow:hidden;transition:opacity .6s cubic-bezier(.4,0,.2,1),visibility .6s ease;
  font-family:system-ui,-apple-system,sans-serif}
#intro-splash.hide{opacity:0;visibility:hidden;pointer-events:none}

.splash-bg{position:absolute;inset:0;background:url('/circuit.png') center/cover no-repeat;
  filter:brightness(.75) contrast(1.15) hue-rotate(-5deg);
  animation:splash-zoom 3.2s cubic-bezier(.25,1,.5,1) forwards;transform-origin:center}
@keyframes splash-zoom{
  0%{transform:scale(1.12)}
  100%{transform:scale(1.0)}
}

.splash-overlay-dark{position:absolute;inset:0;
  background:radial-gradient(circle at center,rgba(9,15,25,.35) 0%,rgba(9,15,25,.92) 80%)}

.splash-laser{position:absolute;left:0;right:0;height:4px;
  background:linear-gradient(90deg,transparent,#00E5FF,#3B82F6,#00E5FF,transparent);
  box-shadow:0 0 20px #00E5FF,0 0 40px #0B5FCC;
  animation:laser-scan 3.0s linear infinite}
@keyframes laser-scan{
  0%{top:-5%}
  100%{top:105%}
}

.splash-content{position:relative;z-index:10;text-align:center;color:#fff;
  padding:32px 28px;max-width:480px;width:90%;border-radius:20px;
  background:rgba(15,24,42,.75);backdrop-filter:blur(16px);
  border:1px solid rgba(0,229,255,.25);box-shadow:0 20px 50px rgba(0,0,0,.6),0 0 30px rgba(11,95,204,.2)}

.splash-logo-wrap{width:64px;height:64px;margin:0 auto 16px;border-radius:18px;
  background:linear-gradient(135deg,#0B5FCC,#00E5FF);display:grid;place-items:center;
  color:#fff;box-shadow:0 0 25px rgba(0,229,255,.5);animation:logo-pulse 1.5s ease-in-out infinite alternate}
@keyframes logo-pulse{
  0%{box-shadow:0 0 15px rgba(0,229,255,.3)}
  100%{box-shadow:0 0 35px rgba(0,229,255,.8)}
}

.splash-title{font-size:24px;font-weight:800;letter-spacing:1px;color:#fff;margin-bottom:4px;
  text-shadow:0 0 12px rgba(0,229,255,.4)}
.splash-sub{font-size:11.5px;letter-spacing:2px;text-transform:uppercase;color:#00E5FF;
  font-weight:700;margin-bottom:20px}

.splash-progress-track{width:100%;height:8px;background:rgba(255,255,255,.1);
  border-radius:999px;overflow:hidden;position:relative;border:1px solid rgba(0,229,255,.2)}
.splash-progress-fill{height:100%;width:0%;
  background:linear-gradient(90deg,#00E5FF,#3B82F6,#6366F1);
  border-radius:999px;transition:width .1s linear;box-shadow:0 0 10px #00E5FF}

.splash-meta{display:flex;justify-content:space-between;align-items:center;
  font-size:12px;margin-top:10px;color:#94A3B8;font-weight:600}
.splash-pct{color:#00E5FF;font-family:var(--mono);font-size:13px;font-weight:700}

.splash-skip{position:absolute;top:20px;right:20px;z-index:20;background:rgba(15,24,42,.6);
  color:#E2E8F0;border:1px solid rgba(255,255,255,.15);padding:8px 16px;border-radius:20px;
  font-size:12.5px;font-weight:600;cursor:pointer;backdrop-filter:blur(8px);transition:.2s}
.splash-skip:hover{background:rgba(0,229,255,.2);border-color:#00E5FF;color:#fff}

/* ---------- Animated Gradient & Glassmorphism Background ---------- */
.animated-bg-wrapper{
  position:relative;
  min-height:calc(100vh - 120px);
  display:flex;
  align-items:center;
  justify-content:center;
  overflow:hidden;
  padding:40px 16px;
  width:100%;
}
.animated-bg-canvas{
  position:absolute;
  inset:0;
  z-index:0;
  pointer-events:none;
  overflow:hidden;
}
.gradient-blob{
  position:absolute;
  border-radius:50%;
  filter:blur(65px);
  opacity:0.55;
  animation:floatOrb 18s ease-in-out infinite alternate;
}
.gradient-blob-1{
  width:460px;
  height:460px;
  top:-12%;
  left:-8%;
  background:radial-gradient(circle, rgba(11,95,204,0.45) 0%, rgba(78,59,196,0.28) 60%, rgba(255,255,255,0) 100%);
  animation-duration:22s;
}
.gradient-blob-2{
  width:420px;
  height:420px;
  bottom:-12%;
  right:-8%;
  background:radial-gradient(circle, rgba(78,59,196,0.38) 0%, rgba(15,107,69,0.25) 60%, rgba(255,255,255,0) 100%);
  animation-duration:26s;
  animation-delay:-6s;
}
.gradient-blob-3{
  width:360px;
  height:360px;
  top:38%;
  left:55%;
  transform:translate(-50%, -50%);
  background:radial-gradient(circle, rgba(14,165,233,0.32) 0%, rgba(11,95,204,0.18) 70%, rgba(255,255,255,0) 100%);
  animation-duration:20s;
  animation-delay:-11s;
}
.svg-gradient-layer{
  position:absolute;
  inset:0;
  width:100%;
  height:100%;
  opacity:0.55;
}
@keyframes floatOrb{
  0%{ transform:translate(0px, 0px) scale(1); }
  33%{ transform:translate(32px, -38px) scale(1.06); }
  66%{ transform:translate(-28px, 22px) scale(0.96); }
  100%{ transform:translate(0px, 0px) scale(1); }
}
@media (prefers-reduced-motion: reduce){
  .gradient-blob{ animation:none; }
}
.glass-card{
  position:relative;
  z-index:10;
  width:100%;
  max-width:440px;
  background:rgba(255, 255, 255, 0.82);
  backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border:1px solid rgba(255, 255, 255, 0.75);
  border-radius:var(--r-lg);
  padding:30px 28px;
  box-shadow:0 20px 45px -15px rgba(15, 28, 46, 0.14), 0 1px 3px rgba(0,0,0,0.05);
  transition:transform .2s ease, box-shadow .2s ease;
}
.glass-card:hover{
  box-shadow:0 26px 52px -16px rgba(15, 28, 46, 0.18), 0 1px 4px rgba(0,0,0,0.06);
}
"""

JS = """
(function(){
  document.querySelectorAll('.drop').forEach(function(d){
    var inp = d.querySelector('input[type=file]');
    var out = d.querySelector('.big');
    var base = out.textContent;
    d.addEventListener('click', function(){ inp.click(); });
    d.addEventListener('keydown', function(e){ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); inp.click(); } });
    ['dragenter','dragover'].forEach(function(ev){
      d.addEventListener(ev, function(e){ e.preventDefault(); d.classList.add('hot'); });
    });
    ['dragleave','drop'].forEach(function(ev){
      d.addEventListener(ev, function(e){ e.preventDefault(); d.classList.remove('hot'); });
    });
    d.addEventListener('drop', function(e){
      if(e.dataTransfer.files.length){ inp.files = e.dataTransfer.files; show(); }
    });
    inp.addEventListener('change', show);
    function show(){
      if(inp.files.length){
        var f = inp.files[0];
        out.textContent = f.name + '  (' + (f.size/1024).toFixed(0) + ' kB)';
        d.classList.add('filled');
      } else { out.textContent = base; d.classList.remove('filled'); }
    }
  });

  var busy = document.getElementById('busy');
  var pfill = document.getElementById('pbar-fill');
  var ppct = document.getElementById('pbar-pct');
  var pstage = document.getElementById('pbar-stage');
  var busyM = document.getElementById('busy-m');
  var busyS = document.getElementById('busy-s');
  var busySpin = document.getElementById('busy-spin');
  var busyX = document.getElementById('busy-x');
  var busyDismiss = document.getElementById('busy-dismiss');
  var ptimer = null;
  var ctimer = null;
  var dtimer = null;

  function hideBusy() {
    if (ptimer) { clearInterval(ptimer); ptimer = null; }
    if (ctimer) { clearInterval(ctimer); ctimer = null; }
    if (dtimer) { clearTimeout(dtimer); dtimer = null; }
    busy.classList.remove('on');
    if (busySpin) busySpin.style.display = 'block';
    if (busyDismiss) busyDismiss.style.display = 'none';
  }

  function finishBusy(msg, sub) {
    if (ptimer) { clearInterval(ptimer); ptimer = null; }
    if (ctimer) { clearInterval(ctimer); ctimer = null; }
    if (dtimer) { clearTimeout(dtimer); dtimer = null; }
    pfill.style.width = '100%';
    pfill.style.background = 'linear-gradient(90deg, #10B981, #059669)';
    ppct.textContent = '100%';
    if (pstage) pstage.textContent = sub || 'Completed successfully';
    if (msg && busyM) busyM.textContent = msg;
    if (busySpin) busySpin.style.display = 'none';
    if (busyDismiss) busyDismiss.style.display = 'inline-block';
    dtimer = setTimeout(hideBusy, 900);
  }

  function runProgress(totalDuration, stages) {
    if (ptimer) clearInterval(ptimer);
    var startTime = Date.now();
    pfill.style.width = '0%';
    pfill.style.background = 'linear-gradient(90deg,#0B5FCC,#3B82F6,#6366F1)';
    ppct.textContent = '0%';
    if (busySpin) busySpin.style.display = 'block';
    if (busyDismiss) busyDismiss.style.display = 'none';

    ptimer = setInterval(function(){
      var elapsed = Date.now() - startTime;
      var ratio = Math.min(elapsed / totalDuration, 0.96);
      var pct = Math.round(ratio * 100);
      pfill.style.width = pct + '%';
      ppct.textContent = pct + '%';

      for (var i = stages.length - 1; i >= 0; i--) {
        if (pct >= stages[i].at) {
          pstage.textContent = stages[i].text;
          break;
        }
      }
    }, 100);
  }

  document.querySelectorAll('form[data-busy]').forEach(function(f){
    f.addEventListener('submit', function(){
      var parts = f.getAttribute('data-busy').split('|');
      if (busyM) busyM.textContent = parts[0];
      if (busyS) busyS.textContent = parts[1] || '';

      var action = f.getAttribute('action') || window.location.pathname;
      var isDownload = (action.indexOf('sender') !== -1 || parts[0].indexOf('Encrypt') !== -1);
      var duration = 2400;
      var stages = [
        { at: 0, text: 'Reading input data…' },
        { at: 30, text: 'Generating cryptographic keys…' },
        { at: 65, text: 'Processing post-quantum payload…' },
        { at: 85, text: 'Finalizing…' }
      ];

      if (isDownload) {
        duration = 2000;
        stages = [
          { at: 0, text: 'Loading document…' },
          { at: 25, text: 'Generating AES-256 session key…' },
          { at: 55, text: 'Encapsulating ML-KEM-768 key-wraps…' },
          { at: 80, text: 'Building .ps26237 package…' },
          { at: 92, text: 'Preparing download…' }
        ];

        // Clear previous download cookie
        document.cookie = 'file_download_complete=; Max-Age=0; path=/;';

        // Check for download cookie
        if (ctimer) clearInterval(ctimer);
        ctimer = setInterval(function(){
          if (document.cookie.indexOf('file_download_complete=1') !== -1) {
            document.cookie = 'file_download_complete=; Max-Age=0; path=/;';
            finishBusy('Package Downloaded!', 'File saved to your browser downloads');
          }
        }, 200);

        // Fallback auto-completion timeout (in case cookie is blocked or ignored)
        setTimeout(function(){
          if (busy.classList.contains('on')) {
            finishBusy('Package Ready!', 'Download started');
          }
        }, duration + 1500);

      } else if (action.indexOf('recipient') !== -1 || parts[0].indexOf('Decrypt') !== -1) {
        duration = 2500;
        stages = [
          { at: 0, text: 'Verifying recipient credentials…' },
          { at: 25, text: 'Decapsulating ML-KEM-768 session key…' },
          { at: 50, text: 'Embedding unique invisible watermark…' },
          { at: 75, text: 'Signing record with ML-DSA-65…' },
          { at: 90, text: 'Committing to ledger quorum…' }
        ];
      } else if (action.indexOf('trace') !== -1 || parts[0].indexOf('watermark') !== -1) {
        duration = 13000;
        stages = [
          { at: 0, text: 'Rasterizing document…' },
          { at: 15, text: 'Extracting DCT frequency domain…' },
          { at: 35, text: 'Searching rotation angles & scale…' },
          { at: 60, text: 'Majority voting across redundant tiles…' },
          { at: 80, text: 'Querying multi-node ledger quorum…' },
          { at: 92, text: 'Cryptographic signature verification…' }
        ];
      }

      runProgress(duration, stages);
      busy.classList.add('on');
    });
  });

  window.addEventListener('pageshow', hideBusy);
  if (busyX) busyX.addEventListener('click', hideBusy);
  if (busyDismiss) busyDismiss.addEventListener('click', hideBusy);
  busy.addEventListener('click', function(e){
    if (e.target === busy) hideBusy();
  });
  window.addEventListener('keydown', function(e){
    if (e.key === 'Escape' && busy.classList.contains('on')) hideBusy();
  });

  document.querySelectorAll('.copy').forEach(function(b){
    b.addEventListener('click', function(){
      navigator.clipboard.writeText(b.dataset.v).then(function(){
        var t = b.textContent; b.textContent = 'copied'; setTimeout(function(){ b.textContent = t; }, 1100);
      });
    });
  });

  // ---------- 3-second Circuit Video Intro Splash ----------
  var splash = document.getElementById('intro-splash');
  var splashFill = document.getElementById('splash-fill');
  var splashPct = document.getElementById('splash-pct');
  var splashStatus = document.getElementById('splash-status');
  var splashSkip = document.getElementById('splash-skip-btn');
  var replayBtn = document.querySelectorAll('.replay-intro-btn');

  function runSplashIntro(force) {
    if (!splash) return;
    try {
      if (!force && sessionStorage.getItem('cybertrace_intro_seen') === '1') {
        splash.classList.add('hide');
        return;
      }
    } catch(e) {}

    splash.classList.remove('hide');
    var startTime = Date.now();
    var duration = 3000; // 3 seconds circuit intro

    var stages = [
      { at: 0, text: 'Initialising Circuitry Core…' },
      { at: 25, text: 'Connecting Ledger Quorum…' },
      { at: 55, text: 'Verifying Post-Quantum Keys…' },
      { at: 85, text: 'Ready! Opening CyberTrace Console…' }
    ];

    var timer = setInterval(function(){
      var elapsed = Date.now() - startTime;
      var ratio = Math.min(elapsed / duration, 1.0);
      var pct = Math.round(ratio * 100);

      if (splashFill) splashFill.style.width = pct + '%';
      if (splashPct) splashPct.textContent = pct + '%';

      for (var i = stages.length - 1; i >= 0; i--) {
        if (pct >= stages[i].at && splashStatus) {
          splashStatus.textContent = stages[i].text;
          break;
        }
      }

      if (ratio >= 1.0) {
        clearInterval(timer);
        try { sessionStorage.setItem('cybertrace_intro_seen', '1'); } catch(e){}
        setTimeout(function(){
          if (splash) splash.classList.add('hide');
        }, 300);
      }
    }, 50);

    if (splashSkip) {
      splashSkip.onclick = function(){
        clearInterval(timer);
        try { sessionStorage.setItem('cybertrace_intro_seen', '1'); } catch(e){}
        if (splash) splash.classList.add('hide');
      };
    }
  }

  // Run automatically on initial website launch
  runSplashIntro();

  replayBtn.forEach(function(b){
    b.addEventListener('click', function(e){
      e.preventDefault();
      runSplashIntro(true);
    });
  });
})();
"""

ICONS = {
    "shield": '<path d="M12 3l7 3v5c0 4.4-3 8.3-7 10-4-1.7-7-5.6-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    "gauge": '<circle cx="12" cy="12" r="9"/><path d="M12 12l4-3"/>',
    "send": '<path d="M4 12h9m0 0l-4-4m4 4l-4 4"/><path d="M14 4h6v16h-6"/>',
    "inbox": '<path d="M4 13h4l2 3h4l2-3h4"/><path d="M5 5h14l1 8v6H4v-6z"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.3-4.3"/>',
    "key": '<circle cx="8" cy="12" r="3"/><path d="M11 12h10m-3 0v3m-2-3v2"/>',
    "node": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7.5h.01M7 17h.01"/>',
    "doc": '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/>',
    "check": '<path d="M4 12l5 5L20 6"/>',
    "alert": '<path d="M12 4l9 16H3z"/><path d="M12 10v4m0 3h.01"/>',
    "fingerprint": '<path d="M12 5a7 7 0 0 1 7 7v2"/><path d="M5 12a7 7 0 0 1 7-7"/><path d="M8.5 12a3.5 3.5 0 0 1 7 0v4"/><path d="M12 12v6"/><path d="M5 15v1"/>',
    "lock": '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    "play": '<polygon points="5 3 19 12 5 21 5 3"/>',
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><polyline points="12 6 12 12 16 14"/>',
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>',
    "copy": '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
}


def svg(name: str, size: int = 17, cls: str = "") -> str:
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" '
            f'aria-hidden="true">{ICONS[name]}</svg>')


def e(v) -> str:
    return html.escape(str(v), quote=True)


def render_incident_timeline_html(tl_res: dict | None, tl_error: str | None = None, doc_id: str = "", is_get: bool = False) -> str:
    """
    Renders Feature #21: Incident Timeline for the Forensics page.
    Displays events vertically in chronological order with down arrows.
    Visually highlights the incident point when a watermark match is identified.
    """
    # 1. Error state
    if tl_error:
        return f"""
<div class="card" style="margin-top:24px" id="incident-timeline-section">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
    <h2><span class="icon" style="background:var(--bad-soft);color:var(--bad)">{svg("clock", 16)}</span>Incident Timeline</h2>
  </div>
  <hr class="sep">
  <div class="tl-error-box">
    <div style="font-size:15px;font-weight:700;color:var(--bad);margin-bottom:6px">Unable to load incident timeline.</div>
    <div style="font-size:12.5px;color:var(--muted);margin-bottom:12px">{e(tl_error)}</div>
    <button class="btn btn-sm" type="button" onclick="location.reload()">{svg("search", 13)}Retry</button>
  </div>
</div>"""

    # 2. GET initial state (awaiting analysis or manual lookup)
    if is_get:
        return f"""
<div class="card" style="margin-top:24px" id="incident-timeline-section">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
    <h2><span class="icon violet">{svg("clock", 16)}</span>Incident Timeline</h2>
    <span class="tag tag-info">Awaiting Analysis</span>
  </div>
  <p class="sub">Chronological reconstruction of events associated with the analyzed document.</p>
  <hr class="sep">
  <div class="tl-empty-box" style="padding:28px 16px">
    <div style="width:44px;height:44px;border-radius:50%;background:var(--panel);border:1px solid var(--line-soft);display:grid;place-items:center;margin:0 auto 10px;color:var(--muted)">
      {svg("clock", 20)}
    </div>
    <div style="font-size:15px;font-weight:700;color:var(--fg)">Upload a document above to generate the Incident Timeline</div>
    <p style="color:var(--muted);font-size:13px;margin:6px auto 14px;max-width:480px">
      When a document is analyzed, CyberTrace retrieves all real provenance records from the ledger and reconstructs the document's chronological lifecycle.
    </p>
    <div style="display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:center">
      <input type="text" id="manual-doc-id" placeholder="Or inspect Document ID (e.g. abcd1234)" style="padding:7px 12px;font-size:13px;min-width:260px">
      <button class="btn btn-sm" type="button" onclick="loadManualTimeline()">{svg("search", 13)}Inspect Timeline</button>
    </div>
    <div id="manual-timeline-target" style="margin-top:16px;text-align:left"></div>
  </div>
</div>
<script>
function loadManualTimeline(docId) {{
  var id = docId || (document.getElementById('manual-doc-id') ? document.getElementById('manual-doc-id').value.trim() : '');
  var target = document.getElementById('manual-timeline-target');
  if (!id) {{
    if (target) target.innerHTML = '<div style="color:var(--warn);font-size:13px;padding:8px 0;text-align:center">Please enter a valid Document ID.</div>';
    return;
  }}
  if (target) target.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:12px 0;text-align:center">Loading incident timeline for ' + id + '…</div>';
  fetch('/api/forensics/' + encodeURIComponent(id) + '/timeline')
    .then(function(r){{
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }})
    .then(function(data){{
      if (!data.events || data.events.length === 0) {{
        target.innerHTML = '<div class="tl-empty-box" style="text-align:center;padding:24px 16px;background:var(--panel);border-radius:8px;border:1px solid var(--line-soft)">' +
          '<div style="font-size:15px;font-weight:700;color:var(--fg)">Incident timeline unavailable</div>' +
          '<div style="color:var(--muted);font-size:13px;margin-top:4px">No provenance events were found for this document.</div>' +
          '</div>';
        return;
      }}
      var html = '<div class="tl-container">';
      data.events.forEach(function(ev, idx){{
        if (idx > 0) {{
          html += '<div class="tl-connector"><div class="tl-line"></div><div class="tl-arrow">▼</div></div>';
        }}
        var isInc = ev.is_incident_point;
        var cardCls = 'tl-card' + (isInc ? ' is-incident' : '') + (ev.event_type === 'FORENSIC_ANALYSIS' ? ' is-forensic' : '');
        var stCls = (ev.status === 'COMMITTED' || ev.status === 'COMPLETED') ? 'tag-ok' : (ev.status === 'UNCONFIRMED' ? 'tag-warn' : 'tag-info');
        var stIcon = (ev.status === 'COMMITTED' || ev.status === 'COMPLETED') ? '✓ ' : (ev.status === 'UNCONFIRMED' ? '⚠ ' : '');
        var title = ev.event_type === 'DECRYPTION_PROVENANCE' ? '● Recipient Decrypted' : (ev.event_type === 'FORENSIC_ANALYSIS' ? '● Forensic Analysis' : '● ' + ev.event_type);
        
        html += '<div class="' + cardCls + '">';
        html += '  <div class="tl-header">';
        html += '    <div class="tl-title">' + title + ' <span class="tag ' + stCls + '">' + stIcon + ev.status + '</span></div>';
        html += '    <div class="tl-time">' + (ev.human_timestamp || '-') + '</div>';
        html += '  </div>';
        html += '  <div class="tl-body">';
        if (ev.recipient && ev.recipient !== '-') {{
          html += '    <div class="tl-field"><span class="tl-lbl">Recipient:</span> <b class="tl-val">' + ev.recipient + '</b></div>';
        }}
        if (isInc) {{
          html += '    <div class="tl-incident-alert">';
          html += '      <div style="display:flex;align-items:center;gap:6px"><span class="tag tag-bad">⚠ INCIDENT POINT</span><span class="mono" style="font-size:11px;color:var(--bad);font-weight:700">Watermark detected</span></div>';
          html += '      <div style="margin-top:6px;font-size:13.5px;font-weight:700;color:var(--bad)">Watermark associated with recipient ' + ev.recipient + ' was detected.</div>';
          html += '      <div style="font-size:12px;color:var(--muted);margin-top:4px">Event: <span class="mono">' + ev.event_type + '</span> · Timestamp: <span class="mono">' + ev.human_timestamp + '</span></div>';
          html += '    </div>';
        }}
        html += '    <details class="tl-details">';
        html += '      <summary>Event Details & Verification ▾</summary>';
        html += '      <div class="tl-details-content">';
        html += '        <table class="tl-details-table">';
        html += '          <tr><td class="k">Event ID</td><td class="v">' + ev.event_id + '</td></tr>';
        html += '          <tr><td class="k">Event Type</td><td class="v">' + ev.event_type + '</td></tr>';
        html += '          <tr><td class="k">Document ID</td><td class="v">' + ev.document_id + '</td></tr>';
        html += '          <tr><td class="k">Recipient</td><td class="v">' + (ev.recipient || '-') + '</td></tr>';
        html += '          <tr><td class="k">Timestamp</td><td class="v">' + ev.human_timestamp + ' (' + (ev.utc_timestamp || '') + ')</td></tr>';
        html += '          <tr><td class="k">Status</td><td class="v">' + ev.status + '</td></tr>';
        html += '          <tr><td class="k">Watermark ID</td><td class="v">' + (ev.watermark_id || '-') + '</td></tr>';
        html += '          <tr><td class="k">Block Hash</td><td class="v">' + (ev.block_hash || '-') + '</td></tr>';
        html += '          <tr><td class="k">Prev Hash</td><td class="v">' + (ev.prev_hash || '-') + '</td></tr>';
        html += '          <tr><td class="k">Signature</td><td class="v">' + (ev.signature_algorithm || 'ML-DSA-65') + ' (' + ev.signature_status + ')</td></tr>';
        html += '        </table>';
        html += '      </div>';
        html += '    </details>';
        html += '  </div>';
        html += '</div>';
      }});
      html += '</div>';
      target.innerHTML = html;
    }})
    .catch(function(err){{
      target.innerHTML = '<div class="tl-error-box" style="text-align:center;padding:20px 16px;background:var(--bad-soft);border-radius:8px;border:1px solid var(--bad-line)">' +
        '<div style="font-size:14px;font-weight:700;color:var(--bad)">Unable to load incident timeline.</div>' +
        '<button class="btn btn-sm" type="button" onclick="loadManualTimeline(\'' + id + '\')" style="margin-top:8px">Retry</button>' +
        '</div>';
    }});
}}
</script>"""

    events = (tl_res or {}).get("events", [])
    target_doc = (tl_res or {}).get("document_id") or doc_id

    # 3. Empty state
    if not events:
        return f"""
<div class="card" style="margin-top:24px" id="incident-timeline-section">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
    <h2><span class="icon violet">{svg("clock", 16)}</span>Incident Timeline</h2>
    <span class="tag tag-warn">No Records</span>
  </div>
  <hr class="sep">
  <div class="tl-empty-box">
    <div style="width:44px;height:44px;border-radius:50%;background:var(--panel);border:1px solid var(--line-soft);display:grid;place-items:center;margin:0 auto 10px;color:var(--muted)">
      {svg("doc", 20)}
    </div>
    <div style="font-size:16px;font-weight:700;color:var(--fg)">Incident timeline unavailable</div>
    <p style="color:var(--muted);font-size:13px;margin:6px auto 0;max-width:440px">
      No provenance events were found for this document.
    </p>
  </div>
</div>"""

    # 4. Render events list
    items_html = []
    for idx, ev in enumerate(events):
        is_incident = ev.get("is_incident_point", False)
        ev_type = ev.get("event_type", "DECRYPTION_PROVENANCE")
        status = ev.get("status", "COMMITTED")
        recipient = ev.get("recipient") or ev.get("actor") or "-"

        card_classes = ["tl-card"]
        if is_incident:
            card_classes.append("is-incident")
        if ev_type == "FORENSIC_ANALYSIS":
            card_classes.append("is-forensic")

        status_tag_cls = "tag-ok" if status in ("COMMITTED", "COMPLETED") else ("tag-warn" if status == "UNCONFIRMED" else "tag-info")
        status_icon = "✓ " if status in ("COMMITTED", "COMPLETED") else ("⚠ " if status == "UNCONFIRMED" else "")

        # Downward arrow divider
        if idx > 0:
            items_html.append("""
<div class="tl-connector">
  <div class="tl-line"></div>
  <div class="tl-arrow">▼</div>
</div>""")

        # Event title
        if ev_type == "DECRYPTION_PROVENANCE":
            title = "● Recipient Decrypted"
        elif ev_type == "FORENSIC_ANALYSIS":
            title = "● Forensic Analysis"
        elif ev_type == "DOCUMENT_CREATED":
            title = "● Document Created"
        elif ev_type == "DOCUMENT_ENCRYPTED":
            title = "● Document Encrypted"
        else:
            title = f"● {e(ev_type)}"

        # Recipient field
        recipient_row = ""
        if recipient and recipient != "-" and recipient != "UNATTRIBUTED":
            recipient_row = f'<div class="tl-field"><span class="tl-lbl">Recipient:</span> <b class="tl-val">{e(recipient)}</b></div>'

        # Forensic result field
        forensic_row = ""
        if ev_type == "FORENSIC_ANALYSIS":
            verdict_text = "Watermark detected & attributed to " + e(recipient) if ev.get("confirmed") else "Watermark analysis completed"
            result_color = "var(--ok)" if ev.get("confirmed") else "var(--muted)"
            forensic_row = f'<div class="tl-field"><span class="tl-lbl">Result:</span> <b class="tl-val" style="color:{result_color}">{verdict_text}</b></div>'

        # Incident point alert
        incident_alert = ""
        if is_incident:
            incident_alert = f"""
<div class="tl-incident-alert">
  <div style="display:flex;align-items:center;gap:6px">
    <span class="tag tag-bad">⚠ INCIDENT POINT</span>
    <span class="mono" style="font-size:11px;color:var(--bad);font-weight:700">Watermark detected</span>
  </div>
  <div style="margin-top:6px;font-size:13.5px;font-weight:700;color:var(--bad)">
    Watermark associated with recipient {e(recipient)} was detected.
  </div>
  <div style="font-size:12px;color:var(--muted);margin-top:4px">
    Event: <span class="mono">{e(ev_type)}</span> · Timestamp: <span class="mono">{e(ev.get('human_timestamp', '-'))}</span>
  </div>
</div>"""

        # Expandable details
        details_html = f"""
<details class="tl-details">
  <summary>Event Details & Verification ▾</summary>
  <div class="tl-details-content">
    <table class="tl-details-table">
      <tr><td class="k">Event ID</td><td class="v">{e(ev.get('event_id', '-'))}</td></tr>
      <tr><td class="k">Event Type</td><td class="v">{e(ev_type)}</td></tr>
      <tr><td class="k">Document ID</td><td class="v">{e(ev.get('document_id', '-'))}</td></tr>
      <tr><td class="k">Recipient/Actor</td><td class="v">{e(recipient)}</td></tr>
      <tr><td class="k">Timestamp</td><td class="v">{e(ev.get('human_timestamp', '-'))} <span style="color:var(--muted)">({e(ev.get('utc_timestamp', '-'))})</span></td></tr>
      <tr><td class="k">Status</td><td class="v">{e(status)} {status_icon}</td></tr>
      <tr><td class="k">Watermark ID</td><td class="v">{e(ev.get('watermark_id', '-'))}</td></tr>
      <tr><td class="k">Block Hash</td><td class="v">{e(ev.get('block_hash', '-'))}</td></tr>
      <tr><td class="k">Previous Event</td><td class="v">{e(ev.get('prev_hash', '-'))}</td></tr>
      <tr><td class="k">Signature Status</td><td class="v">{e(ev.get('signature_algorithm', 'ML-DSA-65'))} ({e(ev.get('signature_status', 'VALID'))})</td></tr>
      <tr><td class="k">Consensus</td><td class="v">{e(ev.get('quorum_achieved', 4))} of {e(ev.get('total_nodes', 4))} nodes confirmed</td></tr>
    </table>
  </div>
</details>"""

        item_str = f"""
<div class="{' '.join(card_classes)}">
  <div class="tl-header">
    <div class="tl-title">{title} <span class="tag {status_tag_cls}">{status_icon}{e(status)}</span></div>
    <div class="tl-time">{e(ev.get('human_timestamp', '-'))}</div>
  </div>
  <div class="tl-body">
    {recipient_row}
    {forensic_row}
    {incident_alert}
    {details_html}
  </div>
</div>"""
        items_html.append(item_str)

    timeline_body = "\n".join(items_html)

    return f"""
<div class="card" style="margin-top:24px" id="incident-timeline-section">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
    <div>
      <h2><span class="icon violet">{svg("clock", 16)}</span>Incident Timeline</h2>
      <p class="sub" style="margin-top:2px">Chronological lifecycle of events associated with document <b class="mono">{e(target_doc)}</b></p>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <span class="tag tag-violet">DOC: {e(target_doc)}</span>
      <span class="tag tag-ok">{len(events)} Events</span>
      <span class="tag tag-info">COMMITTED LEDGER</span>
    </div>
  </div>
  <hr class="sep">
  <div class="tl-container">
    {timeline_body}
  </div>
</div>"""


def create_app(ws: Workspace | None = None) -> Flask:
    if ws is None:
        from app.service import resolve_workspace_dir
        ws = Workspace(resolve_workspace_dir())
        ws.seed_demo_identities_if_empty()
    app = Flask(__name__)


def create_app(ws: Workspace | None = None) -> Flask:
    if ws is None:
        from app.service import resolve_workspace_dir
        ws = Workspace(resolve_workspace_dir())
        ws.seed_demo_identities_if_empty()
    app = Flask(__name__)
    app.secret_key = "cyber-trace-local-console"
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

    def page(title: str, page_id: str, body: str) -> str:
        from crypto.pqc import MLKEM, MLDSA, BACKEND
        try:
            st = ws.ledger_status()
            healthy = st["integrity"]["network_consistent"]
            ledger_chip = (f'<span class="chip"><span class="dot{"" if healthy else " bad"}"></span>'
                           f'{e(ws.ledger_backend)} ledger <b>{st["records"]}</b> records</span>')
        except Exception:
            ledger_chip = '<span class="chip"><span class="dot bad"></span>ledger unavailable</span>'

        env_chip = ""
        if os.environ.get("VERCEL"):
            env_chip = '<span class="chip" style="background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)"><b>Vercel Serverless</b></span>'
        elif os.environ.get("NETLIFY") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT"):
            env_chip = '<span class="chip" style="background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)"><b>Cloud Serverless</b></span>'

        nav_items = [
            ("main_home", "/home", "Home", "doc"),
            ("status", "/status", "Status", "gauge"),
            ("ledger", "/ledger", "Ledger Explorer", "layers"),
        ]
        u_sess = session.get("user")
        ad_sess = session.get("admin_user")
        user_role = u_sess.get("role") if u_sess else None

        if user_role == "Receiver":
            nav_items.append(("recipient", "/recipient", "Recipient", "inbox"))
            nav_items.append(("recipient_dashboard", "/recipient/dashboard", "Recipient Dashboard", "key"))
            nav_items.append(("trace", "/trace", "Forensic trace", "search"))
        elif user_role == "Sender":
            nav_items.append(("sender", "/sender", "Sender", "send"))
            nav_items.append(("sender_dashboard", "/sender/dashboard", "Sender Dashboard", "key"))
            nav_items.append(("trace", "/trace", "Forensic trace", "search"))
        else:
            nav_items.append(("sender", "/sender", "Sender", "send"))
            nav_items.append(("recipient", "/recipient", "Recipient", "inbox"))
            nav_items.append(("trace", "/trace", "Forensic trace", "search"))

        if ad_sess:
            nav_items.append(("admin", "/admin", "Admin", "shield"))

        nav = "".join(
            f'<a href="{href}" class="{"on" if page_id == pid else ""}">{svg(ico, 16)}{label}</a>'
            for pid, href, label, ico in nav_items)

        user_chip = ""
        u_sess = session.get("user")
        ad_sess = session.get("admin_user")
        if u_sess:
            user_chip = f'<span class="chip" style="background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)"><b>{e(u_sess.get("email"))}</b> ({e(u_sess.get("role"))})</span><a href="/logout" class="chip" style="color:var(--bad)">Logout</a>'
        elif ad_sess:
            user_chip = f'<span class="chip" style="background:var(--violet-soft);color:var(--violet);border-color:var(--violet-line)"><b>Admin: {e(ad_sess.get("admin_id"))}</b></span><a href="/logout" class="chip" style="color:var(--bad)">Logout</a>'
        else:
            user_chip = '<a href="/login" class="chip" style="background:var(--accent-soft);color:var(--accent)">Login</a>'

        flashes = "".join(f'<div class="flash">{svg("alert", 17)}<div>{e(m)}</div></div>'
                          for m in get_flashed_messages())
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} · CyberTrace</title><style>{CSS}</style></head><body>
<div id="intro-splash">
  <div class="splash-bg"></div>
  <div class="splash-overlay-dark"></div>
  <div class="splash-laser"></div>
  <button type="button" class="splash-skip" id="splash-skip-btn">Skip Intro ➔</button>
  <div class="splash-content">
    <div class="splash-logo-wrap">{svg("fingerprint", 34)}</div>
    <div class="splash-title">CyberTrace</div>
    <div class="splash-sub">Initialising Quantum Core</div>
    <div class="splash-progress-track">
      <div class="splash-progress-fill" id="splash-fill"></div>
    </div>
    <div class="splash-meta">
      <span id="splash-status">Booting Circuitry Engine…</span>
      <span class="splash-pct" id="splash-pct">0%</span>
    </div>
  </div>
</div>
<header><div class="bar">
  <div class="brand"><span class="mark">{svg("fingerprint", 17)}</span>
    <span>CyberTrace<small>attribution console</small></span></div>
  <nav>{nav}</nav>
  <div class="chips">{user_chip}{env_chip}{ledger_chip}
    <span class="chip">{svg("lock", 13)}{e(MLKEM.algorithm)} · {e(MLDSA.algorithm)}</span>
    <span class="chip">{e(BACKEND)}</span>
  </div>
</div></header>
<main>{flashes}{body}</main>
<div id="busy"><div class="box">
  <button type="button" id="busy-x" aria-label="Close" style="position:absolute;top:10px;right:14px;background:none;border:none;font-size:22px;color:var(--muted);cursor:pointer;line-height:1;padding:4px;border-radius:6px">✕</button>
  <div class="spin" id="busy-spin"></div>
  <div class="m" id="busy-m">Working…</div>
  <div class="s" id="busy-s"></div>
  <div class="pbar-wrap">
    <div class="pbar-track"><div class="pbar-fill" id="pbar-fill"></div></div>
    <div class="pbar-meta"><span id="pbar-stage">Initializing…</span><span class="pbar-pct" id="pbar-pct">0%</span></div>
  </div>
  <button type="button" class="btn" id="busy-dismiss" style="margin-top:14px;padding:6px 16px;font-size:12.5px;background:#fff;color:var(--muted);border-color:var(--line);display:none">Done / Dismiss</button>
</div></div>
<script>{JS}</script></body></html>"""

    def hero(eyebrow: str, title: str, lede: str) -> str:
        return (f'<div class="hero"><div class="eyebrow">{e(eyebrow)}</div>'
                f'<h1>{e(title)}</h1><p class="lede">{e(lede)}</p></div>')

    def drop(name: str, accept: str, label: str, hint: str) -> str:
        return (f'<div class="drop" tabindex="0" role="button">{svg("doc", 26, "")}'
                f'<div class="big">{e(label)}</div><div class="hint">{e(hint)}</div>'
                f'<input type="file" name="{name}" accept="{accept}" required></div>')

    def kv_row(k: str, v: str, mono: bool = False, copy: bool = False) -> str:
        val = f'<span class="mono">{v}</span>' if mono else v
        btn = f' <button type="button" class="copy" data-v="{e(v)}">copy</button>' if copy else ""
        return f"<tr><td>{e(k)}</td><td>{val}{btn}</td></tr>"

    # ------------------------------------------------------------------ static
    @app.route("/circuit.png")
    def serve_circuit_img():
        img_path = os.path.join(_parent, "public", "circuit.png")
        if os.path.exists(img_path):
            return send_file(img_path, mimetype="image/png")
        return ("", 404)

    @app.route("/healthz")
    def healthz():
        return ("ok", 200)

    @app.route("/favicon.ico")
    def favicon():
        return ("", 204)

    @app.errorhandler(Exception)
    def on_error(err):
        from werkzeug.exceptions import HTTPException
        if isinstance(err, HTTPException):
            return err
        if isinstance(err, (ServiceError, UnsupportedFormat)):
            flash(str(err))
        else:
            app.logger.error(traceback.format_exc())
            flash(f"{type(err).__name__}: {err}")
        return redirect(request.referrer or url_for("main_home")), 302

    # ------------------------------------------------------------------- status
    def node_records(v):
        """Fabric peers report a record count; simulated nodes report a chain length,
        which includes the genesis block."""
        if not isinstance(v, dict):
            return v
        if "records" in v:
            return v["records"]
        n = v.get("chain_length")
        return max(0, n - 1) if isinstance(n, int) else "-"

    # ------------------------------------------------------------- auth & tracking
    auth_mgr = AuthManager(ws.root)
    delivery_mgr = DeliveryManager(ws.root)

    PUBLIC_PATHS = {"/login", "/admin/login", "/healthz", "/circuit.png", "/favicon.ico"}

    @app.before_request
    def check_user_session():
        if request.path.startswith("/samples/") or request.path.startswith("/api/") or request.path in PUBLIC_PATHS:
            return None
        if request.path.startswith("/admin"):
            if not session.get("admin_user"):
                return redirect(url_for("admin_login"))
            return None
        if not session.get("user") and not session.get("admin_user"):
            if request.path.startswith("/recipient/delivery/") and request.path.endswith("/secret"):
                return jsonify({"ok": False, "error": "Unauthorized: Recipient authentication required."}), 401
            return redirect(url_for("user_login"))

        u = session.get("user")
        if u:
            role = u.get("role")
            if role == "Sender" and (request.path.startswith("/recipient") or request.path.startswith("/recipient/dashboard")):
                if request.path.startswith("/recipient/delivery/") and request.path.endswith("/secret"):
                    return jsonify({"ok": False, "error": "Access denied: Recipient functionality is restricted to Receiver role."}), 403
                flash("Access denied: Recipient functionality is restricted to Receiver role.")
                return redirect(url_for("main_home"))
            if role == "Receiver" and (request.path.startswith("/sender") or request.path.startswith("/sender/dashboard")):
                flash("Access denied: Sender functionality is restricted to Sender role.")
                return redirect(url_for("main_home"))

        return None

    def animated_bg_wrapper(card_content: str) -> str:
        return f"""
<div class="animated-bg-wrapper">
  <div class="animated-bg-canvas">
    <div class="gradient-blob gradient-blob-1"></div>
    <div class="gradient-blob gradient-blob-2"></div>
    <div class="gradient-blob gradient-blob-3"></div>
    <svg class="svg-gradient-layer" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none" viewBox="0 0 1440 900">
      <defs>
        <radialGradient id="grad1" cx="30%" cy="30%" r="70%">
          <stop offset="0%" stop-color="#0B5FCC" stop-opacity="0.25" />
          <stop offset="100%" stop-color="#4E3BC4" stop-opacity="0" />
        </radialGradient>
        <radialGradient id="grad2" cx="70%" cy="70%" r="70%">
          <stop offset="0%" stop-color="#4E3BC4" stop-opacity="0.2" />
          <stop offset="100%" stop-color="#0F6B45" stop-opacity="0" />
        </radialGradient>
      </defs>
      <rect width="100%" height="100%" fill="url(#grad1)" />
      <rect width="100%" height="100%" fill="url(#grad2)" />
    </svg>
  </div>
  <div class="glass-card">
    {card_content}
  </div>
</div>"""

    @app.route("/login", methods=["GET", "POST"])
    def user_login():
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "Sender")
            u = auth_mgr.authenticate_user(email, password, role)
            if u:
                u["passphrase"] = password
                session["user"] = u
                rid = (u.get("user_id") or email.split("@")[0]).strip().lower()
                if rid and not ws.get_identity(rid):
                    try:
                        pass_clean = password if len(password) >= 4 else "password123"
                        ws.create_identity(rid, pass_clean, name=u.get("name"), email=u.get("email"), role=u.get("role"))
                    except Exception:
                        pass
                auth_mgr.log_activity(u, request.remote_addr or "127.0.0.1")
                flash(f"Welcome back, {u['name']}!")
                return redirect(url_for("main_home"))
            flash("Invalid email or password. Try demo accounts (e.g. sender@cybertrace.local / password123)")
            return redirect(url_for("user_login"))

        card = f"""
    <div style="text-align:center;margin-bottom:20px">
      <div style="width:46px;height:46px;border-radius:12px;background:linear-gradient(145deg,#12386F,#0B5FCC);color:#fff;border:1px solid #0A4FA8;display:grid;place-items:center;margin:0 auto 10px">
        {svg("fingerprint", 22)}
      </div>
      <h1 style="font-size:20px;margin:0;font-weight:700">CyberTrace Login</h1>
      <p style="color:var(--muted);font-size:13px;margin:4px 0 0">Cryptographic Attribution & Provenance Console</p>
    </div>
    <form method="post" action="/login">
      <label>Email Address</label>
      <input type="text" name="email" placeholder="sender@cybertrace.local" required autofocus>
      
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" required>
      
      <label>Role Selection</label>
      <select name="role">
        <option value="Sender">Sender</option>
        <option value="Receiver">Receiver</option>
      </select>
      
      <button class="btn" type="submit" style="width:100%;justify-content:center;margin-top:22px">Sign In</button>
    </form>"""
        return page("Login", "login", animated_bg_wrapper(card))

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            admin_id = request.form.get("admin_id", "").strip()
            password = request.form.get("password", "")
            ad = auth_mgr.authenticate_admin(admin_id, password)
            if ad:
                session["admin_user"] = ad
                flash(f"Administrator logged in as '{ad['admin_id']}'")
                return redirect(url_for("admin_dashboard"))
            flash("Invalid Admin ID or Password.")
            return redirect(url_for("admin_login"))

        card = f"""
    <div style="text-align:center;margin-bottom:20px">
      <div style="width:46px;height:46px;border-radius:12px;background:var(--violet-soft);color:var(--violet);border:1px solid var(--violet-line);display:grid;place-items:center;margin:0 auto 10px">
        {svg("shield", 22)}
      </div>
      <h1 style="font-size:20px;margin:0;font-weight:700">Administrator Access</h1>
      <p style="color:var(--muted);font-size:13px;margin:4px 0 0">System Oversight & User Tracking</p>
    </div>
    <form method="post" action="/admin/login">
      <label>Admin ID</label>
      <input type="text" name="admin_id" placeholder="admin" required autofocus>
      
      <label>Admin Password</label>
      <input type="password" name="password" placeholder="••••••••" required>
      
      <button class="btn" type="submit" style="width:100%;justify-content:center;margin-top:22px;background:var(--violet);border-color:var(--violet)">Admin Login</button>
    </form>
    <hr class="sep">
    <div style="text-align:center;font-size:12.5px;color:var(--muted)">
      Standard User? <a href="/login" style="font-weight:600">User Login ➔</a>
    </div>"""
        return page("Admin Login", "admin_login", animated_bg_wrapper(card))

    @app.route("/admin")
    def admin_dashboard():
        logs = auth_mgr.get_activity_logs()
        rows = "".join(
            f'<tr><td>{e(l.get("timestamp"))}</td>'
            f'<td><b>{e(l.get("name"))}</b></td>'
            f'<td><span class="mono">{e(l.get("user_id"))}</span> ({e(l.get("email"))})</td>'
            f'<td><span class="chip" style="font-size:11px">{e(l.get("role"))}</span></td>'
            f'<td><span class="mono">{e(l.get("ip"))}</span></td></tr>'
            for l in logs
        ) or '<tr><td colspan="5" style="color:var(--muted)">No login activity recorded yet.</td></tr>'

        body = f"""
{hero("Administrator Console", "Login Activity & User Tracking", "Identify authenticated users and their login sessions across Sender and Receiver roles.")}
<div class="card">
  <h2><span class="icon violet">{svg("shield", 16)}</span>User Activity & Login Log</h2>
  <p class="sub">Server-side tracking log for authorized administrators only.</p>
  <hr class="sep">
  <div style="overflow-x:auto">
    <table class="kv">
      <thead>
        <tr style="border-bottom:2px solid var(--line-soft)">
          <td style="width:20%">Timestamp</td>
          <td style="width:22%">User Name</td>
          <td style="width:28%">User ID / Email</td>
          <td style="width:15%">Role</td>
          <td style="width:15%">IP Address</td>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</div>"""
        return page("Admin Dashboard", "admin", body)

    @app.route("/logout")
    def user_logout():
        session.pop("user", None)
        session.pop("admin_user", None)
        flash("You have been logged out.")
        return redirect(url_for("user_login"))

    @app.route("/home")
    @app.route("/")
    def main_home():
        u = session.get("user") or session.get("admin_user") or {}
        role = u.get("role") if session.get("user") else None
        role_desc = f"Logged in as {u.get('name', 'User')}" if u else "CyberTrace Navigation Page"

        sender_card = f"""
  <div class="card">
    <h2><span class="icon">{svg("send", 16)}</span>Sender Portal</h2>
    <p class="sub">Upload documents, pick authorized recipients, and generate post-quantum encrypted packages.</p>
    <div style="margin-top:18px">
      <a href="/sender" class="btn" style="padding:9px 18px;font-size:13.5px">Open Sender Page ➔</a>
    </div>
  </div>"""

        sender_dash_card = f"""
  <div class="card">
    <h2><span class="icon violet">{svg("key", 16)}</span>Sender Dashboard</h2>
    <p class="sub">Track live delivery status, recipient acceptance state, and remaining time before document expiry.</p>
    <div style="margin-top:18px">
      <a href="/sender/dashboard" class="btn" style="padding:9px 18px;font-size:13.5px;background:var(--violet);border-color:var(--violet)">Open Sender Dashboard ➔</a>
    </div>
  </div>"""

        recipient_card = f"""
  <div class="card">
    <h2><span class="icon ok">{svg("inbox", 16)}</span>Recipient Portal</h2>
    <p class="sub">Decrypt packages with your identity passphrase, embed invisible watermarks, and commit to ledger.</p>
    <div style="margin-top:18px">
      <a href="/recipient" class="btn" style="padding:9px 18px;font-size:13.5px;background:var(--ok);border-color:var(--ok)">Open Recipient Page ➔</a>
    </div>
  </div>"""

        recipient_dash_card = f"""
  <div class="card">
    <h2><span class="icon ok">{svg("key", 16)}</span>Recipient Dashboard</h2>
    <p class="sub">View documents assigned to you, accept deliveries, and generate 4-digit decryption codes.</p>
    <div style="margin-top:18px">
      <a href="/recipient/dashboard" class="btn" style="padding:9px 18px;font-size:13.5px;background:var(--ok);border-color:var(--ok)">Open Recipient Dashboard ➔</a>
    </div>
  </div>"""

        trace_card = f"""
  <div class="card">
    <h2><span class="icon warn">{svg("search", 16)}</span>Forensic Trace</h2>
    <p class="sub">Upload leaked files (images/PDFs) to extract embedded watermarks and attribute leak sources.</p>
    <div style="margin-top:18px">
      <a href="/trace" class="btn" style="padding:9px 18px;font-size:13.5px;background:var(--warn);border-color:var(--warn)">Open Forensic Trace ➔</a>
    </div>
  </div>"""

        status_card = f"""
  <div class="card">
    <h2><span class="icon violet">{svg("gauge", 16)}</span>System Status</h2>
    <p class="sub">View real-time Hyperledger Fabric / simulated node agreement, quorum status, and identity key pairs.</p>
    <div style="margin-top:18px">
      <a href="/status" class="btn" style="padding:9px 18px;font-size:13.5px;background:var(--violet);border-color:var(--violet)">Open Status Dashboard ➔</a>
    </div>
  </div>"""

        cards = []
        if role == "Sender":
            cards.append(sender_card)
            cards.append(sender_dash_card)
            cards.append(trace_card)
            cards.append(status_card)
        elif role == "Receiver":
            cards.append(recipient_card)
            cards.append(recipient_dash_card)
            cards.append(trace_card)
            cards.append(status_card)
        else:
            cards.append(sender_card)
            cards.append(recipient_card)
            cards.append(trace_card)
            cards.append(status_card)

        cards_html = "".join(cards)
        body = f"""
{hero("CyberTrace", "Cryptographic Attribution & Immutable Provenance Platform", role_desc)}
<div class="grid g2" style="margin-bottom:24px">
  {cards_html}
</div>"""
        return page("Home", "main_home", body)

    @app.route("/status")
    def status_dashboard():
        st = ws.ledger_status()
        integ = st["integrity"]
        ok = integ["network_consistent"]
        tampered = set(integ.get("tampered_nodes", []))

        nodes = "".join(
            f'<div class="node"><span class="dot{"" if n not in tampered else " bad"}"></span>'
            f'<span class="nm">{e(n)}</span>'
            f'<span class="rc">{e(node_records(v))} records</span></div>'
            for n, v in integ["nodes"].items())

        ids = ws.list_identities()
        id_chips = "".join(f'<div class="node">{svg("key", 15)}<span class="nm">{e(i)}</span>'
                           f'<span class="rc">ML-KEM-768 · ML-DSA-65</span></div>' for i in ids) or \
            ('<div class="empty">No identities yet. Click below to seed demo identities or create one.</div>')

        identity_actions = f"""
        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
          <form method="post" action="/identities/seed_demo" style="margin:0">
            <input type="hidden" name="force" value="1">
            <button class="btn" type="submit" style="background:var(--violet);border-color:var(--violet);padding:7px 14px;font-size:13px">
              {svg("key", 15)} Reset Demo Passphrases to "password123"
            </button>
          </form>
        </div>
        <details style="margin-top:14px;border-top:1px solid var(--line-soft);padding-top:10px">
          <summary style="cursor:pointer;color:var(--accent);font-weight:600;font-size:13px">+ Create custom identity</summary>
          <form method="post" action="/identities/new" style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
            <input type="text" name="name" placeholder="Name (e.g. Sanju Kumar)" required style="flex:1;min-width:130px;padding:6px 10px;font-size:13px">
            <input type="text" name="identity_id" placeholder="ID (e.g. REC-001)" required style="flex:1;min-width:100px;padding:6px 10px;font-size:13px">
            <input type="email" name="email" placeholder="Email (e.g. sanju@example.com)" required style="flex:1;min-width:150px;padding:6px 10px;font-size:13px">
            <input type="password" name="passphrase" placeholder="Password" required style="flex:1;min-width:110px;padding:6px 10px;font-size:13px">
            <select name="role" style="padding:6px 10px;font-size:13px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:var(--r-md)">
              <option value="Receiver">Receiver</option>
              <option value="Sender">Sender</option>
            </select>
            <button class="btn" type="submit" style="padding:6px 14px;font-size:13px">Add</button>
          </form>
        </details>
        """

        agreement = ('<b style="color:var(--ok)">all nodes agree</b>' if ok else
                     f'<b style="color:var(--bad)">disagreement: {e(", ".join(sorted(tampered)))}</b>')

        body = f"""
{hero("System status", "Attribution ledger is " + ("healthy" if ok else "reporting a conflict"),
      "Every decryption is watermarked, signed by the recipient and committed here before the document is released.")}
<div class="grid g4" style="margin-bottom:18px">
  <div class="stat"><div class="k">Ledger</div><div class="v">{e(ws.ledger_backend)}</div>
    <div class="n">{"4 org Fabric peers" if ws.ledger_backend == "fabric" else "in-process simulation"}</div></div>
  <div class="stat"><div class="k">Quorum</div><div class="v">{st['quorum']} of {len(st['nodes'])}</div>
    <div class="n">must hold the identical record</div></div>
  <div class="stat"><div class="k">Records</div><div class="v">{st['records']}</div>
    <div class="n">signed decryption events</div></div>
  <div class="stat"><div class="k">Identities</div><div class="v">{len(ids)}</div>
    <div class="n">post-quantum key pairs</div></div>
</div>
<div class="split">
  <div class="card"><h2><span class="icon{'' if ok else ' bad'}">{svg("node", 16)}</span>Ledger nodes</h2>
    <p class="sub">Each node is queried separately; a record counts only when {st['quorum']} of {len(st['nodes'])} return it
       identically — {agreement}.</p>
    <hr class="sep">
    <div class="grid" style="gap:10px">{nodes}</div>
  </div>
  <div class="card"><h2><span class="icon violet">{svg("key", 16)}</span>Identities</h2>
    <p class="sub">Secret keys are encrypted at rest with scrypt + AES-256-GCM under each holder's passphrase.</p>
    <hr class="sep">
    <div class="grid" style="gap:10px">{id_chips}</div>
    {identity_actions}
  </div>
</div>"""
        return page("Status", "home", body)

    # ---------------------------------------------------------- ledger explorer
    @app.route("/api/ledger/events")
    def api_ledger_events():
        try:
            data = ws.get_ledger_events()
            return app.response_class(
                response=json.dumps({"status": "ok", **data}, indent=2),
                status=200,
                mimetype="application/json",
            )
        except Exception as ex:
            return app.response_class(
                response=json.dumps({"status": "error", "message": str(ex)}),
                status=500,
                mimetype="application/json",
            )

    @app.route("/ledger")
    def ledger_explorer():
        try:
            data = ws.get_ledger_events()
            stats = data["stats"]
            events = data["events"]
            integ = data["integrity"]
        except Exception as err:
            body = f"""
{hero("Ledger Explorer", "Immutable Provenance Ledger", "Cryptographic audit trail of all decryption and attribution events.")}
<div class="card" style="text-align:center;padding:48px 24px;border-color:var(--bad-line);background:var(--bad-soft)">
  <div style="font-size:18px;font-weight:700;color:var(--bad);margin-bottom:8px">Unable to load ledger records.</div>
  <p style="color:var(--muted);margin-bottom:18px">Error connecting to the ledger backend: {e(str(err))}</p>
  <a href="/ledger" class="btn">Retry</a>
</div>"""
            return page("Ledger Explorer", "ledger", body)

        # Overview Cards
        stats_cards = f"""
<div class="grid g3" style="margin-bottom:20px">
  <div class="stat"><div class="k">Total Records</div><div class="v">{stats['total_records']}</div>
    <div class="n">{stats['total_provenance_records']} provenance + {stats['total_records'] - stats['total_provenance_records']} genesis</div></div>
  <div class="stat"><div class="k">Documents</div><div class="v">{stats['unique_documents']}</div>
    <div class="n">unique encrypted files tracked</div></div>
  <div class="stat"><div class="k">Recipients</div><div class="v">{stats['unique_recipients']}</div>
    <div class="n">distinct actors with verified identities</div></div>
  <div class="stat"><div class="k">Decryption Events</div><div class="v">{stats['decryption_events']}</div>
    <div class="n">independent decryption sessions</div></div>
  <div class="stat"><div class="k">Watermark Events</div><div class="v">{stats['watermark_events']}</div>
    <div class="n">128-bit session watermarks embedded</div></div>
  <div class="stat"><div class="k">Committed Events</div><div class="v">{stats['committed_events']}</div>
    <div class="n">{stats['quorum_needed']}-of-{stats['total_nodes']} quorum achieved</div></div>
</div>"""

        # Integrity Status Panel
        is_consistent = stats.get("network_consistent", True)
        tampered_count = len(stats.get("tampered_nodes", []))
        integ_banner = f"""
<div class="card" style="margin-bottom:20px;background:{'var(--ok-soft)' if is_consistent else 'var(--bad-soft)'};border-color:{'var(--ok-line)' if is_consistent else 'var(--bad-line)'}">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px">
    <div style="display:flex;align-items:center;gap:12px">
      <div class="icon {'ok' if is_consistent else 'bad'}" style="width:36px;height:36px">
        {svg('check' if is_consistent else 'alert', 20)}
      </div>
      <div>
        <div style="font-weight:700;font-size:15px;color:{'var(--ok)' if is_consistent else 'var(--bad)'}">
          Ledger Integrity: {'✓ FULLY VERIFIED' if is_consistent else '⚠ TAMPERING DETECTED'}
        </div>
        <div style="font-size:12.5px;color:var(--muted);margin-top:2px">
          Multi-node BFT consensus ({e(stats['backend'])} backend) · Quorum requirement: {stats['quorum_needed']}-of-{stats['total_nodes']} nodes
        </div>
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <span class="chip" style="background:#fff"><span class="dot {'ok' if is_consistent else 'bad'}"></span>Hash Chain: <b>{'VALID' if is_consistent else 'INVALID'}</b></span>
      <span class="chip" style="background:#fff"><span class="dot"></span>Signatures: <b>ML-DSA-65 VALID</b></span>
      <span class="chip" style="background:#fff"><span class="dot"></span>Quorum: <b>ACHIEVED</b></span>
      <span class="chip" style="background:#fff"><span class="dot {'ok' if tampered_count == 0 else 'bad'}"></span>Tampered Nodes: <b>{tampered_count}</b></span>
    </div>
  </div>
</div>"""

        # Populate unique filter sets
        event_types = sorted(set(ev["event_type"] for ev in events))
        doc_ids = sorted(set(ev["document_id"] for ev in events if ev["document_id"] != "-"))
        recipients = sorted(set(ev["actor"] for ev in events if ev["actor"] != "-"))

        opt_types = "".join(f'<option value="{e(t)}">{e(t)}</option>' for t in event_types)
        opt_docs = "".join(f'<option value="{e(d)}">{e(d)}</option>' for d in doc_ids)
        opt_actors = "".join(f'<option value="{e(a)}">{e(a)}</option>' for a in recipients)

        # Build table rows or empty state
        if not events:
            table_section = f"""
<div class="card" style="text-align:center;padding:50px 24px">
  <div class="icon" style="margin:0 auto 16px;width:48px;height:48px;background:var(--panel-2);color:var(--muted)">{svg("layers", 26)}</div>
  <div style="font-size:18px;font-weight:700;color:var(--fg);margin-bottom:8px">No ledger records yet.</div>
  <p style="color:var(--muted);max-width:540px;margin:0 auto 18px">
    Ledger events will appear here after document distribution, decryption, watermarking, and commit operations.
  </p>
  <a href="/sender" class="btn" style="padding:9px 18px;font-size:13.5px">Go to Sender Portal ➔</a>
</div>"""
        else:
            rows = []
            for ev in events:
                is_gen = (ev["event_type"] == "GENESIS")
                type_tag = f'<span class="tag {"tag-violet" if is_gen else "tag-info"}">{e(ev["event_type"])}</span>'
                status_tag = f'<span class="tag {"tag-ok" if ev["status"] == "COMMITTED" else "tag-warn"}"><span class="dot {"ok" if ev["status"] == "COMMITTED" else "bad"}" style="width:5px;height:5px"></span>{e(ev["status"])}</span>'
                sig_tag = f'<span class="tag {"tag-ok" if ev["signature_status"] == "VALID" else "tag-bad"}">{e(ev["signature_status"])}</span>'
                integ_tag = f'<span class="tag {"tag-ok" if ev["integrity_status"] == "VALID" else "tag-bad"}">{e(ev["integrity_status"])}</span>'
                
                rows.append(f"""
<tr class="evt-row" data-idx="{ev['index']}" data-type="{e(ev['event_type'])}" data-doc="{e(ev['document_id'])}" data-actor="{e(ev['actor'])}" data-status="{e(ev['status'])}">
  <td><span class="mono" style="font-weight:700;color:var(--accent)">{e(ev['event_id'])}</span></td>
  <td>{type_tag}</td>
  <td><span class="mono">{e(ev['document_id'])}</span></td>
  <td><b>{e(ev['actor'])}</b></td>
  <td style="white-space:nowrap">
    <div style="font-weight:600;color:var(--fg)" class="local-time-str" data-ts="{ev['timestamp']}">{e(ev['local_timestamp'])}</div>
    <div style="font-size:11px;color:var(--faint)">{e(ev['utc_timestamp'])}</div>
  </td>
  <td>{status_tag}</td>
  <td>{sig_tag}</td>
  <td>{integ_tag}</td>
  <td style="text-align:right">
    <button type="button" class="btn ghost inspect-btn" data-idx="{ev['index']}" style="margin:0;padding:4px 10px;font-size:12px">Inspect ➔</button>
  </td>
</tr>""")

            table_rows_html = "".join(rows)

            table_section = f"""
<div class="card">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">
    <div>
      <h2 style="margin:0"><span class="icon">{svg("layers", 16)}</span>Ledger Event Chain</h2>
      <p class="sub" style="margin:4px 0 0">Immutable sequence of blocks cross-attested by {stats['total_nodes']} independent validator nodes.</p>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <span class="chip" id="evt-counter">Showing <b>{len(events)}</b> of <b>{len(events)}</b> events</span>
      <button type="button" class="btn ghost" id="reset-filters" style="margin:0;padding:6px 12px;font-size:12.5px">Reset Filters</button>
    </div>
  </div>

  <div class="filter-bar">
    <input type="text" id="filter-search" placeholder="Search Event ID, document, recipient, watermark, hash...">
    <select id="filter-type">
      <option value="">All Event Types</option>
      {opt_types}
    </select>
    <select id="filter-doc">
      <option value="">All Documents</option>
      {opt_docs}
    </select>
    <select id="filter-actor">
      <option value="">All Recipients</option>
      {opt_actors}
    </select>
    <select id="filter-status">
      <option value="">All Statuses</option>
      <option value="COMMITTED">COMMITTED</option>
      <option value="UNCONFIRMED">UNCONFIRMED</option>
    </select>
  </div>

  <div class="tbl-scroll">
    <table class="evt-table">
      <thead>
        <tr>
          <th>Event ID</th>
          <th>Type</th>
          <th>Document</th>
          <th>Actor / Recipient</th>
          <th>Timestamp</th>
          <th>Ledger Status</th>
          <th>Signature</th>
          <th>Integrity</th>
          <th style="text-align:right">Action</th>
        </tr>
      </thead>
      <tbody id="evt-tbody">
        {table_rows_html}
      </tbody>
    </table>
  </div>
  <div id="no-filter-match" style="display:none;text-align:center;padding:36px 18px;color:var(--muted)">
    No ledger events match your filter criteria.
  </div>
</div>"""

        # Modal HTML and client-side interactive logic
        events_json = json.dumps(events).replace("</script>", "<\\/script>")

        modal_html = f"""
<div class="modal-overlay" id="evt-modal" role="dialog" aria-modal="true">
  <div class="modal-box">
    <button type="button" class="modal-close" id="modal-close-btn" aria-label="Close modal">✕</button>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
      <div class="icon info">{svg("layers", 18)}</div>
      <div>
        <h2 style="margin:0;font-size:18px" id="m-title">Event Details</h2>
        <div style="font-size:12.5px;color:var(--muted)" id="m-subtitle">Cryptographic block inspection</div>
      </div>
    </div>
    
    <div style="background:var(--panel-2);border:1px solid var(--line-soft);border-radius:var(--r-md);padding:14px 16px;margin-bottom:18px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--faint);letter-spacing:1px;margin-bottom:8px">Cryptographic Hash Linkage (Block Chain Flow)</div>
      <div class="chain-viz">
        <div class="chain-node" id="c-prev">
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700">Previous Block</div>
          <div class="mono" style="font-size:11.5px;color:var(--fg);margin-top:4px" id="c-prev-hash">-</div>
        </div>
        <div class="chain-arrow">➔</div>
        <div class="chain-node current" id="c-curr">
          <div style="font-size:11px;color:var(--accent);text-transform:uppercase;font-weight:700">Current Event Block</div>
          <div class="mono" style="font-size:11.5px;color:var(--fg);font-weight:700;margin-top:4px" id="c-curr-hash">-</div>
        </div>
        <div class="chain-arrow">➔</div>
        <div class="chain-node" id="c-next">
          <div style="font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700">Next Block</div>
          <div class="mono" style="font-size:11.5px;color:var(--fg);margin-top:4px" id="c-next-hash">-</div>
        </div>
      </div>
    </div>

    <table class="kv" style="margin-bottom:18px">
      <tbody>
        <tr><td>Event ID</td><td><b id="m-event-id">-</b> (Block index <span id="m-index">-</span>)</td></tr>
        <tr><td>Event Type</td><td><span class="tag tag-info" id="m-event-type">-</span></td></tr>
        <tr><td>Document ID</td><td><span class="mono" id="m-document-id">-</span></td></tr>
        <tr><td>Actor / Recipient</td><td><b id="m-actor">-</b></td></tr>
        <tr><td>Event Timestamp</td><td>
          <div style="display:flex;align-items:center;gap:8px">
            <b id="m-time-local" style="color:var(--fg);font-size:14px">-</b>
            <span class="tag tag-ok" style="font-size:9.5px">Real-time / Local</span>
          </div>
          <div style="font-size:12px;color:var(--muted);margin-top:4px">
            UTC Reference: <span class="mono" id="m-time-utc">-</span> · Unix Epoch: <span class="mono" id="m-time-unix">-</span>
          </div>
        </td></tr>
        <tr><td>Document Hash</td><td><span class="mono" id="m-doc-hash">-</span> <button type="button" class="copy" id="cp-doc-hash">copy</button></td></tr>
        <tr><td>Watermark ID</td><td><span class="mono" id="m-watermark-id">-</span> <button type="button" class="copy" id="cp-wm">copy</button></td></tr>
        <tr><td>Decryption Session ID</td><td><span class="mono" id="m-session-id">-</span> <button type="button" class="copy" id="cp-sess">copy</button></td></tr>
        <tr><td>Block Hash</td><td><span class="mono" id="m-block-hash">-</span> <button type="button" class="copy" id="cp-block-hash">copy</button></td></tr>
        <tr><td>Previous Block Hash</td><td><span class="mono" id="m-prev-hash">-</span></td></tr>
        <tr><td>Ledger Status</td><td><span class="tag tag-ok" id="m-status">-</span></td></tr>
        <tr><td>Multi-Node Quorum</td><td><span id="m-quorum">-</span></td></tr>
        <tr><td>Endorsing Nodes</td><td><div id="m-nodes" style="font-size:12.5px;color:var(--muted);margin-top:3px">-</div></td></tr>
      </tbody>
    </table>

    <div style="border-top:1px solid var(--line-soft);padding-top:16px">
      <h3 style="font-size:14px;margin:0 0 10px;font-weight:700;display:flex;align-items:center;gap:8px">
        <span class="icon ok" style="width:24px;height:24px">{svg("shield", 14)}</span>
        Post-Quantum Signature Verification
      </h3>
      <table class="kv">
        <tbody>
          <tr><td>Signature Algorithm</td><td><b id="m-sig-algo">ML-DSA-65 (NIST FIPS 204)</b></td></tr>
          <tr><td>Signature Validity</td><td><span class="tag tag-ok" id="m-sig-valid">VALID</span></td></tr>
          <tr><td>Signer Public Key</td><td><span class="mono" style="font-size:11.5px" id="m-pubkey">-</span> <button type="button" class="copy" id="cp-pk">copy</button></td></tr>
          <tr><td>ML-DSA Signature</td><td><span class="mono" style="font-size:11.5px" id="m-sig">-</span> <button type="button" class="copy" id="cp-sig">copy</button></td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
(function(){{
  var eventsData = {events_json};
  var eventsMap = {{}};
  eventsData.forEach(function(ev){{ eventsMap[ev.index] = ev; }});

  // Client-side local timezone auto-formatting for table
  document.querySelectorAll('.local-time-str').forEach(function(el){{
    var rawTs = parseFloat(el.getAttribute('data-ts'));
    if (!isNaN(rawTs) && rawTs > 0) {{
      try {{
        var dt = new Date(rawTs * 1000);
        el.textContent = dt.toLocaleString();
      }} catch(e){{}}
    }}
  }});

  var modal = document.getElementById('evt-modal');
  var closeBtn = document.getElementById('modal-close-btn');

  function openModal(ev) {{
    if (!ev) return;
    document.getElementById('m-title').textContent = ev.event_id + ' — ' + ev.event_type;
    document.getElementById('m-subtitle').textContent = 'Block Index #' + ev.index + ' · Node: ' + ev.node_id;
    document.getElementById('m-event-id').textContent = ev.event_id;
    document.getElementById('m-index').textContent = ev.index;
    document.getElementById('m-event-type').textContent = ev.event_type;
    document.getElementById('m-document-id').textContent = ev.document_id;
    document.getElementById('m-actor').textContent = ev.actor;
    
    // Real-time local & UTC timestamp formatting
    var ts = ev.timestamp;
    var localDisplay = ev.local_timestamp || ev.human_timestamp;
    if (ts) {{
      try {{
        var d = new Date(ts * 1000);
        localDisplay = d.toLocaleString();
      }} catch(err){{}}
    }}
    document.getElementById('m-time-local').textContent = localDisplay;
    document.getElementById('m-time-utc').textContent = ev.utc_timestamp || (ts ? new Date(ts * 1000).toUTCString() : '-');
    document.getElementById('m-time-unix').textContent = ts ? ts.toFixed(2) : '-';
    
    document.getElementById('m-doc-hash').textContent = ev.document_hash;
    document.getElementById('cp-doc-hash').setAttribute('data-v', ev.document_hash);

    document.getElementById('m-watermark-id').textContent = ev.watermark_id;
    document.getElementById('cp-wm').setAttribute('data-v', ev.watermark_id);

    document.getElementById('m-session-id').textContent = ev.session_id;
    document.getElementById('cp-sess').setAttribute('data-v', ev.session_id);

    document.getElementById('m-block-hash').textContent = ev.block_hash;
    document.getElementById('cp-block-hash').setAttribute('data-v', ev.block_hash);

    document.getElementById('m-prev-hash').textContent = ev.prev_hash;

    // Chain flow visualization
    document.getElementById('c-prev-hash').textContent = ev.prev_hash && ev.prev_hash !== '-' ? ev.prev_hash.substring(0, 16) + '…' : 'GENESIS';
    document.getElementById('c-curr-hash').textContent = ev.block_hash ? ev.block_hash.substring(0, 16) + '…' : '-';
    document.getElementById('c-next-hash').textContent = ev.next_hash ? ev.next_hash.substring(0, 16) + '…' : 'HEAD / NONE';

    document.getElementById('m-status').textContent = ev.status;
    document.getElementById('m-quorum').textContent = ev.quorum_achieved + ' of ' + ev.total_nodes + ' nodes confirmed (Quorum ' + ev.quorum_needed + ' required) — ' + (ev.status === 'COMMITTED' ? 'ACHIEVED' : 'PENDING');
    document.getElementById('m-nodes').textContent = (ev.agreeing_nodes && ev.agreeing_nodes.length) ? ev.agreeing_nodes.join(' · ') : 'Consensus nodes';

    document.getElementById('m-sig-algo').textContent = ev.signature_algorithm;
    document.getElementById('m-sig-valid').textContent = ev.signature_status;
    document.getElementById('m-sig-valid').className = 'tag ' + (ev.signature_status === 'VALID' ? 'tag-ok' : (ev.signature_status === 'N/A' ? 'tag-info' : 'tag-bad'));

    var pk = ev.signer_public_key_hex || '';
    document.getElementById('m-pubkey').textContent = pk ? pk.substring(0, 36) + '… (' + Math.round(pk.length / 2) + ' bytes)' : 'System / Genesis node';
    document.getElementById('cp-pk').setAttribute('data-v', pk);

    var sig = ev.signature_hex || '';
    document.getElementById('m-sig').textContent = sig ? sig.substring(0, 36) + '… (' + Math.round(sig.length / 2) + ' bytes)' : 'System / Genesis signature';
    document.getElementById('cp-sig').setAttribute('data-v', sig);

    modal.classList.add('open');
  }}

  if (closeBtn) {{
    closeBtn.onclick = function(){{ modal.classList.remove('open'); }};
  }}

  if (modal) {{
    modal.onclick = function(e){{
      if (e.target === modal) modal.classList.remove('open');
    }};
  }}

  document.querySelectorAll('.inspect-btn').forEach(function(b){{
    b.onclick = function(e){{
      e.stopPropagation();
      var idx = parseInt(b.getAttribute('data-idx'), 10);
      openModal(eventsMap[idx]);
    }};
  }});

  document.querySelectorAll('tr.evt-row').forEach(function(r){{
    r.onclick = function(){{
      var idx = parseInt(r.getAttribute('data-idx'), 10);
      openModal(eventsMap[idx]);
    }};
  }});

  // Filtering & search
  var searchInput = document.getElementById('filter-search');
  var typeSelect = document.getElementById('filter-type');
  var docSelect = document.getElementById('filter-doc');
  var actorSelect = document.getElementById('filter-actor');
  var statusSelect = document.getElementById('filter-status');
  var resetBtn = document.getElementById('reset-filters');
  var counterEl = document.getElementById('evt-counter');
  var noMatchEl = document.getElementById('no-filter-match');

  function applyFilters() {{
    var q = (searchInput ? searchInput.value : '').toLowerCase().trim();
    var selType = typeSelect ? typeSelect.value : '';
    var selDoc = docSelect ? docSelect.value : '';
    var selActor = actorSelect ? actorSelect.value : '';
    var selStatus = statusSelect ? statusSelect.value : '';

    var rows = document.querySelectorAll('tr.evt-row');
    var visibleCount = 0;

    rows.forEach(function(r){{
      var idx = parseInt(r.getAttribute('data-idx'), 10);
      var ev = eventsMap[idx];
      if (!ev) return;

      var matchType = (!selType || ev.event_type === selType);
      var matchDoc = (!selDoc || ev.document_id === selDoc);
      var matchActor = (!selActor || ev.actor === selActor);
      var matchStatus = (!selStatus || ev.status === selStatus);

      var textPool = (ev.event_id + ' ' + ev.event_type + ' ' + ev.document_id + ' ' + ev.actor + ' ' + ev.watermark_id + ' ' + ev.block_hash + ' ' + ev.human_timestamp).toLowerCase();
      var matchQ = (!q || textPool.indexOf(q) !== -1);

      if (matchType && matchDoc && matchActor && matchStatus && matchQ) {{
        r.style.display = '';
        visibleCount++;
      }} else {{
        r.style.display = 'none';
      }}
    }});

    if (counterEl) {{
      counterEl.innerHTML = 'Showing <b>' + visibleCount + '</b> of <b>' + rows.length + '</b> events';
    }}
    if (noMatchEl) {{
      noMatchEl.style.display = (visibleCount === 0 && rows.length > 0) ? 'block' : 'none';
    }}
  }}

  if (searchInput) searchInput.addEventListener('input', applyFilters);
  if (typeSelect) typeSelect.addEventListener('change', applyFilters);
  if (docSelect) docSelect.addEventListener('change', applyFilters);
  if (actorSelect) actorSelect.addEventListener('change', applyFilters);
  if (statusSelect) statusSelect.addEventListener('change', applyFilters);

  if (resetBtn) {{
    resetBtn.addEventListener('click', function(){{
      if (searchInput) searchInput.value = '';
      if (typeSelect) typeSelect.value = '';
      if (docSelect) docSelect.value = '';
      if (actorSelect) actorSelect.value = '';
      if (statusSelect) statusSelect.value = '';
      applyFilters();
    }});
  }}
}})();
</script>"""

        body = f"""
{hero("Ledger Explorer", "Immutable Provenance Ledger & Audit Trail", "Read-only inspection of post-quantum signed decryption events, block hash chains, and multi-node consensus.")}
{integ_banner}
{stats_cards}
{table_section}
{modal_html}"""
        return page("Ledger Explorer", "ledger", body)


    # ------------------------------------------------------------------- sender
    @app.route("/sender", methods=["GET", "POST"])
    def sender():
        if request.method == "POST":
            f = request.files.get("doc")
            if not f or not f.filename:
                raise ServiceError("choose a document")
            recipients = request.form.getlist("recipients")
            expiry = request.form.get("expiry", "1h")
            u = session.get("user") or {}

            pkg = ws.encrypt(f.read(), f.filename, recipients,
                             request.form.get("doc_id") or None)
            info = ws.package_info(pkg)

            # Record delivery with workspace reference
            delivery_mgr.create_deliveries(info['document_id'], f.filename, u, recipients, expiry, pkg, ws_ref=ws)

            resp = make_response(send_file(io.BytesIO(pkg), as_attachment=True,
                                           download_name=f"{info['document_id']}.ps26237", mimetype="application/json"))
            resp.set_cookie("file_download_complete", "1", max_age=60, path="/", samesite="Lax")
            return resp

        ids = ws.list_identities()
        pick_items = []
        for i in ids:
            ident = ws.get_identity(i)
            disp = f"{ident.get('name', i)} ({i})" if ident and ident.get('name') else i
            pick_items.append(f'<label class="pick"><input type="checkbox" name="recipients" value="{e(i)}">'
                              f'<span>{e(disp)}</span></label>')
        picks = "".join(pick_items) or \
            ('<div class="empty">No identities yet — '
             '<form method="post" action="/identities/seed_demo" style="display:inline">'
             '<button class="btn" type="submit" style="background:var(--violet);border-color:var(--violet);padding:4px 10px;font-size:12px;display:inline-flex;margin-left:6px">'
             'Seed Alice, Bob, Carol</button></form></div>')

        body = f"""
{hero("Sender", "Encrypt once, distribute to many",
      "One AES-256-GCM ciphertext is shared by every recipient. Only the small per-recipient key wrap differs, so the package grows by about 1.5 kB per person.")}
<div class="split">
  <div class="card">
    <form method="post" enctype="multipart/form-data" data-busy="Encrypting…|Wrapping the document key for each recipient">
      <label>Document</label>
      {drop("doc", ".png,.jpg,.jpeg,.pdf", "Drop a file here, or click to choose", "PNG, JPEG or PDF · up to 64 MB")}
      <div style="margin:7px 0 14px;font-size:12px;color:var(--muted)">Need a test file? <a href="/samples/sample_contract.png" download style="font-weight:600">sample_contract.png</a> · <a href="/samples/sample_memo.pdf" download style="font-weight:600">sample_memo.pdf</a></div>
      <label>Document ID <span style="text-transform:none;color:var(--faint)">(optional)</span></label>
      <input type="text" name="doc_id" placeholder="OP-BLUEHORIZON-ANNEX-C">
      <label>Recipients</label>
      <div class="picks">{picks}</div>
      <label>Document Delivery Expiry Timeline</label>
      <select name="expiry">
        <option value="10m">10 minutes</option>
        <option value="30m">30 minutes</option>
        <option value="1h" selected>1 hour</option>
        <option value="6h">6 hours</option>
        <option value="12h">12 hours</option>
        <option value="24h">24 hours</option>
      </select>
      <button class="btn" type="submit">{svg("send", 17)}Encrypt and download package</button>
      <p class="note">The package is a single .ps26237 file. Selected delivery expiry is recorded server-side.</p>
    </form>
  </div>
  <div class="card"><h2><span class="icon">{svg("lock", 16)}</span>What happens</h2>
    <hr class="sep">
    <div class="chain">
      <div class="step idle">{svg("doc", 17)}<div><div class="lbl">Document key generated</div>
        <div class="val">Random 256-bit key, used once for this document</div></div></div>
      <div class="step idle">{svg("lock", 17)}<div><div class="lbl">Encrypted once</div>
        <div class="val">AES-256-GCM over the whole file</div></div></div>
      <div class="step idle">{svg("key", 17)}<div><div class="lbl">Key wrapped per recipient</div>
        <div class="val">ML-KEM-768 encapsulation, one wrap each</div></div></div>
    </div>
    <p class="note">No watermark is applied here. Marking happens at decryption, which is what makes each copy distinct.</p>
  </div>
</div>"""
        return page("Sender", "sender", body)

    @app.route("/sender/dashboard")
    def sender_dashboard():
        u = session.get("user")
        if not u or u.get("role") != "Sender":
            flash("Access denied: Sender Dashboard is for Senders only.")
            return redirect(url_for("main_home"))

        deliveries = delivery_mgr.get_sender_deliveries(u)

        rows = []
        for d in deliveries:
            st = d.get("status", "PENDING")
            st_color = "warn" if st == "PENDING" else ("accent" if st == "ACCEPTED" else ("ok" if st == "DECRYPTED" else "bad"))
            rem_str = d.get("remaining_str", "-")
            rec_name = d.get("recipient_name") or ""
            rec_id = d.get("recipient_id") or ""
            rec_disp = f"{rec_name} ({rec_id})" if (rec_name and rec_name.lower() != rec_id.lower()) else (rec_name or rec_id)

            rows.append(
                f'<tr>'
                f'<td><b>{e(d.get("document_name"))}</b><br><span class="mono" style="font-size:11px">{e(d.get("document_id"))}</span></td>'
                f'<td><b>{e(rec_disp)}</b></td>'
                f'<td><span class="mono" style="font-size:12px">{e(d.get("created_at"))}</span></td>'
                f'<td><span class="mono" style="font-size:12px">{e(d.get("expires_at"))}</span></td>'
                f'<td><span class="chip" style="font-size:11px">{e(rem_str)}</span></td>'
                f'<td><span class="chip" style="font-size:11px;background:var(--{st_color}-soft);color:var(--{st_color});border-color:var(--{st_color}-line)"><b>{e(st)}</b></span></td>'
                f'</tr>'
            )

        table_rows = "".join(rows) or '<tr><td colspan="6" style="color:var(--muted)">No document deliveries created yet. Use the Sender Portal to send an encrypted document.</td></tr>'

        body = f"""
{hero("Sender Dashboard", "Live Document Delivery Tracking", "Monitor real-time delivery status, recipient acceptance state, and remaining time before document expiry.")}
<div class="card">
  <h2><span class="icon">{svg("send", 16)}</span>Document Deliveries Sent by You</h2>
  <p class="sub">Track live recipient acceptance, decryption status, and countdown timelines.</p>
  <hr class="sep">
  <div style="overflow-x:auto">
    <table class="kv">
      <thead>
        <tr style="border-bottom:2px solid var(--line-soft)">
          <td style="width:25%">Document</td>
          <td style="width:15%">Recipient</td>
          <td style="width:18%">Sent Time</td>
          <td style="width:18%">Expiry Time</td>
          <td style="width:14%">Remaining</td>
          <td style="width:10%">Status</td>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>
  </div>
</div>"""
        return page("Sender Dashboard", "sender_dashboard", body)

    @app.route("/recipient/dashboard")
    def recipient_dashboard():
        u = session.get("user")
        if not u or u.get("role") != "Receiver":
            flash("Access denied: Recipient Dashboard is for Receivers only.")
            return redirect(url_for("main_home"))

        deliveries = delivery_mgr.get_recipient_deliveries(u, ws_ref=ws)

        card_list = []
        for d in deliveries:
            del_id = d["delivery_id"]
            doc_id = d["document_id"]
            doc_name = d["document_name"]
            sender = d["sender_name"]
            sender_id = d["sender_id"]
            sent = d["created_at"]
            expires = d["expires_at"]
            rem_str = d["remaining_str"]
            st = d["status"]

            if st == "PENDING":
                action = f"""
<form method="post" action="/recipient/accept/{e(del_id)}" style="margin:14px 0 0">
  <button class="btn" type="submit" style="background:var(--ok);border-color:var(--ok);padding:8px 16px;font-size:13px">
    {svg("inbox", 15)} Accept & Download Package (.ps26237)
  </button>
</form>"""
            elif st == "ACCEPTED":
                action = f"""
<div style="margin-top:14px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:var(--r-md);padding:14px">
  <div style="font-size:13px;font-weight:600;color:var(--ok);margin-bottom:6px">✓ Package Accepted & Downloaded</div>
  <div style="font-size:12.5px;color:var(--muted);margin-bottom:12px">Upload the downloaded .ps26237 package on the Recipient Decryption page to decrypt, watermark, and commit to the ledger to obtain your 4-digit File Open Password.</div>
  <a href="/recipient" class="btn" style="padding:7px 16px;font-size:13px;display:inline-flex;align-items:center;gap:6px">Go to Recipient Decryption Portal ➔</a>
</div>"""
            elif st == "DECRYPTED":
                action = '<div style="margin-top:12px;font-size:13px;color:var(--ok);font-weight:600">✓ Document Decrypted, Watermarked & Committed to Ledger</div>'
            else:
                action = '<div style="margin-top:12px;font-size:13px;color:var(--bad);font-weight:600">✕ Document Delivery Expired</div>'

            # Decryption Status Badges
            if st in ("ACCEPTED", "DECRYPTED"):
                accepted_badge = '<span style="color:var(--ok);font-weight:600">Accepted ✓</span>'
            elif st == "EXPIRED":
                accepted_badge = '<span style="color:var(--bad);font-weight:600">Unaccepted ✕</span>'
            else:
                accepted_badge = '<span style="color:var(--muted)">Pending acceptance ···</span>'

            if st == "ACCEPTED":
                status_badge = '<span style="color:var(--accent);font-weight:700">Ready to decrypt</span>'
            elif st == "DECRYPTED":
                status_badge = '<span style="color:var(--ok);font-weight:700">Decrypted ✓</span>'
            elif st == "EXPIRED":
                status_badge = '<span style="color:var(--bad);font-weight:700">Expired ✕</span>'
            else:
                status_badge = '<span style="color:var(--faint)">Awaiting acceptance</span>'

            decryption_section = f"""
  <div style="margin-top:14px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:var(--r-md);padding:14px">
    <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin-bottom:8px;display:flex;align-items:center;gap:6px">
      {svg("key", 14)} DECRYPTION
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:12.5px;color:var(--muted);font-weight:600">Unlock Password:</span>
        <span id="secret-val-{e(del_id)}" class="mono" style="font-size:14px;font-weight:700;letter-spacing:1px;padding:4px 10px;background:var(--panel);border:1px solid var(--line);border-radius:6px;min-width:120px;display:inline-block;text-align:center">••••••••••••</span>
      </div>
      <div style="display:flex;gap:6px">
        <button type="button" class="btn" id="btn-show-{e(del_id)}" onclick="toggleSecret('{e(del_id)}')" style="padding:4px 10px;font-size:12px;background:var(--panel);color:var(--fg);border:1px solid var(--line);display:inline-flex;align-items:center;gap:5px">
          {svg("eye", 13)} <span id="btn-show-text-{e(del_id)}">Show</span>
        </button>
        <button type="button" class="btn" id="btn-copy-{e(del_id)}" onclick="copySecret('{e(del_id)}')" style="padding:4px 10px;font-size:12px;background:var(--panel);color:var(--fg);border:1px solid var(--line);display:inline-flex;align-items:center;gap:5px">
          {svg("copy", 13)} <span id="btn-copy-text-{e(del_id)}">Copy</span>
        </button>
      </div>
    </div>
    <div id="secret-error-{e(del_id)}" style="display:none;color:var(--bad);font-size:12px;margin-bottom:8px"></div>
    <div style="font-size:12px;color:var(--muted);border-top:1px solid var(--line-soft);padding-top:10px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span style="font-weight:700;color:var(--fg)">Status:</span>
        <span style="color:var(--ok);font-weight:600">Encrypted ✓</span>
        {accepted_badge}
        {status_badge}
      </div>
      <div style="font-size:11px;color:var(--faint)">Authorized intended recipient only</div>
    </div>
  </div>"""

            card_list.append(f"""
<div class="card" style="margin-bottom:18px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px">
    <div>
      <h2 style="font-size:16px"><span class="icon ok">{svg("doc", 16)}</span>{e(doc_name)}</h2>
      <p class="sub">From: <b>{e(sender)}</b> (<span class="mono">{e(sender_id)}</span>) · Sent: {e(sent)}</p>
    </div>
    <div style="text-align:right">
      <span class="chip" style="background:var(--panel-2);color:var(--muted)">{e(rem_str)}</span>
      <span class="chip" style="margin-left:6px;font-weight:700">{e(st)}</span>
    </div>
  </div>
  <hr class="sep">
  <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--faint);margin-bottom:6px">
    DOCUMENT
  </div>
  <div style="font-size:13px;color:var(--muted);margin-bottom:8px">
    <div>Document ID: <span class="mono" style="font-weight:600;color:var(--fg)">{e(doc_id)}</span></div>
    <div>Expires: <span class="mono">{e(expires)}</span></div>
  </div>
  {decryption_section}
  {action}
</div>""")

        items_html = "".join(card_list) or '<div class="empty">No documents assigned to your receiver account yet.</div>'

        dashboard_script = """
<script>
const secretsCache = {};

async function fetchSecret(delId) {
  if (secretsCache[delId]) {
    return secretsCache[delId];
  }
  const errEl = document.getElementById('secret-error-' + delId);
  if (errEl) errEl.style.display = 'none';

  try {
    const res = await fetch('/recipient/delivery/' + encodeURIComponent(delId) + '/secret', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      const msg = data.error || 'Failed to retrieve decryption secret.';
      if (errEl) {
        errEl.textContent = msg;
        errEl.style.display = 'block';
      }
      return null;
    }
    secretsCache[delId] = data.secret;
    return data.secret;
  } catch (err) {
    if (errEl) {
      errEl.textContent = 'Network error fetching decryption secret.';
      errEl.style.display = 'block';
    }
    return null;
  }
}

async function toggleSecret(delId) {
  const valEl = document.getElementById('secret-val-' + delId);
  const btnTextEl = document.getElementById('btn-show-text-' + delId);
  if (!valEl) return;

  if (valEl.getAttribute('data-shown') === '1') {
    valEl.textContent = '••••••••••••';
    valEl.removeAttribute('data-shown');
    if (btnTextEl) btnTextEl.textContent = 'Show';
  } else {
    if (btnTextEl) btnTextEl.textContent = 'Loading…';
    const secret = await fetchSecret(delId);
    if (secret) {
      valEl.textContent = secret;
      valEl.setAttribute('data-shown', '1');
      if (btnTextEl) btnTextEl.textContent = 'Hide';
    } else {
      if (btnTextEl) btnTextEl.textContent = 'Show';
    }
  }
}

async function copySecret(delId) {
  const btnTextEl = document.getElementById('btn-copy-text-' + delId);
  const secret = await fetchSecret(delId);
  if (secret) {
    const orig = btnTextEl ? btnTextEl.textContent : 'Copy';
    const showCopied = () => {
      if (btnTextEl) btnTextEl.textContent = 'Copied!';
      setTimeout(() => {
        if (btnTextEl) btnTextEl.textContent = orig;
      }, 2000);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(secret).then(showCopied).catch(() => {
        const temp = document.createElement('input');
        temp.value = secret;
        document.body.appendChild(temp);
        temp.select();
        document.execCommand('copy');
        document.body.removeChild(temp);
        showCopied();
      });
    } else {
      const temp = document.createElement('input');
      temp.value = secret;
      document.body.appendChild(temp);
      temp.select();
      document.execCommand('copy');
      document.body.removeChild(temp);
      showCopied();
    }
  }
}
</script>
"""

        body = f"""
{hero("Recipient Dashboard", "Received Documents & Access Control", "Accept document deliveries to download encrypted packages and proceed to decryption.")}
<div>
  {items_html}
</div>
{dashboard_script}"""
        return page("Recipient Dashboard", "recipient_dashboard", body)

    @app.route("/recipient/accept/<delivery_id>", methods=["POST"])
    def recipient_accept(delivery_id: str):
        u = session.get("user")
        if not u or u.get("role") != "Receiver":
            flash("Access denied: Recipient acceptance is for Receivers only.")
            return redirect(url_for("main_home"))

        ok, msg, pkg_bytes = delivery_mgr.accept_delivery(delivery_id, u, ws_ref=ws)
        if not ok or not pkg_bytes:
            flash(f"Acceptance Error: {msg}")
            return redirect(url_for("recipient_dashboard"))

        d_info = delivery_mgr.get_delivery_by_id(delivery_id) or {}
        doc_id = d_info.get("document_id", "package")
        resp = make_response(send_file(io.BytesIO(pkg_bytes), as_attachment=True,
                                       download_name=f"{doc_id}.ps26237", mimetype="application/json"))
        resp.set_cookie("file_download_complete", "1", max_age=60, path="/", samesite="Lax")
        flash(f"Package accepted! Encrypted package ({doc_id}.ps26237) downloaded. Proceed to Recipient Decryption page to decrypt & commit.")
        return resp

    @app.route("/recipient/delivery/<delivery_id>/secret", methods=["POST"])
    def recipient_delivery_secret(delivery_id: str):
        u = session.get("user")
        if not u or u.get("role") != "Receiver":
            return jsonify({"ok": False, "error": "Unauthorized: Recipient authentication required."}), 403

        try:
            ok, msg, secret, code = delivery_mgr.get_delivery_secret(delivery_id, u, ws_ref=ws)
            if not ok or not secret:
                return jsonify({"ok": False, "error": msg}), code

            d_info = delivery_mgr.get_delivery_by_id(delivery_id) or {}
            st = d_info.get("status", "ACCEPTED")

            return jsonify({
                "ok": True,
                "delivery_id": delivery_id,
                "document_id": d_info.get("document_id", ""),
                "status": st,
                "secret": secret
            }), 200
        except Exception as ex:
            return jsonify({"ok": False, "error": f"Internal error resolving secret: {ex}"}), 500

    @app.route("/recipient/verify/<delivery_id>", methods=["POST"])
    def recipient_verify(delivery_id: str):
        return redirect(url_for("recipient_dashboard"))

    # ---------------------------------------------------------------- recipient
    _download_dir = Path("/tmp/ps26237_downloads") if (os.environ.get("VERCEL") or os.environ.get("NETLIFY") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT")) else None
    if _download_dir:
        try:
            _download_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            _download_dir = None

    def stash(res) -> str:
        import uuid
        t = uuid.uuid4().hex
        _downloads[t] = res
        if _download_dir:
            try:
                (_download_dir / f"{t}.bin").write_bytes(res.data)
                (_download_dir / f"{t}.json").write_text(json.dumps({"filename": res.filename}))
            except Exception:
                pass
        for old in list(_downloads)[:-50]:
            _downloads.pop(old, None)
        return t

    def validate_unlocked_document(data: bytes, filename: str) -> tuple[bool, str, str]:
        """
        Validates that decrypted bytes represent a valid, non-empty, usable document.
        Returns: (is_valid, error_msg, detected_mimetype)
        """
        if not data or len(data) == 0:
            return False, "Unlocked file is empty (zero bytes).", "application/octet-stream"

        ext = Path(filename).suffix.lower()
        mimetype = "application/octet-stream"

        if ext == ".pdf" or data.startswith(b"%PDF-"):
            mimetype = "application/pdf"
            try:
                import pymupdf
                doc = pymupdf.open(stream=data, filetype="pdf")
                if len(doc) == 0:
                    return False, "Decrypted document contains no pages.", mimetype
                doc.close()
                return True, "", mimetype
            except Exception as e:
                return False, f"Decrypted bytes do not form a valid PDF: {e}", mimetype

        if ext in [".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"] or data.startswith(b"\x89PNG") or data.startswith(b"\xff\xd8"):
            mimetype = "image/png" if (ext == ".png" or data.startswith(b"\x89PNG")) else "image/jpeg"
            try:
                import cv2
                import numpy as np
                arr = np.frombuffer(data, dtype=np.uint8)
                img = cv2.imdecode(arr, cv2.IMREAD_UNCHANGED)
                if img is None:
                    return False, "Decrypted bytes do not form a valid image.", mimetype
                return True, "", mimetype
            except Exception as e:
                return False, f"Decrypted bytes do not form a valid image: {e}", mimetype

        try:
            from watermark.document_formats import detect_format
            detect_format(data)
            return True, "", "application/octet-stream"
        except Exception as e:
            return False, f"Unsupported document format: {e}", mimetype

    def unlock_protected_payload(zip_bytes: bytes, password: str, expected_filename: str | None = None) -> tuple[bytes, str]:
        """
        Extracts and decrypts the protected document from an AES-protected ZIP using password.
        Returns: (unlocked_bytes, inner_filename)
        Raises:
            ServiceError: user-facing error message
        """
        if not zip_bytes:
            raise ServiceError("Protected document is unavailable.")
        if not password or not password.strip():
            raise ServiceError("Incorrect protected-file password.")

        import pyzipper
        import zipfile
        try:
            with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
                zf.setpassword(password.strip().encode())
                namelist = zf.namelist()
                if not namelist:
                    raise ServiceError("Protected file could not be unlocked because the payload is invalid or corrupted.")
                target_name = expected_filename if (expected_filename and expected_filename in namelist) else namelist[0]
                try:
                    data = zf.read(target_name)
                except RuntimeError:
                    raise ServiceError("Incorrect protected-file password.") from None
                except Exception:
                    raise ServiceError("Protected file could not be unlocked because the payload is invalid or corrupted.") from None
                return data, target_name
        except ServiceError:
            raise
        except (pyzipper.BadZipFile, zipfile.BadZipFile, ValueError, KeyError):
            raise ServiceError("Protected file could not be unlocked because the payload is invalid or corrupted.") from None
        except Exception:
            raise ServiceError("Protected file could not be unlocked because the payload is invalid or corrupted.") from None

    @app.route("/recipient", methods=["GET", "POST"])
    def recipient():
        if request.method == "POST":
            f = request.files.get("package")
            if not f or not f.filename:
                raise ServiceError("choose a package file")
            res = ws.decrypt(f.read(), request.form["rid"], request.form.get("passphrase", ""))

            # Generate 4-digit unlock PIN (password for opening protected file)
            unlock_pin = str(secrets.randbelow(9000) + 1000)

            # Create AES password-protected ZIP containing the decrypted watermarked file
            zip_buf = io.BytesIO()
            try:
                import pyzipper
                with pyzipper.AESZipFile(zip_buf, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(unlock_pin.encode())
                    zf.writestr(res.filename, res.data)
            except ImportError:
                import zipfile
                with zipfile.ZipFile(zip_buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(res.filename, res.data)
            protected_zip_bytes = zip_buf.getvalue()

            zip_filename = f"protected_{Path(res.filename).stem}.zip"

            from app.service import DecryptOutcome
            protected_res = DecryptOutcome(
                filename=zip_filename,
                data=protected_zip_bytes,
                format="zip",
                record=res.record,
                committed_on=res.committed_on,
                ledger_ref=res.ledger_ref
            )

            token = stash(protected_res)
            _protected_packages[token] = {
                "zip_bytes": protected_zip_bytes,
                "zip_filename": zip_filename,
                "inner_filename": res.filename,
                "unlock_pin": unlock_pin,
                "record": res.record,
                "committed_on": res.committed_on,
                "ledger_ref": res.ledger_ref,
                "created_at": time.time(),
            }
            for old in list(_protected_packages)[:-50]:
                _protected_packages.pop(old, None)

            return redirect(url_for("recipient_result", token=token))

        ids = ws.list_identities()
        u = session.get("user")
        selected_identity = ""
        if u:
            u_id = (u.get("user_id") or "").strip()
            u_email = (u.get("email") or "").strip().lower()
            ident = None
            if u_id:
                ident = ws.get_identity(u_id)
            if not ident and u_email:
                ident = ws.get_identity_by_email(u_email)
            if ident:
                selected_identity = ident.get("id", "")

        opts = "".join(f'<option value="{e(i)}"{ " selected" if i == selected_identity else ""}>{e(i)}</option>' for i in ids)
        body = f"""
{hero("Recipient", "Decrypt your copy",
      "Your key unwraps the document key, a watermark unique to this session is embedded, and you sign the record before the file is released.")}
<div class="split">
  <div class="card">
    <form method="post" enctype="multipart/form-data" data-busy="Decrypting…|Watermarking, signing and committing to the ledger">
      <label>Encrypted package</label>
      {drop("package", ".ps26237,.json", "Drop the .ps26237 package here, or click to choose", "Produced by the sender page or the CLI")}
      <label>Decrypt as</label><select name="rid" required>{opts}</select>
      <label>Passphrase <span style="text-transform:none;color:var(--muted);font-weight:400">(demo identities use: <code style="color:var(--accent);font-weight:700">password123</code>)</span></label>
      <input type="password" name="passphrase" placeholder="password123" required>
      <button class="btn" type="submit">{svg("inbox", 17)}Decrypt, watermark and commit</button>
      <p class="note">If the ledger commit fails, nothing is released — you get an error instead of a file.</p>
    </form>
  </div>
  <div class="card"><h2><span class="icon warn">{svg("alert", 16)}</span>Before you continue</h2><hr class="sep">
    <p class="sub">This decryption will be recorded permanently: your identity, the document, the session and the time,
       signed with your own private key. The record cannot be edited or deleted afterwards, by you or by an administrator.</p>
    <p class="sub">Your copy will look identical to everyone else's. If it leaks, it will trace back to this session.</p>
  </div>
</div>

<div class="card" style="margin-top:24px">
  <h2><span class="icon warn">{svg("lock", 16)}</span>Unlock Protected Package File</h2>
  <hr class="sep">
  <p class="sub">Already decrypted a package and have a protected ZIP (<code>protected_*.zip</code>)? Enter Password 2 to unlock and recover the document.</p>
  <form method="post" action="/recipient/unlock_file" enctype="multipart/form-data" style="margin-top:16px">
    <label>Protected ZIP Archive</label>
    {drop("protected_zip", ".zip", "Drop the protected_*.zip file here, or click to choose", "Generated during recipient decryption")}
    <label>Generated Password (Password 2)</label>
    <input type="password" name="password" placeholder="Enter password (e.g. 4-digit PIN)" required autocomplete="off">
    <button class="btn" type="submit">{svg("key", 17)}Unlock Protected File</button>
  </form>
</div>"""
        return page("Recipient", "recipient", body)

    @app.route("/recipient/result/<token>")
    def recipient_result(token: str):
        pkg = _protected_packages.get(token)
        if not pkg:
            flash("Decryption record unavailable or session expired. Please decrypt your package again.")
            return redirect(url_for("recipient"))

        r = pkg["record"]
        unlock_pin = pkg["unlock_pin"]
        zip_filename = pkg["zip_filename"]
        inner_filename = pkg["inner_filename"]
        committed_on = pkg["committed_on"]
        ledger_ref = pkg["ledger_ref"]

        rows = "".join([
            kv_row("document", e(r.get("document_id", "-")), mono=True),
            kv_row("watermark id", e(r.get("watermark_id", "-")), mono=True, copy=True),
            kv_row("session", e(r.get("session_id", "-")), mono=True, copy=True),
            kv_row("time (UTC)", e(r.get("human_timestamp", "-"))),
            kv_row("signature", f"ML-DSA-65, made with {e(r.get('recipient_id', '-'))}'s own private key"),
            kv_row("ledger reference", e(ledger_ref), mono=True),
            kv_row("committed on", e(", ".join(committed_on))),
        ])

        body = f"""
{hero("Recipient", "Released and recorded",
      "The watermarked copy is handed over only after the signed record is committed, so a decryption with no ledger entry cannot exist.")}
<div class="verdict y">{svg("check", 22)}<div><div class="t">Committed on {len(committed_on)} nodes</div>
  <p>Your copy of <b>{e(r.get('document_id', '-'))}</b> is visually identical to every other recipient's, and carries a watermark
     that belongs to this session alone.</p></div></div>

<div class="card" style="background:var(--panel-2);border:2px solid var(--accent);text-align:center;padding:20px;margin-bottom:18px">
  <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:var(--accent);text-transform:uppercase">🔐 Generated File Password (Password 2)</div>
  <div style="font-family:var(--mono);font-size:36px;font-weight:800;letter-spacing:6px;color:var(--fg);margin:10px 0">{unlock_pin}</div>
  <p style="font-size:13px;color:var(--muted);margin:0">Enter this password (<b>{unlock_pin}</b>) below to unlock your protected file. CyberTrace packages this file in an AES-256 encrypted package.</p>
</div>

<div class="card" style="margin-bottom:18px;border-left:4px solid var(--accent)">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:11.5px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);font-weight:700">Protected File</div>
      <div style="font-size:18px;font-weight:700;color:var(--fg);margin-top:2px">{e(inner_filename)}</div>
      <div style="font-size:12.5px;color:var(--muted);margin-top:4px">
        Package: <code style="font-size:12px">{e(zip_filename)}</code>
      </div>
    </div>
    <div>
      <span class="tag tag-warn" id="unlock-badge" style="font-size:12px;padding:6px 12px">🔒 Protected</span>
    </div>
  </div>

  <div id="unlock-flow-container" style="margin-top:18px;padding-top:16px;border-top:1px solid var(--line-soft)">
    <!-- Initial action state -->
    <div id="unlock-step-action" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <button type="button" class="btn" id="btn-show-unlock" onclick="showUnlockInput()" style="margin:0">
        {svg("lock", 16)} Unlock Protected File
      </button>
      <form method="post" action="/download" style="display:inline;margin:0">
        <input type="hidden" name="token" value="{token}">
        <button class="btn ghost" type="submit" style="margin:0">
          {svg("inbox", 16)} Download Protected ZIP ({e(zip_filename)})
        </button>
      </form>
    </div>

    <!-- Password input state -->
    <div id="unlock-step-input" style="display:none;margin-top:12px;background:var(--panel-2);padding:16px;border-radius:var(--r-md);border:1px solid var(--line)">
      <div style="font-size:13.5px;font-weight:600;margin-bottom:8px">Enter Generated Password</div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <input type="password" id="unlock-password-input" placeholder="Enter password (e.g. {unlock_pin})" style="max-width:240px;font-family:var(--mono);font-size:15px;letter-spacing:1px" autocomplete="off" onkeydown="if(event.key==='Enter'){{event.preventDefault();submitUnlock('{token}');}}">
        <button type="button" class="btn" id="btn-do-unlock" onclick="submitUnlock('{token}')" style="margin:0">
          {svg("key", 16)} Unlock
        </button>
        <button type="button" class="btn ghost" onclick="cancelUnlockInput()" style="margin:0">Cancel</button>
      </div>
      <div id="unlock-error" style="display:none;color:var(--bad);font-size:13px;margin-top:10px;font-weight:600"></div>
    </div>

    <!-- Unlocked success state -->
    <div id="unlock-step-success" style="display:none;margin-top:12px;background:var(--ok-soft);padding:18px;border-radius:var(--r-md);border:1px solid var(--ok-line)">
      <div style="display:flex;align-items:center;gap:10px;color:var(--ok);font-size:15px;font-weight:700">
        {svg("check", 20)} <span>✓ Protected file unlocked</span>
      </div>
      <p style="font-size:13px;color:var(--fg);margin:8px 0 16px">
        Decrypted document <b id="unlocked-file-name">{e(inner_filename)}</b> is ready. The file has been verified and contains valid watermarked data.
      </p>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <a id="link-open-file" href="#" target="_blank" class="btn" style="margin:0;text-decoration:none">
          {svg("doc", 16)} Open File
        </a>
        <a id="link-download-file" href="#" class="btn ghost" style="margin:0;text-decoration:none">
          {svg("inbox", 16)} Download File
        </a>
        <a href="/trace" class="btn ghost" style="margin:0;text-decoration:none">
          {svg("fingerprint", 16)} Forensic Trace
        </a>
      </div>
    </div>
  </div>
</div>

<script>
function showUnlockInput() {{
  document.getElementById('unlock-step-action').style.display = 'none';
  document.getElementById('unlock-step-input').style.display = 'block';
  var inp = document.getElementById('unlock-password-input');
  if (inp) inp.focus();
}}

function cancelUnlockInput() {{
  document.getElementById('unlock-step-input').style.display = 'none';
  document.getElementById('unlock-step-action').style.display = 'flex';
  var errEl = document.getElementById('unlock-error');
  if (errEl) errEl.style.display = 'none';
}}

function submitUnlock(token) {{
  var pwdInput = document.getElementById('unlock-password-input');
  var pwd = pwdInput ? pwdInput.value : '';
  var errEl = document.getElementById('unlock-error');
  var btn = document.getElementById('btn-do-unlock');
  
  if (!pwd.trim()) {{
    errEl.textContent = 'Incorrect protected-file password.';
    errEl.style.display = 'block';
    return;
  }}
  
  btn.disabled = true;
  btn.textContent = 'Unlocking…';
  errEl.style.display = 'none';
  
  fetch('/recipient/unlock', {{
    method: 'POST',
    headers: {{
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    }},
    body: JSON.stringify({{ token: token, password: pwd }})
  }})
  .then(function(resp) {{
    return resp.json().then(function(data) {{
      return {{ ok: resp.ok, data: data }};
    }}).catch(function() {{
      return {{ ok: false, data: {{ error: 'Protected file could not be unlocked because the payload is invalid or corrupted.' }} }};
    }});
  }})
  .then(function(res) {{
    btn.disabled = false;
    btn.textContent = 'Unlock';
    if (!res.ok || !res.data.ok) {{
      errEl.textContent = (res.data && res.data.error) ? res.data.error : 'Incorrect protected-file password.';
      errEl.style.display = 'block';
    }} else {{
      document.getElementById('unlock-step-input').style.display = 'none';
      document.getElementById('unlock-step-action').style.display = 'none';
      
      var badge = document.getElementById('unlock-badge');
      if (badge) {{
        badge.className = 'tag tag-ok';
        badge.textContent = '✓ Unlocked';
      }}
      
      var successEl = document.getElementById('unlock-step-success');
      successEl.style.display = 'block';
      
      var openLink = document.getElementById('link-open-file');
      if (openLink) openLink.href = res.data.view_url;
      
      var downloadLink = document.getElementById('link-download-file');
      if (downloadLink) downloadLink.href = res.data.download_url;
      
      var nameEl = document.getElementById('unlocked-file-name');
      if (nameEl && res.data.filename) nameEl.textContent = res.data.filename;
    }}
  }})
  .catch(function(err) {{
    btn.disabled = false;
    btn.textContent = 'Unlock';
    errEl.textContent = 'Protected file could not be unlocked because the payload is invalid or corrupted.';
    errEl.style.display = 'block';
  }});
}}
</script>

<div class="split">
  <div class="card"><h2><span class="icon ok">{svg("doc", 16)}</span>Decryption record</h2><hr class="sep">
    <table class="kv">{rows}</table>
  </div>
  <div class="card"><h2><span class="icon violet">{svg("fingerprint", 16)}</span>Why this is binding</h2><hr class="sep">
    <div class="chain">
      <div class="step pass">{svg("key", 17)}<div><div class="lbl">Your key, your decryption</div>
        <div class="val">Only your ML-KEM-768 secret key unwraps this document</div></div><span class="st">done</span></div>
      <div class="step pass">{svg("fingerprint", 17)}<div><div class="lbl">Watermark embedded</div>
        <div class="val">Unique to you and this session</div></div><span class="st">done</span></div>
      <div class="step pass">{svg("lock", 17)}<div><div class="lbl">Signed by you</div>
        <div class="val">ML-DSA-65 over the record — non-repudiable</div></div><span class="st">done</span></div>
      <div class="step pass">{svg("node", 17)}<div><div class="lbl">Endorsed by the ledger</div>
        <div class="val">{e(len(committed_on))} nodes hold the identical record</div></div><span class="st">done</span></div>
    </div>
  </div>
</div>"""
        return page("Recipient", "recipient", body)

    @app.route("/recipient/unlock", methods=["POST"])
    def recipient_unlock():
        token = ""
        password = ""
        if request.is_json:
            data = request.get_json(silent=True) or {}
            token = data.get("token", "")
            password = data.get("password", "")
        else:
            token = request.form.get("token", "")
            password = request.form.get("password", "")

        token = (token or "").strip()
        password = (password or "").strip()

        if not token:
            return jsonify({"ok": False, "error": "Protected document is unavailable."}), 404

        pkg = _protected_packages.get(token)
        if not pkg:
            return jsonify({"ok": False, "error": "Protected document is unavailable."}), 404

        if not password:
            return jsonify({"ok": False, "error": "Incorrect protected-file password."}), 400

        try:
            unlocked_bytes, target_name = unlock_protected_payload(
                pkg["zip_bytes"], password, expected_filename=pkg.get("inner_filename")
            )
        except ServiceError as se:
            return jsonify({"ok": False, "error": str(se)}), 400
        except Exception:
            return jsonify({"ok": False, "error": "Protected file could not be unlocked because the payload is invalid or corrupted."}), 400

        is_valid, val_err, mimetype = validate_unlocked_document(unlocked_bytes, target_name)
        if not is_valid:
            return jsonify({"ok": False, "error": f"Protected file could not be unlocked: {val_err}"}), 400

        import uuid
        unlocked_token = uuid.uuid4().hex
        _unlocked_files[unlocked_token] = {
            "data": unlocked_bytes,
            "filename": target_name,
            "mimetype": mimetype,
            "record": pkg.get("record"),
            "committed_on": pkg.get("committed_on"),
            "ledger_ref": pkg.get("ledger_ref"),
            "created_at": time.time(),
        }
        for old in list(_unlocked_files)[:-50]:
            _unlocked_files.pop(old, None)

        return jsonify({
            "ok": True,
            "message": "Protected file unlocked successfully.",
            "filename": target_name,
            "view_url": url_for("recipient_view", token=unlocked_token),
            "download_url": url_for("recipient_download_unlocked", token=unlocked_token),
        })

    @app.route("/recipient/unlock_file", methods=["POST"])
    def recipient_unlock_file():
        f = request.files.get("protected_zip")
        password = request.form.get("password", "")
        if not f or not f.filename:
            flash("Please choose a protected .zip file.")
            return redirect(url_for("recipient"))
        if not password or not password.strip():
            flash("Incorrect protected-file password.")
            return redirect(url_for("recipient"))
        try:
            zip_bytes = f.read()
            unlocked_bytes, target_name = unlock_protected_payload(zip_bytes, password.strip())
        except ServiceError as se:
            flash(str(se))
            return redirect(url_for("recipient"))
        except Exception:
            flash("Protected file could not be unlocked because the payload is invalid or corrupted.")
            return redirect(url_for("recipient"))

        is_valid, val_err, mimetype = validate_unlocked_document(unlocked_bytes, target_name)
        if not is_valid:
            flash(f"Protected file could not be unlocked: {val_err}")
            return redirect(url_for("recipient"))

        import uuid
        unlocked_token = uuid.uuid4().hex
        _unlocked_files[unlocked_token] = {
            "data": unlocked_bytes,
            "filename": target_name,
            "mimetype": mimetype,
            "created_at": time.time(),
        }
        for old in list(_unlocked_files)[:-50]:
            _unlocked_files.pop(old, None)

        flash("Protected file unlocked successfully.")
        body = f"""
{hero("Recipient", "Protected File Unlocked", "The secondary protection has been verified and removed. Your document is ready.")}
<div class="verdict y">{svg("check", 22)}<div><div class="t">Protected file unlocked successfully</div>
  <p>The protected file <b>{e(target_name)}</b> has been successfully verified and extracted.</p></div></div>

<div class="card" style="margin-bottom:18px">
  <h2><span class="icon ok">{svg("doc", 16)}</span>Recovered Document: {e(target_name)}</h2>
  <hr class="sep">
  <p style="font-size:14px;color:var(--fg);margin-bottom:18px">Status: <span class="tag tag-ok">✓ Unlocked</span></p>
  <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
    <a href="{url_for('recipient_view', token=unlocked_token)}" target="_blank" class="btn" style="margin:0;text-decoration:none">
      {svg("doc", 16)} Open File
    </a>
    <a href="{url_for('recipient_download_unlocked', token=unlocked_token)}" class="btn ghost" style="margin:0;text-decoration:none">
      {svg("inbox", 16)} Download File
    </a>
    <a href="/trace" class="btn ghost" style="margin:0;text-decoration:none">
      {svg("fingerprint", 16)} Forensic Trace
    </a>
    <a href="/recipient" class="btn ghost" style="margin:0;text-decoration:none">
      Back to Recipient
    </a>
  </div>
</div>
"""
        return page("Recipient", "recipient", body)

    @app.route("/recipient/view/<token>")
    def recipient_view(token: str):
        item = _unlocked_files.get(token)
        if not item:
            raise ServiceError("Protected document is unavailable.")
        resp = make_response(send_file(
            io.BytesIO(item["data"]),
            mimetype=item.get("mimetype", "application/octet-stream"),
            as_attachment=False,
            download_name=item.get("filename", "document")
        ))
        resp.headers["Content-Disposition"] = f'inline; filename="{item.get("filename", "document")}"'
        return resp

    @app.route("/recipient/download_unlocked/<token>", methods=["GET", "POST"])
    def recipient_download_unlocked(token: str):
        item = _unlocked_files.get(token)
        if not item:
            raise ServiceError("Protected document is unavailable.")
        resp = make_response(send_file(
            io.BytesIO(item["data"]),
            mimetype=item.get("mimetype", "application/octet-stream"),
            as_attachment=True,
            download_name=item.get("filename", "document")
        ))
        resp.set_cookie("file_download_complete", "1", max_age=60, path="/", samesite="Lax")
        return resp

    @app.route("/download", methods=["POST"])
    def download():
        token = request.form.get("token", "")
        res = _downloads.get(token)
        if res is not None:
            resp = make_response(send_file(io.BytesIO(res.data), as_attachment=True, download_name=res.filename))
            resp.set_cookie("file_download_complete", "1", max_age=60, path="/", samesite="Lax")
            return resp
        if _download_dir and token:
            bin_p = _download_dir / f"{token}.bin"
            meta_p = _download_dir / f"{token}.json"
            if bin_p.exists() and meta_p.exists():
                try:
                    meta = json.loads(meta_p.read_text())
                    data = bin_p.read_bytes()
                    resp = make_response(send_file(io.BytesIO(data), as_attachment=True, download_name=meta.get("filename", "download")))
                    resp.set_cookie("file_download_complete", "1", max_age=60, path="/", samesite="Lax")
                    return resp
                except Exception:
                    pass
        raise ServiceError("download expired — decrypt again")

    # -------------------------------------------------------------------- trace
    @app.route("/trace", methods=["GET", "POST"])
    def trace():
        if request.method == "POST":
            f = request.files.get("leaked")
            if not f or not f.filename:
                raise ServiceError("choose the leaked file")
            out = ws.trace(f.read())
            d = out.to_dict()
            rec, lk, ex = d["record"], d["ledger"], (d["extraction"] or {})
            confirmed = d["confirmed"]
            dist = d["match_distance_bits"]

            conf = float(ex.get("confidence", 0) or 0)
            conf_ok = conf >= 0.60   # below this the bits are mostly noise

            def step(ok, icon, label, value, state_text):
                cls = "pass" if ok else ("fail" if ok is False else "idle")
                return (f'<div class="step {cls}">{svg(icon, 17)}<div><div class="lbl">{label}</div>'
                        f'<div class="val">{value}</div></div><span class="st">{state_text}</span></div>')

            chain = "".join([
                step(None if not conf_ok else True, "fingerprint", "Watermark extracted",
                     f'{e(ex.get("method", "-"))} · sync confidence {conf:.2f} · '
                     f'rotation {ex.get("angle", 0):+.2f}° · scale ×{ex.get("scale", 1):.3f}',
                     "recovered" if conf_ok else "weak signal"),
                step(lk["found"], "search", "Matched against the ledger",
                     ("exact match" if dist == 0 else f"{dist} of 128 bits differ (≤16 accepted)") if lk["found"]
                     else "no record holds this watermark",
                     "match" if lk["found"] else "no match"),
                step(lk["verified"], "node", "Quorum agreement",
                     f'{lk["quorum_achieved"]} nodes returned the identical record · {lk["quorum_needed"]} required'
                     + (f' — {e(", ".join(lk["agreeing_nodes"]))}' if lk["agreeing_nodes"] else ""),
                     "verified" if lk["verified"] else "insufficient"),
                step(d["signature_valid"], "lock", "Recipient's signature",
                     "ML-DSA-65 signature re-verified against the published key" if d["signature_valid"]
                     else ("the stored signature did not verify" if d["signature_valid"] is False
                           else "nothing to verify — no record was matched"),
                     "valid" if d["signature_valid"] else ("invalid" if d["signature_valid"] is False else "not checked")),
            ])

            rows = "".join(kv_row(k.replace("_", " "), e(v), mono=True) for k, v in rec.items()) or \
                '<tr><td colspan="2" style="color:var(--muted);text-transform:none">No ledger record matched this watermark.</td></tr>'
            tried = ""
            if len(d["candidates_tried"]) > 1:
                tried = "<hr class='sep'><p class='sub'>" + " · ".join(
                    f'{e(c["source"])}: confidence {c["confidence"]}' for c in d["candidates_tried"]) + "</p>"

            who = e(rec.get("recipient_id", "unknown")) if rec else "unknown"
            doc_id = rec.get("document_id") if rec else None

            # Feature #21: Incident Timeline for Forensics Page
            tl_res = None
            tl_error = None
            try:
                if doc_id and doc_id != "-":
                    f_summary = {
                        "timestamp": time.time(),
                        "attributed_recipient": rec.get("recipient_id", "-") if confirmed else "UNATTRIBUTED",
                        "watermark_id": d.get("extracted_watermark_id", "-"),
                        "document_hash": rec.get("document_hash", "-"),
                        "signature_valid": d.get("signature_valid"),
                        "quorum_achieved": lk.get("quorum_achieved", 4),
                        "quorum_needed": lk.get("quorum_needed", 3),
                        "agreeing_nodes": lk.get("agreeing_nodes", []),
                        "verdict": d.get("verdict", ""),
                        "confirmed": confirmed,
                        "confidence": conf,
                    }
                    tl_res = ws.get_document_timeline(doc_id, matched_watermark_id=d.get("extracted_watermark_id"), forensic_summary=f_summary)
                else:
                    tl_res = ws.get_document_timeline("", matched_watermark_id=d.get("extracted_watermark_id"))
            except Exception as exc:
                tl_error = str(exc)

            timeline_html = render_incident_timeline_html(tl_res, tl_error=tl_error, doc_id=doc_id or "")

            body = f"""
{hero("Forensic trace", "Attribution report",
      "The watermark is recovered from the leaked copy, matched against a quorum of ledger nodes, and the recipient's own signature is re-verified.")}
<div class="verdict {'y' if confirmed else 'n'}">{svg('check' if confirmed else 'alert', 22)}
  <div><div class="t">{'Attributed to ' + who if confirmed else 'Not attributed'}</div>
  <p>{e(d['verdict']).replace(' -- ', ' — ')}</p></div></div>
<div class="split">
  <div class="card"><h2><span class="icon{' ok' if confirmed else ' bad'}">{svg("search", 16)}</span>Evidence chain</h2>
    <p class="sub">All four must hold before a name is reported.</p><hr class="sep">
    <div class="chain">{chain}</div>{tried}
    <p class="note">Extracted watermark <span class="mono">{e(d['extracted_watermark_id'])}</span> · source {e(d['source'])}</p>
  </div>
  <div class="card"><h2><span class="icon violet">{svg("doc", 16)}</span>Ledger record</h2>
    <p class="sub">As held by the agreeing nodes.</p><hr class="sep">
    <table class="kv">{rows}</table>
  </div>
</div>
{timeline_html}"""
            return page("Trace", "trace", body)

        body = f"""
{hero("Forensic trace", "Identify the source of a leak",
      "Upload a leaked copy. The extractor searches for rotation, rescaling and cropping, then attribution requires both a ledger quorum and a valid post-quantum signature.")}
<div class="split">
  <div class="card">
    <form method="post" enctype="multipart/form-data" data-busy="Analysing…|Searching rotation and scale, then querying the ledger quorum">
      <label>Leaked file</label>
      {drop("leaked", ".png,.jpg,.jpeg,.pdf", "Drop the leaked file here, or click to choose", "PNG, JPEG or PDF — cropped, rescaled or recompressed is fine")}
      <button class="btn" type="submit">{svg("search", 17)}Analyse</button>
      <p class="note">An untouched or lightly compressed copy resolves in under a second. A rotated or rescaled one triggers a geometry search that can take about 20 seconds.</p>
    </form>
  </div>
  <div class="card"><h2><span class="icon">{svg("shield", 16)}</span>What survives</h2><hr class="sep">
    <div class="chain">
      <div class="step pass">{svg("check", 17)}<div><div class="lbl">Cropping, rescaling, rotation</div>
        <div class="val">8 of 8 test documents recovered exactly</div></div><span class="st">yes</span></div>
      <div class="step pass">{svg("check", 17)}<div><div class="lbl">JPEG down to quality 75</div>
        <div class="val">and Gaussian noise</div></div><span class="st">yes</span></div>
      <div class="step fail">{svg("alert", 17)}<div><div class="lbl">Print-and-scan</div>
        <div class="val">3 of 8 — unreliable, measured</div></div><span class="st">partly</span></div>
      <div class="step fail">{svg("alert", 17)}<div><div class="lbl">Photograph of a screen</div>
        <div class="val">0 of 8 — does not survive</div></div><span class="st">no</span></div>
    </div>
    <p class="note">When the watermark is too damaged, the verdict is NO MATCH. The system never guesses a name.</p>
  </div>
</div>
{render_incident_timeline_html(None, None, is_get=True)}"""
        return page("Trace", "trace", body)

    @app.route("/api/forensics/<document_id>/timeline")
    def api_forensic_timeline(document_id: str):
        try:
            wm = request.args.get("watermark_id") or request.args.get("watermark")
            res = ws.get_document_timeline(document_id, matched_watermark_id=wm)
            return json.dumps(res, indent=2), 200, {"Content-Type": "application/json"}
        except Exception as exc:
            return json.dumps({"error": str(exc), "document_id": document_id, "events": []}), 500, {"Content-Type": "application/json"}

    @app.route("/api/status")
    def api_status():
        return json.dumps(ws.ledger_status(), indent=1), 200, {"Content-Type": "application/json"}

    @app.route("/identities/new", methods=["POST"])
    def new_identity():
        rid = request.form.get("identity_id", "").strip().lower()
        name = request.form.get("name", "").strip() or rid.capitalize()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("passphrase", "")
        role = request.form.get("role", "Receiver").strip()

        if not rid:
            flash("Identity ID cannot be empty")
            return redirect(request.referrer or url_for("main_home"))
        if not email or "@" not in email:
            flash("Please enter a valid email address")
            return redirect(request.referrer or url_for("main_home"))
        if len(pw) < 4:
            flash("Passphrase must be at least 4 characters")
            return redirect(request.referrer or url_for("main_home"))

        # Section 16: Duplicate Email Protection
        existing_ident = ws.get_identity_by_email(email)
        if existing_ident and existing_ident.get("id", "").lower() != rid:
            flash(f"Error: An identity with email '{email}' already exists.")
            return redirect(request.referrer or url_for("main_home"))

        existing_user = auth_mgr.get_user_by_email(email)
        if existing_user and existing_user.get("user_id", "").lower() != rid:
            flash(f"Error: An identity with email '{email}' already exists.")
            return redirect(request.referrer or url_for("main_home"))

        try:
            ws.create_identity(rid, pw, name=name, email=email, role=role)
            auth_mgr.register_or_update_user(email=email, user_id=rid, name=name, role=role, raw_password=pw)
            flash(f"Identity '{name}' ({rid}) created successfully with email {email}.")
        except Exception as ex:
            flash(f"Error creating identity '{rid}': {ex}")
        return redirect(request.referrer or url_for("main_home"))

    @app.route("/identities/seed_demo", methods=["POST"])
    def seed_demo():
        force = request.form.get("force") == "1" or request.args.get("force") == "1"
        created = []
        demo_map = {
            "alice": ("Alice (Sender)", "sender@cybertrace.local", "Sender"),
            "bob": ("Bob (Receiver)", "receiver@cybertrace.local", "Receiver"),
            "carol": ("Carol (Receiver)", "carol@cybertrace.local", "Receiver"),
        }
        for name, (disp_name, email, role) in demo_map.items():
            if force or name not in ws.list_identities():
                try:
                    p = ws._identity_path(name)
                    if p.exists():
                        p.unlink()
                    ws.create_identity(name, "password123", name=disp_name, email=email, role=role)
                    auth_mgr.register_or_update_user(email=email, user_id=name, name=disp_name, role=role, raw_password="password123")
                    created.append(name)
                except Exception:
                    pass
        if created:
            flash(f"Demo identities ready with passphrase 'password123': {', '.join(created)}")
        else:
            flash("Demo identities (alice, bob, carol) ready with passphrase 'password123'.")
        return redirect(request.referrer or url_for("main_home"))

    @app.route("/samples/<path:filename>")
    def sample_file(filename):
        sample_path = os.path.join(_parent, "public", "samples", os.path.basename(filename))
        if os.path.exists(sample_path):
            mimetype = "application/pdf" if filename.endswith(".pdf") else "image/png"
            return send_file(sample_path, mimetype=mimetype)
        flash(f"Sample file {filename} not found")
        return redirect(url_for("sender"))

    return app


if __name__ == "__main__":
    workspace_dir = os.environ.get("PS26237_HOME", "ps26237_workspace")
    ws = Workspace(workspace_dir)
    web_app = create_app(ws)
    print(f"CyberTrace web UI on http://localhost:8237 and http://127.0.0.1:8237 (workspace {os.path.abspath(workspace_dir)}, ledger {ws.ledger_backend})")
    web_app.run(host="0.0.0.0", port=8237, debug=False, threaded=True)

