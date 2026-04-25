/* =============================================
   PhishGuard — Frontend Application Logic
   ============================================= */

const API_BASE = '';  // Same origin (Flask serves frontend)

// ─────────────────────────────────────────────
// Sample phishing email for demo
// ─────────────────────────────────────────────
const SAMPLE_EMAIL = `From: PayPal Security <security@paypa1-support.xyz>
Reply-To: phisher@gmail.com
Return-Path: <bounce@evil-mailer.ru>
To: customer@example.com
Subject: URGENT: Your PayPal account has been suspended!
Date: Mon, 25 Apr 2026 10:00:00 +0000

Dear Customer,

We have detected suspicious activity on your PayPal account. Your account has been temporarily suspended due to unauthorized access attempts.

You must verify your account IMMEDIATELY or it will be permanently closed within 24 hours.

Click here to restore your account now:
http://paypa1-verify.xyz/restore?token=abc123

Alternatively visit: http://192.168.1.254/paypal/login

We have also sent a document to review: Account_Statement.exe

Failure to respond immediately will result in legal action and your account will be permanently terminated.

Congratulations! You have also won a $500 reward. Claim your prize here:
https://bit.ly/freeprize99

PayPal Security Team`;

// ─────────────────────────────────────────────
// DOM Refs
// ─────────────────────────────────────────────
const emailInput   = document.getElementById('email-input');
const charCount    = document.getElementById('char-count');
const btnAnalyze   = document.getElementById('btn-analyze');
const btnLoader    = document.getElementById('btn-loader');
const btnText      = btnAnalyze.querySelector('.btn-text');
const btnIcon      = btnAnalyze.querySelector('.btn-icon');
const inputSection = document.getElementById('input-section');
const resultsPanel = document.getElementById('results-panel');

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}

// ─────────────────────────────────────────────
// Char counter
// ─────────────────────────────────────────────
emailInput.addEventListener('input', () => {
  const n = emailInput.value.length;
  charCount.textContent = `${n.toLocaleString()} character${n !== 1 ? 's' : ''}`;
});

// ─────────────────────────────────────────────
// Load sample
// ─────────────────────────────────────────────
document.getElementById('btn-sample').addEventListener('click', () => {
  emailInput.value = SAMPLE_EMAIL;
  emailInput.dispatchEvent(new Event('input'));
  emailInput.focus();
});

// ─────────────────────────────────────────────
// Clear
// ─────────────────────────────────────────────
document.getElementById('btn-clear').addEventListener('click', () => {
  emailInput.value = '';
  emailInput.dispatchEvent(new Event('input'));
  emailInput.focus();
});

// ─────────────────────────────────────────────
// Reset to input view
// ─────────────────────────────────────────────
function resetAnalysis() {
  resultsPanel.style.display = 'none';
  inputSection.style.display = 'block';
  inputSection.scrollIntoView({ behavior: 'smooth' });
}

// ─────────────────────────────────────────────
// Set button loading state
// ─────────────────────────────────────────────
function setLoading(loading) {
  btnAnalyze.disabled = loading;
  btnLoader.style.display = loading ? 'block' : 'none';
  btnIcon.style.display   = loading ? 'none'  : 'block';
  btnText.textContent     = loading ? 'Analyzing…' : 'Analyze Email';
}

// ─────────────────────────────────────────────
// Main analyze function
// ─────────────────────────────────────────────
async function analyzeEmail() {
  const email = emailInput.value.trim();

  if (!email) {
    shakeTextarea();
    showToast('Please paste an email to analyze.');
    return;
  }
  if (email.length < 20) {
    showToast('Email content is too short. Please include more text.');
    return;
  }

  setLoading(true);

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server error: ${res.status}`);
    }

    const data = await res.json();
    renderReport(data);

    inputSection.style.display = 'none';
    resultsPanel.style.display = 'flex';
    resultsPanel.scrollIntoView({ behavior: 'smooth' });

  } catch (err) {
    showToast('Error: ' + err.message);
    console.error(err);
  } finally {
    setLoading(false);
  }
}

// ─────────────────────────────────────────────
// Render Report
// ─────────────────────────────────────────────
function renderReport(data) {
  const { risk, findings, url_analysis, headers, finding_counts, url_count } = data;

  // -- Risk Header --
  renderRiskHeader(risk);

  // -- Stat Cards --
  renderStatCards(risk, finding_counts, url_count);

  // -- Findings --
  const findingsBlock = document.getElementById('findings-block');
  const findingsList  = document.getElementById('findings-list');
  if (findings && findings.length > 0) {
    findingsList.innerHTML = findings.map((f, i) => renderFinding(f, i)).join('');
    findingsBlock.style.display = 'block';
  } else {
    findingsBlock.style.display = 'none';
  }

  // -- URL Table --
  const urlBlock = document.getElementById('url-block');
  const urlBody  = document.getElementById('url-table-body');
  if (url_analysis && url_analysis.length > 0) {
    urlBody.innerHTML = url_analysis.map(renderUrlRow).join('');
    urlBlock.style.display = 'block';
  } else {
    urlBlock.style.display = 'none';
  }

  // -- Headers --
  const headersBlock = document.getElementById('headers-block');
  const headersGrid  = document.getElementById('headers-grid');
  const headerEntries = Object.entries(headers || {});
  if (headerEntries.length > 0) {
    headersGrid.innerHTML = headerEntries.map(([k, v]) => `
      <div class="header-item">
        <div class="header-key">${escHtml(k)}</div>
        <div class="header-val">${escHtml(truncate(v, 120))}</div>
      </div>
    `).join('');
    headersBlock.style.display = 'block';
  } else {
    headersBlock.style.display = 'none';
  }

  // -- Conclusion --
  renderConclusion(risk);
}

// ─────────────────────────────────────────────
// Risk Header + Gauge
// ─────────────────────────────────────────────
function renderRiskHeader(risk) {
  const riskHeader  = document.getElementById('risk-header');
  const verdictBadge = document.getElementById('verdict-badge');
  const riskLevel   = document.getElementById('risk-level-text');
  const gaugeScore  = document.getElementById('gauge-score');
  const gaugeArc    = document.getElementById('gauge-arc');
  const gaugeNeedle = document.getElementById('gauge-needle');

  // Color the risk header border
  const borderColor = risk.level === 'Safe' ? 'rgba(34,197,94,0.35)'
                    : risk.level === 'Suspicious' ? 'rgba(234,179,8,0.35)'
                    : 'rgba(239,68,68,0.35)';
  riskHeader.style.borderColor = borderColor;

  // Verdict badge & level
  const emojiMap = { 'Safe': '🟢', 'Suspicious': '🟡', 'High Risk': '🔴' };
  verdictBadge.textContent = emojiMap[risk.level] || risk.emoji;
  riskLevel.textContent = `${risk.level} — ${risk.verdict_label}`;
  riskLevel.className = 'risk-level ' + (
    risk.level === 'Safe' ? 'color-safe'
    : risk.level === 'Suspicious' ? 'color-suspicious'
    : 'color-danger'
  );

  // Animate gauge score
  animateNumber(gaugeScore, 0, risk.score, 900);

  // Gauge arc
  // Arc total length ≈ 157 (semicircle circumference for r=50)
  const arcLen = 157;
  const filled = (risk.score / 100) * arcLen;
  setTimeout(() => {
    gaugeArc.style.transition = 'stroke-dasharray 1s ease';
    gaugeArc.setAttribute('stroke-dasharray', `${filled} ${arcLen}`);
  }, 100);

  // Needle rotation: -90° (0) → +90° (100)
  const angle = -90 + (risk.score / 100) * 180;
  setTimeout(() => {
    gaugeNeedle.style.transition = 'transform 1s ease';
    gaugeNeedle.setAttribute('transform', `rotate(${angle}, 60, 65)`);
  }, 100);

  gaugeScore.className = 'gauge-score ' + (
    risk.level === 'Safe' ? 'color-safe'
    : risk.level === 'Suspicious' ? 'color-suspicious'
    : 'color-danger'
  );
}

// ─────────────────────────────────────────────
// Stat Cards
// ─────────────────────────────────────────────
function renderStatCards(risk, finding_counts, url_count) {
  const container = document.getElementById('stat-cards');

  const cards = [
    {
      num: risk.score,
      label: 'Risk Score',
      colorClass: risk.level === 'Safe' ? 'color-safe'
                : risk.level === 'Suspicious' ? 'color-suspicious'
                : 'color-danger',
      delay: 0
    },
    {
      num: risk.severity_counts?.high || 0,
      label: 'High Risk Flags',
      colorClass: 'color-danger',
      delay: 80
    },
    {
      num: risk.severity_counts?.medium || 0,
      label: 'Medium Risk Flags',
      colorClass: 'color-suspicious',
      delay: 160
    },
    {
      num: url_count || 0,
      label: 'URLs Detected',
      colorClass: 'color-blue',
      delay: 240
    },
    {
      num: risk.total_findings || 0,
      label: 'Total Findings',
      colorClass: 'color-blue',
      delay: 320
    }
  ];

  container.innerHTML = cards.map((c, i) => `
    <div class="stat-card" style="animation-delay: ${c.delay}ms">
      <div class="stat-num ${c.colorClass}" id="stat-num-${i}">0</div>
      <div class="stat-label">${c.label}</div>
    </div>
  `).join('');

  // Animate numbers after render
  cards.forEach((c, i) => {
    setTimeout(() => {
      const el = document.getElementById(`stat-num-${i}`);
      animateNumber(el, 0, c.num, 700);
    }, c.delay);
  });
}

// ─────────────────────────────────────────────
// Single Finding Item
// ─────────────────────────────────────────────
function renderFinding(f, index) {
  const sevClass = `sev-${f.severity || 'low'}`;
  const typeIcons = {
    sender: '✉️', url: '🔗', homograph: '🔤', content: '📝', other: '⚠️'
  };
  const icon = typeIcons[f.type] || '⚠️';

  return `
    <div class="finding-item ${sevClass}" style="animation-delay: ${index * 60}ms">
      <div class="finding-sev-dot"></div>
      <div class="finding-body" style="flex:1">
        <div class="finding-title">${icon} ${escHtml(f.title)}</div>
        <div class="finding-detail">${escHtml(f.detail)}</div>
      </div>
      <div class="finding-score">+${f.score || 0} pts</div>
    </div>
  `;
}

// ─────────────────────────────────────────────
// URL Table Row
// ─────────────────────────────────────────────
function renderUrlRow(u) {
  const riskClass = u.risk === 'High'   ? 'risk-pill-high'
                  : u.risk === 'Medium' ? 'risk-pill-medium'
                  : 'risk-pill-low';
  return `
    <tr>
      <td>${escHtml(truncate(u.original, 60))}</td>
      <td>${escHtml(truncate(u.domain, 40))}</td>
      <td><span class="risk-pill ${riskClass}">${escHtml(u.risk)}</span></td>
      <td>${escHtml(truncate(u.reason, 80))}</td>
    </tr>
  `;
}

// ─────────────────────────────────────────────
// Conclusion
// ─────────────────────────────────────────────
function renderConclusion(risk) {
  const iconMap   = { Safe: '✅', Suspicious: '⚠️', 'High Risk': '🚨' };
  const titleMap  = {
    Safe:       'Verdict: This email appears safe',
    Suspicious: 'Verdict: Proceed with caution',
    'High Risk':'Verdict: PHISHING DETECTED'
  };

  document.getElementById('conclusion-icon').textContent  = iconMap[risk.level] || '🔍';
  document.getElementById('conclusion-title').textContent = titleMap[risk.level] || 'Analysis Complete';
  document.getElementById('conclusion-text').textContent  = risk.conclusion;

  const block = document.getElementById('conclusion-block');
  const borderColor = risk.level === 'Safe' ? 'rgba(34,197,94,0.3)'
                    : risk.level === 'Suspicious' ? 'rgba(234,179,8,0.3)'
                    : 'rgba(239,68,68,0.3)';
  block.style.borderColor = borderColor;
}

// ─────────────────────────────────────────────
// Animate number counter
// ─────────────────────────────────────────────
function animateNumber(el, from, to, duration) {
  if (!el) return;
  const start = performance.now();
  const diff  = to - from;

  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(from + diff * eased);
    if (progress < 1) requestAnimationFrame(step);
  }

  requestAnimationFrame(step);
}

// ─────────────────────────────────────────────
// Shake textarea on empty submit
// ─────────────────────────────────────────────
function shakeTextarea() {
  emailInput.style.animation = 'none';
  emailInput.offsetHeight; // reflow
  emailInput.style.animation = 'shake 0.4s ease';
  emailInput.style.borderColor = 'rgba(239,68,68,0.6)';
  setTimeout(() => {
    emailInput.style.borderColor = '';
    emailInput.style.animation = '';
  }, 600);
}

// Add shake keyframe dynamically
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `
  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    20%       { transform: translateX(-8px); }
    40%       { transform: translateX(8px); }
    60%       { transform: translateX(-5px); }
    80%       { transform: translateX(5px); }
  }
`;
document.head.appendChild(shakeStyle);

// ─────────────────────────────────────────────
// Toast notification
// ─────────────────────────────────────────────
function showToast(message) {
  let toast = document.getElementById('pg-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'pg-toast';
    toast.style.cssText = `
      position: fixed; bottom: 24px; right: 24px; z-index: 9999;
      background: rgba(20,25,40,0.95); color: #f0f4ff;
      padding: 14px 20px; border-radius: 12px;
      border: 1px solid rgba(239,68,68,0.4);
      font-size: 0.85rem; font-family: Inter, sans-serif;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      backdrop-filter: blur(12px);
      max-width: 320px; line-height: 1.4;
      transition: opacity 0.3s;
    `;
    document.body.appendChild(toast);
  }

  toast.textContent = message;
  toast.style.opacity = '1';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, 4000);
}

// ─────────────────────────────────────────────
// Keyboard shortcut: Ctrl+Enter to analyze
// ─────────────────────────────────────────────
emailInput.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    analyzeEmail();
  }
});
