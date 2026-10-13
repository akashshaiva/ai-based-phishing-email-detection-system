/**
 * AI Phishing Email Detection System - Advanced Cyber SOC Client Application
 * Features:
 * - Live Screen Capture (getDisplayMedia API)
 * - Direct Clipboard Paste (Ctrl+V) & Drag-and-Drop
 * - Client-Side OCR Engine (Tesseract.js)
 * - Multi-Factor Threat Intelligence Visualizer
 * - Incident Report JSON & Print/PDF Export
 */

// Application State
const state = {
  currentTab: 'screenshot',
  selectedImageFile: null,
  imageBase64: null,
  ocrExtractedText: '',
  isScanning: false,
  lastAnalysisResult: null,
  geminiApiKey: localStorage.getItem('phish_gemini_api_key') || '',
  apiBaseUrl: localStorage.getItem('phish_api_base_url') || (window.API_BASE || '')
};

// Returns fully-qualified API URL if apiBaseUrl is configured, else relative path
function getApiUrl(endpoint) {
  const base = (state.apiBaseUrl || '').trim().replace(/\/+$/, '');
  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return base ? `${base}${path}` : path;
}

// DOM Element Selectors
const elements = {
  tabs: document.querySelectorAll('.tab-btn'),
  panes: document.querySelectorAll('.tab-pane'),
  
  // Screenshot Mode
  dropzone: document.getElementById('screenshotDropzone'),
  fileInput: document.getElementById('screenshotFileInput'),
  btnScreenCapture: document.getElementById('btnScreenCapture'),
  previewContainer: document.getElementById('screenshotPreviewContainer'),
  previewImg: document.getElementById('screenshotPreviewImg'),
  ocrProgressBox: document.getElementById('ocrProgressBox'),
  ocrStatusText: document.getElementById('ocrStatusText'),
  ocrProgressBar: document.getElementById('ocrProgressBar'),
  btnAnalyzeScreenshot: document.getElementById('btnAnalyzeScreenshot'),
  btnClearScreenshot: document.getElementById('btnClearScreenshot'),

  // Text Mode
  inputSender: document.getElementById('inputSender'),
  inputSubject: document.getElementById('inputSubject'),
  inputBody: document.getElementById('inputBody'),
  inputHeaders: document.getElementById('inputHeaders'),
  btnAnalyzeText: document.getElementById('btnAnalyzeText'),
  sampleChipsContainer: document.getElementById('sampleChipsContainer'),

  // URL Mode
  inputSingleUrl: document.getElementById('inputSingleUrl'),
  btnAnalyzeUrl: document.getElementById('btnAnalyzeUrl'),
  urlScanResult: document.getElementById('urlScanResult'),

  // Threat Report Elements
  reportContainer: document.getElementById('reportContainer'),
  reportPlaceholder: document.getElementById('reportPlaceholder'),
  verdictHero: document.getElementById('verdictHero'),
  verdictBadge: document.getElementById('verdictBadge'),
  verdictTitle: document.getElementById('verdictTitle'),
  verdictDesc: document.getElementById('verdictDesc'),
  gaugeCircleVal: document.getElementById('gaugeCircleVal'),
  gaugePercent: document.getElementById('gaugePercent'),
  
  // Breakdown Bars
  barMl: document.getElementById('barMl'),
  valMl: document.getElementById('valMl'),
  barUrl: document.getElementById('barUrl'),
  valUrl: document.getElementById('valUrl'),
  barUrgency: document.getElementById('barUrgency'),
  valUrgency: document.getElementById('valUrgency'),
  barHeader: document.getElementById('barHeader'),
  valHeader: document.getElementById('valHeader'),
  barVisual: document.getElementById('barVisual'),
  valVisual: document.getElementById('valVisual'),

  // Report Sections
  flagsList: document.getElementById('flagsList'),
  recsContainer: document.getElementById('recsContainer'),
  highlightEmailBody: document.getElementById('highlightEmailBody'),
  linksTableBody: document.getElementById('linksTableBody'),
  linksTableSection: document.getElementById('linksTableSection'),
  screenshotMetaSection: document.getElementById('screenshotMetaSection'),
  screenshotMetaText: document.getElementById('screenshotMetaText'),

  // Actions
  btnExportJson: document.getElementById('btnExportJson'),
  btnPrintReport: document.getElementById('btnPrintReport'),
  btnCopySummary: document.getElementById('btnCopySummary'),

  // Drawer & Modal
  btnOpenHistory: document.getElementById('btnOpenHistory'),
  btnCloseHistory: document.getElementById('btnCloseHistory'),
  drawerHistory: document.getElementById('drawerHistory'),
  drawerBackdrop: document.getElementById('drawerBackdrop'),
  historyList: document.getElementById('historyList'),

  btnOpenSettings: document.getElementById('btnOpenSettings'),
  btnCloseSettings: document.getElementById('btnCloseSettings'),
  modalSettings: document.getElementById('modalSettings'),
  inputGeminiKey: document.getElementById('inputGeminiKey'),
  inputApiBase: document.getElementById('inputApiBase'),
  btnSaveSettings: document.getElementById('btnSaveSettings')
};

// ============================================================================
// Initialization & Tab Switching
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupScreenshotHandlers();
  setupTextHandlers();
  setupUrlHandlers();
  setupGlobalClipboardPaste();
  setupModalsAndDrawers();
  loadSampleEmails();
  checkSystemHealth();

  if (state.geminiApiKey && elements.inputGeminiKey) {
    elements.inputGeminiKey.value = state.geminiApiKey;
  }
  if (state.apiBaseUrl && elements.inputApiBase) {
    elements.inputApiBase.value = state.apiBaseUrl;
  }
});

function setupTabs() {
  elements.tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.dataset.tab;
      state.currentTab = targetId;

      elements.tabs.forEach(t => t.classList.remove('active'));
      elements.panes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPane = document.getElementById(`tabPane-${targetId}`);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}

// ============================================================================
// Screenshot & Screen Capture Logic
// ============================================================================
function setupScreenshotHandlers() {
  // Dropzone click
  elements.dropzone.addEventListener('click', () => {
    elements.fileInput.click();
  });

  // File input change
  elements.fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) handleImageFile(file);
  });

  // Drag and drop
  elements.dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.dropzone.classList.add('dragover');
  });

  elements.dropzone.addEventListener('dragleave', () => {
    elements.dropzone.classList.remove('dragover');
  });

  elements.dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    elements.dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleImageFile(e.dataTransfer.files[0]);
    }
  });

  // Clear Screenshot
  elements.btnClearScreenshot.addEventListener('click', resetScreenshot);

  // Live Screen Capture Button (getDisplayMedia)
  elements.btnScreenCapture.addEventListener('click', captureLiveScreen);

  // Analyze Screenshot Button
  elements.btnAnalyzeScreenshot.addEventListener('click', () => {
    if (!state.imageBase64 && !state.selectedImageFile) {
      alert("Please upload, paste, or capture a screenshot first.");
      return;
    }
    submitScreenshotAnalysis();
  });
}

// Global Clipboard Paste Handler (Ctrl+V)
function setupGlobalClipboardPaste() {
  window.addEventListener('paste', (e) => {
    const items = (e.clipboardData || e.originalEvent.clipboardData).items;
    for (const item of items) {
      if (item.type.indexOf('image') !== -1) {
        const file = item.getAsFile();
        if (file) {
          // Switch to screenshot tab automatically
          switchTab('screenshot');
          handleImageFile(file);
          break;
        }
      }
    }
  });
}

function switchTab(tabId) {
  state.currentTab = tabId;
  elements.tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
  elements.panes.forEach(p => p.classList.toggle('active', p.id === `tabPane-${tabId}`));
}

function handleImageFile(file) {
  if (!file.type.startsWith('image/')) {
    alert("Please select a valid image file (PNG, JPG, WEBP).");
    return;
  }
  state.selectedImageFile = file;

  const reader = new FileReader();
  reader.onload = (e) => {
    state.imageBase64 = e.target.result;
    displayImagePreview(state.imageBase64);
    // Run client-side OCR automatically
    startClientOCR(state.imageBase64);
  };
  reader.readAsDataURL(file);
}

function displayImagePreview(src) {
  elements.previewImg.src = src;
  elements.previewContainer.style.display = 'block';
  elements.dropzone.style.display = 'none';
  elements.btnAnalyzeScreenshot.disabled = false;
}

function resetScreenshot() {
  state.selectedImageFile = null;
  state.imageBase64 = null;
  state.ocrExtractedText = '';
  elements.fileInput.value = '';
  elements.previewImg.src = '';
  elements.previewContainer.style.display = 'none';
  elements.dropzone.style.display = 'block';
  elements.ocrProgressBox.style.display = 'none';
  elements.btnAnalyzeScreenshot.disabled = true;
}

// Live Screen Capture using browser Web API
async function captureLiveScreen() {
  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      alert("Screen capture is not supported in this browser version. You can paste with Ctrl+V or upload an image.");
      return;
    }

    const stream = await navigator.mediaDevices.getDisplayMedia({
      video: { displaySurface: "window" }
    });

    const video = document.createElement('video');
    video.srcObject = stream;
    await video.play();

    // Create canvas to grab snapshot
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth || 1280;
    canvas.height = video.videoHeight || 720;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    // Stop tracks immediately
    stream.getTracks().forEach(track => track.stop());

    // Get Base64 PNG
    const dataUrl = canvas.toDataURL('image/png');
    state.imageBase64 = dataUrl;
    state.selectedImageFile = null;

    displayImagePreview(dataUrl);
    startClientOCR(dataUrl);

  } catch (err) {
    if (err.name !== 'NotAllowedError') {
      console.warn("Screen capture error:", err);
    }
  }
}

// Client-side OCR with Tesseract.js
async function startClientOCR(imageDataUrl) {
  elements.ocrProgressBox.style.display = 'block';
  elements.ocrStatusText.textContent = "Initializing Optical Character Recognition (OCR)...";
  elements.ocrProgressBar.style.width = '15%';

  // Check if Tesseract.js is loaded
  if (typeof Tesseract === 'undefined') {
    elements.ocrStatusText.textContent = "Tesseract client library loading... (Backend OCR active)";
    elements.ocrProgressBar.style.width = '100%';
    setTimeout(() => { elements.ocrProgressBox.style.display = 'none'; }, 2000);
    return;
  }

  try {
    elements.ocrStatusText.textContent = "Scanning screenshot and extracting text...";
    elements.ocrProgressBar.style.width = '45%';

    const worker = await Tesseract.createWorker('eng');
    
    elements.ocrStatusText.textContent = "Extracting email headers, links, and content...";
    elements.ocrProgressBar.style.width = '75%';

    const ret = await worker.recognize(imageDataUrl);
    state.ocrExtractedText = ret.data.text || '';
    await worker.terminate();

    elements.ocrProgressBar.style.width = '100%';
    elements.ocrStatusText.textContent = `OCR complete! Extracted ${state.ocrExtractedText.split(/\s+/).filter(Boolean).length} words.`;
    
    setTimeout(() => {
      elements.ocrProgressBox.style.display = 'none';
    }, 2500);

  } catch (err) {
    console.warn("Client OCR error:", err);
    elements.ocrStatusText.textContent = "Client OCR bypassed. Backend OCR will process image.";
    elements.ocrProgressBar.style.width = '100%';
    setTimeout(() => { elements.ocrProgressBox.style.display = 'none'; }, 2000);
  }
}

async function submitScreenshotAnalysis() {
  setLoading(true);

  try {
    const payload = {
      image_base64: state.imageBase64,
      client_ocr_text: state.ocrExtractedText,
      gemini_api_key: state.geminiApiKey,
      mime_type: state.selectedImageFile ? state.selectedImageFile.type : 'image/png'
    };

    const response = await fetch(getApiUrl('/api/analyze/image-base64'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Image analysis failed.");
    }

    const data = await response.json();
    state.lastAnalysisResult = data;
    renderThreatReport(data);

  } catch (error) {
    alert(`Error analyzing screenshot: ${error.message}`);
  } finally {
    setLoading(false);
  }
}

// ============================================================================
// Text Email Analysis Logic
// ============================================================================
function setupTextHandlers() {
  elements.btnAnalyzeText.addEventListener('click', submitTextAnalysis);
}

async function submitTextAnalysis() {
  const body = elements.inputBody.value.trim();
  const subject = elements.inputSubject.value.trim();
  const sender = elements.inputSender.value.trim();
  const raw_headers = elements.inputHeaders ? elements.inputHeaders.value.trim() : "";

  if (!body && !subject) {
    alert("Please provide the email body or subject to inspect.");
    return;
  }

  setLoading(true);

  try {
    const payload = {
      subject,
      body,
      sender,
      raw_headers,
      gemini_api_key: state.geminiApiKey
    };

    const response = await fetch(getApiUrl('/api/analyze/text'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Text analysis failed.");
    }

    const data = await response.json();
    state.lastAnalysisResult = data;
    renderThreatReport(data, body);

  } catch (error) {
    alert(`Analysis error: ${error.message}`);
  } finally {
    setLoading(false);
  }
}

// ============================================================================
// URL Analysis Logic
// ============================================================================
function setupUrlHandlers() {
  elements.btnAnalyzeUrl.addEventListener('click', async () => {
    const url = elements.inputSingleUrl.value.trim();
    if (!url) {
      alert("Please enter a URL to inspect.");
      return;
    }

    try {
      elements.btnAnalyzeUrl.disabled = true;
      elements.btnAnalyzeUrl.textContent = "Scanning...";

      const res = await fetch(getApiUrl('/api/analyze/url'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!res.ok) throw new Error("URL scan failed");
      const data = await res.json();
      renderSingleUrlResult(data);
    } catch (e) {
      alert(e.message);
    } finally {
      elements.btnAnalyzeUrl.disabled = false;
      elements.btnAnalyzeUrl.textContent = "Inspect URL";
    }
  });
}

function renderSingleUrlResult(data) {
  elements.urlScanResult.style.display = 'block';
  const riskColor = data.risk_level === 'High' ? 'var(--threat-critical)' : (data.risk_level === 'Medium' ? 'var(--threat-warning)' : 'var(--threat-safe)');
  
  elements.urlScanResult.innerHTML = `
    <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 10px; padding: 1rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <span style="font-weight: 700; color: ${riskColor}; font-size: 0.9rem;">${data.risk_level.toUpperCase()} RISK (Score: ${Math.round(data.risk_score * 100)}%)</span>
        <span style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${data.hostname || 'Unknown Host'}</span>
      </div>
      <div style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--accent-cyan); word-break: break-all; margin-bottom: 0.75rem;">
        ${data.url}
      </div>
      ${data.reasons.length > 0 ? `
        <ul style="padding-left: 1.2rem; font-size: 0.8rem; color: var(--text-muted);">
          ${data.reasons.map(r => `<li style="margin-bottom: 0.25rem;">${r}</li>`).join('')}
        </ul>
      ` : '<p style="font-size: 0.8rem; color: var(--threat-safe);">No suspicious domain or URL indicators found.</p>'}
    </div>
  `;
}

// ============================================================================
// Sample Emails Loader
// ============================================================================
async function loadSampleEmails() {
  try {
    const res = await fetch(getApiUrl('/api/samples'));
    if (!res.ok) return;
    const data = await res.json();
    renderSampleChips(data.samples || []);
  } catch (e) {
    console.warn("Could not load sample emails:", e);
  }
}

function renderSampleChips(samples) {
  if (!elements.sampleChipsContainer) return;
  elements.sampleChipsContainer.innerHTML = '';

  samples.forEach(sample => {
    const chip = document.createElement('div');
    chip.className = `sample-chip ${sample.type === 'phishing' ? 'phish' : 'legit'}`;
    chip.textContent = sample.title;
    chip.title = `Category: ${sample.category} (${sample.type})`;

    chip.addEventListener('click', () => {
      // Switch to text tab
      switchTab('text');
      elements.inputSender.value = sample.sender;
      elements.inputSubject.value = sample.subject;
      elements.inputBody.value = sample.body;
      if (elements.inputHeaders) elements.inputHeaders.value = sample.raw_headers || '';

      // Auto submit
      submitTextAnalysis();
    });

    elements.sampleChipsContainer.appendChild(chip);
  });
}

// ============================================================================
// Threat Intelligence Report Rendering
// ============================================================================
function renderThreatReport(data, originalText = "") {
  elements.reportPlaceholder.style.display = 'none';
  elements.reportContainer.style.display = 'block';

  // 1. Verdict & Gauge Meter
  const score = data.risk_score;
  const badgeColor = data.badge_color; // 'danger', 'warning', 'success'
  
  elements.verdictHero.className = `verdict-hero ${badgeColor}`;
  elements.verdictBadge.className = `verdict-badge badge-${badgeColor}`;
  elements.verdictBadge.textContent = data.verdict;
  elements.verdictTitle.textContent = `${score}% Phishing Probability`;
  elements.verdictDesc.textContent = data.summary_statement;

  // Animate Circular Gauge
  animateRadialGauge(score, badgeColor);

  // 2. Metric Breakdown Bars
  const breakdown = data.threat_breakdown || {};
  animateBar(elements.barMl, elements.valMl, breakdown.ml_probability || 0, 'bar-purple');
  animateBar(elements.barUrl, elements.valUrl, breakdown.url_risk || 0, 'bar-red');
  animateBar(elements.barUrgency, elements.valUrgency, breakdown.urgency_heuristics || 0, 'bar-amber');
  animateBar(elements.barHeader, elements.valHeader, breakdown.header_risk || 0, 'bar-cyan');
  animateBar(elements.barVisual, elements.valVisual, breakdown.visual_risk || 0, 'bar-pink');

  // 3. Red Flags & Threat Vectors
  elements.flagsList.innerHTML = '';
  if (data.threat_flags && data.threat_flags.length > 0) {
    data.threat_flags.forEach(flag => {
      const item = document.createElement('div');
      item.className = 'flag-item';
      item.innerHTML = `
        <span class="flag-icon">⚠️</span>
        <div><strong>Threat Vector:</strong> ${escapeHtml(flag)}</div>
      `;
      elements.flagsList.appendChild(item);
    });
  } else {
    elements.flagsList.innerHTML = `
      <div style="font-size: 0.82rem; color: var(--threat-safe); padding: 0.5rem 0;">
        ✓ Zero critical threat flags detected across linguistic, network, or authentication layers.
      </div>
    `;
  }

  // 4. Actionable Recommendations
  elements.recsContainer.innerHTML = '';
  if (data.recommendations && data.recommendations.length > 0) {
    data.recommendations.forEach(rec => {
      const item = document.createElement('div');
      item.className = 'rec-item';
      item.innerHTML = `
        <span class="rec-badge ${rec.level}">${rec.level}</span>
        <div>
          <div class="rec-title">${escapeHtml(rec.action)}</div>
          <div class="rec-desc">${escapeHtml(rec.details)}</div>
        </div>
      `;
      elements.recsContainer.appendChild(item);
    });
  }

  // 5. Highlighted Email Body
  const textToHighlight = originalText || (data.screenshot_meta ? data.screenshot_meta.extracted_text : "");
  if (textToHighlight) {
    elements.highlightEmailBody.parentElement.style.display = 'block';
    elements.highlightEmailBody.innerHTML = generateHighlightedText(textToHighlight, data.heuristics ? data.heuristics.highlights : []);
  } else {
    elements.highlightEmailBody.parentElement.style.display = 'none';
  }

  // 6. Discovered Links Table
  const urls = (data.url_analysis && data.url_analysis.urls) || [];
  if (urls.length > 0) {
    elements.linksTableSection.style.display = 'block';
    elements.linksTableBody.innerHTML = '';
    urls.forEach(u => {
      const tr = document.createElement('tr');
      const badgeClass = u.risk_level === 'High' ? 'badge-danger' : (u.risk_level === 'Medium' ? 'badge-warning' : 'badge-success');
      tr.innerHTML = `
        <td class="url-code">${escapeHtml(u.url)}</td>
        <td>${escapeHtml(u.hostname || '-')}</td>
        <td>
          <span class="verdict-badge ${badgeClass}" style="font-size: 0.68rem; padding: 0.15rem 0.5rem;">
            ${u.risk_level} (${Math.round(u.risk_score * 100)}%)
          </span>
        </td>
        <td style="font-size: 0.75rem;">${escapeHtml(u.reasons ? u.reasons.join('; ') : 'Safe link')}</td>
      `;
      elements.linksTableBody.appendChild(tr);
    });
  } else {
    elements.linksTableSection.style.display = 'none';
  }

  // 7. Screenshot Meta (if applicable)
  if (data.screenshot_meta) {
    elements.screenshotMetaSection.style.display = 'block';
    const meta = data.screenshot_meta;
    elements.screenshotMetaText.textContent = `OCR Source: ${meta.ocr_source} | Resolution: ${meta.visuals?.resolution || 'N/A'} | Urgent Red Banner: ${meta.visuals?.has_urgent_red_banner ? 'Detected' : 'None'}`;
  } else {
    elements.screenshotMetaSection.style.display = 'none';
  }

  // Scroll to report smoothly
  elements.reportContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function animateRadialGauge(score, badgeColor) {
  // circumference = 2 * PI * r = 2 * 3.14159 * 45 = ~282.74
  const circumference = 282.74;
  const offset = circumference - (score / 100) * circumference;
  
  elements.gaugeCircleVal.style.strokeDashoffset = offset;
  
  if (badgeColor === 'danger') {
    elements.gaugeCircleVal.style.stroke = 'var(--threat-critical)';
  } else if (badgeColor === 'warning') {
    elements.gaugeCircleVal.style.stroke = 'var(--threat-warning)';
  } else {
    elements.gaugeCircleVal.style.stroke = 'var(--threat-safe)';
  }

  elements.gaugePercent.textContent = `${Math.round(score)}%`;
}

function animateBar(barEl, valEl, val, colorClass) {
  if (!barEl) return;
  barEl.className = `metric-bar ${colorClass}`;
  barEl.style.width = `${Math.min(100, Math.max(0, val))}%`;
  if (valEl) valEl.textContent = `${val}%`;
}

function generateHighlightedText(text, highlights) {
  if (!highlights || highlights.length === 0) {
    return escapeHtml(text);
  }

  // Sort highlights by starting index
  const sorted = [...highlights].sort((a, b) => a.span[0] - b.span[0]);
  let result = '';
  let lastIndex = 0;

  for (const h of sorted) {
    const start = h.span[0];
    const end = h.span[1];

    if (start < lastIndex) continue; // Skip overlaps

    // Append safe text before highlight
    result += escapeHtml(text.slice(lastIndex, start));

    // Append highlight span
    const hlClass = h.category === 'urgency' || h.category === 'credential_harvesting' ? 'hl-danger' : 'hl-warning';
    result += `<span class="${hlClass}" title="Threat Category: ${h.category}">${escapeHtml(text.slice(start, end))}</span>`;
    lastIndex = end;
  }

  // Append remaining text
  if (lastIndex < text.length) {
    result += escapeHtml(text.slice(lastIndex));
  }

  return result;
}

// ============================================================================
// Actions: PDF, JSON Export & Copy
// ============================================================================
elements.btnPrintReport.addEventListener('click', () => {
  window.print();
});

elements.btnExportJson.addEventListener('click', () => {
  if (!state.lastAnalysisResult) return;
  const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.lastAnalysisResult, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", jsonStr);
  dlAnchor.setAttribute("download", `phishing_threat_report_${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
});

elements.btnCopySummary.addEventListener('click', () => {
  if (!state.lastAnalysisResult) return;
  const r = state.lastAnalysisResult;
  const text = `[PHISHING INCIDENT REPORT]\nVerdict: ${r.verdict}\nRisk Score: ${r.risk_score}%\nSummary: ${r.summary_statement}\nThreat Flags:\n- ${r.threat_flags.join('\n- ')}`;
  navigator.clipboard.writeText(text).then(() => {
    elements.btnCopySummary.textContent = "Copied to Clipboard!";
    setTimeout(() => { elements.btnCopySummary.innerHTML = "📋 Copy Summary"; }, 2000);
  });
});

// ============================================================================
// Drawer & Settings Modals
// ============================================================================
function setupModalsAndDrawers() {
  // History Drawer
  elements.btnOpenHistory.addEventListener('click', openHistoryDrawer);
  elements.btnCloseHistory.addEventListener('click', closeHistoryDrawer);
  elements.drawerBackdrop.addEventListener('click', () => {
    closeHistoryDrawer();
    closeSettingsModal();
  });

  // Settings Modal
  elements.btnOpenSettings.addEventListener('click', openSettingsModal);
  elements.btnCloseSettings.addEventListener('click', closeSettingsModal);

  elements.btnSaveSettings.addEventListener('click', () => {
    state.geminiApiKey = elements.inputGeminiKey.value.trim();
    localStorage.setItem('phish_gemini_api_key', state.geminiApiKey);

    if (elements.inputApiBase) {
      state.apiBaseUrl = elements.inputApiBase.value.trim().replace(/\/+$/, '');
      localStorage.setItem('phish_api_base_url', state.apiBaseUrl);
    }

    checkSystemHealth();
    closeSettingsModal();
    alert("Settings updated successfully!");
  });
}

async function openHistoryDrawer() {
  elements.drawerBackdrop.style.display = 'block';
  elements.drawerHistory.classList.add('open');
  
  try {
    const res = await fetch(getApiUrl('/api/history'));
    if (!res.ok) return;
    const data = await res.json();
    renderHistoryList(data.history || []);
  } catch (e) {
    console.warn("History fetch error:", e);
  }
}

function closeHistoryDrawer() {
  elements.drawerBackdrop.style.display = 'none';
  elements.drawerHistory.classList.remove('open');
}

function renderHistoryList(history) {
  elements.historyList.innerHTML = '';
  if (history.length === 0) {
    elements.historyList.innerHTML = '<p style="color: var(--text-dim); font-size: 0.82rem;">No previous scans recorded.</p>';
    return;
  }

  history.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
        <span class="verdict-badge badge-${item.badge_color}" style="font-size: 0.65rem; padding: 0.1rem 0.4rem;">
          ${item.verdict} (${item.risk_score}%)
        </span>
        <span style="font-size: 0.72rem; color: var(--text-dim);">${item.timestamp}</span>
      </div>
      <div style="font-weight: 600; font-size: 0.82rem; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
        ${escapeHtml(item.title)}
      </div>
      <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">
        Type: ${item.scan_type}
      </div>
    `;
    elements.historyList.appendChild(div);
  });
}

function openSettingsModal() {
  if (elements.inputGeminiKey) elements.inputGeminiKey.value = state.geminiApiKey || '';
  if (elements.inputApiBase) elements.inputApiBase.value = state.apiBaseUrl || '';
  elements.drawerBackdrop.style.display = 'block';
  elements.modalSettings.classList.add('open');
}

function closeSettingsModal() {
  elements.drawerBackdrop.style.display = 'none';
  elements.modalSettings.classList.remove('open');
}

// Helpers
function setLoading(isLoading) {
  state.isScanning = isLoading;
  const primaryButtons = [elements.btnAnalyzeScreenshot, elements.btnAnalyzeText];
  primaryButtons.forEach(btn => {
    if (btn) {
      btn.disabled = isLoading;
      if (isLoading) {
        btn.dataset.prevHtml = btn.innerHTML;
        btn.innerHTML = `<span class="status-dot"></span> Analyzing Threat Vectors...`;
      } else if (btn.dataset.prevHtml) {
        btn.innerHTML = btn.dataset.prevHtml;
      }
    }
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
}

async function checkSystemHealth() {
  try {
    const res = await fetch(getApiUrl('/api/health'));
    if (res.ok) {
      const data = await res.json();
      const dot = document.getElementById('systemHealthDot');
      if (dot) dot.style.background = 'var(--threat-safe)';
    }
  } catch (e) {
    const dot = document.getElementById('systemHealthDot');
    if (dot) dot.style.background = 'var(--threat-critical)';
  }
}
