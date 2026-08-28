/**
 * DeceptiGuard Autonomous Cyber Intelligence & Zero-Trust Sandbox Platform
 */

document.addEventListener('DOMContentLoaded', () => {
  // Views
  const intakeSection = document.getElementById('intakeSection');
  const radarPanel = document.getElementById('radarPanel');
  const dossierSection = document.getElementById('dossierSection');

  // Form & Inputs
  const scanForm = document.getElementById('scanForm');
  const targetUrlInput = document.getElementById('targetUrl');
  const contextMessageInput = document.getElementById('contextMessage');
  const submitBtn = document.getElementById('submitBtn');
  const newScanBtn = document.getElementById('newScanBtn');

  // OCR Image Dropzone Elements
  const imageDropzone = document.getElementById('imageDropzone');
  const imageFileInput = document.getElementById('imageFileInput');
  const dropzoneContent = document.getElementById('dropzoneContent');
  const dropzoneLoading = document.getElementById('dropzoneLoading');
  const dropzonePreview = document.getElementById('dropzonePreview');
  const previewThumbnail = document.getElementById('previewThumbnail');
  const previewFilename = document.getElementById('previewFilename');
  const ocrStatusBadge = document.getElementById('ocrStatusBadge');
  const clearImageBtn = document.getElementById('clearImageBtn');

  // Pipeline Radar Elements
  const radarStatusMsg = document.getElementById('radarStatusMsg');
  const progressBarFill = document.getElementById('progressBarFill');
  const stepsList = document.getElementById('stepsList');
  const historyTableBody = document.getElementById('historyTableBody');

  let activeWebSocket = null;
  let pollInterval = null;

  // 7-Stage Pipeline Configuration
  const PIPELINE_STEPS = [
    { key: 'INITIALIZING', label: '1. Zero-Trust Isolation', pct: 15 },
    { key: 'SANDBOX_BROWSING', label: '2. DOM De-cloaking & Forms', pct: 35 },
    { key: 'SCREENSHOT_CAPTURED', label: '3. Viewport Simulation Capture', pct: 55 },
    { key: 'AI_MULTIMODAL_ANALYSIS', label: '4. 6-Factor Gemini Reasoning', pct: 75 },
    { key: 'HONEYPOT_SYNTHESIS', label: '5. Decoy Credential Synthesis', pct: 85 },
    { key: 'HONEYPOT_INJECTION', label: '6. Playwright Decoy Tarpitting', pct: 92 },
    { key: 'COMPLETED', label: '7. Intelligence Dossier Ready', pct: 100 }
  ];

  // Helper: Switch active 3-step view
  function switchView(viewName) {
    intakeSection.classList.remove('active');
    radarPanel.classList.remove('active');
    dossierSection.classList.remove('active');

    if (viewName === 'intake') {
      intakeSection.classList.add('active');
    } else if (viewName === 'scanning') {
      radarPanel.classList.add('active');
    } else if (viewName === 'results') {
      dossierSection.classList.add('active');
    }
  }

  // --- OCR IMAGE UPLOAD & TEXT/URL SEGREGATION ---
  imageDropzone.addEventListener('click', (e) => {
    if (e.target !== clearImageBtn) {
      imageFileInput.click();
    }
  });

  imageDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    imageDropzone.classList.add('dragover');
  });

  imageDropzone.addEventListener('dragleave', () => {
    imageDropzone.classList.remove('dragover');
  });

  imageDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    imageDropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleImageUpload(e.dataTransfer.files[0]);
    }
  });

  imageFileInput.addEventListener('change', () => {
    if (imageFileInput.files && imageFileInput.files.length > 0) {
      handleImageUpload(imageFileInput.files[0]);
    }
  });

  clearImageBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    resetDropzone();
  });

  function resetDropzone() {
    imageFileInput.value = '';
    dropzoneContent.style.display = 'flex';
    dropzoneLoading.style.display = 'none';
    dropzonePreview.style.display = 'none';
    previewThumbnail.src = '';
  }

  async function handleImageUpload(file) {
    if (!file.type.startsWith('image/')) {
      alert('Please upload an image file (PNG, JPG, WEBP).');
      return;
    }

    // Show loading state
    dropzoneContent.style.display = 'none';
    dropzonePreview.style.display = 'none';
    dropzoneLoading.style.display = 'flex';

    // Show thumbnail preview locally
    const reader = new FileReader();
    reader.onload = (e) => {
      previewThumbnail.src = e.target.result;
    };
    reader.readAsDataURL(file);
    previewFilename.textContent = file.name;

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/v1/extract-from-image', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error('OCR Vision extraction failed.');
      }

      const data = await response.json();
      console.log('[OCR Result]', data);

      // Auto-populate URL if segregated
      if (data.primary_url) {
        targetUrlInput.value = data.primary_url;
      } else if (data.extracted_urls && data.extracted_urls.length > 0) {
        targetUrlInput.value = data.extracted_urls[0];
      }

      // Auto-populate message text if extracted
      if (data.extracted_message) {
        contextMessageInput.value = data.extracted_message;
      } else if (data.raw_text) {
        contextMessageInput.value = data.raw_text;
      }

      // Update badge
      dropzoneLoading.style.display = 'none';
      dropzonePreview.style.display = 'flex';
      ocrStatusBadge.textContent = `✓ Auto-Extracted (${data.detected_language || 'Text'})`;
      ocrStatusBadge.style.color = 'var(--risk-green)';

    } catch (err) {
      console.error('Image extraction error:', err);
      dropzoneLoading.style.display = 'none';
      dropzonePreview.style.display = 'flex';
      ocrStatusBadge.textContent = '⚠️ OCR Offline / Fallback applied';
      ocrStatusBadge.style.color = 'var(--risk-yellow)';
    }
  }

  // --- PRESETS ---
  window.setPreset = function(type) {
    resetDropzone();
    if (type === 'usps') {
      targetUrlInput.value = 'https://usps-redeliv-track.info';
      contextMessageInput.value = 'USPS Post: Your package could not be delivered due to a missing street number. Please update your address within 24hrs to avoid the package being returned to sender.';
    } else if (type === 'ms365') {
      targetUrlInput.value = 'http://login-microsoft365-verify.auth-portal.xyz/login.php';
      contextMessageInput.value = 'URGENT: Your Microsoft 365 Password expires in 2 hours. Click here immediately to verify account identity or risk account termination.';
    } else if (type === 'paypal') {
      targetUrlInput.value = 'http://paypal-security-alert.verify-user.net/auth';
      contextMessageInput.value = 'Notice: Unauthorized access attempt detected on your PayPal account. Confirm your identity within 24 hours to restore full access.';
    } else if (type === 'google') {
      targetUrlInput.value = 'http://google-workspace-auth.cloud-login.info/index.html';
      contextMessageInput.value = 'Security alert: Your Google Workspace storage quota exceeded. Please sign in to verify credentials.';
    } else if (type === 'spanish') {
      targetUrlInput.value = 'http://login-microsoft365-verify.auth-portal.xyz/login.php';
      contextMessageInput.value = 'ALERTA DE SEGURIDAD: Su cuenta ha sido suspendida temporalmente por actividad no autorizada. Verifique su contraseña inmediatamente dentro de las próximas 2 horas.';
    } else if (type === 'safe') {
      targetUrlInput.value = 'https://www.wikipedia.org';
      contextMessageInput.value = 'Check out this interesting Wikipedia article on computer cybersecurity and zero-trust architecture.';
    }
  };

  // --- RESET TO STEP 1 ---
  newScanBtn.addEventListener('click', () => {
    switchView('intake');
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="btn-icon">⚡</span><span class="btn-text">ANALYZE THREAT IN SANDBOX</span>';
  });

  // --- FORM SUBMISSION & STEP 2 LAUNCH ---
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = targetUrlInput.value.trim();
    const contextMsg = contextMessageInput.value.trim();

    if (!url) {
      alert('Please provide a target URL to scan or upload an image.');
      return;
    }

    if (pollInterval) clearInterval(pollInterval);

    // Switch to Step 2: Scanning View
    switchView('scanning');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="btn-icon">⚡</span><span class="btn-text">SANDBOX SCANNING ACTIVE...</span>';

    renderPipelineSteps('INITIALIZING');
    progressBarFill.style.width = '15%';

    try {
      // POST scan initiation request
      const response = await fetch('/api/v1/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, context_message: contextMsg })
      });

      if (!response.ok) {
        throw new Error('Failed to initiate threat scan');
      }

      const scanData = await response.json();
      const jobId = scanData.id;

      // Connect to WebSocket for real-time streaming
      if (activeWebSocket) activeWebSocket.close();

      activeWebSocket = new PhishTrapWebSocket(
        jobId,
        (event) => handlePipelineEvent(event),
        (err) => console.error('WS Error:', err)
      );

      // Polling fallback
      pollInterval = setInterval(async () => {
        try {
          const pollRes = await fetch(`/api/v1/scans/${jobId}`);
          if (pollRes.ok) {
            const scan = await pollRes.json();
            if (scan.status === 'COMPLETED') {
              clearInterval(pollInterval);
              handleScanCompletion(scan);
            } else if (scan.status === 'PROCESSING') {
              if (scan.visual_analysis || scan.factor_brand_spoofing) {
                renderPipelineSteps('AI_MULTIMODAL_ANALYSIS');
                progressBarFill.style.width = '75%';
              } else if (scan.screenshot_filename) {
                renderPipelineSteps('SCREENSHOT_CAPTURED');
                progressBarFill.style.width = '55%';
              }
            } else if (scan.status === 'FAILED') {
              clearInterval(pollInterval);
              alert('Scan pipeline failed.');
              switchView('intake');
              resetScanButton();
            }
          }
        } catch (err) {
          console.error('Poll error:', err);
        }
      }, 1500);

    } catch (err) {
      alert(`Scan launch error: ${err.message}`);
      switchView('intake');
      resetScanButton();
    }
  });

  function handlePipelineEvent(event) {
    console.log('[Pipeline Event]', event);
    radarStatusMsg.textContent = event.message;
    progressBarFill.style.width = `${event.progress_percent}%`;

    renderPipelineSteps(event.step);

    if (event.step === 'COMPLETED') {
      if (pollInterval) clearInterval(pollInterval);
      setTimeout(() => {
        handleScanCompletion(event.payload);
      }, 500);
    } else if (event.step === 'FAILED') {
      if (pollInterval) clearInterval(pollInterval);
      alert(`Scan failed: ${event.message}`);
      switchView('intake');
      resetScanButton();
    }
  }

  function handleScanCompletion(scan) {
    switchView('results');
    resetScanButton();
    renderDossier(scan);
    loadScanHistory();
  }

  function renderPipelineSteps(activeStepKey) {
    const activeIndex = PIPELINE_STEPS.findIndex(s => s.key === activeStepKey);

    stepsList.innerHTML = PIPELINE_STEPS.map((step, idx) => {
      let stateClass = '';
      if (idx < activeIndex || activeStepKey === 'COMPLETED') {
        stateClass = 'completed';
      } else if (idx === activeIndex) {
        stateClass = 'active';
      }
      return `
        <div class="step-item ${stateClass}">
          <div class="step-badge">${idx < activeIndex ? '✓' : idx + 1}</div>
          <span>${step.label}</span>
        </div>
      `;
    }).join('');
  }

  function resetScanButton() {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="btn-icon">⚡</span><span class="btn-text">ANALYZE THREAT IN SANDBOX</span>';
  }

  // --- STEP 3: RENDER COMPLETE RESULTS DOSSIER ---
  function renderDossier(scan) {
    // 1. Language Detected
    const langValue = document.getElementById('detectedLanguageValue');
    langValue.textContent = scan.detected_language || 'English';

    // 2. Risk Level Meter: 0-30 Green, 31-65 Yellow, 66-100 Red
    const scoreVal = document.getElementById('riskScoreValue');
    const scoreCircle = document.getElementById('scoreCircle');
    const threatBadge = document.getElementById('threatBadge');
    const dossierSummary = document.getElementById('dossierSummary');
    const targetUrlDisplay = document.getElementById('targetUrlDisplay');

    const score = Math.round(scan.risk_score);
    scoreVal.textContent = score;

    let gaugeColor = 'var(--risk-green)';
    let levelName = 'SAFE';

    if (score >= 66 || scan.threat_level === 'MALICIOUS' || scan.threat_level === 'CRITICAL') {
      gaugeColor = 'var(--risk-red)';
      levelName = 'MALICIOUS';
    } else if (score >= 31 || scan.threat_level === 'SUSPICIOUS') {
      gaugeColor = 'var(--risk-yellow)';
      levelName = 'SUSPICIOUS';
    } else {
      gaugeColor = 'var(--risk-green)';
      levelName = 'SAFE';
    }

    scoreCircle.style.borderColor = gaugeColor;
    scoreVal.style.color = gaugeColor;
    threatBadge.textContent = levelName;
    threatBadge.className = `threat-badge threat-${levelName}`;

    dossierSummary.textContent = scan.summary || 'Scan evaluation complete.';
    targetUrlDisplay.innerHTML = `<strong>Inspected Target:</strong> ${scan.url}`;

    // 3. Brand Spoofing Warning Banner
    const brandBanner = document.getElementById('targetBrandBanner');
    if (scan.target_brand && (levelName === 'MALICIOUS' || levelName === 'CRITICAL')) {
      brandBanner.style.display = 'flex';
      document.getElementById('targetBrandName').textContent = scan.target_brand;
      document.getElementById('claimedVsActual').textContent = `Target Claims '${scan.target_brand}' identity on unauthorized host '${scan.url.split('/')[2] || scan.url}'`;
    } else {
      brandBanner.style.display = 'none';
    }

    // 4. Render the 6 Mandatory Factors
    renderFactorCard('Msg', scan.factor_message_suspicion, 'Message Suspicion', 'Urgency & Pretexting');
    renderFactorCard('Dom', scan.factor_url_domain_name, 'URL Domain Name', 'Domain Host Analysis');
    renderFactorCard('Legit', scan.factor_url_legitness, 'URL Legitness', 'Protocol & Redirect Integrity');
    renderFactorCard('Spoof', scan.factor_brand_spoofing, 'Brand Spoofing', 'Brand Spoofing & Visual Identity');
    renderFactorCard('Intent', scan.factor_malicious_intent, 'Malicious Intent', 'Intent Categorization');
    renderFactorCard('Claims', scan.factor_deceptive_claims, 'Deceptive Claims', 'Deceptive Pretexts');

    // 5. Sandbox Viewport Simulation Render
    const screenshotImg = document.getElementById('screenshotImg');
    if (scan.screenshot_filename) {
      screenshotImg.src = `/storage/screenshots/${scan.screenshot_filename}`;
      screenshotImg.style.display = 'block';
    } else {
      screenshotImg.style.display = 'none';
    }

    // 6. Sandbox Telemetry Indicators
    const tech = scan.technical_indicators || {};
    document.getElementById('tSsl').textContent = (scan.url || '').startsWith('https://') ? 'Valid HTTPS (TLS Encrypted)' : 'Insecure HTTP Protocol';
    document.getElementById('tForms').textContent = `${tech.forms_detected || 0} Form(s) Enumerated`;
    document.getElementById('tPass').textContent = `${tech.password_fields_detected || 0} Input(s) Found`;
    document.getElementById('tRedirects').textContent = `${tech.redirect_count || 0} Hop(s)`;
    document.getElementById('tObfuscation').textContent = (tech.obfuscation_tokens_found && tech.obfuscation_tokens_found.length > 0) ? tech.obfuscation_tokens_found.join(', ') : 'None Detected';

    // Visual reasoning anomalies
    const visual = scan.visual_analysis || {};
    const visualList = document.getElementById('visualAnalysisList');
    const anomalies = visual.visual_anomalies || [];
    visualList.innerHTML = `
      <li class="analysis-item"><strong>Brand Spoofing:</strong> ${visual.is_brand_spoofing ? '🚨 Brand Identity Dissonance' : 'Authentic Brand Identity'}</li>
      <li class="analysis-item"><strong>Fake Login Form:</strong> ${visual.fake_login_detected ? 'Yes (Credential harvesting fields)' : 'No'}</li>
      ${anomalies.map(a => `<li class="analysis-item threat">⚠️ ${a}</li>`).join('')}
    `;

    // 7. Active Honeypot Countermeasure Log
    const honeypotCard = document.getElementById('honeypotCard');
    const honeypotLogs = scan.honeypot_logs || [];
    if (scan.honeypot_triggered && honeypotLogs.length > 0) {
      honeypotCard.style.display = 'block';
      const log = honeypotLogs[0];
      const creds = log.credentials_injected || {};

      document.getElementById('wastedTimeValue').textContent = `${log.attacker_resource_wasted_seconds}s`;
      document.getElementById('injectedUsername').textContent = creds.username || 'N/A';
      document.getElementById('injectedPassword').textContent = creds.password || 'N/A';
      document.getElementById('injectedMfa').textContent = creds.mfa_code || 'N/A';
      document.getElementById('honeypotEndpoint').textContent = log.target_url || scan.url;
    } else {
      honeypotCard.style.display = 'none';
    }
  }

  function renderFactorCard(prefix, factorData, defaultName, defaultTitle) {
    const badgeEl = document.getElementById(`badgeFactor${prefix}`);
    const titleEl = document.getElementById(`titleFactor${prefix}`);
    const expEl = document.getElementById(`expFactor${prefix}`);
    const tagEl = document.getElementById(`highlightFactor${prefix}`);

    if (factorData) {
      const rating = factorData.rating || 'SAFE';
      badgeEl.textContent = rating;
      badgeEl.className = `factor-badge ${rating}`;
      titleEl.textContent = factorData.title || defaultTitle;
      expEl.textContent = factorData.explanation || 'No anomalies detected.';
      tagEl.textContent = factorData.highlight_badge || `${rating}`;
    } else {
      badgeEl.textContent = 'SAFE';
      badgeEl.className = 'factor-badge SAFE';
      titleEl.textContent = defaultTitle;
      expEl.textContent = 'Factor evaluated as standard / safe.';
      tagEl.textContent = 'Verified';
    }
  }

  // --- LOAD THREAT SCAN HISTORY ---
  async function loadScanHistory() {
    try {
      const res = await fetch('/api/v1/scans?limit=15');
      if (!res.ok) return;
      const scans = await res.json();

      historyTableBody.innerHTML = scans.map(s => {
        const score = Math.round(s.risk_score);
        let lvl = s.threat_level;
        if (score >= 66) lvl = 'MALICIOUS';
        else if (score >= 31) lvl = 'SUSPICIOUS';
        else lvl = 'SAFE';

        return `
          <tr>
            <td><span class="factor-badge ${lvl}">${lvl}</span></td>
            <td style="font-family: var(--font-mono); font-weight: 700; color: ${lvl === 'MALICIOUS' ? 'var(--risk-red)' : lvl === 'SUSPICIOUS' ? 'var(--risk-yellow)' : 'var(--risk-green)'};">
              ${score}%
            </td>
            <td style="font-family: var(--font-mono); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${s.url}
            </td>
            <td>${s.target_brand || 'None'}</td>
            <td>${s.detected_language || 'English'}</td>
            <td>${s.honeypot_triggered ? '🪤 TRIGGERED' : '—'}</td>
            <td style="color: var(--text-dim); font-size: 0.75rem;">${new Date(s.created_at).toLocaleTimeString()}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load history:', err);
    }
  }

  // Initial history load
  loadScanHistory();
});

