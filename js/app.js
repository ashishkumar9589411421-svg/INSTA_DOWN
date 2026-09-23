/* ============================================
   In.dl V2 — Main Application
   Initialization, status, UI state management
   ============================================ */

const InApp = (() => {
  'use strict';

  const API = '/api';
  let appState = {
    credits: 0,
    plan: 'Guest',
    isAdmin: false,
    username: 'Guest',
    maintenance: false,
    announcement: ''
  };

  // ---------- Initialize ----------
  async function init() {
    // Init UI utilities
    InUI.init();
    InUI.spawnParticles();

    // Init Supabase auth with config from page
    const configEl = document.getElementById('supabaseConfig');
    if (configEl) {
      const url = configEl.dataset.url;
      const key = configEl.dataset.key;
      InAuth.init(url, key);
    }

    // Listen for auth changes
    InAuth.onAuthChange(async (event, session) => {
      await refreshStatus();
      renderUserArea();
      renderHistory();
    });

    // Setup search bar
    setupSearchBar();

    // Setup auth form
    setupAuthForm();

    // Load history
    renderHistory();

    // Initial status check (will fire after auth resolves)
    setTimeout(refreshStatus, 500);

    // Setup keyboard shortcut
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') InUI.closeAllModals();
    });
  }

  // ---------- Status Check ----------
  async function refreshStatus() {
    try {
      const headers = await InAuth.getAuthHeaders();
      const res = await fetch(`${API}/status`, { headers });
      const data = await res.json();

      appState = {
        credits: data.tokens || 0,
        plan: data.plan || 'Guest',
        isAdmin: data.is_admin || false,
        username: data.username || (InAuth.isLoggedIn() ? InAuth.getUserMeta().displayName : 'Guest'),
        maintenance: data.maintenance || false,
        announcement: data.announcement || ''
      };

      renderCreditPill();
      renderAnnouncement();
      handleMaintenance();
    } catch (err) {
      console.warn('[App] Status check failed:', err);
    }
  }

  // ---------- Render Credit Pill ----------
  function renderCreditPill() {
    const el = document.getElementById('creditCount');
    if (el) {
      const max = appState.plan === 'God Mode' ? '∞' : (InAuth.isLoggedIn() ? '15' : '5');
      el.textContent = `${appState.credits} / ${max}`;
    }
  }

  // ---------- Render User Area ----------
  function renderUserArea() {
    const container = document.getElementById('userArea');
    if (!container) return;

    const meta = InAuth.getUserMeta();
    const isLoggedIn = InAuth.isLoggedIn();
    const avatarContent = meta.avatarUrl
      ? `<img src="${InUI.escapeHtml(meta.avatarUrl)}" alt="Avatar" referrerpolicy="no-referrer">`
      : `<i class="fas fa-user${isLoggedIn ? '-astronaut' : ''}"></i>`;

    container.innerHTML = `
      <div class="profile-wrap">
        <div class="profile-btn">${avatarContent}</div>
        <div class="dropdown">
          <div class="dropdown__user">${InUI.escapeHtml(isLoggedIn ? meta.displayName : appState.username)}</div>
          <div class="dropdown__badge">${InUI.escapeHtml(appState.plan)}</div>
          ${appState.isAdmin ? '<a href="admin.html" class="dropdown__link"><i class="fas fa-shield-alt"></i> Admin Panel</a>' : ''}
          ${isLoggedIn ? `
            <a href="#" class="dropdown__link" onclick="InUI.openModal('planModal');return false;"><i class="fas fa-bolt"></i> Upgrade Plan</a>
          ` : ''}
          <button class="btn btn--primary btn--pill btn--block btn--sm mt-md" onclick="${isLoggedIn ? 'InApp.handleLogout()' : 'InApp.openAuthModal()'}">
            ${isLoggedIn ? 'LOGOUT' : 'SIGN IN'}
          </button>
        </div>
      </div>
    `;
  }

  // ---------- Announcement ----------
  function renderAnnouncement() {
    const bar = document.getElementById('announcementBar');
    if (!bar) return;

    if (appState.announcement) {
      bar.textContent = appState.announcement;
      bar.classList.add('visible');
    } else {
      bar.classList.remove('visible');
    }
  }

  // ---------- Maintenance ----------
  function handleMaintenance() {
    const overlay = document.getElementById('maintOverlay');
    if (!overlay) return;

    if (appState.maintenance && !appState.isAdmin) {
      overlay.classList.add('visible');
    } else {
      overlay.classList.remove('visible');
    }
  }

  // ---------- Search Bar Setup ----------
  function setupSearchBar() {
    const input = document.getElementById('urlInput');
    const clearBtn = document.getElementById('clearBtn');
    const goBtn = document.getElementById('searchBtn');

    if (!input) return;

    // Enter key
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleAnalyze();
    });

    // Clear button visibility
    input.addEventListener('input', () => {
      if (clearBtn) {
        clearBtn.classList.toggle('visible', input.value.length > 0);
      }
    });

    // Clear button
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        input.value = '';
        clearBtn.classList.remove('visible');
        input.focus();
        hideResults();
      });
    }

    // Go button
    if (goBtn) {
      goBtn.addEventListener('click', handleAnalyze);
    }
  }

  // ---------- Analyze Handler ----------
  async function handleAnalyze() {
    const input = document.getElementById('urlInput');
    const btn = document.getElementById('searchBtn');
    const url = input?.value?.trim();

    if (!url) {
      InUI.toast('Please paste an Instagram URL', 'info');
      input?.focus();
      return;
    }

    // Show loading
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-circle-notch spinner"></i>';
    }

    // Show skeleton
    const resultCard = document.getElementById('resultCard');
    if (resultCard) {
      resultCard.classList.add('visible');
      InUI.showSkeleton('resultContent', 'result');
    }

    try {
      const data = await InDownloader.analyzeUrl(url);
      renderResults(data, url);
      renderHistory();
      refreshStatus();
    } catch (err) {
      hideResults();
      InUI.toast(err.message || 'Failed to analyze URL', 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-arrow-right"></i>';
      }
    }
  }

  // ---------- Render Results ----------
  function renderResults(data, url) {
    const resultCard = document.getElementById('resultCard');
    const content = document.getElementById('resultContent');
    if (!resultCard || !content) return;

    const badge = InDownloader.getMediaTypeBadge(data.media_type);

    let formatsHtml = '';
    if (data.formats && data.formats.length > 0) {
      formatsHtml = data.formats.map(fmt => {
        const icon = InDownloader.getFormatIcon(fmt.type);
        return `
          <div class="format-item">
            <div>
              <div class="format-info__quality"><i class="fas ${icon}" style="margin-right:6px;color:var(--text-muted)"></i>${InUI.escapeHtml(fmt.quality)}</div>
              <div class="format-info__detail">${InUI.escapeHtml(fmt.ext?.toUpperCase() || 'MP4')} • ${InUI.escapeHtml(fmt.size || 'N/A')}</div>
            </div>
            <button class="btn btn--get" data-url="${InUI.escapeHtml(url)}" data-format="${InUI.escapeHtml(fmt.id)}" onclick="InApp.handleDownload(this)">
              GET
            </button>
          </div>
        `;
      }).join('');
    }

    // Handle carousel items
    let carouselHtml = '';
    if (data.items && data.items.length > 0) {
      carouselHtml = `
        <div class="section-title" style="margin-top:var(--space-lg);margin-bottom:var(--space-md)">
          ${data.items.length} Items Detected
        </div>
        ${data.items.map((item, i) => `
          <div class="format-item">
            <div class="flex items-center gap-md">
              ${item.thumbnail ? `<img src="${InUI.escapeHtml(item.thumbnail)}" style="width:48px;height:48px;border-radius:var(--radius-sm);object-fit:cover" referrerpolicy="no-referrer">` : ''}
              <div>
                <div class="format-info__quality">Item ${i + 1} — ${InUI.escapeHtml(item.type || 'media')}</div>
                <div class="format-info__detail">${InUI.escapeHtml(item.ext?.toUpperCase() || (item.type === 'image' ? 'JPG' : 'MP4'))}</div>
              </div>
            </div>
            <button class="btn btn--get" data-url="${InUI.escapeHtml(item.url || url)}" data-format="${InUI.escapeHtml(item.format_id || 'best')}" onclick="InApp.handleDownload(this)">
              GET
            </button>
          </div>
        `).join('')}
      `;
    }

    content.innerHTML = `
      <div class="result-header">
        ${data.thumbnail ? `<img src="${InUI.escapeHtml(data.thumbnail)}" class="result-thumb" referrerpolicy="no-referrer" onerror="this.style.display='none'">` : ''}
        <div class="result-info">
          <div class="result-badge" style="margin-bottom:var(--space-sm)">
            <i class="fas ${badge.icon}"></i> ${badge.label}
          </div>
          <h3 class="result-title">${InUI.escapeHtml(data.title || 'Instagram Media')}</h3>
          <div class="result-meta">
            ${data.duration ? `<span><i class="fas fa-clock"></i> ${InUI.escapeHtml(data.duration)}</span>` : ''}
            ${data.author ? `<span><i class="fas fa-user"></i> ${InUI.escapeHtml(data.author)}</span>` : ''}
            ${data.platform ? `<span><i class="fab fa-instagram"></i> ${InUI.escapeHtml(data.platform)}</span>` : ''}
          </div>
        </div>
      </div>
      <div class="format-list">
        ${formatsHtml}
        ${carouselHtml}
      </div>
    `;

    resultCard.classList.add('visible');
  }

  function hideResults() {
    const resultCard = document.getElementById('resultCard');
    if (resultCard) resultCard.classList.remove('visible');
  }

  // ---------- Download Handler ----------
  async function handleDownload(btn) {
    if (btn.disabled) return;

    const url = btn.dataset.url;
    const formatId = btn.dataset.format;
    const originalHtml = btn.innerHTML;

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-circle-notch spinner"></i>';

    const jobId = await InDownloader.startDownload(
      url,
      formatId,
      // onProgress
      (progress) => {
        if (progress.status === 'queued') {
          btn.innerHTML = '<i class="fas fa-hourglass-half"></i>';
        } else {
          const pct = Math.round(progress.percent);
          btn.innerHTML = `${pct}%`;
        }
      },
      // onComplete
      (result) => {
        btn.innerHTML = '<i class="fas fa-check"></i> DONE';
        btn.classList.add('btn--success');

        InUI.toast('Download ready!', 'success');
        InDownloader.downloadFile(result.jobId);
        refreshStatus();

        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.disabled = false;
          btn.classList.remove('btn--success');
        }, 3000);
      },
      // onError
      (errorCode, message) => {
        btn.innerHTML = originalHtml;
        btn.disabled = false;

        if (errorCode === 'LIMIT_REACHED') {
          if (InAuth.isLoggedIn()) {
            InUI.toast('Daily limit reached. Upgrade for more credits!', 'warning');
            InUI.openModal('planModal');
          } else {
            InUI.toast('Guest limit reached. Sign in for more downloads!', 'warning');
            openAuthModal();
          }
        } else {
          InUI.toast(message, 'error');
        }
      }
    );

    if (!jobId) {
      btn.innerHTML = originalHtml;
      btn.disabled = false;
    }
  }

  // ---------- History Rendering ----------
  function renderHistory() {
    const section = document.getElementById('historySection');
    const list = document.getElementById('historyList');
    if (!section || !list) return;

    const history = InCache.getHistory();

    if (history.length === 0) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    list.innerHTML = history.map(item => `
      <div class="hist-card card card--interactive" onclick="document.getElementById('urlInput').value='${InUI.escapeHtml(item.url)}'; InApp.handleAnalyze();">
        <img src="${InUI.escapeHtml(item.thumbnail)}" class="hist-thumb" referrerpolicy="no-referrer" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 160 100%22><rect fill=%22%23111%22 width=%22160%22 height=%22100%22/></svg>'">
        <div class="hist-title">${InUI.escapeHtml(item.title)}</div>
      </div>
    `).join('');
  }

  // ---------- Auth Modal ----------
  function openAuthModal() {
    InUI.openModal('authModal');
  }

  let isLoginMode = true;

  function toggleAuthMode() {
    isLoginMode = !isLoginMode;
    const title = document.getElementById('authTitle');
    const sub = document.getElementById('authSub');
    const submitBtn = document.getElementById('authSubmitBtn');
    const switchText = document.getElementById('authSwitchText');
    const emailInput = document.getElementById('emailInput');
    const refInput = document.getElementById('refInput');

    if (isLoginMode) {
      if (title) title.textContent = 'Welcome Back';
      if (sub) sub.textContent = 'Sign in to your account';
      if (submitBtn) submitBtn.textContent = 'LOGIN';
      if (switchText) switchText.innerHTML = 'New here? <span style="color:var(--primary);cursor:pointer">Create Account</span>';
      if (emailInput) emailInput.style.display = 'none';
      if (refInput) refInput.style.display = 'none';
    } else {
      if (title) title.textContent = 'Create Account';
      if (sub) sub.textContent = 'Sign up for 15 free credits daily';
      if (submitBtn) submitBtn.textContent = 'SIGN UP';
      if (switchText) switchText.innerHTML = 'Have an account? <span style="color:var(--primary);cursor:pointer">Sign In</span>';
      if (emailInput) emailInput.style.display = 'block';
      if (refInput) refInput.style.display = 'block';
    }
  }

  function setupAuthForm() {
    const form = document.getElementById('authForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('userInput')?.value;
      const password = document.getElementById('passInput')?.value;
      const email = document.getElementById('emailInput')?.value;
      const msgEl = document.getElementById('authMsg');

      if (msgEl) msgEl.textContent = '';

      try {
        if (isLoginMode) {
          await InAuth.legacyLogin(username, password);
          InUI.closeModal('authModal');
          InUI.toast('Welcome back!', 'success');
          await refreshStatus();
          renderUserArea();
        } else {
          const refCode = document.getElementById('refCodeInput')?.value || '';
          await InAuth.legacyRegister(username, email, password, refCode);
          InUI.toast('Account created! Please log in.', 'success');
          toggleAuthMode();
        }
      } catch (err) {
        if (msgEl) msgEl.textContent = err.message;
      }
    });
  }

  // ---------- Google Sign In ----------
  async function handleGoogleSignIn() {
    await InAuth.signInWithGoogle();
  }

  // ---------- Logout ----------
  async function handleLogout() {
    await InAuth.signOut();
    InUI.toast('Logged out', 'info');
    appState = { credits: 0, plan: 'Guest', isAdmin: false, username: 'Guest', maintenance: false, announcement: '' };
    renderCreditPill();
    renderUserArea();
    refreshStatus();
  }

  // ---------- Payment ----------
  function openPaymentModal(planName) {
    if (!InAuth.isLoggedIn()) {
      InUI.toast('Please sign in first', 'info');
      openAuthModal();
      return;
    }
    InUI.closeModal('planModal');
    const planInput = document.getElementById('selectedPlanName');
    if (planInput) planInput.value = planName;
    showPaymentScan();
    InUI.openModal('paymentModal');
  }

  function showPaymentScan() {
    const scan = document.getElementById('stepScan');
    const upload = document.getElementById('stepUpload');
    if (scan) scan.style.display = 'block';
    if (upload) upload.style.display = 'none';
  }

  function showPaymentUpload() {
    const scan = document.getElementById('stepScan');
    const upload = document.getElementById('stepUpload');
    if (scan) scan.style.display = 'none';
    if (upload) upload.style.display = 'block';
  }

  async function submitPayment(e) {
    e.preventDefault();
    const plan = document.getElementById('selectedPlanName')?.value;
    const file = document.getElementById('proofFile')?.files[0];
    if (!file) {
      InUI.toast('Please select a screenshot', 'warning');
      return;
    }

    const formData = new FormData();
    formData.append('plan_name', plan);
    formData.append('screenshot', file);

    try {
      const token = await InAuth.getAccessToken();
      const res = await fetch(`${API}/payment/request`, {
        method: 'POST',
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
        body: formData
      });

      if (res.ok) {
        InUI.closeModal('paymentModal');
        showPaymentScan();
        InUI.toast('Payment submitted! Awaiting admin approval.', 'success');
      } else {
        const data = await res.json();
        InUI.toast(data.message || 'Upload failed', 'error');
      }
    } catch {
      InUI.toast('Connection error. Please try again.', 'error');
    }
  }

  // ---------- Credits / Plan ----------
  function openPlanModal() {
    if (!InAuth.isLoggedIn() && !InAuth.isAnonymous()) {
      InUI.toast('Please sign in first', 'info');
      openAuthModal();
      return;
    }
    InUI.openModal('planModal');
  }

  // ---------- Public API ----------
  return {
    init,
    refreshStatus,
    handleAnalyze,
    handleDownload,
    handleGoogleSignIn,
    handleLogout,
    openAuthModal,
    toggleAuthMode,
    openPlanModal,
    openPaymentModal,
    showPaymentScan,
    showPaymentUpload,
    submitPayment,
    renderHistory,
    get state() { return appState; }
  };
})();

// Auto-init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    InApp.init();
    
    // Register Service Worker for PWA
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js')
                .then(reg => console.log('SW registered:', reg.scope))
                .catch(err => console.log('SW registration failed:', err));
        });
    }
});
