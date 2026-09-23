/* ============================================
   In.dl V2 — UI Utilities
   Toast notifications, modals, particles,
   FAQ, dropdown, skeleton loaders
   ============================================ */

const InUI = (() => {
  'use strict';

  // ---------- Toast Notifications ----------
  function toast(message, type = 'info', duration = 4000) {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const icons = {
      success: 'fa-check-circle',
      error: 'fa-exclamation-circle',
      warning: 'fa-exclamation-triangle',
      info: 'fa-info-circle'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `
      <i class="fas ${icons[type] || icons.info}" style="font-size:1.2rem;flex-shrink:0;"></i>
      <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    const timer = setTimeout(() => removeToast(toast), duration);
    toast.addEventListener('click', () => {
      clearTimeout(timer);
      removeToast(toast);
    });
  }

  function removeToast(el) {
    el.classList.add('removing');
    setTimeout(() => el.remove(), 300);
  }

  // ---------- Modal System ----------
  function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
      modal.classList.add('visible');
      document.body.style.overflow = 'hidden';
    }
  }

  function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
      modal.classList.remove('visible');
      document.body.style.overflow = '';
    }
  }

  function closeAllModals() {
    document.querySelectorAll('.modal-overlay.visible').forEach(m => {
      m.classList.remove('visible');
    });
    document.body.style.overflow = '';
  }

  // Close modal on overlay click
  function initModalCloseHandlers() {
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal-overlay')) {
        e.target.classList.remove('visible');
        document.body.style.overflow = '';
      }
      if (e.target.classList.contains('modal__close') || e.target.closest('.modal__close')) {
        const overlay = e.target.closest('.modal-overlay');
        if (overlay) {
          overlay.classList.remove('visible');
          document.body.style.overflow = '';
        }
      }
    });
  }

  // ---------- Dropdown ----------
  function initDropdown() {
    document.addEventListener('click', (e) => {
      // Toggle profile dropdown
      const profileBtn = e.target.closest('.profile-btn');
      if (profileBtn) {
        e.stopPropagation();
        const dropdown = profileBtn.parentElement.querySelector('.dropdown');
        if (dropdown) {
          const isOpen = dropdown.classList.contains('show');
          closeAllDropdowns();
          if (!isOpen) {
            dropdown.classList.add('show');
            profileBtn.classList.add('active');
          }
        }
        return;
      }

      // Close dropdowns on outside click
      if (!e.target.closest('.dropdown')) {
        closeAllDropdowns();
      }
    });
  }

  function closeAllDropdowns() {
    document.querySelectorAll('.dropdown.show').forEach(d => d.classList.remove('show'));
    document.querySelectorAll('.profile-btn.active').forEach(b => b.classList.remove('active'));
  }

  // ---------- FAQ Toggle ----------
  function initFAQ() {
    document.addEventListener('click', (e) => {
      const faqItem = e.target.closest('.faq-item');
      if (faqItem) {
        faqItem.classList.toggle('active');
      }
    });
  }

  // ---------- Floating Particles ----------
  function spawnParticles(containerId = 'voidParticles', icons = null) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Check reduced motion preference
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const defaultIcons = ['fa-camera', 'fa-image', 'fa-video', 'fa-heart', 'fa-play'];
    const iconSet = icons || defaultIcons;
    const count = Math.min(15, Math.floor(window.innerWidth / 80));

    for (let i = 0; i < count; i++) {
      const el = document.createElement('i');
      el.className = `fas ${iconSet[Math.floor(Math.random() * iconSet.length)]} particle-icon`;
      el.style.left = Math.random() * 100 + '%';
      el.style.animationDuration = (Math.random() * 8 + 12) + 's';
      el.style.animationDelay = Math.random() * 8 + 's';
      el.style.fontSize = (Math.random() * 1 + 1.2) + 'rem';
      container.appendChild(el);
    }
  }

  // ---------- Skeleton Loading ----------
  function showSkeleton(containerId, type = 'result') {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (type === 'result') {
      container.innerHTML = `
        <div class="result-header">
          <div class="skeleton skeleton--thumb"></div>
          <div style="flex:1">
            <div class="skeleton skeleton--title"></div>
            <div class="skeleton skeleton--text"></div>
            <div class="skeleton skeleton--text" style="width:40%"></div>
          </div>
        </div>
        <div style="display:flex;flex-direction:column;gap:8px">
          <div class="skeleton" style="height:56px"></div>
          <div class="skeleton" style="height:56px"></div>
          <div class="skeleton" style="height:56px"></div>
        </div>
      `;
    }
  }

  // ---------- Clipboard ----------
  async function pasteFromClipboard(inputId) {
    try {
      const text = await navigator.clipboard.readText();
      const input = document.getElementById(inputId);
      if (input && text) {
        input.value = text.trim();
        input.dispatchEvent(new Event('input'));
        return true;
      }
    } catch {
      toast('Unable to access clipboard. Please paste manually.', 'info');
    }
    return false;
  }

  // ---------- HTML Escape ----------
  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ---------- Date Formatting ----------
  function formatDate(dateStr) {
    if (!dateStr) return 'Unknown';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;

    if (date.toDateString() === now.toDateString()) return 'Today';

    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';

    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  // ---------- Confirmation Dialog ----------
  function confirm(message) {
    return window.confirm(message);
  }

  // ---------- Debounce ----------
  function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(null, args), delay);
    };
  }

  // ---------- Init All ----------
  function init() {
    initModalCloseHandlers();
    initDropdown();
    initFAQ();
  }

  // ---------- Public API ----------
  return {
    toast,
    openModal,
    closeModal,
    closeAllModals,
    initDropdown,
    initFAQ,
    spawnParticles,
    showSkeleton,
    pasteFromClipboard,
    escapeHtml,
    formatDate,
    confirm,
    debounce,
    init
  };
})();
