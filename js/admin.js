/* ============================================
   In.dl V2 — Admin Dashboard
   Users, payments, bans, settings, messages
   ============================================ */

const InAdmin = (() => {
  'use strict';

  const API = '/api/admin';

  // ---------- Init ----------
  async function init() {
    InUI.init();

    // Check auth
    const configEl = document.getElementById('supabaseConfig');
    if (configEl) {
      InAuth.init(configEl.dataset.url, configEl.dataset.key);
    }

    // Wait for auth then load data
    InAuth.onAuthChange(async () => {
      await loadAll();
    });

    setTimeout(loadAll, 1000);
  }

  async function loadAll() {
    await Promise.all([
      fetchUsers(),
      fetchRequests(),
      fetchSettings(),
      fetchBans(),
      fetchMessages()
    ]);
  }

  // ---------- Auth Headers ----------
  async function headers() {
    return await InAuth.getAuthHeaders();
  }

  // ---------- Settings ----------
  async function fetchSettings() {
    try {
      const res = await fetch(`${API}/settings`, { headers: await headers() });
      if (!res.ok) return;
      const d = await res.json();
      const sw = document.getElementById('maintSwitch');
      const ann = document.getElementById('annInp');
      if (sw) sw.checked = d.maintenance;
      if (ann) ann.value = d.announcement || '';
    } catch (e) { console.warn('Settings fetch failed'); }
  }

  async function saveSettings() {
    const maint = document.getElementById('maintSwitch')?.checked;
    const ann = document.getElementById('annInp')?.value;
    await fetch(`${API}/settings`, {
      method: 'POST',
      headers: await headers(),
      body: JSON.stringify({ maintenance: maint, announcement: ann })
    });
    InUI.toast('Settings saved', 'success');
  }

  // ---------- Bans ----------
  async function fetchBans() {
    try {
      const res = await fetch(`${API}/ban`, { headers: await headers() });
      if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('banBody');
      if (!tbody) return;

      tbody.innerHTML = data.map(b => `
        <tr>
          <td><code>${InUI.escapeHtml(b.ip)}</code></td>
          <td>${InUI.escapeHtml(b.reason || 'Admin Ban')}</td>
          <td class="text-sm text-muted">${InUI.formatDate(b.timestamp)}</td>
          <td><button class="btn btn--success btn--sm" onclick="InAdmin.unbanIp('${InUI.escapeHtml(b.ip)}')"><i class="fas fa-unlock"></i></button></td>
        </tr>
      `).join('');
    } catch { /* silent */ }
  }

  async function banIp() {
    const input = document.getElementById('banIpInp');
    const ip = input?.value?.trim();
    if (!ip) return;

    await fetch(`${API}/ban`, {
      method: 'POST',
      headers: await headers(),
      body: JSON.stringify({ ip })
    });
    if (input) input.value = '';
    InUI.toast('IP banned', 'success');
    fetchBans();
  }

  async function unbanIp(ip) {
    await fetch(`${API}/ban`, {
      method: 'DELETE',
      headers: await headers(),
      body: JSON.stringify({ ip })
    });
    InUI.toast('IP unbanned', 'success');
    fetchBans();
  }

  // ---------- Users ----------
  async function fetchUsers() {
    try {
      const res = await fetch(`${API}/users`, { headers: await headers() });
      if (!res.ok) return;
      const d = await res.json();

      const totalEl = document.getElementById('totalUsers');
      const creditsEl = document.getElementById('totalCredits');
      if (totalEl) totalEl.textContent = d.users.length;
      if (creditsEl) creditsEl.textContent = d.users.reduce((a, b) => a + (b.tokens || 0), 0);

      const tbody = document.getElementById('userBody');
      if (!tbody) return;

      tbody.innerHTML = d.users.map(u => `
        <tr>
          <td>
            <div class="font-bold">${InUI.escapeHtml(u.username)}</div>
            <span class="badge ${u.is_admin ? 'badge--admin' : 'badge--user'}">${u.is_admin ? 'Admin' : 'User'}</span>
            <div class="text-xs text-muted">${InUI.escapeHtml(u.email || 'No email')}</div>
          </td>
          <td><span class="badge badge--plan">${InUI.escapeHtml(u.plan)}</span></td>
          <td class="font-bold">${u.tokens}</td>
          <td>
            <div class="action-group">
              <button class="btn btn--success btn--sm" onclick="InAdmin.addCredits(${u.id})" title="Add Credits"><i class="fas fa-plus"></i></button>
              <button class="btn btn--primary btn--sm" onclick="InAdmin.toggleAdmin(${u.id}, ${u.is_admin})" title="Toggle Admin"><i class="fas fa-user-shield"></i></button>
              <button class="btn btn--warning btn--sm" onclick="InAdmin.resetPass(${u.id})" title="Reset Password"><i class="fas fa-key"></i></button>
              <button class="btn btn--danger btn--sm" onclick="InAdmin.delUser(${u.id})" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
          </td>
        </tr>
      `).join('');
    } catch { /* silent */ }
  }

  async function addCredits(id) {
    const amount = prompt('Credits to add (e.g. 50):', '50');
    if (!amount || isNaN(amount)) return;
    await fetch(`${API}/credits`, {
      method: 'POST',
      headers: await headers(),
      body: JSON.stringify({ user_id: id, amount: parseInt(amount) })
    });
    InUI.toast(`Added ${amount} credits`, 'success');
    fetchUsers();
  }

  async function toggleAdmin(id, current) {
    const newStatus = !current;
    if (!confirm(`Make this user ${newStatus ? 'Admin' : 'Regular User'}?`)) return;
    await fetch(`${API}/promote`, {
      method: 'POST',
      headers: await headers(),
      body: JSON.stringify({ user_id: id, is_admin: newStatus })
    });
    InUI.toast('Role updated', 'success');
    fetchUsers();
  }

  async function resetPass(id) {
    const pw = prompt('Enter new password:');
    if (!pw) return;
    await fetch(`${API}/reset-password`, {
      method: 'POST',
      headers: await headers(),
      body: JSON.stringify({ user_id: id, password: pw })
    });
    InUI.toast('Password reset', 'success');
  }

  async function delUser(id) {
    if (!confirm('Delete this user? This cannot be undone.')) return;
    await fetch(`${API}/user/${id}`, { method: 'DELETE', headers: await headers() });
    InUI.toast('User deleted', 'success');
    fetchUsers();
  }

  // ---------- Payment Requests ----------
  async function fetchRequests() {
    try {
      const res = await fetch(`${API}/requests`, { headers: await headers() });
      if (!res.ok) return;
      const d = await res.json();
      const pendingEl = document.getElementById('pendingPayments');
      if (pendingEl) pendingEl.textContent = d.requests.length;

      const tbody = document.getElementById('reqBody');
      if (!tbody) return;

      if (d.requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No pending requests</td></tr>';
        return;
      }

      tbody.innerHTML = d.requests.map(r => `
        <tr>
          <td class="font-bold">${InUI.escapeHtml(r.username)}</td>
          <td><span class="badge badge--plan">${InUI.escapeHtml(r.plan_name)}</span></td>
          <td><button class="btn btn--outline btn--sm" onclick="InAdmin.showProof('${InUI.escapeHtml(r.screenshot_path)}')"><i class="fas fa-eye"></i> View</button></td>
          <td>
            <div class="action-group">
              <button class="btn btn--success btn--sm" onclick="InAdmin.handleReq(${r.id}, 'approve')"><i class="fas fa-check"></i></button>
              <button class="btn btn--danger btn--sm" onclick="InAdmin.handleReq(${r.id}, 'reject')"><i class="fas fa-times"></i></button>
            </div>
          </td>
        </tr>
      `).join('');
    } catch { /* silent */ }
  }

  async function handleReq(id, action) {
    await fetch(`${API}/approve`, {
      method: 'POST',
      headers: await headers(),
      body: JSON.stringify({ request_id: id, action })
    });
    InUI.toast(`Request ${action}d`, action === 'approve' ? 'success' : 'info');
    fetchRequests();
    fetchUsers();
  }

  function showProof(path) {
    const modal = document.getElementById('proofModal');
    const img = document.getElementById('proofImg');
    if (!modal || !img) return;

    modal.classList.add('visible');
    img.src = '';

    // If path is a full URL (Supabase Storage), use it directly
    if (path.startsWith('http')) {
      img.src = path;
    } else {
      // Legacy: try fetching from uploads endpoint
      img.src = path;
    }
  }

  function closeProof() {
    const modal = document.getElementById('proofModal');
    if (modal) modal.classList.remove('visible');
  }

  // ---------- Messages ----------
  async function fetchMessages() {
    try {
      const res = await fetch(`${API}/messages`, { headers: await headers() });
      if (!res.ok) return;
      const data = await res.json();

      const tbody = document.getElementById('msgBody');
      if (!tbody) return;

      if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No messages</td></tr>';
        return;
      }

      tbody.innerHTML = data.map(m => `
        <tr>
          <td class="font-bold">${InUI.escapeHtml(m.name || 'Anonymous')}</td>
          <td style="color:var(--primary)">${InUI.escapeHtml(m.email || 'No email')}</td>
          <td class="message-content">${InUI.escapeHtml(m.message || '')}</td>
          <td class="text-sm text-muted">${InUI.formatDate(m.timestamp)}</td>
          <td>
            <div class="action-group">
              <button class="btn btn--danger btn--sm" onclick="InAdmin.deleteMessage(${m.id})"><i class="fas fa-trash"></i></button>
              ${m.email ? `<a href="mailto:${InUI.escapeHtml(m.email)}" class="btn btn--primary btn--sm"><i class="fas fa-reply"></i></a>` : ''}
            </div>
          </td>
        </tr>
      `).join('');
    } catch { /* silent */ }
  }

  async function deleteMessage(id) {
    if (!confirm('Delete this message?')) return;
    await fetch(`${API}/message/${id}`, { method: 'DELETE', headers: await headers() });
    InUI.toast('Message deleted', 'info');
    fetchMessages();
  }

  // ---------- Public API ----------
  return {
    init,
    loadAll,
    saveSettings,
    fetchBans,
    banIp,
    unbanIp,
    fetchUsers,
    addCredits,
    toggleAdmin,
    resetPass,
    delUser,
    fetchRequests,
    handleReq,
    showProof,
    closeProof,
    fetchMessages,
    deleteMessage
  };
})();

// Auto-init
document.addEventListener('DOMContentLoaded', InAdmin.init);
