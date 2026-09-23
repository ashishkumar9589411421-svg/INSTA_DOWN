/* ============================================
   In.dl V2 — Supabase Authentication
   Handles: anonymous auth, Google OAuth,
   guest→Google linking, session management
   ============================================ */

const InAuth = (() => {
  'use strict';

  // Supabase client — initialized from config injected by backend
  let supabase = null;
  let currentSession = null;
  let authListeners = [];

  // ---------- Initialize ----------
  function init(supabaseUrl, supabaseAnonKey) {
    if (!supabaseUrl || !supabaseAnonKey) {
      console.warn('[Auth] Supabase credentials not provided. Auth disabled.');
      return false;
    }
    try {
      supabase = window.supabase.createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
          autoRefreshToken: true,
          persistSession: true,
          detectSessionInUrl: true
        }
      });

      // Listen for auth state changes
      supabase.auth.onAuthStateChange((event, session) => {
        currentSession = session;
        notifyListeners(event, session);
      });

      // Check existing session
      supabase.auth.getSession().then(({ data: { session } }) => {
        currentSession = session;
        if (!session) {
          signInAnonymously();
        } else {
          notifyListeners('INITIAL_SESSION', session);
        }
      });

      return true;
    } catch (err) {
      console.error('[Auth] Init failed:', err);
      return false;
    }
  }

  // ---------- Anonymous Sign In ----------
  async function signInAnonymously() {
    if (!supabase) return null;
    try {
      const { data, error } = await supabase.auth.signInAnonymously();
      if (error) throw error;
      currentSession = data.session;
      return data;
    } catch (err) {
      console.error('[Auth] Anonymous sign-in failed:', err.message);
      return null;
    }
  }

  // ---------- Google OAuth ----------
  async function signInWithGoogle() {
    if (!supabase) {
      InUI.toast('Authentication not configured', 'error');
      return null;
    }
    try {
      // If user is currently anonymous, attempt to link Google credential
      const isAnon = isAnonymous();

      if (isAnon) {
        // Link Google identity to existing anonymous account
        const { data, error } = await supabase.auth.linkIdentity({
          provider: 'google',
          options: {
            redirectTo: window.location.origin
          }
        });
        if (error) throw error;
        return data;
      } else {
        // Fresh Google sign-in
        const { data, error } = await supabase.auth.signInWithOAuth({
          provider: 'google',
          options: {
            redirectTo: window.location.origin
          }
        });
        if (error) throw error;
        return data;
      }
    } catch (err) {
      console.error('[Auth] Google sign-in failed:', err);
      handleAuthError(err);
      return null;
    }
  }

  // ---------- Legacy Login (bridge for existing users) ----------
  async function legacyLogin(username, password) {
    try {
      const res = await fetch('/api/auth/legacy-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Login failed');

      // If legacy login returns Supabase session tokens, set them
      if (data.access_token && data.refresh_token) {
        const { data: sessionData, error } = await supabase.auth.setSession({
          access_token: data.access_token,
          refresh_token: data.refresh_token
        });
        if (error) throw error;
        currentSession = sessionData.session;
      }
      return data;
    } catch (err) {
      console.error('[Auth] Legacy login failed:', err);
      throw err;
    }
  }

  // ---------- Legacy Register ----------
  async function legacyRegister(username, email, password, referralCode) {
    try {
      const res = await fetch('/api/auth/legacy-register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, referral_code: referralCode })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Registration failed');
      return data;
    } catch (err) {
      console.error('[Auth] Legacy register failed:', err);
      throw err;
    }
  }

  // ---------- Sign Out ----------
  async function signOut() {
    if (!supabase) return;
    try {
      await supabase.auth.signOut();
      currentSession = null;
      // Re-create anonymous session
      await signInAnonymously();
    } catch (err) {
      console.error('[Auth] Sign-out failed:', err);
    }
  }

  // ---------- Get Access Token ----------
  async function getAccessToken() {
    if (!supabase) return null;
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (session) {
        currentSession = session;
        return session.access_token;
      }
      return null;
    } catch {
      return null;
    }
  }

  // ---------- Get Auth Headers ----------
  async function getAuthHeaders() {
    const token = await getAccessToken();
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  // ---------- Get Current User ----------
  function getUser() {
    return currentSession?.user || null;
  }

  function getUID() {
    return currentSession?.user?.id || null;
  }

  function isLoggedIn() {
    const user = getUser();
    return user && !user.is_anonymous;
  }

  function isAnonymous() {
    const user = getUser();
    return user?.is_anonymous === true;
  }

  function getUserEmail() {
    return getUser()?.email || null;
  }

  function getUserMeta() {
    const user = getUser();
    if (!user) return {};
    const meta = user.user_metadata || {};
    return {
      displayName: meta.full_name || meta.name || user.email?.split('@')[0] || 'User',
      avatarUrl: meta.avatar_url || meta.picture || null,
      email: user.email || null
    };
  }

  // ---------- Event Listeners ----------
  function onAuthChange(callback) {
    authListeners.push(callback);
    // Fire immediately with current state
    if (currentSession) {
      callback('INITIAL_SESSION', currentSession);
    }
  }

  function notifyListeners(event, session) {
    authListeners.forEach(cb => {
      try { cb(event, session); } catch (e) { console.error('[Auth] Listener error:', e); }
    });
  }

  // ---------- Error Handling ----------
  function handleAuthError(err) {
    const msg = err.message || 'Authentication error';

    if (msg.includes('popup_closed') || msg.includes('popup closed')) {
      InUI.toast('Sign-in cancelled', 'info');
    } else if (msg.includes('popup_blocked')) {
      InUI.toast('Pop-up blocked. Please allow pop-ups for this site.', 'warning');
    } else if (msg.includes('already registered') || msg.includes('already been registered')) {
      InUI.toast('This account is already linked. Try signing in instead.', 'warning');
    } else if (msg.includes('network') || msg.includes('fetch')) {
      InUI.toast('Network error. Please check your connection.', 'error');
    } else {
      InUI.toast(msg, 'error');
    }
  }

  // ---------- Public API ----------
  return {
    init,
    signInAnonymously,
    signInWithGoogle,
    legacyLogin,
    legacyRegister,
    signOut,
    getAccessToken,
    getAuthHeaders,
    getUser,
    getUID,
    isLoggedIn,
    isAnonymous,
    getUserEmail,
    getUserMeta,
    onAuthChange
  };
})();
