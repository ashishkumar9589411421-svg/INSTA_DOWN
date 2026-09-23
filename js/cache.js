/* ============================================
   In.dl V2 — Cache & Request Deduplication
   URL normalization, short-lived caching,
   localStorage management
   ============================================ */

const InCache = (() => {
  'use strict';

  const INFO_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  const MAX_HISTORY_ITEMS = 20;
  const STORAGE_KEYS = {
    theme: 'indl_theme',
    history: 'indl_history',
    recentUrls: 'indl_recent_urls',
    preferences: 'indl_prefs',
    onboarded: 'indl_onboarded'
  };

  // In-memory caches
  const infoCache = new Map();
  const pendingRequests = new Map();

  // ---------- URL Normalization ----------
  function normalizeUrl(url) {
    if (!url) return '';
    let normalized = url.trim();

    // Remove tracking params
    try {
      const u = new URL(normalized);
      u.searchParams.delete('igshid');
      u.searchParams.delete('igsh');
      u.searchParams.delete('utm_source');
      u.searchParams.delete('utm_medium');
      u.searchParams.delete('utm_campaign');
      normalized = u.toString();
    } catch {
      // Not a valid URL, return as-is
    }

    // Remove trailing slash
    normalized = normalized.replace(/\/+$/, '');

    return normalized;
  }

  // ---------- Cache Key Generation ----------
  function getCacheKey(url) {
    return normalizeUrl(url).toLowerCase();
  }

  // ---------- Info Cache ----------
  function getCachedInfo(url) {
    const key = getCacheKey(url);
    const entry = infoCache.get(key);
    if (!entry) return null;

    if (Date.now() - entry.timestamp > INFO_CACHE_TTL) {
      infoCache.delete(key);
      return null;
    }

    return entry.data;
  }

  function setCachedInfo(url, data) {
    const key = getCacheKey(url);
    infoCache.set(key, { data, timestamp: Date.now() });

    // Limit cache size
    if (infoCache.size > 50) {
      const oldest = infoCache.keys().next().value;
      infoCache.delete(oldest);
    }
  }

  // ---------- Request Deduplication ----------
  async function deduplicatedFetch(url, fetchFn) {
    const key = getCacheKey(url);

    // Check cache first
    const cached = getCachedInfo(url);
    if (cached) return cached;

    // Check if same request is already pending
    if (pendingRequests.has(key)) {
      return pendingRequests.get(key);
    }

    // Create new request
    const promise = fetchFn().then(data => {
      setCachedInfo(url, data);
      pendingRequests.delete(key);
      return data;
    }).catch(err => {
      pendingRequests.delete(key);
      throw err;
    });

    pendingRequests.set(key, promise);
    return promise;
  }

  // ---------- Download History ----------
  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEYS.history) || '[]');
    } catch {
      return [];
    }
  }

  function addToHistory(item) {
    try {
      let history = getHistory();
      // Remove duplicate
      history = history.filter(h => h.url !== item.url);
      // Add to front
      history.unshift({
        title: (item.title || 'Untitled').substring(0, 100),
        thumbnail: item.thumbnail || '',
        url: item.url,
        mediaType: item.media_type || item.mediaType || 'video',
        platform: item.platform || 'instagram',
        timestamp: Date.now()
      });
      // Limit size
      if (history.length > MAX_HISTORY_ITEMS) {
        history = history.slice(0, MAX_HISTORY_ITEMS);
      }
      localStorage.setItem(STORAGE_KEYS.history, JSON.stringify(history));
    } catch {
      // localStorage might be full or disabled
    }
  }

  function removeFromHistory(url) {
    try {
      let history = getHistory();
      history = history.filter(h => h.url !== url);
      localStorage.setItem(STORAGE_KEYS.history, JSON.stringify(history));
    } catch { /* silent */ }
  }

  function clearHistory() {
    try {
      localStorage.removeItem(STORAGE_KEYS.history);
    } catch { /* silent */ }
  }

  // ---------- Preferences ----------
  function getPref(key, defaultValue = null) {
    try {
      const prefs = JSON.parse(localStorage.getItem(STORAGE_KEYS.preferences) || '{}');
      return prefs[key] !== undefined ? prefs[key] : defaultValue;
    } catch {
      return defaultValue;
    }
  }

  function setPref(key, value) {
    try {
      const prefs = JSON.parse(localStorage.getItem(STORAGE_KEYS.preferences) || '{}');
      prefs[key] = value;
      localStorage.setItem(STORAGE_KEYS.preferences, JSON.stringify(prefs));
    } catch { /* silent */ }
  }

  // ---------- Onboarding ----------
  function isOnboarded() {
    return localStorage.getItem(STORAGE_KEYS.onboarded) === 'true';
  }

  function setOnboarded() {
    localStorage.setItem(STORAGE_KEYS.onboarded, 'true');
  }

  // ---------- Cleanup ----------
  function clearExpiredCache() {
    const now = Date.now();
    for (const [key, entry] of infoCache) {
      if (now - entry.timestamp > INFO_CACHE_TTL) {
        infoCache.delete(key);
      }
    }
  }

  // Run cleanup periodically
  setInterval(clearExpiredCache, 60000);

  // ---------- Public API ----------
  return {
    normalizeUrl,
    getCachedInfo,
    setCachedInfo,
    deduplicatedFetch,
    getHistory,
    addToHistory,
    removeFromHistory,
    clearHistory,
    getPref,
    setPref,
    isOnboarded,
    setOnboarded,
    STORAGE_KEYS
  };
})();
