/* ============================================
   In.dl V2 — Downloader Module
   URL analysis, download flow, progress,
   media detection, carousel support
   ============================================ */

const InDownloader = (() => {
  'use strict';

  const API = '/api';
  let activePollers = new Map();

  // ---------- Supported URL Validation ----------
  const SUPPORTED_PATTERNS = [
    /instagram\.com\/(p|reel|reels|stories|tv)\//i,
    /instagram\.com\/[\w.]+\/?$/i,
    /instagr\.am\//i
  ];

  function isValidUrl(url) {
    if (!url || typeof url !== 'string') return false;
    if (url.length > 2048) return false;
    try {
      const u = new URL(url);
      return ['http:', 'https:'].includes(u.protocol);
    } catch {
      return false;
    }
  }

  function isSupportedUrl(url) {
    return SUPPORTED_PATTERNS.some(p => p.test(url));
  }

  function detectPlatform(url) {
    if (/instagram\.com|instagr\.am/i.test(url)) return 'instagram';
    return 'unknown';
  }

  // ---------- Analyze URL ----------
  async function analyzeUrl(url) {
    const normalizedUrl = InCache.normalizeUrl(url);

    if (!isValidUrl(normalizedUrl)) {
      throw new Error('Please enter a valid URL');
    }

    if (!isSupportedUrl(normalizedUrl)) {
      throw new Error('This URL is not supported. Please enter an Instagram link.');
    }

    return InCache.deduplicatedFetch(normalizedUrl, async () => {
      const headers = await InAuth.getAuthHeaders();
      const res = await fetch(`${API}/info`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ url: normalizedUrl })
      });

      const data = await res.json();

      if (!res.ok || data.error) {
        throw new Error(data.message || data.error || 'Failed to analyze URL');
      }

      // Add to history
      InCache.addToHistory({
        title: data.title,
        thumbnail: data.thumbnail,
        url: normalizedUrl,
        media_type: data.media_type,
        platform: data.platform
      });

      return data;
    });
  }

  // ---------- Start Download ----------
  async function startDownload(url, formatId, onProgress, onComplete, onError) {
    const normalizedUrl = InCache.normalizeUrl(url);
    const headers = await InAuth.getAuthHeaders();

    try {
      const res = await fetch(`${API}/download`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ url: normalizedUrl, format_id: formatId })
      });

      const data = await res.json();

      if (!res.ok) {
        if (res.status === 403 && data.error === 'BANNED') {
          onError('IP_BANNED', data.message || 'Your IP has been banned.');
          return null;
        }
        if (res.status === 503) {
          onError('MAINTENANCE', data.message || 'Server is under maintenance.');
          return null;
        }
        if (res.status === 403 && data.error === 'LIMIT_REACHED') {
          onError('LIMIT_REACHED', data.message || 'Download limit reached.');
          return null;
        }
        if (res.status === 429) {
          onError('RATE_LIMITED', data.message || 'Too many requests. Please wait.');
          return null;
        }
        onError('DOWNLOAD_ERROR', data.message || 'Download failed.');
        return null;
      }

      const jobId = data.job_id;

      // Start progress polling
      pollProgress(jobId, onProgress, onComplete, onError);

      return jobId;
    } catch (err) {
      onError('NETWORK_ERROR', 'Connection failed. Please try again.');
      return null;
    }
  }

  // ---------- Progress Polling ----------
  function pollProgress(jobId, onProgress, onComplete, onError) {
    // Clear any existing poller for this job
    cancelPoll(jobId);

    let failCount = 0;
    const maxFails = 5;

    const poll = async () => {
      try {
        const res = await fetch(`${API}/progress/${jobId}`);
        const data = await res.json();

        if (data.status === 'downloading' || data.status === 'processing') {
          const percent = parseFloat(data.percent) || 0;
          onProgress({
            status: data.status,
            percent: Math.min(percent, 99),
            speed: data.speed || '',
            message: data.message || getStatusMessage(data.status, percent)
          });
          failCount = 0;
        } else if (data.status === 'completed') {
          cancelPoll(jobId);
          onComplete({
            jobId,
            filename: data.filename || 'download',
            fileUrl: `${API}/file/${jobId}`,
            mediaType: data.media_type
          });
          return;
        } else if (data.status === 'error') {
          cancelPoll(jobId);
          onError('PROCESS_ERROR', data.message || 'Download processing failed.');
          return;
        } else if (data.status === 'queued') {
          onProgress({
            status: 'queued',
            percent: 0,
            message: 'Queued — waiting to start...'
          });
        }
      } catch {
        failCount++;
        if (failCount >= maxFails) {
          cancelPoll(jobId);
          onError('POLL_ERROR', 'Lost connection to server.');
          return;
        }
      }
    };

    const interval = setInterval(poll, 500);
    activePollers.set(jobId, interval);
    poll(); // Immediate first poll
  }

  function cancelPoll(jobId) {
    if (activePollers.has(jobId)) {
      clearInterval(activePollers.get(jobId));
      activePollers.delete(jobId);
    }
  }

  function cancelAllPolls() {
    activePollers.forEach((interval) => clearInterval(interval));
    activePollers.clear();
  }

  // ---------- File Download ----------
  function downloadFile(jobId) {
    window.location.href = `${API}/file/${jobId}`;
  }

  // ---------- Status Messages ----------
  function getStatusMessage(status, percent) {
    if (status === 'queued') return 'Queued — waiting to start...';
    if (status === 'processing') return 'Processing media...';
    if (percent < 10) return 'Starting download...';
    if (percent < 50) return 'Downloading...';
    if (percent < 90) return 'Almost there...';
    return 'Finalizing...';
  }

  // ---------- Media Type Badges ----------
  function getMediaTypeBadge(mediaType) {
    const types = {
      reel: { icon: 'fa-clapperboard', label: 'Reel', color: '#e1306c' },
      video: { icon: 'fa-video', label: 'Video', color: '#833AB4' },
      image: { icon: 'fa-image', label: 'Image', color: '#405DE6' },
      carousel: { icon: 'fa-images', label: 'Carousel', color: '#F77737' },
      story: { icon: 'fa-clock', label: 'Story', color: '#FD1D1D' },
      audio: { icon: 'fa-music', label: 'Audio', color: '#C13584' },
      post: { icon: 'fa-square', label: 'Post', color: '#833AB4' }
    };
    return types[mediaType] || types.video;
  }

  // ---------- Format Display Helpers ----------
  function getFormatIcon(type) {
    if (type === 'audio') return 'fa-music';
    if (type === 'image') return 'fa-image';
    return 'fa-video';
  }

  // ---------- Public API ----------
  return {
    isValidUrl,
    isSupportedUrl,
    detectPlatform,
    analyzeUrl,
    startDownload,
    cancelPoll,
    cancelAllPolls,
    downloadFile,
    getMediaTypeBadge,
    getFormatIcon
  };
})();
