const axios = require('axios');

const INTERESTING_EXT = /\.(env|git|sql|bak|backup|old|swp|log|cfg|conf|config|json|xml|yml|yaml|key|pem|pfx|p12|zip|tar|gz|7z|rar|db|sqlite|mdb|jsp|asp|aspx|do|action)(\?|$)/i;

const SECRET_INDICATORS = [
  /api[-_]?key/i, /access[-_]?token/i, /authorization/i, /secret/i, /password/i,
  /credentials?/i, /private[-_]?key/i, /aws[-_]?access/i, /firebase/i, /jwt/i,
];

const investigate = async (domain) => {
  const cleanDomain = String(domain).replace(/^https?:\/\//, '').split('/')[0];

  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${cleanDomain}/*&output=json&collapse=urlkey&limit=400&fl=original,timestamp,statuscode,mimetype`;
    const response = await axios.get(url, { timeout: 20000 });

    if (!Array.isArray(response.data) || response.data.length <= 1) {
      return { domain: cleanDomain, count: 0, snapshots: [], interesting: [], firstSeen: null, lastSeen: null, perYear: {}, yearsActive: 0 };
    }

    const rows = response.data.slice(1).map(([original, timestamp, statuscode, mimetype]) => ({
      url: original,
      timestamp,
      statusCode: statuscode || null,
      mimeType: mimetype || null,
      viewUrl: `https://web.archive.org/web/${timestamp}/${original}`,
    }));

    // Dedupe by url, keep most-recent capture
    const seen = new Map();
    for (const r of rows) {
      if (!seen.has(r.url) || seen.get(r.url).timestamp < r.timestamp) seen.set(r.url, r);
    }
    const all = Array.from(seen.values()).sort((a, b) => b.timestamp.localeCompare(a.timestamp));

    const interesting = all.filter(r => INTERESTING_EXT.test(r.url) || SECRET_INDICATORS.some(rx => rx.test(r.url)));

    const perYear = {};
    let firstSeen = null, lastSeen = null;
    for (const r of all) {
      const y = parseInt(String(r.timestamp).substring(0, 4), 10);
      if (!y) continue;
      perYear[y] = (perYear[y] || 0) + 1;
      if (!firstSeen || r.timestamp < firstSeen) firstSeen = r.timestamp;
      if (!lastSeen || r.timestamp > lastSeen) lastSeen = r.timestamp;
    }

    const fmtDate = (ts) => ts ? `${ts.substring(0, 4)}-${ts.substring(4, 6)}-${ts.substring(6, 8)}` : null;

    return {
      domain: cleanDomain,
      count: all.length,
      snapshots: all.slice(0, 40),
      interesting: interesting.slice(0, 25),
      firstSeen: fmtDate(firstSeen),
      lastSeen: fmtDate(lastSeen),
      perYear,
      yearsActive: Object.keys(perYear).length,
    };
  } catch (error) {
    const isTimeout = error.code === 'ECONNABORTED';
    console.error('[Wayback] Error:', error.message);
    return {
      count: 0,
      snapshots: [],
      interesting: [],
      error: isTimeout ? 'Wayback Machine took too long to respond. Try again or use a smaller domain.' : 'Wayback service unavailable',
    };
  }
};

module.exports = { investigate };
