const axios = require('axios');

// Each platform has a precise detection rule:
//  - "json": GET endpoint that returns JSON, look at HTTP status (200 found / 404 not found)
//  - "status": HTTP status code on regular page (200 = found, 404 = not found)
//  - "negative": fetch URL & match a "not found" string in body (status 200 may still mean missing)
const PLATFORMS = [
  { name: 'GitHub',        category: 'Code',    url: u => `https://github.com/${u}`,                 api: u => `https://api.github.com/users/${u}`, type: 'json' },
  { name: 'GitLab',        category: 'Code',    url: u => `https://gitlab.com/${u}`,                 api: u => `https://gitlab.com/api/v4/users?username=${u}`, type: 'json-array' },
  { name: 'Bitbucket',     category: 'Code',    url: u => `https://bitbucket.org/${u}/`,             api: u => `https://api.bitbucket.org/2.0/users/${u}`, type: 'json' },
  { name: 'Codeberg',      category: 'Code',    url: u => `https://codeberg.org/${u}`,               api: u => `https://codeberg.org/api/v1/users/${u}`, type: 'json' },
  { name: 'StackOverflow', category: 'Code',    url: u => `https://stackoverflow.com/users/${u}`,    type: 'status' },

  { name: 'Reddit',        category: 'Social',  url: u => `https://www.reddit.com/user/${u}`,        api: u => `https://www.reddit.com/user/${u}/about.json`, type: 'json' },
  { name: 'Twitter / X',   category: 'Social',  url: u => `https://x.com/${u}`,                      type: 'negative', notFound: 'this account doesn’t exist' },
  { name: 'Mastodon (mas.to)', category: 'Social', url: u => `https://mas.to/@${u}`,                 type: 'status' },
  { name: 'Bluesky',       category: 'Social',  url: u => `https://bsky.app/profile/${u}.bsky.social`, type: 'negative', notFound: 'profile not found' },
  { name: 'Threads',       category: 'Social',  url: u => `https://www.threads.net/@${u}`,           type: 'status' },
  { name: 'Instagram',     category: 'Social',  url: u => `https://www.instagram.com/${u}/`,         type: 'negative', notFound: 'page-isn-t-available' },
  { name: 'Facebook',      category: 'Social',  url: u => `https://www.facebook.com/${u}`,           type: 'status' },
  { name: 'TikTok',        category: 'Social',  url: u => `https://www.tiktok.com/@${u}`,            type: 'negative', notFound: 'couldn\'t find this account' },
  { name: 'Pinterest',     category: 'Social',  url: u => `https://www.pinterest.com/${u}/`,         type: 'status' },
  { name: 'Snapchat',      category: 'Social',  url: u => `https://www.snapchat.com/add/${u}`,       type: 'status' },

  { name: 'Medium',        category: 'Writing', url: u => `https://medium.com/@${u}`,                type: 'status' },
  { name: 'Dev.to',        category: 'Writing', url: u => `https://dev.to/${u}`,                     api: u => `https://dev.to/api/users/by_username?url=${u}`, type: 'json' },
  { name: 'Hashnode',      category: 'Writing', url: u => `https://hashnode.com/@${u}`,              type: 'status' },
  { name: 'Substack',      category: 'Writing', url: u => `https://${u}.substack.com`,               type: 'negative', notFound: 'this site doesn\'t exist' },

  { name: 'YouTube',       category: 'Video',   url: u => `https://www.youtube.com/@${u}`,           type: 'status' },
  { name: 'Vimeo',         category: 'Video',   url: u => `https://vimeo.com/${u}`,                  type: 'status' },
  { name: 'Twitch',        category: 'Video',   url: u => `https://www.twitch.tv/${u}`,              type: 'status' },

  { name: 'SoundCloud',    category: 'Audio',   url: u => `https://soundcloud.com/${u}`,             type: 'status' },
  { name: 'Spotify Profile', category: 'Audio', url: u => `https://open.spotify.com/user/${u}`,      type: 'status' },

  { name: 'Steam',         category: 'Gaming',  url: u => `https://steamcommunity.com/id/${u}`,      type: 'negative', notFound: 'the specified profile could not be found' },
  { name: 'Roblox (search)', category: 'Gaming',url: u => `https://www.roblox.com/users/profile?username=${u}`, type: 'status' },

  { name: 'Keybase',       category: 'Identity', url: u => `https://keybase.io/${u}`,                api: u => `https://keybase.io/_/api/1.0/user/lookup.json?username=${u}`, type: 'json-keybase' },
  { name: 'About.me',      category: 'Identity', url: u => `https://about.me/${u}`,                  type: 'status' },
  { name: 'Linktree',      category: 'Identity', url: u => `https://linktr.ee/${u}`,                 type: 'status' },
  { name: 'Linkedin',      category: 'Identity', url: u => `https://www.linkedin.com/in/${u}`,       type: 'status' },

  { name: 'Patreon',       category: 'Commerce', url: u => `https://www.patreon.com/${u}`,           type: 'status' },
  { name: 'Buy Me A Coffee', category: 'Commerce', url: u => `https://www.buymeacoffee.com/${u}`,    type: 'status' },
  { name: 'Ko-fi',         category: 'Commerce', url: u => `https://ko-fi.com/${u}`,                 type: 'status' },
  { name: 'Etsy',          category: 'Commerce', url: u => `https://www.etsy.com/shop/${u}`,         type: 'status' },

  { name: 'HackerOne',     category: 'Security', url: u => `https://hackerone.com/${u}`,             type: 'status' },
  { name: 'Bugcrowd',      category: 'Security', url: u => `https://bugcrowd.com/${u}`,              type: 'status' },
  { name: 'TryHackMe',     category: 'Security', url: u => `https://tryhackme.com/p/${u}`,           type: 'status' },
];

const USER_AGENT = 'Mozilla/5.0 (CyberMindSpace OSINT Toolkit/2.0)';

async function checkPlatform(platform, username) {
  const url = platform.url(username);
  const entry = { name: platform.name, category: platform.category, url, found: false };
  try {
    if (platform.type === 'json' && platform.api) {
      const r = await axios.get(platform.api(username), { timeout: 6000, validateStatus: () => true, headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' } });
      entry.found = r.status === 200;
      if (entry.found && platform.name === 'GitHub') {
        entry.profile = {
          name: r.data.name, bio: r.data.bio, company: r.data.company, location: r.data.location,
          followers: r.data.followers, following: r.data.following, publicRepos: r.data.public_repos,
          avatarUrl: r.data.avatar_url, profileUrl: r.data.html_url, createdAt: r.data.created_at,
        };
      }
      if (entry.found && platform.name === 'Reddit') {
        entry.profile = {
          karma: (r.data?.data?.link_karma || 0) + (r.data?.data?.comment_karma || 0),
          createdAt: r.data?.data?.created_utc ? new Date(r.data.data.created_utc * 1000).toISOString() : null,
          verified: r.data?.data?.verified,
          avatarUrl: r.data?.data?.icon_img?.split('?')[0] || null,
        };
      }
    } else if (platform.type === 'json-array' && platform.api) {
      const r = await axios.get(platform.api(username), { timeout: 6000, validateStatus: () => true, headers: { 'User-Agent': USER_AGENT } });
      entry.found = Array.isArray(r.data) && r.data.length > 0;
    } else if (platform.type === 'json-keybase' && platform.api) {
      const r = await axios.get(platform.api(username), { timeout: 6000, validateStatus: () => true, headers: { 'User-Agent': USER_AGENT } });
      entry.found = r.data?.status?.code === 0 && r.data?.them;
    } else if (platform.type === 'negative') {
      const r = await axios.get(url, { timeout: 7000, validateStatus: () => true, headers: { 'User-Agent': USER_AGENT } });
      const body = typeof r.data === 'string' ? r.data.toLowerCase() : '';
      const notFound = platform.notFound.toLowerCase();
      entry.found = r.status === 200 && !body.includes(notFound);
    } else {
      const r = await axios.head(url, { timeout: 5000, validateStatus: () => true, headers: { 'User-Agent': USER_AGENT } });
      entry.found = r.status === 200 || (r.status >= 300 && r.status < 400);
      if (r.status === 0 || r.status === 405) {
        // Some servers reject HEAD; fall back to GET (cap content)
        const g = await axios.get(url, { timeout: 5000, validateStatus: () => true, maxContentLength: 8192, headers: { 'User-Agent': USER_AGENT } });
        entry.found = g.status === 200;
      }
    }
  } catch (e) {
    entry.found = false;
    entry.error = e.code || e.message;
  }
  return entry;
}

async function investigate(rawUsername) {
  const username = String(rawUsername).trim().replace(/^@/, '');
  if (!/^[a-zA-Z0-9._-]{1,40}$/.test(username)) {
    return { error: 'Invalid username (use 1-40 alphanumerics, dots, dashes, underscores)', username };
  }

  const result = {
    username,
    platforms: [],
    foundCount: 0,
    totalChecked: PLATFORMS.length,
    githubProfile: null,
    redditProfile: null,
    grouped: {},
  };

  // Concurrency-limited execution
  const concurrency = 8;
  let cursor = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (cursor < PLATFORMS.length) {
      const idx = cursor++;
      const r = await checkPlatform(PLATFORMS[idx], username);
      result.platforms.push(r);
      if (r.found) {
        result.foundCount++;
        if (r.name === 'GitHub' && r.profile) result.githubProfile = r.profile;
        if (r.name === 'Reddit' && r.profile) result.redditProfile = r.profile;
      }
    }
  });
  await Promise.all(workers);

  result.platforms.sort((a, b) => {
    if (a.found !== b.found) return a.found ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  result.grouped = result.platforms.reduce((acc, p) => {
    (acc[p.category] = acc[p.category] || []).push(p);
    return acc;
  }, {});

  return result;
}

module.exports = { investigate };
