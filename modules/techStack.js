const axios = require('axios');

// Compact Wappalyzer-style signature library. Each rule:
//  { name, category, header?, headerVal?, cookie?, body?, bodyVersion?, type }
const SIGNATURES = [
  // CMS
  { name: 'WordPress',     category: 'CMS',           type: 'cms',          body: /wp-(content|includes|json)/i, bodyVersion: /<meta[^>]*generator[^>]*WordPress\s*([\d.]+)/i },
  { name: 'Drupal',        category: 'CMS',           type: 'cms',          body: /drupal\.org|sites\/all\/modules/i, header: 'x-generator', headerVal: /drupal\s*([\d.]+)/i },
  { name: 'Joomla',        category: 'CMS',           type: 'cms',          body: /joomla|com_content/i },
  { name: 'Ghost',         category: 'CMS',           type: 'cms',          body: /ghost\?v=|content\/images\/\d{4}/i },
  { name: 'Shopify',       category: 'E-Commerce',    type: 'cms',          body: /cdn\.shopify\.com|shopify\.com\/checkout/i },
  { name: 'Magento',       category: 'E-Commerce',    type: 'cms',          body: /Magento|skin\/frontend/i, cookie: /frontend=|X-Magento/ },
  { name: 'WooCommerce',   category: 'E-Commerce',    type: 'cms',          body: /woocommerce/i },
  { name: 'BigCommerce',   category: 'E-Commerce',    type: 'cms',          body: /bigcommerce|cdn11\.bigcommerce/i },
  { name: 'Squarespace',   category: 'CMS',           type: 'cms',          body: /squarespace\.com|static1\.squarespace/i },
  { name: 'Wix',           category: 'CMS',           type: 'cms',          body: /static\.wixstatic\.com|_wixCIDX/i },
  { name: 'Webflow',       category: 'CMS',           type: 'cms',          body: /webflow\.(com|io)/i },
  { name: 'HubSpot',       category: 'Marketing',     type: 'marketing',    body: /hs-scripts\.com|hubspot\.com/i },

  // Frontend frameworks
  { name: 'React',         category: 'JavaScript Library', type: 'frontend', body: /react-root|__react_devtools|data-reactroot|react-dom/i, bodyVersion: /react@([\d.]+)/i },
  { name: 'Next.js',       category: 'JavaScript Framework', type: 'frontend', body: /_next\/static|__NEXT_DATA__/i, header: 'x-powered-by', headerVal: /next\.js/i },
  { name: 'Vue.js',        category: 'JavaScript Framework', type: 'frontend', body: /vue@|v-app|__VUE__|data-v-app/i },
  { name: 'Nuxt.js',       category: 'JavaScript Framework', type: 'frontend', body: /__NUXT__|_nuxt\//i },
  { name: 'Angular',       category: 'JavaScript Framework', type: 'frontend', body: /ng-version|angular\.(js|min)/i },
  { name: 'Svelte',        category: 'JavaScript Framework', type: 'frontend', body: /__svelte|svelte-/i },
  { name: 'SvelteKit',     category: 'JavaScript Framework', type: 'frontend', body: /__sveltekit/i },
  { name: 'Remix',         category: 'JavaScript Framework', type: 'frontend', body: /__remix-run|remix:manifest/i },
  { name: 'Gatsby',        category: 'Static Site',          type: 'frontend', body: /gatsby-(focus-wrapper|chunk-mapping)/i },
  { name: 'Astro',         category: 'Static Site',          type: 'frontend', body: /astro-island|astro-slot/i },
  { name: 'Ember.js',      category: 'JavaScript Framework', type: 'frontend', body: /ember\.(min\.)?js|ember-application/i },
  { name: 'Alpine.js',     category: 'JavaScript Library',   type: 'frontend', body: /x-data=|alpine\.js/i },
  { name: 'jQuery',        category: 'JavaScript Library',   type: 'frontend', body: /jquery[.\-]([\d.]+)?(\.min)?\.js/i, bodyVersion: /jquery[.\-]([\d.]+)/i },
  { name: 'htmx',          category: 'JavaScript Library',   type: 'frontend', body: /htmx\.org|hx-(get|post|swap)=/i },

  // CSS / UI
  { name: 'Tailwind CSS',  category: 'UI',  type: 'frontend', body: /tailwind|tw-/i },
  { name: 'Bootstrap',     category: 'UI',  type: 'frontend', body: /bootstrap[.\-]([\d.]+)?(\.min)?\.css/i, bodyVersion: /bootstrap[.\-]([\d.]+)/i },
  { name: 'Material-UI',   category: 'UI',  type: 'frontend', body: /MuiButton|@material-ui|@mui\//i },
  { name: 'Chakra UI',     category: 'UI',  type: 'frontend', body: /chakra-ui-(light|dark)|css-[a-z0-9]+\s+chakra/i },

  // Backend / language
  { name: 'PHP',           category: 'Programming Language', type: 'backend', cookie: /PHPSESSID/, header: 'x-powered-by', headerVal: /php\/([\d.]+)/i },
  { name: 'Laravel',       category: 'Web Framework',        type: 'backend', cookie: /laravel_session/i },
  { name: 'Django',        category: 'Web Framework',        type: 'backend', cookie: /django_(language|session)|csrftoken/i },
  { name: 'Flask',         category: 'Web Framework',        type: 'backend', header: 'server', headerVal: /werkzeug/i },
  { name: 'Ruby on Rails', category: 'Web Framework',        type: 'backend', cookie: /_session_id=|_rails_session/, header: 'x-powered-by', headerVal: /rails/i },
  { name: 'Express',       category: 'Web Framework',        type: 'backend', header: 'x-powered-by', headerVal: /express/i },
  { name: 'ASP.NET',       category: 'Web Framework',        type: 'backend', header: 'x-aspnet-version' },
  { name: 'Java (JSP)',    category: 'Programming Language', type: 'backend', cookie: /JSESSIONID/ },
  { name: 'Tomcat',        category: 'Web Server',           type: 'infrastructure', header: 'server', headerVal: /tomcat/i },
  { name: 'Jetty',         category: 'Web Server',           type: 'infrastructure', header: 'server', headerVal: /jetty/i },

  // Web servers
  { name: 'Nginx',         category: 'Web Server', type: 'infrastructure', header: 'server', headerVal: /nginx(?:\/([\d.]+))?/i },
  { name: 'Apache',        category: 'Web Server', type: 'infrastructure', header: 'server', headerVal: /apache(?:\/([\d.]+))?/i },
  { name: 'LiteSpeed',     category: 'Web Server', type: 'infrastructure', header: 'server', headerVal: /litespeed/i },
  { name: 'Caddy',         category: 'Web Server', type: 'infrastructure', header: 'server', headerVal: /caddy/i },
  { name: 'IIS',           category: 'Web Server', type: 'infrastructure', header: 'server', headerVal: /microsoft-iis(?:\/([\d.]+))?/i },

  // CDN / proxies / cloud
  { name: 'Cloudflare',    category: 'CDN', type: 'infrastructure', header: 'server', headerVal: /cloudflare/i },
  { name: 'Cloudflare',    category: 'CDN', type: 'infrastructure', header: 'cf-ray' },
  { name: 'Fastly',        category: 'CDN', type: 'infrastructure', header: 'x-served-by', headerVal: /fastly|cache-/i },
  { name: 'Akamai',        category: 'CDN', type: 'infrastructure', header: 'x-akamai-transformed' },
  { name: 'Amazon CloudFront', category: 'CDN', type: 'infrastructure', header: 'x-amz-cf-id' },
  { name: 'Vercel',        category: 'PaaS', type: 'infrastructure', header: 'server', headerVal: /vercel/i },
  { name: 'Vercel',        category: 'PaaS', type: 'infrastructure', header: 'x-vercel-id' },
  { name: 'Netlify',       category: 'PaaS', type: 'infrastructure', header: 'server', headerVal: /netlify/i },
  { name: 'Heroku',        category: 'PaaS', type: 'infrastructure', header: 'via', headerVal: /heroku-router/i },
  { name: 'GitHub Pages',  category: 'PaaS', type: 'infrastructure', header: 'server', headerVal: /^github\.com$/i },
  { name: 'GitHub.com',    category: 'Web Service', type: 'infrastructure', header: 'server', headerVal: /github\.com/i },
  { name: 'MediaWiki',     category: 'CMS', type: 'cms', body: /wgWikiID|mediawiki\.|wgPageName/i },
  { name: 'Discourse',     category: 'CMS', type: 'cms', body: /discourse|<meta name="generator" content="Discourse/i },
  { name: 'Sentry',        category: 'Monitoring', type: 'security', body: /sentry-trace|sentry\.io\/api/i },
  { name: 'Datadog RUM',   category: 'Monitoring', type: 'analytics', body: /datadog-rum|browser-agent\.datadoghq/i },
  { name: 'New Relic',     category: 'Monitoring', type: 'analytics', body: /NREUM|newrelic\.com/i },
  { name: 'Intercom',      category: 'Marketing', type: 'marketing', body: /widget\.intercom\.io/i },
  { name: 'Zendesk Chat',  category: 'Marketing', type: 'marketing', body: /static\.zdassets\.com/i },
  { name: 'Drift',         category: 'Marketing', type: 'marketing', body: /js\.driftt\.com/i },
  { name: 'Crisp',         category: 'Marketing', type: 'marketing', body: /client\.crisp\.chat/i },
  { name: 'OneTrust',      category: 'Privacy', type: 'security', body: /cdn\.cookielaw\.org|otBannerSdk/i },
  { name: 'Cookiebot',     category: 'Privacy', type: 'security', body: /consent\.cookiebot\.com/i },
  { name: 'Render',        category: 'PaaS', type: 'infrastructure', header: 'x-render-origin-server' },
  { name: 'AWS',           category: 'PaaS', type: 'infrastructure', header: 'server', headerVal: /amazons3|amazonec2/i },
  { name: 'AWS S3',        category: 'PaaS', type: 'infrastructure', header: 'x-amz-request-id' },

  // Analytics / Tag managers
  { name: 'Google Analytics',     category: 'Analytics', type: 'analytics', body: /www\.google-analytics\.com\/(ga|analytics)\.js|gtag\(/i },
  { name: 'Google Tag Manager',   category: 'Tag Manager', type: 'analytics', body: /googletagmanager\.com|gtm\.js/i },
  { name: 'Plausible',            category: 'Analytics', type: 'analytics', body: /plausible\.io\/js/i },
  { name: 'Fathom',               category: 'Analytics', type: 'analytics', body: /usefathom\.com\/script/i },
  { name: 'Mixpanel',             category: 'Analytics', type: 'analytics', body: /mixpanel\.com|mixpanel-/i },
  { name: 'Segment',              category: 'Analytics', type: 'analytics', body: /cdn\.segment\.com\/analytics/i },
  { name: 'Hotjar',               category: 'Analytics', type: 'analytics', body: /static\.hotjar\.com/i },
  { name: 'Amplitude',            category: 'Analytics', type: 'analytics', body: /api\.amplitude\.com|amplitude\.js/i },

  // Auth / Payment
  { name: 'Stripe',         category: 'Payment',  type: 'payment',  body: /js\.stripe\.com/i },
  { name: 'PayPal',         category: 'Payment',  type: 'payment',  body: /paypal(\.com|objects)/i },
  { name: 'Razorpay',       category: 'Payment',  type: 'payment',  body: /checkout\.razorpay\.com/i },
  { name: 'Auth0',          category: 'Auth',     type: 'security', body: /auth0\.com|cdn\.auth0\.com/i },
  { name: 'Firebase',       category: 'PaaS',     type: 'backend',  body: /firebaseapp\.com|firebase\.js|firestore/i },
  { name: 'Clerk',          category: 'Auth',     type: 'security', body: /clerk\.accounts\.dev|@clerk\//i },

  // Misc
  { name: 'reCAPTCHA',      category: 'Security', type: 'security', body: /www\.google\.com\/recaptcha|grecaptcha/i },
  { name: 'hCaptcha',       category: 'Security', type: 'security', body: /hcaptcha\.com\/(1|api)/i },
];

const investigate = async (input) => {
  let url = String(input);
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  let response;
  try {
    response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      maxRedirects: 5,
      maxContentLength: 1024 * 1024 * 4, // 4MB cap
      responseType: 'text',
      transformResponse: [d => d],
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
      },
    });
  } catch (e) {
    // On size overflow, retry with larger cap then truncate
    if (/maxContentLength|exceeded/i.test(e.message)) {
      try {
        response = await axios.get(url, { timeout: 10000, validateStatus: () => true, maxRedirects: 5, responseType: 'arraybuffer', maxContentLength: 1024 * 1024 * 8, headers: { 'User-Agent': 'CyberMindSpace/2.0' } });
        response.data = Buffer.from(response.data).toString('utf8', 0, 1024 * 256);
      } catch (e2) {
        return { url, technologies: [], error: e2.message };
      }
    } else {
      return { url, technologies: [], error: e.message };
    }
  }

  const headers = Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const cookies = (Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : (headers['set-cookie'] ? [headers['set-cookie']] : [])).join('\n');
  const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

  const found = new Map();

  for (const sig of SIGNATURES) {
    let match = false;
    let version = null;

    if (sig.header) {
      const v = headers[sig.header];
      if (v !== undefined) {
        if (!sig.headerVal) match = true;
        else {
          const m = String(v).match(sig.headerVal);
          if (m) { match = true; version = m[1] || null; }
        }
      }
    }
    if (!match && sig.cookie && sig.cookie.test(cookies)) match = true;
    if (!match && sig.body && sig.body.test(body)) {
      match = true;
      if (sig.bodyVersion) {
        const m = body.match(sig.bodyVersion);
        if (m && m[1]) version = m[1];
      }
    }

    if (match) {
      const key = sig.name;
      const existing = found.get(key);
      if (!existing || (!existing.version && version)) {
        found.set(key, {
          name: sig.name,
          category: sig.category,
          type: sig.type,
          version: version || existing?.version || null,
        });
      }
    }
  }

  const technologies = Array.from(found.values()).sort((a, b) => a.category.localeCompare(b.category));

  // Group for UI rendering
  const grouped = technologies.reduce((acc, t) => {
    (acc[t.category] = acc[t.category] || []).push(t);
    return acc;
  }, {});

  return {
    url,
    statusCode: response.status,
    server: headers['server'] || null,
    poweredBy: headers['x-powered-by'] || null,
    technologies,
    grouped,
    count: technologies.length,
  };
};

module.exports = { investigate };
