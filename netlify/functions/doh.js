// Netlify Function: server-side DNS-over-HTTPS proxy for the AMUN scan tool.
// GET /.netlify/functions/doh?name=example.com&type=A
// Returns the same normalized shape the console tool expects:
// { requestedType, status, answers:[{name,type,ttl,data}], provider, error }

const TYPE_CODES = {1:'A',2:'NS',5:'CNAME',6:'SOA',15:'MX',16:'TXT',28:'AAAA'};

async function doh(provider, name, type) {
  const url = provider === 'cf'
    ? `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`
    : `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 9000);
  try {
    const res = await fetch(url, {
      headers: provider === 'cf' ? { accept: 'application/dns-json' } : {},
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json(), provider: provider === 'cf' ? 'Cloudflare DNS' : 'Google Public DNS' };
  } finally {
    clearTimeout(timer);
  }
}

exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
  };
  try {
    const name = (event.queryStringParameters && event.queryStringParameters.name || '').trim().toLowerCase();
    const type = (event.queryStringParameters && event.queryStringParameters.type || 'A').toUpperCase();
    if (!name || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(name)) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'invalid domain' }) };
    }
    let raw, provider, primaryError = '';
    try {
      ({ data: raw, provider } = await doh('cf', name, type));
    } catch (e) {
      primaryError = e && e.message ? e.message : String(e);
      try {
        ({ data: raw, provider } = await doh('google', name, type));
      } catch (e2) {
        const msg = e2 && e2.message ? e2.message : String(e2);
        return { statusCode: 200, headers, body: JSON.stringify({
          requestedType: type, status: null, answers: [], provider: null,
          error: primaryError + '\n' + msg,
        })};
      }
    }
    const answers = Array.isArray(raw.Answer) ? raw.Answer.map((a) => ({
      name: String(a.name || ''),
      type: TYPE_CODES[Number(a.type)] || ('TYPE' + a.type),
      ttl: Number(a.TTL) || 0,
      data: String(a.data || ''),
    })) : [];
    return { statusCode: 200, headers, body: JSON.stringify({
      requestedType: type,
      status: typeof raw.Status === 'number' ? raw.Status : null,
      answers, provider, error: null,
    })};
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: String((e && e.message) || e) }) };
  }
};
