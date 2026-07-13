// Relais Zimbra pour bilan-passage + repartition_stocks.html — Olivier Baroukh / Optical Center
// Ce Worker retransmet les appels SOAP et l'upload de pièce jointe vers Zimbra
// à côté serveur, pour contourner le blocage CORS du navigateur.
// Il persiste aussi une copie structurée de chaque bilan dans D1 (routes /store-bilan, /bilans)
// pour alimenter l'analyse centralisée, indépendante du localStorage de chaque animateur.

const ALLOWED_ORIGIN = 'https://olibaroukh.github.io';
const ZIMBRA_SOAP_URL = 'https://zimbra.oc-pratique.com/service/soap';
const ZIMBRA_UPLOAD_URL = 'https://zimbra.oc-pratique.com/service/upload?fmt=raw';

// Token secret pour sécuriser la route /notify
// À changer si compromis — doit correspondre à NOTIFY_SECRET dans index.html
const NOTIFY_SECRET = 'OC-bilan-notify-2026';

// Token secret pour sécuriser les routes de persistance D1 (/store-bilan, /bilans)
// À changer si compromis — doit correspondre à STORE_SECRET dans index.html / dashboard
const STORE_SECRET = 'OC-bilan-store-2026';

export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Zimbra-Auth-Token, X-Notify-Token, X-Store-Token',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (request.method !== 'POST' && !(request.method === 'GET' && url.pathname === '/bilans')) {
      return new Response('Méthode non autorisée', { status: 405, headers: corsHeaders });
    }

    try {
      if (url.pathname === '/upload') {
        const token = request.headers.get('X-Zimbra-Auth-Token');
        if (!token) {
          return new Response('Jeton manquant', { status: 400, headers: corsHeaders });
        }
        const contentType = request.headers.get('Content-Type') || '';
        const bodyBuffer = await request.arrayBuffer();
        const uploadRes = await fetch(ZIMBRA_UPLOAD_URL, {
          method: 'POST',
          headers: { 'Content-Type': contentType, 'Cookie': `ZM_AUTH_TOKEN=${token}` },
          body: bodyBuffer,
        });
        const text = await uploadRes.text();
        return new Response(text, {
          status: uploadRes.status,
          headers: { 'Content-Type': 'text/plain', ...corsHeaders },
        });
      }

      if (url.pathname === '/notify') {
        // Vérification du token secret
        const notifyToken = request.headers.get('X-Notify-Token');
        if (notifyToken !== NOTIFY_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        const { to, subject, body, zimbraUser, zimbraPass } = await request.json();
        if (!to || !subject || !body || !zimbraUser || !zimbraPass) {
          return new Response('Paramètres manquants', { status: 400, headers: corsHeaders });
        }
        // Authentification Zimbra
        const authResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            Header: { context: { _jsns: 'urn:zimbra', format: { _content: 'js', type: 'js' } } },
            Body: {
              AuthRequest: {
                _jsns: 'urn:zimbraAccount',
                account: { by: 'name', _content: zimbraUser },
                password: { _content: zimbraPass }
              }
            }
          })
        });
        const authData = await authResp.json();
        const token = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
        if (!token) {
          return new Response('Auth Zimbra échouée', { status: 401, headers: corsHeaders });
        }
        // Envoi du mail de notification
        const sendResp = await fetch(ZIMBRA_SOAP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `ZM_AUTH_TOKEN=${token}` },
          body: JSON.stringify({
            Header: {
              context: {
                _jsns: 'urn:zimbra',
                format: { _content: 'js', type: 'js' },
                authToken: [{ _content: token }]
              }
            },
            Body: {
              SendMsgRequest: {
                _jsns: 'urn:zimbraMail',
                m: {
                  su: { _content: subject },
                  e: [{ t: 't', a: to }],
                  mp: { ct: 'text/plain', content: { _content: body } }
                }
              }
            }
          })
        });
        const sendText = await sendResp.text();
        return new Response(sendText, {
          status: sendResp.status,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      if (url.pathname === '/store-bilan') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        if (!env.DB) {
          return new Response('Base D1 non liée au Worker', { status: 500, headers: corsHeaders });
        }
        const data = await request.json();
        const magasinCode = data?.magasin?.code || null;
        const magasinLibelle = data?.magasin?.libelle || null;
        if (!magasinCode || !data?.date) {
          return new Response('Champs requis manquants (magasin.code, date)', { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          `INSERT INTO bilans (magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          magasinCode,
          magasinLibelle,
          data.ar || null,
          data.date,
          data.passage || null,
          data.humeur !== undefined && data.humeur !== '' ? parseInt(data.humeur) : null,
          data.ca_mensuel || null,
          data.ca_annuel || null,
          data.renta || null,
          JSON.stringify(data)
        ).run();
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      if (url.pathname === '/bilans') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        if (!env.DB) {
          return new Response('Base D1 non liée au Worker', { status: 500, headers: corsHeaders });
        }
        const magasinCode = url.searchParams.get('magasin_code');
        const ar = url.searchParams.get('ar');
        const from = url.searchParams.get('from'); // date ISO
        const to = url.searchParams.get('to');     // date ISO
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '200'), 1000);

        let query = 'SELECT id, magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json, created_at FROM bilans WHERE 1=1';
        const binds = [];
        if (magasinCode) { query += ' AND magasin_code = ?'; binds.push(magasinCode); }
        if (ar) { query += ' AND ar = ?'; binds.push(ar); }
        if (from) { query += ' AND date >= ?'; binds.push(from); }
        if (to) { query += ' AND date <= ?'; binds.push(to); }
        query += ' ORDER BY date DESC LIMIT ?';
        binds.push(limit);

        const { results } = await env.DB.prepare(query).bind(...binds).all();
        return new Response(JSON.stringify({ ok: true, results }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }

      // par défaut : relais SOAP (AuthRequest, SendMsgRequest, ...)
      const body = await request.text();
      const zimbraResponse = await fetch(ZIMBRA_SOAP_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const text = await zimbraResponse.text();
      return new Response(text, {
        status: zimbraResponse.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err) }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }
  }
};
