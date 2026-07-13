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

// Clé de signature interne des sessions animateur (HMAC), jamais exposée côté client
const AR_SESSION_SECRET = 'OC-bilan-arsession-2026-signing-key';
const AR_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const MAGASINS_CSV_URL = 'https://raw.githubusercontent.com/olibaroukh/bilan-passage/main/magasins.csv';

let _magasinsCache = null;
let _magasinsCacheAt = 0;

async function getMagasinsServerSide() {
  const now = Date.now();
  if (_magasinsCache && (now - _magasinsCacheAt) < 10 * 60 * 1000) return _magasinsCache;
  const resp = await fetch(MAGASINS_CSV_URL + '?v=' + now);
  const text = await resp.text();
  const lines = text.split(/\r?\n/).filter(Boolean);
  const header = lines[0].split(';').map(h => h.trim());
  const idxAnimateur = header.indexOf('animateur');
  const idxCode = header.indexOf('code');
  const rows = lines.slice(1).map(line => {
    const cols = line.split(';');
    return { code: (cols[idxCode] || '').trim(), animateur: (cols[idxAnimateur] || '').trim() };
  }).filter(r => r.code);
  _magasinsCache = rows;
  _magasinsCacheAt = now;
  return rows;
}

function normalizeName(s) {
  return (s || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '.')
    .replace(/^\.+|\.+$/g, '');
}

async function hmacSign(payloadStr) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(AR_SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payloadStr));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createArSession(ar) {
  const payload = JSON.stringify({ ar, exp: Date.now() + AR_SESSION_TTL_MS });
  const b64 = btoa(unescape(encodeURIComponent(payload)));
  const sig = await hmacSign(b64);
  return b64 + '.' + sig;
}

async function verifyArSession(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  const expectedSig = await hmacSign(b64);
  if (sig !== expectedSig) return null;
  let payload;
  try { payload = JSON.parse(decodeURIComponent(escape(atob(b64)))); } catch(e) { return null; }
  if (!payload || !payload.ar || !payload.exp || payload.exp < Date.now()) return null;
  return payload.ar;
}

function jsonError(msg, status, corsHeaders) {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
}

export default {
  async fetch(request, env) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Zimbra-Auth-Token, X-Notify-Token, X-Store-Token, X-AR-Session',
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

      if (url.pathname === '/ar-login') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);

        const { zimbraUser, zimbraPass } = await request.json();
        if (!zimbraUser || !zimbraPass) return jsonError('Identifiant et mot de passe requis', 400, corsHeaders);

        // Authentification réelle auprès de Zimbra (preuve de possession du compte)
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
        const zimbraToken = authData?.Body?.AuthResponse?.authToken?.[0]?._content;
        if (!zimbraToken) return jsonError('Identifiants Zimbra invalides', 401, corsHeaders);

        // Résolution serveur de l'identité AR à partir du référentiel magasins.csv
        // (jamais depuis des données envoyées par le téléphone)
        const localPart = zimbraUser.split('@')[0];
        const normalizedLogin = normalizeName(localPart);
        let ar = null;
        if (normalizedLogin.includes('baroukh')) {
          ar = 'ALL';
        } else {
          const stores = await getMagasinsServerSide();
          const uniqueARs = [...new Set(stores.map(s => s.animateur).filter(Boolean))];
          ar = uniqueARs.find(a => normalizeName(a) === normalizedLogin) || null;
        }
        if (!ar) {
          return jsonError("Identifiants valides mais aucun animateur ne correspond à '" + zimbraUser + "' dans le référentiel magasins. Vérifie l'orthographe du login vs le nom animateur dans magasins.csv.", 403, corsHeaders);
        }

        const sessionToken = await createArSession(ar);
        return new Response(JSON.stringify({ ok: true, sessionToken, ar, expiresInMs: AR_SESSION_TTL_MS }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
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
        if (storeToken !== STORE_SECRET) return jsonError('Non autorisé', 401, corsHeaders);
        if (!env.DB) return jsonError('Base D1 non liée au Worker', 500, corsHeaders);

        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);

        let allowedCodes = null;
        if (sessionAr !== 'ALL') {
          const stores = await getMagasinsServerSide();
          allowedCodes = stores.filter(s => s.animateur === sessionAr).map(s => s.code);
        }

        const magasinCode = url.searchParams.get('magasin_code');
        if (magasinCode && allowedCodes && !allowedCodes.includes(magasinCode)) {
          return jsonError('Accès non autorisé à ce magasin', 403, corsHeaders);
        }
        const from = url.searchParams.get('from');
        const to = url.searchParams.get('to');
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '200'), 1000);

        let query = 'SELECT id, magasin_code, magasin_libelle, ar, date, passage, humeur, ca_mensuel, ca_annuel, renta, data_json, created_at FROM bilans WHERE 1=1';
        const binds = [];
        if (magasinCode) {
          query += ' AND magasin_code = ?'; binds.push(magasinCode);
        } else if (allowedCodes) {
          if (!allowedCodes.length) return new Response(JSON.stringify({ ok: true, results: [] }), { status: 200, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
          query += ' AND magasin_code IN (' + allowedCodes.map(() => '?').join(',') + ')';
          binds.push(...allowedCodes);
        }
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

      if (url.pathname === '/analyze') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response(JSON.stringify({ error: 'Non autorisé' }), { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        const sessionAr = await verifyArSession(request.headers.get('X-AR-Session'));
        if (!sessionAr) return jsonError('Session animateur invalide ou expirée, reconnecte-toi.', 401, corsHeaders);
        if (!env.ANTHROPIC_API_KEY) {
          return new Response(JSON.stringify({ error: 'Clé API Anthropic non configurée sur le Worker (secret ANTHROPIC_API_KEY manquant ou non déployé)' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }
        const { mode, bilans } = await request.json();
        if (!Array.isArray(bilans) || !bilans.length) {
          return new Response(JSON.stringify({ error: 'Aucune donnée à analyser' }), { status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
        }

        function resumeBilan(b) {
          const actions = (b.actions || []).map(a => `- [${a.status || 'en cours'}] ${a.label || a.text || JSON.stringify(a)}`).join('\n') || 'Aucune action notée';
          return [
            `Date: ${b.date}${b.passage ? ' (passage n°' + b.passage + ')' : ''}`,
            `Magasin: ${b.magasin?.libelle || b.magasin_libelle || '?'} (${b.magasin?.code || b.magasin_code || '?'})`,
            `Animateur: ${b.ar || '?'}`,
            b.humeur !== undefined && b.humeur !== null ? `Humeur/ambiance (0-10): ${b.humeur}` : '',
            b.renta ? `Rentabilité: ${b.renta}%` : '',
            b.ca_mensuel ? `CA mensuel: ${b.ca_mensuel}` : '',
            b.forts ? `Points forts: ${b.forts}` : '',
            b.diff ? `Difficultés: ${b.diff}` : '',
            `Actions:\n${actions}`,
            b.manager_obs ? `Observations manager: ${b.manager_obs}` : '',
            b.remarque_libre ? `Remarque libre: ${b.remarque_libre}` : '',
          ].filter(Boolean).join('\n');
        }

        let systemPrompt, userContent;
        if (mode === 'group') {
          systemPrompt = `Tu es un assistant qui aide un animateur réseau (AR) d'Optical Center à préparer sa tournée terrain. On te donne l'historique récent de plusieurs magasins. Pour chaque magasin, produis une synthèse courte et actionnable : tendance générale, actions non résolues qui traînent, et 1 à 2 points de vigilance prioritaires. Reste factuel, base-toi uniquement sur les données fournies, sois concis (pas de blabla). Structure ta réponse par magasin avec un titre clair.`;
          userContent = bilans.map((storeBilans, i) =>
            `=== Magasin ${i + 1} ===\n` + storeBilans.map(resumeBilan).join('\n\n---\n\n')
          ).join('\n\n\n');
        } else {
          systemPrompt = `Tu es un assistant qui aide un animateur réseau (AR) d'Optical Center à analyser l'historique d'un magasin. On te donne les bilans de passage successifs. Identifie les tendances (amélioration/dégradation), les actions récurrentes qui ne sont jamais résolues, et les points d'alerte. Reste factuel, base-toi uniquement sur les données fournies, sois concis et actionnable.`;
          userContent = bilans.map(resumeBilan).join('\n\n---\n\n');
        }

        const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model: 'claude-sonnet-5',
            max_tokens: 1500,
            system: systemPrompt,
            messages: [{ role: 'user', content: userContent }],
          }),
        });
        const claudeData = await claudeResp.json();
        if (!claudeResp.ok) {
          return new Response(JSON.stringify({ error: claudeData }), {
            status: claudeResp.status,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        const analysis = (claudeData.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
        return new Response(JSON.stringify({ ok: true, analysis }), {
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
