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

      if (url.pathname === '/analyze') {
        const storeToken = request.headers.get('X-Store-Token');
        if (storeToken !== STORE_SECRET) {
          return new Response('Non autorisé', { status: 401, headers: corsHeaders });
        }
        if (!env.ANTHROPIC_API_KEY) {
          return new Response('Clé API Anthropic non configurée sur le Worker', { status: 500, headers: corsHeaders });
        }
        const { mode, bilans } = await request.json();
        if (!Array.isArray(bilans) || !bilans.length) {
          return new Response('Aucune donnée à analyser', { status: 400, headers: corsHeaders });
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
