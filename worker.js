// Cloudflare Worker — Encrypted Chat Server
// All configuration (PASSWORD secret, CHAT_KV namespace) is set in Cloudflare Dashboard.
// Nothing here except the binding names that match dashboard bindings.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
    
    // Validate required bindings exist
    if (!env.CHAT_KV) {
      return new Response(JSON.stringify({ error: 'CHAT_KV namespace not bound' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (!env.PASSWORD) {
      return new Response(JSON.stringify({ error: 'PASSWORD secret not configured' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
    
    try {
      // API: Config — returns password for client-side comparison
      if (url.pathname === '/api/config') {
        return new Response(JSON.stringify({ password: env.PASSWORD, ready: true }), {
          headers: { 'Content-Type': 'application/json', ...cors }
        });
      }
      
      // API: Messages
      if (url.pathname === '/api/messages') {
        if (request.method === 'GET') {
          const raw = await env.CHAT_KV.get('messages', 'json') || [];
          return new Response(JSON.stringify({ messages: raw }), {
            headers: { 'Content-Type': 'application/json', ...cors }
          });
        }
        
        if (request.method === 'POST') {
          const { content, user } = await request.json();
          const raw = await env.CHAT_KV.get('messages', 'json') || [];
          raw.push({ user: user || 'Guest', content, ts: Date.now() });
          if (raw.length > 100) raw.splice(0, raw.length - 100); // keep last 100
          await env.CHAT_KV.put('messages', JSON.stringify(raw));
          return new Response(JSON.stringify({ ok: true }), {
            headers: { 'Content-Type': 'application/json', ...cors }
          });
        }
      }
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
    
    return new Response('Not Found', { status: 404 });
  }
};