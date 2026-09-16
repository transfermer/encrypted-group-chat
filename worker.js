// Cloudflare Worker - Encrypted Chat Server
// Stores messages in Cloudflare KV (persistent across invocations)

const PASSWORD = 'secret123'; // Change this to your password

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    try {
      if (url.pathname === '/api/config') {
        return new Response(JSON.stringify({ password: PASSWORD, ready: true }), {
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      if (url.pathname === '/api/messages') {
        if (request.method === 'GET') {
          const raw = await env.CHAT_KV.get('messages', 'json') || [];
          return new Response(JSON.stringify({ messages: raw }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        
        if (request.method === 'POST') {
          const { content, user } = await request.json();
          const raw = await env.CHAT_KV.get('messages', 'json') || [];
          raw.push({ user: user || 'Guest', content, ts: Date.now() });
          if (raw.length > 100) raw.splice(0, raw.length - 100); // keep last 100
          await env.CHAT_KV.put('messages', JSON.stringify(raw));
          return new Response(JSON.stringify({ ok: true }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
    
    // Fallback: serve static files from assets if configured
    try {
      return await env.ASSETS.fetch(request);
    } catch {}
    
    return new Response('Not Found', { status: 404 });
  }
};