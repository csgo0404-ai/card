export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname === '/api/cards') {
      if (req.method === 'GET') {
        const data = await env.CARDS.get('cards');
        return new Response(data || '[]', {
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store'
          }
        });
      }
      if (req.method === 'PUT') {
        if (req.headers.get('x-auth') !== env.ADMIN_PW) {
          return new Response('Forbidden', { status: 403 });
        }
        const body = await req.text();
        let parsed;
        try { parsed = JSON.parse(body); } catch { return new Response('Bad JSON', { status: 400 }); }
        if (!Array.isArray(parsed)) return new Response('Expected array', { status: 400 });
        await env.CARDS.put('cards', JSON.stringify(parsed));
        return new Response('OK');
      }
      return new Response('Method not allowed', { status: 405 });
    }

    return env.ASSETS.fetch(req);
  }
};
