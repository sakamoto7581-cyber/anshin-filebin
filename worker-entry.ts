// worker-entry.ts — Cloudflare Pages の _worker.js（advanced mode）用エントリ。
// /api/* は Hono アプリ（src/api.ts）へ、それ以外は静的アセット（ASSETS）へ振り分ける。
import app from './src/api';

type Env = {
  ASSETS: Fetcher;
  KV: KVNamespace;
};

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return app.fetch(request, env, ctx);
    }
    return env.ASSETS.fetch(request);
  },
};
