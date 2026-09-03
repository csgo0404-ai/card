// card 워커 (card.csgo0404.workers.dev)
// 원본에서 바뀐 점만 요약:
//   1) GET 에 ETag — no-store 를 걷어내 재방문 시 본문 전송을 없앤다(요청 수는 동일).
//   2) PUT 검증 강화 — 배열이기만 하면 통과하던 것을, 원소가 id 있는 객체인지까지 본다.
//   3) 빈 배열 저장 차단 — 실수 한 번에 전체 카드가 사라지던 경로. 정말 비우려면 ?allowEmpty=1.
//   4) 직전 값 백업(cards_prev) — 잘못 덮어써도 되돌릴 수 있게.
//   5) 선택적 낙관적 동시성 — 클라이언트가 If-Match 를 보내면 최신본과 다를 때 409.
//      (헤더를 안 보내면 예전처럼 동작하므로, 워커만 먼저 배포해도 안전하다)
//
// ⚠ KV 는 최종적 일관성이다. PUT 직후 다른 지역에서 GET 하면 최대 1분간 옛 값이 올 수 있다.
//    그래서 저장 직후 서버를 다시 읽어 화면을 갱신하면 안 된다(클라이언트에서 그 재조회를 제거했다).

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };

async function etagOf(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return '"' + [...new Uint8Array(buf)].slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('') + '"';
}

// donghwa-api 와 이름을 맞춰 TEACHER_PW 를 쓰되, 기존 ADMIN_PW 도 계속 받는다.
// (시크릿 이름을 바꾸는 도중에 저장이 막히는 일이 없도록)
function teacherPw(env) {
  return env.TEACHER_PW || env.ADMIN_PW || '';
}

// 길이 비교로 새는 정보를 줄이고, 빈 시크릿이면 무조건 거부한다.
// 헤더에 한글을 실을 수 없어 클라이언트가 인코딩해 보낼 수 있다.
function authPw(req) {
  const raw = req.headers.get('x-auth');
  if (raw == null) return null;
  if (req.headers.get('x-auth-enc') !== '1') return raw;
  try { return decodeURIComponent(raw); } catch { return raw; }
}

function pwOk(env, given) {
  const expected = teacherPw(env);
  return !!expected && typeof given === 'string' && given === expected;
}

// ── 비밀번호 시도 제한 ───────────────────────────────────────────────
// /api/auth 는 200/403 이라는 깔끔한 신호를 주므로 무차별 대입에 유리하다.
// 격리(isolate) 메모리라 재시작하면 초기화되고 지역별로 따로 센다 —
// 완전한 차단이 아니라 '스크립트로 초당 수천 번' 을 막는 속도 제한이다.
const AUTH_FAILS = new Map();
const RL_MAX = 30;              // 이 횟수를 넘기면 (학교 공용 IP 를 감안해 넉넉히)
const RL_WINDOW = 60 * 1000;    // 이 시간 창 안에서
const RL_BLOCK = 60 * 1000;     // 이만큼 '틀린 시도만' 막는다

function rlKey(req) {
  return req.headers.get('cf-connecting-ip') || 'unknown';
}
function rlBlocked(req) {
  const e = AUTH_FAILS.get(rlKey(req));
  if (!e || !e.until) return false;
  if (Date.now() >= e.until) { AUTH_FAILS.delete(rlKey(req)); return false; }
  return true;
}
function rlFail(req) {
  const k = rlKey(req), now = Date.now();
  let e = AUTH_FAILS.get(k);
  if (!e || now - e.first > RL_WINDOW) e = { first: now, n: 0 };
  e.n++;
  if (e.n >= RL_MAX) e.until = now + RL_BLOCK;
  AUTH_FAILS.set(k, e);
  if (AUTH_FAILS.size > 5000) AUTH_FAILS.clear();   // 메모리 폭주 방지
}
function rlPass(req) { AUTH_FAILS.delete(rlKey(req)); }

const sleep = ms => new Promise(r => setTimeout(r, ms));

function jsonErr(code, message, status) {
  return new Response(JSON.stringify({ error: code, message }), { status, headers: JSON_HEADERS });
}

function isCardArray(v) {
  return Array.isArray(v) && v.every(c => c && typeof c === 'object' && !Array.isArray(c) && c.id);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // 클라이언트에 비밀번호를 박아두지 않기 위한 판정 전용 엔드포인트.
    if (url.pathname === '/api/auth') {
      // 비밀번호를 먼저 본다. 맞으면 어떤 경우에도 통과시킨다(같은 IP 를 쓰는 교사가 잠기지 않도록).
      const ok = pwOk(env, authPw(req));
      if (ok) rlPass(req);
      else {
        rlFail(req);
        await sleep(400);                       // 실패는 일부러 느리게 답한다
        if (rlBlocked(req)) {
          return jsonErr('rate_limited', '시도가 너무 잦습니다. 잠시 후 다시 시도해 주세요', 429);
        }
      }
      return new Response(JSON.stringify({ ok }), {
        status: ok ? 200 : 403,
        headers: { ...JSON_HEADERS, 'cache-control': 'no-store' }
      });
    }

    if (url.pathname === '/api/cards') {
      if (req.method === 'GET') {
        const data = (await env.CARDS.get('cards')) || '[]';
        const etag = await etagOf(data);
        // 내용이 그대로면 본문을 보내지 않는다(6.5KB -> 0).
        if (req.headers.get('if-none-match') === etag) {
          return new Response(null, { status: 304, headers: { etag, 'cache-control': 'no-cache' } });
        }
        return new Response(data, {
          headers: { ...JSON_HEADERS, etag, 'cache-control': 'no-cache' }
        });
      }

      if (req.method === 'PUT') {
        // 저장 경로에는 차단을 걸지 않는다. 맞는 비밀번호를 가진 교사를 막을 이유가 없고,
        // 틀리면 어차피 403 이라 무차별 대입에 이득이 없다.
        if (!pwOk(env, authPw(req))) {
          rlFail(req);
          await sleep(400);
          return jsonErr('forbidden', '비밀번호가 일치하지 않습니다', 403);
        }
        rlPass(req);

        // 복구: 직전 값과 현재 값을 맞바꾼다. 맞바꾸기라서 잘못 눌러도 한 번 더 누르면 되돌아온다.
        if (url.searchParams.get('restore') === 'prev') {
          const cur  = (await env.CARDS.get('cards')) || '[]';
          const prev = await env.CARDS.get('cards_prev');
          if (!prev) return jsonErr('no_backup', '되돌릴 직전 값이 없습니다', 404);
          let prevArr = null;
          try { const t = JSON.parse(prev); if (Array.isArray(t)) prevArr = t; } catch {}
          if (!prevArr) return jsonErr('bad_backup', '직전 값이 손상되어 되돌릴 수 없습니다', 409);
          await env.CARDS.put('cards', prev);
          await env.CARDS.put('cards_prev', cur);
          return new Response(JSON.stringify({ ok: true, restored: prevArr.length }), {
            headers: { ...JSON_HEADERS, etag: await etagOf(prev) }
          });
        }

        const body = await req.text();
        // 글자 수가 아니라 바이트로 잰다(한글은 글자당 3바이트라 한도가 3배로 늘어났었다).
        if (new TextEncoder().encode(body).length > 2 * 1024 * 1024) {
          return jsonErr('too_large', '저장 용량 초과', 413);
        }

        let parsed;
        try { parsed = JSON.parse(body); }
        catch { return jsonErr('bad_json', '잘못된 JSON', 400); }

        // 배열이기만 하면 받아주던 검증을 조인다. 쓰레기 배열이 들어오면
        // 모든 학생 화면이 깨지고, 되돌릴 근거도 남지 않는다.
        if (!isCardArray(parsed)) {
          return jsonErr('bad_shape', 'id 가 있는 카드 객체의 배열이어야 합니다', 400);
        }

        const current = (await env.CARDS.get('cards')) || '[]';
        // KV 값이 깨져 있을 수도 있다. 아래 분기들이 파싱에 기대지 않도록 여기서 한 번만 시도한다.
        let currentArr = null;
        try { const t = JSON.parse(current); if (Array.isArray(t)) currentArr = t; } catch {}

        // 선택적 낙관적 동시성. 클라이언트가 If-Match 를 보낼 때만 검사한다.
        const ifMatch = req.headers.get('if-match');
        if (ifMatch) {
          const curEtag = await etagOf(current);
          if (ifMatch !== curEtag) {
            // current 가 깨져 있으면 파싱하지 않는다(예전엔 여기서 500 이 났다).
            return new Response(JSON.stringify({
              error: 'conflict',
              message: '다른 기기에서 먼저 저장했습니다',
              current: currentArr
            }), { status: 409, headers: JSON_HEADERS });
          }
        }

        // 전부 지우는 저장은 사고일 가능성이 훨씬 크다. 의도적일 때만 허용.
        const currentLen = currentArr ? currentArr.length : 0;
        if (parsed.length === 0 && currentLen > 0 && url.searchParams.get('allowEmpty') !== '1') {
          // 동시편집 충돌과 뜻이 다르므로 코드로 구분한다(클라이언트가 안내 문구를 나눈다).
          return jsonErr('empty_refused', '카드를 전부 지우는 저장은 막았습니다 (allowEmpty=1)', 409);
        }

        const next = JSON.stringify(parsed);
        // 직전 값을 남겨 되돌릴 수 있게 한다.
        if (current !== next) await env.CARDS.put('cards_prev', current);
        await env.CARDS.put('cards', next);

        return new Response(JSON.stringify({ ok: true, count: parsed.length }), {
          headers: { ...JSON_HEADERS, etag: await etagOf(next) }
        });
      }

      return new Response('Method not allowed', { status: 405 });
    }

    return env.ASSETS.fetch(req);
  }
};
