import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "site");
const host = process.env.HOST || (process.env.RENDER ? "0.0.0.0" : "127.0.0.1");
const port = Number(process.env.PORT || 4173);
const password = process.env.PORTFOLIO_PASSWORD;
if (!password || password.length < 16) throw new Error("PORTFOLIO_PASSWORD must be at least 16 characters.");
const secret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const passwordSalt = crypto.randomBytes(32);
const passwordHash = crypto.scryptSync(password, passwordSalt, 64);
const attempts = new Map();
const sessions = new Map();
const inactivityLimit = 5 * 60 * 1000;
const loginLayoutFix = `body{background:linear-gradient(180deg,#fbf7ef 0%,#fff 40%,#f8fafc 100%)!important}.shell,.access{background:#fffdf8!important}.story{background:linear-gradient(135deg,#071a33,#123b63)!important}.brand{width:max-content;padding:8px 14px 8px 8px;border-radius:16px;background:#fffdf8;color:#071a33}.monogram{display:flex!important;align-items:center;justify-content:center;width:34px!important;height:34px!important;border-radius:12px!important;background:#071a33!important;color:#c9a24d!important;font-weight:800;line-height:1;letter-spacing:-.02em;box-shadow:none!important}.monogram b{color:#c9a24d!important}.lock{background:#071a33!important;color:#c9a24d!important}.accent{background:#c9a24d!important}@media(min-width:801px){.shell{width:min(1120px,100%);min-height:620px;grid-template-columns:minmax(0,.95fr) minmax(430px,1.05fr)}.story{justify-content:flex-start;padding:50px 56px;gap:76px}.intro{max-width:440px}.intro h1{max-width:8.5ch;margin-bottom:20px;font-size:clamp(3.2rem,3.6vw,3.8rem);line-height:1;letter-spacing:-.04em}.intro p{max-width:42ch;font-size:1rem}.values{margin-top:24px}.access{padding:60px clamp(58px,5vw,76px)}.lock{margin-bottom:20px}.access h2{font-size:clamp(2.5rem,3.2vw,3.05rem)}form{margin-top:28px}}@media(max-width:800px){.story{min-height:0!important;padding:26px clamp(22px,7vw,52px) 30px!important;gap:34px}.story:after{width:250px;height:250px;right:-135px;bottom:-160px}.intro{max-width:620px}.eyebrow{margin-bottom:9px;font-size:.68rem}.intro h1{max-width:18ch;margin-bottom:0;font-size:clamp(2.25rem,8vw,3.25rem)!important;line-height:1.02}.intro>p,.values{display:none}.access{align-content:start!important;padding:36px clamp(22px,7vw,52px) 46px!important}.lock{width:48px;height:48px;margin-bottom:18px}.access h2{font-size:clamp(2.15rem,8vw,2.8rem)}.accent{top:18px;right:18px}}@media(max-width:430px){.story{padding-top:22px!important;padding-bottom:25px!important;gap:26px}.brand{font-size:.92rem}.intro h1{font-size:2.15rem!important}.access{padding-top:30px!important}.lock{width:44px;height:44px;border-radius:14px;margin-bottom:16px}form{margin-top:22px}.privacy{align-items:flex-start}}`;

const mime = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".png": "image/png", ".svg": "image/svg+xml", ".pdf": "application/pdf"
};

function headers(extra = {}) {
  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    ...extra
  };
}

function sign(value) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

function cookie(req, value, clear = false) {
  const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const secure = forwardedProto === "https" || process.env.NODE_ENV === "production";
  return `portfolio_session=${value}; HttpOnly; SameSite=Strict; Path=/${clear ? "; Max-Age=0" : ""}${secure ? "; Secure" : ""}`;
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const fetchSite = String(req.headers["sec-fetch-site"] || "").toLowerCase();
  if (fetchSite && fetchSite !== "same-origin") return false;
  try {
    const supplied = new URL(origin);
    const forwardedProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
    if (forwardedProto && supplied.protocol !== `${forwardedProto}:`) return false;
    const validHosts = [
      req.headers["x-forwarded-host"],
      req.headers.host,
      process.env.RENDER_EXTERNAL_HOSTNAME
    ].flatMap(value => String(value || "").split(",")).map(value => value.trim().toLowerCase()).filter(Boolean);
    return validHosts.includes(supplied.host.toLowerCase());
  } catch {
    return false;
  }
}

function sessionId(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)portfolio_session=([^;]+)/);
  if (!match) return null;
  const [id, signature] = match[1].split(".");
  if (!id || !signature) return null;
  const expected = sign(id);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return id;
}

function authenticated(req, touch = false) {
  const id = sessionId(req);
  const session = id && sessions.get(id);
  if (!session) return false;
  if (Date.now() - session.lastActivity > inactivityLimit) {
    sessions.delete(id);
    return false;
  }
  if (touch) session.lastActivity = Date.now();
  return true;
}

function loginPage(message = "") {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#071a33"><title>Private Portfolio | Jaysheel Desai</title><style>
  :root{--navy:#071a33;--blue:#123b63;--gold:#c9a24d;--cream:#f6f1e8;--paper:#fffdf8;--ink:#132033;--muted:#667085}*{box-sizing:border-box}html{min-height:100%;background:var(--cream)}body{margin:0;min-height:100vh;min-height:100svh;display:grid;place-items:center;padding:clamp(18px,4vw,54px);overflow-x:hidden;color:var(--ink);font:16px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:radial-gradient(circle at 8% 10%,rgba(201,162,77,.22),transparent 25%),radial-gradient(circle at 90% 85%,rgba(18,59,99,.16),transparent 28%),linear-gradient(135deg,#fbf7ef,#f3f7fb)}body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.055;background-image:radial-gradient(#071a33 1px,transparent 1px);background-size:18px 18px}.shell{position:relative;z-index:1;width:min(1080px,100%);min-height:min(680px,calc(100svh - 60px));display:grid;grid-template-columns:minmax(0,1.08fr) minmax(360px,.92fr);overflow:hidden;border:1px solid rgba(19,32,51,.13);border-radius:32px;background:rgba(255,253,248,.92);box-shadow:0 32px 90px rgba(7,26,51,.18);animation:arrive .75s cubic-bezier(.2,.8,.2,1) both}.story{position:relative;display:flex;flex-direction:column;justify-content:space-between;padding:clamp(38px,6vw,72px);overflow:hidden;color:white;background:linear-gradient(145deg,var(--navy),#123b63 70%,#174d7c)}.story:after{content:"";position:absolute;width:390px;height:390px;right:-170px;bottom:-175px;border:1px solid rgba(255,255,255,.19);border-radius:50%;box-shadow:0 0 0 55px rgba(255,255,255,.035),0 0 0 110px rgba(255,255,255,.025);animation:drift 7s ease-in-out infinite}.brand{position:relative;z-index:1;display:flex;align-items:center;gap:12px;font-weight:800}.monogram{display:grid;place-items:center;width:44px;height:44px;border-radius:14px;background:var(--paper);color:var(--navy);box-shadow:0 10px 30px rgba(0,0,0,.18)}.monogram b{color:var(--gold)}.intro{position:relative;z-index:1;max-width:560px}.eyebrow{margin:0 0 16px;color:#e4c982;font-size:.76rem;font-weight:850;letter-spacing:.2em;text-transform:uppercase}.intro h1{margin:0 0 22px;color:#fff;font:700 clamp(2.8rem,5vw,5.2rem)/.98 Georgia,"Times New Roman",serif;letter-spacing:-.045em}.intro p{max-width:48ch;margin:0;color:#dce7f2;font-size:1.05rem}.values{position:relative;z-index:1;display:flex;gap:9px;flex-wrap:wrap;margin-top:30px}.values span{padding:8px 12px;border:1px solid rgba(255,255,255,.18);border-radius:999px;background:rgba(255,255,255,.08);font-size:.78rem;font-weight:750;backdrop-filter:blur(8px)}.access{display:grid;align-content:center;padding:clamp(34px,5vw,66px);background:rgba(255,253,248,.88)}.lock{display:grid;place-items:center;width:54px;height:54px;margin-bottom:24px;border-radius:17px;color:var(--gold);background:var(--navy);box-shadow:0 14px 34px rgba(7,26,51,.19);animation:float 4s ease-in-out infinite}.lock svg{width:25px;height:25px}.kicker{margin:0 0 9px;color:var(--gold);font-size:.75rem;font-weight:850;letter-spacing:.17em;text-transform:uppercase}.access h2{margin:0 0 12px;color:var(--navy);font:700 clamp(2.1rem,4vw,3.2rem)/1.04 Georgia,"Times New Roman",serif;letter-spacing:-.035em}.access>p{margin:0;color:var(--muted)}form{margin-top:30px}label{display:block;margin-bottom:9px;color:var(--navy);font-size:.88rem;font-weight:800}.field{position:relative}.field svg{position:absolute;left:16px;top:50%;width:19px;height:19px;color:#7a8797;transform:translateY(-50%);pointer-events:none}input{width:100%;min-height:54px;padding:14px 16px 14px 48px;border:1px solid rgba(19,32,51,.18);border-radius:15px;background:#fff;color:var(--ink);font:inherit;box-shadow:0 7px 20px rgba(7,26,51,.04);transition:border-color .2s,box-shadow .2s,transform .2s}input:hover{border-color:rgba(18,59,99,.38)}input:focus{outline:0;border-color:var(--gold);box-shadow:0 0 0 4px rgba(201,162,77,.18),0 12px 30px rgba(7,26,51,.08);transform:translateY(-1px)}button{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;min-height:54px;margin-top:14px;padding:14px 20px;border:0;border-radius:15px;background:var(--navy);color:#fff;font:800 1rem/1 system-ui,sans-serif;cursor:pointer;box-shadow:0 14px 34px rgba(7,26,51,.2);transition:transform .2s,box-shadow .2s,background .2s}button:hover{transform:translateY(-2px);background:var(--blue);box-shadow:0 18px 40px rgba(7,26,51,.25)}button:focus-visible{outline:3px solid rgba(201,162,77,.5);outline-offset:3px}.arrow{transition:transform .2s}button:hover .arrow{transform:translateX(4px)}.error{margin:18px 0 -10px!important;padding:11px 13px;border:1px solid #e7b4ae;border-radius:12px;background:#fff0ee;color:#9f2f25!important;font-size:.88rem;font-weight:750}.privacy{display:flex;align-items:center;gap:8px;margin-top:18px!important;color:#7a8797!important;font-size:.78rem}.privacy svg{flex:0 0 auto;width:15px;height:15px}.accent{position:absolute;top:24px;right:24px;width:12px;height:12px;border-radius:50%;background:var(--gold);box-shadow:0 0 0 8px rgba(201,162,77,.13);animation:pulse 2.5s ease-in-out infinite}@keyframes arrive{from{opacity:0;transform:translateY(24px) scale(.985)}to{opacity:1;transform:none}}@keyframes float{50%{transform:translateY(-7px) rotate(-2deg)}}@keyframes pulse{50%{box-shadow:0 0 0 14px rgba(201,162,77,0)}}@keyframes drift{50%{transform:translate(-18px,-12px)}}@media(max-width:800px){body{padding:0;place-items:stretch}.shell{min-height:100svh;grid-template-columns:1fr;border:0;border-radius:0}.story{min-height:340px;padding:34px clamp(22px,7vw,52px)}.intro h1{font-size:clamp(2.7rem,11vw,4.3rem)}.values{margin-top:22px}.access{padding:44px clamp(22px,7vw,52px) 54px}.accent{top:18px;right:18px}}@media(max-width:430px){.story{min-height:300px}.intro p{font-size:.95rem}.values span:nth-child(n+3){display:none}.lock{width:48px;height:48px;border-radius:15px;margin-bottom:20px}.access h2{font-size:2.25rem}form{margin-top:24px}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.001ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.001ms!important}}</style></head><body><main class="shell"><section class="story" aria-label="Portfolio introduction"><div class="brand"><span class="monogram"><b>J</b>D</span><span>Jaysheel Desai</span></div><div class="intro"><p class="eyebrow">Biomedical Sciences · Pre-Med</p><h1>A journey shaped by service and science.</h1><p>Welcome to a private portfolio exploring clinical experience, research, teaching, mentorship, and the path toward medicine.</p><div class="values" aria-label="Portfolio themes"><span>Compassion</span><span>Curiosity</span><span>Leadership</span><span>Growth</span></div></div></section><section class="access"><span class="accent" aria-hidden="true"></span><div class="lock" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></div><p class="kicker">Private access</p><h2>Welcome in.</h2><p>This portfolio is reserved for invited visitors.</p>${message ? `<p class="error" role="alert">${message}</p>` : ""}<form method="post" action="/login"><label for="password">Access password</label><div class="field"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M7 10V7a5 5 0 0 1 10 0v3"/><rect x="4" y="10" width="16" height="11" rx="3"/></svg><input id="password" name="password" type="password" required autofocus autocomplete="current-password" placeholder="Enter your password"></div><button type="submit"><span>Enter portfolio</span><span class="arrow" aria-hidden="true">→</span></button></form><p class="privacy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Secure access · Session ends after 5 minutes of inactivity</p></section></main></body></html>`;
}

function send(res, status, body, extra = {}) {
  res.writeHead(status, headers({ "Content-Type": "text/html; charset=utf-8", ...extra }));
  res.end(body);
}

function themedLogin(message = "") {
  return loginPage(message).replace("</head>", '<link rel="stylesheet" href="/login-layout.css"></head>');
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/login-layout.css") {
    res.writeHead(200, headers({ "Content-Type": "text/css; charset=utf-8" }));
    return res.end(loginLayoutFix);
  }

  if (req.method === "GET" && req.url === "/login") return send(res, 200, themedLogin());

  if (req.method === "GET" && req.url === "/logout") {
    const id = sessionId(req);
    if (id) sessions.delete(id);
    res.writeHead(303, headers({ Location: "/login", "Set-Cookie": cookie(req, "", true) }));
    return res.end();
  }

  if (req.method === "POST" && req.url === "/session-touch") {
    if (!sameOrigin(req)) return send(res, 403, "Forbidden");
    if (!authenticated(req, true)) return send(res, 401, "Session expired");
    res.writeHead(204, headers());
    return res.end();
  }

  if (req.method === "GET" && req.url === "/session-guard.js") {
    if (!authenticated(req)) return send(res, 401, "Session expired");
    res.writeHead(200, headers({ "Content-Type": "text/javascript; charset=utf-8" }));
    return res.end(`(()=>{let active=true,lastTouch=0,idleTimer;const expire=()=>location.replace('/logout');const mark=()=>{active=true;clearTimeout(idleTimer);idleTimer=setTimeout(expire,300000)};['pointerdown','keydown','scroll','touchstart'].forEach(e=>addEventListener(e,mark,{passive:true}));mark();setInterval(async()=>{if(!active)return;active=false;if(Date.now()-lastTouch<30000)return;lastTouch=Date.now();try{const r=await fetch('/session-touch',{method:'POST',credentials:'same-origin'});if(r.status===401)location.replace('/login')}catch{}},15000)})();`);
  }

  if (req.method === "POST" && req.url === "/login") {
    if (!sameOrigin(req)) return send(res, 403, "Forbidden");
    const ip = req.socket.remoteAddress || "local";
    const record = attempts.get(ip) || { count: 0, blockedUntil: 0 };
    if (record.blockedUntil > Date.now()) {
      const retrySeconds = Math.ceil((record.blockedUntil - Date.now()) / 1000);
      return send(res, 429, themedLogin("Too many attempts. Please wait before trying again."), { "Retry-After": String(retrySeconds) });
    }
    let body = "";
    req.on("data", chunk => { body += chunk; if (body.length > 4096) req.destroy(); });
    req.on("end", () => {
      const supplied = (new URLSearchParams(body).get("password") || "").slice(0, 1024);
      const suppliedHash = crypto.scryptSync(supplied, passwordSalt, 64);
      const valid = crypto.timingSafeEqual(suppliedHash, passwordHash);
      if (!valid) {
        record.count += 1;
        if (record.count >= 5) {
          const lockMs = Math.min(15 * 60_000, 30_000 * (2 ** Math.min(record.count - 5, 5)));
          record.blockedUntil = Date.now() + lockMs;
        }
        attempts.set(ip, record);
        return send(res, 401, themedLogin("That password is not correct."));
      }
      attempts.delete(ip);
      const id = crypto.randomBytes(24).toString("base64url");
      sessions.set(id, { lastActivity: Date.now() });
      res.writeHead(303, headers({ Location: "/", "Set-Cookie": cookie(req, `${id}.${sign(id)}`) }));
      res.end();
    });
    return;
  }

  if (!authenticated(req)) {
    res.writeHead(303, headers({ Location: "/login" }));
    return res.end();
  }

  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "Method not allowed");
  let requested;
  try { requested = decodeURIComponent(new URL(req.url, `http://${host}`).pathname); } catch { return send(res, 400, "Bad request"); }
  if (requested.endsWith("/")) requested += "index.html";
  const file = path.resolve(root, `.${requested}`);
  if (file !== root && !file.startsWith(root + path.sep)) return send(res, 403, "Forbidden");
  fs.stat(file, (error, stat) => {
    if (error || !stat.isFile()) return send(res, 404, "Not found");
    const extension = path.extname(file).toLowerCase();
    if (extension === ".html") {
      if (!authenticated(req, true)) {
        res.writeHead(303, headers({ Location: "/login" }));
        return res.end();
      }
      return fs.readFile(file, "utf8", (readError, html) => {
        if (readError) return send(res, 500, "Unable to load page");
        const protectedHtml = html.replace(/<\/body>/i, '<script src="/session-guard.js" defer></script></body>');
        res.writeHead(200, headers({ "Content-Type": mime[extension] }));
        res.end(protectedHtml);
      });
    }
    res.writeHead(200, headers({ "Content-Type": mime[extension] || "application/octet-stream" }));
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(file).pipe(res);
  });
});

server.listen(port, host, () => console.log(`Secure preview: http://${host}:${port}\nLocal preview password: ${password}`));
