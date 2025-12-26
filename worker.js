/* =======================
   JWT UTILS (Cloudflare)
======================= */

const encoder = new TextEncoder();

async function signJWT(payload, secret, expiresInSeconds = 604800) {
  const header = { alg: "HS256", typ: "JWT" };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;

  const base64 = obj =>
    btoa(JSON.stringify(obj))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const headerPart = base64(header);
  const payloadPart = base64({ ...payload, exp });

  const data = `${headerPart}.${payloadPart}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(data)
  );

  const signaturePart = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signaturePart}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, payload, signature] = token.split(".");
    const data = `${header}.${payload}`;

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const sig = Uint8Array.from(
      atob(signature.replace(/-/g, "+").replace(/_/g, "/")),
      c => c.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sig,
      encoder.encode(data)
    );

    if (!valid) return null;

    const decoded = JSON.parse(
      atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
    );

    if (decoded.exp < Math.floor(Date.now() / 1000)) return null;

    return decoded;
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const headers = {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store"
    };

    const url = new URL(request.url);
    const now = Date.now();

    /* =======================
       HELPERS
    ======================= */

    const isAuthorized = req =>
      req.headers.get("X-Status-Secret") === env.SECRET;

    const getJWT = req =>
      req.headers.get("Authorization")?.replace("Bearer ", "");

    const requireAdmin = async req => {
      const token = getJWT(req);
      if (!token) return null;

      const valid = await jwt.verify(token, env.JWT_SECRET);
      if (!valid) return null;

      return jwt.decode(token).payload;
    };

    const dayKey = () => new Date().toISOString().slice(0, 10);
    const monthKey = () => new Date().toISOString().slice(0, 7);

    /* =======================
       CORS
    ======================= */
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Status-Secret",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
        }
      });
    }

    /* =======================
       HEARTBEAT BOT
       POST /heartbeat
    ======================= */
    if (request.method === "POST" && url.pathname === "/heartbeat") {
      if (!isAuthorized(request)) {
        return new Response(JSON.stringify({ message: "Unauthorized" }), { status: 401, headers });
      }

      const body = await request.json();
      const raw = await env.KV.get("stats");
      const previous = raw ? JSON.parse(raw) : {};

      const stats = {
        servers: Number(body.servers) || previous.servers || 0,
        users: Number(body.users) || previous.users || 0,
        shards: Number(body.shards) || previous.shards || 1,
        startedAt: previous.startedAt || now,
        lastHeartbeat: now,
        forcedStatus: previous.forcedStatus || null
      };

      await env.KV.put("stats", JSON.stringify(stats));

      /* ===== UPTIME TRACKING ===== */
      const day = dayKey();
      const month = monthKey();

      const dayStat = JSON.parse(await env.KV.get(`uptime:${day}`) || '{"online":0,"offline":0}');
      dayStat.online += 1;
      await env.KV.put(`uptime:${day}`, JSON.stringify(dayStat));

      const monthStat = JSON.parse(await env.KV.get(`uptime:${month}`) || '{"online":0,"offline":0}');
      monthStat.online += 1;
      await env.KV.put(`uptime:${month}`, JSON.stringify(monthStat));

      return new Response(JSON.stringify({ success: true }), { headers });
    }

    /* =======================
       PUBLIC STATS
       GET /stats
    ======================= */
    if (request.method === "GET" && url.pathname === "/stats") {
      const raw = await env.KV.get("stats");
      if (!raw) {
        return new Response(JSON.stringify({
          status: "offline",
          servers: 0,
          users: 0,
          shards: 0,
          uptime: 0,
          timestamp: now
        }), { headers });
      }

      const stats = JSON.parse(raw);
      const isOnline = now - stats.lastHeartbeat < 90_000;
      let status = isOnline ? "online" : "offline";
      if (stats.forcedStatus) status = stats.forcedStatus;

      const uptime = stats.startedAt ? (now - stats.startedAt) / 3600000 : 0;

      return new Response(JSON.stringify({
        status,
        servers: stats.servers,
        users: stats.users,
        shards: stats.shards,
        uptime: Number(uptime.toFixed(2)),
        timestamp: now
      }), { headers });
    }

    /* =======================
       OAUTH DISCORD
    ======================= */

    if (request.method === "GET" && url.pathname === "/auth/login") {
      const redirect =
        "https://discord.com/oauth2/authorize" +
        `?client_id=${env.DISCORD_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(env.DISCORD_REDIRECT_URI)}` +
        `&response_type=code&scope=identify guilds.members.read`;

      return Response.redirect(redirect, 302);
    }

    if (request.method === "GET" && url.pathname === "/auth/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("Missing code", { status: 400 });

      const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.DISCORD_CLIENT_ID,
          client_secret: env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: env.DISCORD_REDIRECT_URI
        })
      });

      const token = await tokenRes.json();

      const userRes = await fetch("https://discord.com/api/users/@me", {
        headers: { Authorization: `Bearer ${token.access_token}` }
      });
      const user = await userRes.json();

      const memberRes = await fetch(
        `https://discord.com/api/users/@me/guilds/${env.DISCORD_GUILD_ID}/member`,
        { headers: { Authorization: `Bearer ${token.access_token}` } }
      );
      const member = await memberRes.json();

      const isAdmin = member.roles?.includes(env.DISCORD_ADMIN_ROLE_ID);
      if (!isAdmin) return new Response("Forbidden", { status: 403 });

    const jwtToken = await signJWT(
  { id: user.id, username: user.username, avatar: user.avatar },
  env.JWT_SECRET
);


      return Response.redirect(`${env.FRONTEND_URL}/dashboard?token=${jwtToken}`, 302);
    }

    /* =======================
       INCIDENTS
    ======================= */

    if (request.method === "GET" && url.pathname === "/incidents") {
      return new Response(await env.KV.get("incidents") || "[]", { headers });
    }

    if (request.method === "POST" && url.pathname === "/add-incident") {
      if (!(await requireAdmin(request)))
        return new Response("Unauthorized", { status: 401 });

      const body = await request.json();
      const incidents = JSON.parse(await env.KV.get("incidents") || "[]");

      incidents.unshift({
        id: crypto.randomUUID(),
        title: body.title,
        description: body.description,
        severity: body.severity || "minor",
        start: now,
        end: null
      });

      await env.KV.put("incidents", JSON.stringify(incidents));
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    if (request.method === "POST" && url.pathname === "/resolve-incident") {
      if (!(await requireAdmin(request)))
        return new Response("Unauthorized", { status: 401 });

      const { id } = await request.json();
      const incidents = JSON.parse(await env.KV.get("incidents") || "[]");
      const incident = incidents.find(i => i.id === id);
      if (!incident) return new Response("Not found", { status: 404 });

      incident.end = now;
      await env.KV.put("incidents", JSON.stringify(incidents));
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    /* =======================
       GRAPH DATA
    ======================= */

    if (request.method === "GET" && url.pathname === "/graphs/uptime/month") {
      const month = monthKey();
      return new Response(
        await env.KV.get(`uptime:${month}`) || "{}",
        { headers }
      );
    }

    if (request.method === "GET" && url.pathname === "/graphs/uptime/day") {
      const day = dayKey();
      return new Response(
        await env.KV.get(`uptime:${day}`) || "{}",
        { headers }
      );
    }

    return new Response(JSON.stringify({ message: "Not Found" }), {
      status: 404, headers
    });
  }
};
