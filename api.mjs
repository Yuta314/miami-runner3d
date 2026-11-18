import { getStore } from "@netlify/blobs";
import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHmac } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const store = getStore("miami-runner-data");
const enc = (v) => Buffer.from(v).toString("base64url");
const json = (statusCode, data) => ({
  statusCode,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  body: JSON.stringify(data)
});
const norm = (s) => String(s || "").trim().toLowerCase();
const validName = (s) => /^[a-zA-Z0-9_]{3,18}$/.test(String(s || ""));
const secret = process.env.SESSION_SECRET;
const ownerName = norm(process.env.OWNER_USERNAME);

async function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const key = await scrypt(password, salt, 64);
  return { salt, hash: Buffer.from(key).toString("hex") };
}
async function verifyPassword(password, record) {
  const key = Buffer.from(await scrypt(password, record.salt, 64));
  const expected = Buffer.from(record.hash, "hex");
  return key.length === expected.length && timingSafeEqual(key, expected);
}
function sign(payload) {
  const body = enc(JSON.stringify(payload));
  const sig = createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function readToken(token) {
  if (!secret || !token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = createHmac("sha256", secret).update(body).digest();
  let actual;
  try { actual = Buffer.from(sig, "base64url"); } catch { return null; }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
async function getUser(username) {
  return await store.get(`user:${norm(username)}`, { type: "json" });
}
async function saveUser(user) {
  await store.setJSON(`user:${user.username}`, user);
}
async function requireAuth(event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const payload = readToken(token);
  if (!payload) return { error: json(401, { error: "Connexion requise" }) };
  const user = await getUser(payload.username);
  if (!user || user.role !== payload.role) return { error: json(401, { error: "Session invalide" }) };
  return { user };
}
function method(event) { return event.httpMethod || "GET"; }
function body(event) {
  try { return JSON.parse(event.body || "{}"); } catch { return {}; }
}

export default async (event) => {
  try {
    if (!secret || secret.length < 32 || !ownerName || !process.env.OWNER_PASSWORD) {
      return json(503, { error: "Configuration serveur manquante. Ajoute OWNER_USERNAME, OWNER_PASSWORD et SESSION_SECRET dans Netlify." });
    }
    const path = (event.path || "").replace(/^\/.netlify\/functions\/api\/?/, "/").replace(/^\/api/, "") || "/";
    const data = body(event);

    if (path === "/register" && method(event) === "POST") {
      const username = norm(data.username);
      const password = String(data.password || "");
      if (!validName(data.username)) return json(400, { error: "Pseudo : 3 à 18 caractères, lettres, chiffres ou _." });
      if (password.length < 10) return json(400, { error: "Choisis un mot de passe d'au moins 10 caractères." });
      if (await getUser(username)) return json(409, { error: "Ce pseudo est déjà utilisé." });

      const isOwner = username === ownerName && password === process.env.OWNER_PASSWORD;
      if (username === ownerName && !isOwner) return json(403, { error: "Ce pseudo est réservé au propriétaire." });
      const credentials = await hashPassword(password);
      const user = { username, ...credentials, role: isOwner ? "owner" : "player", createdAt: new Date().toISOString() };
      await saveUser(user);
      const token = sign({ username, role: user.role, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 });
      return json(201, { token, username, role: user.role });
    }

    if (path === "/login" && method(event) === "POST") {
      const username = norm(data.username);
      const user = await getUser(username);
      if (!user || !(await verifyPassword(String(data.password || ""), user))) {
        return json(401, { error: "Pseudo ou mot de passe incorrect." });
      }
      const token = sign({ username, role: user.role, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 });
      return json(200, { token, username, role: user.role });
    }

    if (path === "/me" && method(event) === "GET") {
      const auth = await requireAuth(event);
      if (auth.error) return auth.error;
      return json(200, { username: auth.user.username, role: auth.user.role });
    }

    if (path === "/coins" && (method(event) === "GET" || method(event) === "POST")) {
      const auth = await requireAuth(event);
      if (auth.error) return auth.error;
      const user = auth.user;
      if (method(event) === "POST") {
        const amount = Number(data.amount);
        if (!Number.isInteger(amount) || amount < 1 || amount > 10) return json(400, { error: "Nombre de pièces invalide." });
        user.coins = Math.max(0, Number(user.coins) || 0) + amount;
        await saveUser(user);
      }
      return json(200, { coins: Math.max(0, Number(user.coins) || 0) });
    }

    if (path.startsWith("/admin/")) {
      const auth = await requireAuth(event);
      if (auth.error) return auth.error;
      if (auth.user.role !== "owner") return json(403, { error: "Réservé au OWNER." });

      if (path === "/admin/users" && method(event) === "GET") {
        const { blobs } = await store.list({ prefix: "user:" });
        const users = [];
        for (const item of blobs) {
          const u = await getUser(item.key.slice(5));
          if (u) users.push({ username: u.username, role: u.role, createdAt: u.createdAt });
        }
        users.sort((a,b) => a.username.localeCompare(b.username));
        return json(200, { users });
      }

      if (path === "/admin/grant" && method(event) === "POST") {
        const username = norm(data.username);
        const user = await getUser(username);
        if (!user) return json(404, { error: "Joueur introuvable. Il doit d'abord créer son compte." });
        if (user.role === "owner") return json(400, { error: "Le OWNER ne peut pas être modifié." });
        user.role = "admin";
        await saveUser(user);
        return json(200, { message: `${user.username} est maintenant ADMIN.` });
      }

      if (path === "/admin/revoke" && method(event) === "POST") {
        const username = norm(data.username);
        const user = await getUser(username);
        if (!user) return json(404, { error: "Joueur introuvable." });
        if (user.role === "owner") return json(400, { error: "Impossible de retirer le OWNER." });
        user.role = "player";
        await saveUser(user);
        return json(200, { message: `${user.username} est redevenu PLAYER.` });
      }
    }

    return json(404, { error: "Route inconnue." });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Erreur serveur. Réessaie plus tard." });
  }
};
