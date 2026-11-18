import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { sql } from "server/db";
import { resetRateLimits } from "server/lib/ratelimit";
import { forgetAuthClient } from "server/lib/sso";
import { checkSocketSessions } from "server/realtime/ws";
import { startTestServer, type Client, type TestContext } from "server/test-helpers";

// A stand-in for the identity provider: discovery, keys, token, revocation.
const ISSUER = "https://auth.example.test";

const keyPair = (kid: string) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "EdDSA", use: "sig" } };
};
const k1 = keyPair("k1");
const stranger = keyPair("k1");

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Handler = (form: URLSearchParams) => Response;

const fake = {
  keysDown: false,
  seen: [] as { path: string; form: URLSearchParams }[],
  token: (() => json(500, {})) as Handler,
};

const issuer = Bun.serve({
  port: 0,
  async fetch(req) {
    const path = new URL(req.url).pathname;
    const form = new URLSearchParams(req.method === "POST" ? await req.text() : "");
    fake.seen.push({ path, form });
    const at = (p: string) => `${ISSUER}${p}`;
    switch (path) {
      case "/.well-known/openid-configuration":
        return json(200, {
          issuer: ISSUER,
          authorization_endpoint: at("/oauth/authorize"),
          token_endpoint: at("/oauth/token"),
          revocation_endpoint: at("/oauth/revoke"),
          jwks_uri: at("/.well-known/jwks.json"),
          end_session_endpoint: at("/logout"),
        });
      case "/.well-known/jwks.json":
        return fake.keysDown ? json(503, {}) : json(200, { keys: [k1.jwk] });
      case "/oauth/token":
        return fake.token(form);
      case "/oauth/revoke":
        return new Response(null, { status: 200 });
    }
    return json(404, { error: "not_found" });
  },
});

const nowS = () => Math.floor(Date.now() / 1000);

const jwt = (header: object, payload: object, key: KeyObject = k1.privateKey) => {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${p}.${edSign(null, Buffer.from(`${h}.${p}`), key).toString("base64url")}`;
};

interface Person {
  sub: string;
  username: string;
  name?: string;
  role?: string;
  sid?: string;
  email?: string | null;
  emailVerified?: boolean;
}

const accessToken = (p: Person) =>
  jwt(
    { alg: "EdDSA", typ: "at+jwt", kid: "k1" },
    { iss: ISSUER, sub: p.sub, aud: "doc", iat: nowS(), exp: nowS() + 600, sid: p.sid ?? `ses_${p.username}`, username: p.username, name: p.name ?? p.username, role: p.role ?? "member" },
  );

const idToken = (p: Person, nonce: string) =>
  jwt(
    { alg: "EdDSA", typ: "JWT", kid: "k1" },
    {
      iss: ISSUER,
      sub: p.sub,
      aud: "doc",
      iat: nowS(),
      exp: nowS() + 600,
      nonce,
      auth_time: nowS(),
      ...(p.email === null ? {} : { email: p.email ?? `${p.username}@example.com`, email_verified: p.emailVerified ?? true }),
    },
  );

const eventToken = (events: object, key: KeyObject = k1.privateKey) =>
  jwt({ alg: "EdDSA", typ: "secevent+jwt", kid: "k1" }, { iss: ISSUER, aud: "doc", iat: nowS(), jti: `evt_${crypto.randomUUID()}`, events }, key);

/** Answers refreshes as the provider would for this person now. */
const refreshesAs = (p: Person) => {
  fake.token = (form) =>
    form.get("grant_type") === "refresh_token" && form.get("refresh_token") === `rt_${p.username}`
      ? json(200, { access_token: accessToken(p), token_type: "Bearer", expires_in: 600 })
      : json(400, { error: "invalid_grant" });
};

const SSO_ENV = {
  AUTH_ISSUER: ISSUER,
  AUTH_BACKCHANNEL_URL: `http://localhost:${issuer.port}`,
  AUTH_CLIENT_ID: "doc",
  AUTH_CLIENT_SECRET: "s3cret",
};
const AUTH_NAMES = [...Object.keys(SSO_ENV), "AUTH_LOCAL_LOGIN", "AUTH_LINK_USERS", "AUTH_REDIRECT_URI", "AUTH_AUDIENCE"];

const setEnv = (vars: Record<string, string>) => {
  for (const name of AUTH_NAMES) delete process.env[name];
  Object.assign(process.env, vars);
};

let t: TestContext;
let alice: Client;
let aliceId: string;

beforeAll(async () => {
  t = await startTestServer();
});

afterAll(async () => {
  setEnv({});
  forgetAuthClient();
  issuer.stop(true);
  await t.close();
});

beforeEach(() => {
  resetRateLimits();
  fake.seen = [];
  fake.keysDown = false;
});

const sessionCookie = (res: Response) => {
  const header = res.headers.getSetCookie().find((c) => c.startsWith("session="));
  return header ? /^session=([^;]*)/.exec(header)![1]! : null;
};

/** Signs in through the provider as `p`: the app's login redirect, then its callback. */
const ssoSignIn = async (p: Person, returnTo = "/") => {
  resetRateLimits();
  const start = await fetch(`${t.base}/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`, { redirect: "manual" });
  expect(start.status).toBe(302);
  const authorize = new URL(start.headers.get("location")!);
  const loginCookie = start.headers.getSetCookie().find((c) => c.startsWith("__Host-login="))!.split(";")[0]!;
  const challenge = authorize.searchParams.get("code_challenge");
  fake.token = (form) => {
    const verified = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") === challenge;
    if (form.get("code") !== "c0de" || !verified) return json(400, { error: "invalid_grant" });
    return json(200, {
      access_token: accessToken(p),
      id_token: idToken(p, authorize.searchParams.get("nonce")!),
      refresh_token: `rt_${p.username}`,
      token_type: "Bearer",
      expires_in: 600,
    });
  };
  const res = await fetch(`${t.base}/api/auth/callback?code=c0de&state=${authorize.searchParams.get("state")}`, {
    headers: { cookie: loginCookie },
    redirect: "manual",
  });
  const client = t.client();
  client.cookie = sessionCookie(res);
  return { res, client, location: res.headers.get("location"), authorize };
};

const userBySub = async (sub: string) => (await sql`SELECT * FROM users WHERE auth_sub = ${sub}`)[0];

const postEvent = (token: string, headers: Record<string, string> = {}) =>
  fetch(`${t.base}/api/auth/events`, { method: "POST", body: token, headers: { "Content-Type": "application/secevent+jwt", ...headers } });

/** A socket on the app's realtime endpoint, with a promise of its close code. */
const openSocket = async (client: Client) => {
  const ws = new WebSocket(`${t.base.replace("http", "ws")}/api/ws`, { headers: { cookie: `session=${client.cookie}` } } as never);
  const closed = new Promise<number>((resolve) => (ws.onclose = (e) => resolve(e.code)));
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  return { ws, closed };
};

const settle = <T>(promise: Promise<T>, ms = 1000) =>
  Promise.race([promise, Bun.sleep(ms).then(() => "still open" as const)]);

describe("with single sign-on off", () => {
  test("the browser learns that only passwords are used", async () => {
    expect((await t.client().get("/auth/config")).body.data).toEqual({ sso: { enabled: false, localLogin: true } });
  });

  test("its routes answer as unknown routes do", async () => {
    const anon = t.client();
    const unknown = await anon.get("/auth/nothing-here");
    expect(unknown.status).toBe(404);
    for (const res of [await anon.get("/auth/login?returnTo=/"), await anon.get("/auth/callback?code=c0de&state=x"), await anon.post("/auth/events")]) {
      expect(res.status).toBe(404);
      expect(res.body).toEqual(unknown.body);
    }
  });
});

describe("signing in", () => {
  beforeAll(() => {
    setEnv(SSO_ENV);
  });

  test("the browser learns that single sign-on is the only way in", async () => {
    expect((await t.client().get("/auth/config")).body.data).toEqual({ sso: { enabled: true, localLogin: false } });
  });

  test("the login route sends the browser to the provider with a login cookie", async () => {
    const res = await fetch(`${t.base}/api/auth/login?returnTo=/s/general`, { redirect: "manual" });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(`${ISSUER}/oauth/authorize`);
    expect(location.searchParams.get("client_id")).toBe("doc");
    expect(location.searchParams.get("redirect_uri")).toBe("http://doc.test/api/auth/callback");
    expect(res.headers.getSetCookie().some((c) => /^__Host-login=[A-Za-z0-9_-]+;/.test(c))).toBe(true);
  });

  test("the first sign-in sets up an empty workspace, with the provider's role", async () => {
    expect((await t.client().get("/setup")).body.data).toEqual({ needsSetup: true });
    const { res, client, location } = await ssoSignIn({ sub: "usr_alice", username: "alice", name: "Alice", role: "owner" }, "/s/general");
    expect(res.status).toBe(302);
    expect(location).toBe("/s/general");
    expect(res.headers.getSetCookie()).toContain("__Host-login=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    alice = client;
    const me = await alice.get("/me");
    expect(me.status).toBe(200);
    expect(me.body.data.user).toMatchObject({ name: "Alice", email: "alice@example.com", role: "owner" });
    expect(me.body.data.workspace.name).toBe("My workspace");
    aliceId = me.body.data.user.id;
    expect((await t.client().get("/setup")).body.data).toEqual({ needsSetup: false });
    const spaces = await alice.get("/spaces");
    expect(spaces.body.data).toEqual([expect.objectContaining({ name: "General", slug: "general", role: "admin" })]);
    expect(me.body.data.workspace.defaultSpaceId).toBe(spaces.body.data[0].id);
    const groups = await alice.get("/groups");
    expect(groups.body.data).toEqual([expect.objectContaining({ name: "Everyone", isDefault: true, memberCount: 1 })]);
    const [session] = await sql`SELECT auth_sid, auth_refresh_token, auth_recheck_at FROM sessions WHERE user_id = ${aliceId}`;
    expect(session.auth_sid).toBe("ses_alice");
    expect(session.auth_refresh_token).toBe("rt_alice");
    expect(new Date(session.auth_recheck_at).getTime() - Date.now()).toBeGreaterThan(9 * 60_000);
  });

  test("a return path that isn't local lands on the home page", async () => {
    const { location } = await ssoSignIn({ sub: "usr_alice", username: "alice", name: "Alice", role: "owner" }, "//evil.example/x");
    expect(location).toBe("/");
  });

  test("passwords, setup, resets and invitations are refused", async () => {
    const anon = t.client();
    const refusals = [
      await anon.post("/auth/login", { email: "alice@example.com", password: "whatever-pw" }),
      await anon.post("/setup", { workspaceName: "X", name: "X", email: "x@example.com", password: "whatever-pw" }),
      await anon.post("/auth/forgot-password", { email: "alice@example.com" }),
      await anon.post("/auth/reset-password", { token: "x", password: "whatever-pw" }),
      await alice.post("/auth/change-password", { currentPassword: "whatever-pw", newPassword: "whatever-pw2" }),
      await alice.post("/invitations", { emails: ["new@example.com"] }),
      await anon.get(`/invitations/${crypto.randomUUID()}?token=x`),
      await anon.post("/invitations/accept", { id: crypto.randomUUID(), token: "x", name: "X", password: "whatever-pw" }),
    ];
    for (const res of refusals) {
      expect(res.status).toBe(403);
      expect(res.body.error!.code).toBe("local_login_disabled");
    }
  });

  test("a new person joins as a member of the default group, with an unknown role as member", async () => {
    const { location, client } = await ssoSignIn({ sub: "usr_bob", username: "bob", name: "Bob", role: "editor" });
    expect(location).toBe("/");
    const me = (await client.get("/me")).body.data.user;
    expect(me).toMatchObject({ name: "Bob", email: "bob@example.com", role: "member" });
    const groups = await client.get("/groups");
    expect(groups.body.data[0].memberCount).toBe(2);
    expect((await client.get("/spaces")).body.data.map((s: { slug: string }) => s.slug)).toEqual([]);
  });

  test("signing in again finds the same user and takes the provider's name, role and verified email", async () => {
    const before = await userBySub("usr_bob");
    const { client } = await ssoSignIn({ sub: "usr_bob", username: "bob", name: "Robert", role: "admin", email: "robert@example.com" });
    const me = (await client.get("/me")).body.data.user;
    expect(me).toMatchObject({ id: before.id, name: "Robert", role: "admin", email: "robert@example.com" });
    const unverified = await ssoSignIn({ sub: "usr_bob", username: "bob", name: "Robert", role: "admin", email: "bobby@example.com", emailVerified: false });
    expect((await unverified.client.get("/me")).body.data.user.email).toBe("robert@example.com");
  });

  test("a person without an email is refused", async () => {
    const { location, client, res } = await ssoSignIn({ sub: "usr_noemail", username: "nomail", email: null });
    expect(location).toBe("/login?sso_error=no_email");
    expect(client.cookie).toBeNull();
    expect(res.headers.getSetCookie()).toContain("__Host-login=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    expect(await userBySub("usr_noemail")).toBeUndefined();
  });

  test("a callback the provider didn't start, or that it refused, goes back to sign-in", async () => {
    const forged = await fetch(`${t.base}/api/auth/callback?code=c0de&state=x`, { redirect: "manual" });
    expect(forged.headers.get("location")).toBe("/login?sso_error=login_failed");
    const start = await fetch(`${t.base}/api/auth/login`, { redirect: "manual" });
    const authorize = new URL(start.headers.get("location")!);
    const cookie = start.headers.getSetCookie()[0]!.split(";")[0]!;
    const denied = await fetch(`${t.base}/api/auth/callback?error=access_denied&state=${authorize.searchParams.get("state")}`, {
      headers: { cookie },
      redirect: "manual",
    });
    expect(denied.headers.get("location")).toBe("/login?sso_error=access_denied");
  });
});

describe("linking existing accounts", () => {
  let local: Record<string, string> = {};

  beforeAll(async () => {
    // Local accounts made while passwords still worked.
    setEnv({ ...SSO_ENV, AUTH_LOCAL_LOGIN: "true" });
    for (const email of ["dave.local@example.com", "erin@example.com", "frank@example.com", "gina@example.com"]) {
      local[email] = (await t.addMember(alice, email)).user.id;
    }
    await alice.post("/members/deactivate", { userId: local["gina@example.com"] });
    setEnv({ ...SSO_ENV, AUTH_LINK_USERS: "dave.local@example.com=dave" });
  });

  afterAll(() => {
    local = {};
  });

  test("AUTH_LINK_USERS links the account it names", async () => {
    const { client } = await ssoSignIn({ sub: "usr_dave", username: "dave", name: "Dave", email: "dave@example.com", emailVerified: false });
    expect((await client.get("/me")).body.data.user.id).toBe(local["dave.local@example.com"]);
    expect((await userBySub("usr_dave")).id).toBe(local["dave.local@example.com"]);
  });

  test("a verified email links the one account with that address", async () => {
    const { client } = await ssoSignIn({ sub: "usr_erin", username: "erin", email: "Erin@Example.com" });
    expect((await client.get("/me")).body.data.user.id).toBe(local["erin@example.com"]);
  });

  test("an unverified email that an unlinked account has is refused", async () => {
    const { location } = await ssoSignIn({ sub: "usr_frank", username: "frank", email: "frank@example.com", emailVerified: false });
    expect(location).toBe("/login?sso_error=account_exists");
    expect(await userBySub("usr_frank")).toBeUndefined();
  });

  test("a deactivated account isn't linked by email", async () => {
    const { location } = await ssoSignIn({ sub: "usr_gina", username: "gina", email: "gina@example.com" });
    expect(location).toBe("/login?sso_error=account_exists");
  });

  test("an account already linked to someone else isn't taken over", async () => {
    const { location } = await ssoSignIn({ sub: "usr_mallory", username: "mallory", email: "erin@example.com" });
    expect(location).toBe("/login?sso_error=account_exists");
    expect((await userBySub("usr_erin")).id).toBe(local["erin@example.com"]);
  });
});

describe("re-checking access", () => {
  let carol: Client;
  let sessionId: string;

  beforeAll(async () => {
    setEnv(SSO_ENV);
    carol = (await ssoSignIn({ sub: "usr_carol", username: "carol", name: "Carol" })).client;
    [{ id: sessionId }] = await sql`SELECT s.id FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.auth_sub = 'usr_carol'`;
  });

  const due = (minutesAgo: number) => sql`UPDATE sessions SET auth_recheck_at = now() - make_interval(mins => ${minutesAgo}) WHERE id = ${sessionId}`;
  const refreshes = () => fake.seen.filter((s) => s.path === "/oauth/token").length;

  test("is not done before it is due", async () => {
    expect((await carol.get("/me")).status).toBe(200);
    expect(refreshes()).toBe(0);
  });

  test("applies the provider's answer and waits another 10 minutes", async () => {
    await due(1);
    refreshesAs({ sub: "usr_carol", username: "carol", name: "Carol C", role: "admin" });
    const me = await carol.get("/me");
    expect(me.status).toBe(200);
    expect(me.body.data.user).toMatchObject({ name: "Carol C", role: "admin" });
    expect(refreshes()).toBe(1);
    const [row] = await sql`SELECT auth_recheck_at FROM sessions WHERE id = ${sessionId}`;
    expect(new Date(row.auth_recheck_at).getTime() - Date.now()).toBeGreaterThan(9 * 60_000);
    await carol.get("/me");
    expect(refreshes()).toBe(1);
  });

  test("serves the request while the provider is unreachable, and asks again on the next", async () => {
    await due(30);
    fake.token = () => json(503, { error: "temporarily_unavailable" });
    expect((await carol.get("/me")).status).toBe(200);
    expect((await carol.get("/me")).status).toBe(200);
    expect(refreshes()).toBe(2);
  });

  test("ends the session once the provider has been unreachable for an hour past the re-check", async () => {
    await due(61);
    fake.token = () => json(503, { error: "temporarily_unavailable" });
    expect((await carol.get("/me")).status).toBe(401);
    expect(await sql`SELECT 1 FROM sessions WHERE id = ${sessionId}`).toHaveLength(0);
  });

  test("ends the session when the provider refuses the refresh token", async () => {
    carol = (await ssoSignIn({ sub: "usr_carol", username: "carol", name: "Carol" })).client;
    [{ id: sessionId }] = await sql`SELECT s.id FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.auth_sub = 'usr_carol'`;
    const socket = await openSocket(carol);
    await due(1);
    fake.token = () => json(400, { error: "invalid_grant" });
    expect((await carol.get("/me")).status).toBe(401);
    expect(await sql`SELECT 1 FROM sessions WHERE id = ${sessionId}`).toHaveLength(0);
    expect(await settle(socket.closed)).toBe(4001);
  });
});

describe("events from the provider", () => {
  beforeAll(() => {
    setEnv(SSO_ENV);
  });

  test("session.ended signs out the sessions of that provider session and closes their sockets", async () => {
    const one = await ssoSignIn({ sub: "usr_hal", username: "hal", sid: "ses_hal_1" });
    const two = await ssoSignIn({ sub: "usr_hal", username: "hal", sid: "ses_hal_2" });
    const socket = await openSocket(one.client);
    const res = await postEvent(eventToken({ "session.ended": { sid: "ses_hal_1" } }));
    expect(res.status).toBe(202);
    expect((await one.client.get("/me")).status).toBe(401);
    expect((await two.client.get("/me")).status).toBe(200);
    expect(await settle(socket.closed)).toBe(4001);
    // Delivered again: nothing left to do, and still acknowledged.
    expect((await postEvent(eventToken({ "session.ended": { sid: "ses_hal_1" } }))).status).toBe(202);
  });

  test("access.changed applies the new role, and a removal deactivates the user", async () => {
    const { client } = await ssoSignIn({ sub: "usr_ivy", username: "ivy" });
    expect((await postEvent(eventToken({ "access.changed": { sub: "usr_ivy", role: "admin" } }))).status).toBe(202);
    expect((await client.get("/me")).body.data.user.role).toBe("admin");
    const socket = await openSocket(client);
    expect((await postEvent(eventToken({ "access.changed": { sub: "usr_ivy", role: null } }))).status).toBe(202);
    expect((await client.get("/me")).status).toBe(401);
    expect(await settle(socket.closed)).toBe(4001);
    const user = await userBySub("usr_ivy");
    expect(user.deactivated_at).not.toBeNull();
    expect(await sql`SELECT 1 FROM sessions WHERE user_id = ${user.id}`).toHaveLength(0);
    // Access given back: the deactivation is lifted.
    expect((await postEvent(eventToken({ "access.changed": { sub: "usr_ivy", role: "member" } }))).status).toBe(202);
    expect(await userBySub("usr_ivy")).toMatchObject({ role: "member", deactivated_at: null });
  });

  test("user.disabled deactivates the user until they sign in again", async () => {
    const { client } = await ssoSignIn({ sub: "usr_jack", username: "jack" });
    expect((await postEvent(eventToken({ "user.disabled": { sub: "usr_jack" } }))).status).toBe(202);
    expect((await client.get("/me")).status).toBe(401);
    expect((await userBySub("usr_jack")).deactivated_at).not.toBeNull();
    const again = await ssoSignIn({ sub: "usr_jack", username: "jack" });
    expect((await again.client.get("/me")).status).toBe(200);
    expect((await userBySub("usr_jack")).deactivated_at).toBeNull();
  });

  test("user.deleted deactivates the user and keeps what they wrote", async () => {
    const { client } = await ssoSignIn({ sub: "usr_kim", username: "kim" });
    const { id } = await userBySub("usr_kim");
    expect((await postEvent(eventToken({ "user.deleted": { sub: "usr_kim" } }))).status).toBe(202);
    expect((await client.get("/me")).status).toBe(401);
    const [row] = await sql`SELECT deactivated_at FROM users WHERE id = ${id}`;
    expect(row.deactivated_at).not.toBeNull();
  });

  test("other events are acknowledged and ignored, whatever the content type and origin", async () => {
    const accepted = await postEvent(eventToken({ "invite.accepted": { invite: "inv_1", sub: "usr_zoe" } }), { "Content-Type": "text/plain" });
    expect(accepted.status).toBe(202);
    expect((await postEvent(eventToken({ "something.new": {} }), { Origin: "https://auth.example.test" })).status).toBe(202);
  });

  test("an event that doesn't verify is refused", async () => {
    expect((await postEvent(eventToken({ "user.disabled": { sub: "usr_alice" } }, stranger.privateKey))).status).toBe(400);
    expect((await postEvent("not a token")).status).toBe(400);
    expect((await userBySub("usr_alice")).deactivated_at).toBeNull();
  });

  test("an event that can't be checked while the provider is unreachable is answered 503, so it is sent again", async () => {
    forgetAuthClient();
    fake.keysDown = true;
    try {
      expect((await postEvent(eventToken({ "user.disabled": { sub: "usr_alice" } }))).status).toBe(503);
      expect((await userBySub("usr_alice")).deactivated_at).toBeNull();
    } finally {
      fake.keysDown = false;
      forgetAuthClient();
    }
  });
});

describe("signing out", () => {
  test("of a single sign-on session revokes its refresh token and returns the provider's sign-out address", async () => {
    setEnv(SSO_ENV);
    const { client } = await ssoSignIn({ sub: "usr_alice", username: "alice", name: "Alice", role: "owner" });
    const res = await client.post("/auth/logout");
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ logoutUrl: "https://auth.example.test/logout?client_id=doc&post_logout_redirect_uri=http%3A%2F%2Fdoc.test%2F" });
    expect((await client.get("/me")).status).toBe(401);
    for (let i = 0; i < 50 && !fake.seen.some((s) => s.path === "/oauth/revoke"); i++) await Bun.sleep(10);
    expect(fake.seen.find((s) => s.path === "/oauth/revoke")?.form.get("token")).toBe("rt_alice");
  });

  test("of a password session answers as before", async () => {
    setEnv({ ...SSO_ENV, AUTH_LOCAL_LOGIN: "true" });
    const local = t.client();
    expect((await local.post("/auth/login", { email: "erin@example.com", password: "member-password" })).status).toBe(200);
    expect((await local.post("/auth/logout")).body.data).toEqual({});
  });
});

describe("members managed by the provider", () => {
  let bobId: string;
  let frankId: string;

  beforeAll(async () => {
    setEnv({ ...SSO_ENV, AUTH_LOCAL_LOGIN: "true" });
    alice = (await ssoSignIn({ sub: "usr_alice", username: "alice", name: "Alice", role: "owner" })).client;
    bobId = (await userBySub("usr_bob")).id;
    [{ id: frankId }] = await sql`SELECT id FROM users WHERE email = 'frank@example.com'`;
  });

  test("are marked in the member list", async () => {
    const items = (await alice.get("/members?limit=200")).body.data.items as { id: string; ssoManaged?: boolean }[];
    expect(items.find((m) => m.id === bobId)?.ssoManaged).toBe(true);
    expect(items.find((m) => m.id === frankId)?.ssoManaged).toBe(false);
  });

  test("can't have their role or activation changed here, but can be removed", async () => {
    for (const res of [
      await alice.post("/members/role", { userId: bobId, role: "member" }),
      await alice.post("/members/deactivate", { userId: bobId }),
      await alice.post("/members/activate", { userId: bobId }),
    ]) {
      expect(res.status).toBe(403);
      expect(res.body.error!.code).toBe("sso_managed");
    }
    expect((await alice.post("/members/role", { userId: frankId, role: "admin" })).status).toBe(200);
    expect((await alice.post("/members/deactivate", { userId: frankId })).status).toBe(200);
    expect((await alice.post("/members/delete", { userId: bobId })).status).toBe(200);
  });
});

describe("open sockets", () => {
  beforeAll(() => {
    setEnv(SSO_ENV);
  });

  test("close within a check once their session ends or their user is deactivated elsewhere", async () => {
    const ended = await ssoSignIn({ sub: "usr_liz", username: "liz" });
    const deactivated = await ssoSignIn({ sub: "usr_max", username: "max" });
    const kept = await ssoSignIn({ sub: "usr_ned", username: "ned" });
    const sockets = await Promise.all([openSocket(ended.client), openSocket(deactivated.client), openSocket(kept.client)]);
    try {
      // As another copy of the server would: in the database only.
      await sql`DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE auth_sub = 'usr_liz')`;
      await sql`UPDATE users SET deactivated_at = now() WHERE auth_sub = 'usr_max'`;
      await checkSocketSessions();
      expect(await settle(sockets[0].closed)).toBe(4001);
      expect(await settle(sockets[1].closed)).toBe(4001);
      expect(await settle(sockets[2].closed, 300)).toBe("still open");
    } finally {
      for (const { ws } of sockets) ws.close();
    }
  });

  test("of a password session close too once it is revoked elsewhere", async () => {
    setEnv({ ...SSO_ENV, AUTH_LOCAL_LOGIN: "true" });
    const local = t.client();
    await local.post("/auth/login", { email: "erin@example.com", password: "member-password" });
    const socket = await openSocket(local);
    try {
      await sql`DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email = 'erin@example.com')`;
      await checkSocketSessions();
      expect(await settle(socket.closed)).toBe(4001);
    } finally {
      socket.ws.close();
    }
  });
});

describe("turning single sign-on off again", () => {
  test("restores the password-only answers", async () => {
    setEnv({ ...SSO_ENV, AUTH_LOCAL_LOGIN: "true" });
    const { client } = await ssoSignIn({ sub: "usr_alice", username: "alice", name: "Alice", role: "owner" });
    setEnv({});
    expect((await t.client().get("/auth/config")).body.data).toEqual({ sso: { enabled: false, localLogin: true } });
    expect((await t.client().get("/auth/login")).status).toBe(404);
    const items = (await client.get("/members?limit=200")).body.data.items as Record<string, unknown>[];
    expect(items.every((m) => !("ssoManaged" in m))).toBe(true);
    const [ivy] = await sql`SELECT id FROM users WHERE auth_sub = 'usr_ivy'`;
    expect((await client.post("/members/deactivate", { userId: ivy.id })).status).toBe(200);
    // A session whose re-check is due goes on as a password session would.
    await sql`UPDATE sessions SET auth_recheck_at = now() - interval '2 hours' WHERE user_id = ${aliceId}`;
    expect((await client.get("/me")).status).toBe(200);
    expect((await client.post("/auth/logout")).body.data).toEqual({});
  });
});
