import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ApiError,
  SESSION_EXPIRED_EVENT,
  downloadFile,
  exportAudit,
  getSession,
  listFileShares,
  uploadFile,
} from "../src/lib/api/client.ts";

const authenticated = {
  authenticated: true,
  user: { id: "usr_test", username: "test", role: "admin", enabled: true },
  csrf_token: "csrf-test-token",
};
const unauthenticated = {
  authenticated: false,
  user: null,
  csrf_token: null,
};

const json = (value, status = 200) => Response.json(value, { status });
const unauthorized = () => json({ code: "SESSION_INVALID", message: "expired" }, 401);

async function scenario(run) {
  const oldFetch = globalThis.fetch;
  const oldWindow = globalThis.window;
  const windowMock = new EventTarget();
  let expired = 0;
  windowMock.addEventListener(SESSION_EXPIRED_EVENT, () => expired++);
  globalThis.window = windowMock;
  try {
    await run({
      get expired() {
        return expired;
      },
      mockFetch(callback) {
        globalThis.fetch = callback;
      },
    });
  } finally {
    globalThis.fetch = oldFetch;
    globalThis.window = oldWindow;
  }
}

test("an authenticated API 401 expires the session exactly once", async () => {
  await scenario(async (ctx) => {
    ctx.mockFetch(async (url) =>
      url === "/api/v1/auth/session" ? json(authenticated) : unauthorized(),
    );
    assert.equal((await getSession()).authenticated, true);
    await assert.rejects(listFileShares(), (error) => error instanceof ApiError && error.status === 401);
    await assert.rejects(listFileShares(), (error) => error instanceof ApiError && error.status === 401);
    assert.equal(ctx.expired, 1);
  });
});

test("session polling detects a revoked cookie returned as HTTP 200", async () => {
  await scenario(async (ctx) => {
    let calls = 0;
    ctx.mockFetch(async () => json(++calls === 1 ? authenticated : unauthenticated));
    await getSession();
    assert.equal((await getSession()).authenticated, false);
    assert.equal(ctx.expired, 1);
    await getSession();
    assert.equal(ctx.expired, 1);
  });
});

test("file upload and download propagate 401 session invalidation", async () => {
  await scenario(async (ctx) => {
    ctx.mockFetch(async (url) =>
      url === "/api/v1/auth/session" ? json(authenticated) : unauthorized(),
    );
    await getSession();
    await assert.rejects(
      uploadFile("share", "/demo.txt", new File(["hello"], "demo.txt")),
      (error) => error instanceof ApiError && error.status === 401,
    );
    assert.equal(ctx.expired, 1);
    await getSession();
    await assert.rejects(
      downloadFile("share", "/demo.txt"),
      (error) => error instanceof ApiError && error.status === 401,
    );
    assert.equal(ctx.expired, 2);
  });
});

test("audit CSV export participates in session invalidation", async () => {
  await scenario(async (ctx) => {
    ctx.mockFetch(async (url) =>
      url === "/api/v1/auth/session" ? json(authenticated) : unauthorized(),
    );
    await getSession();
    await assert.rejects(exportAudit({ q: "denied" }), (error) => error instanceof ApiError && error.status === 401);
    assert.equal(ctx.expired, 1);
  });
});

test("binary upload includes current session CSRF without changing content type", async () => {
  await scenario(async (ctx) => {
    let seen = false;
    ctx.mockFetch(async (url, init) => {
      if (url === "/api/v1/auth/session") return json(authenticated);
      assert.match(url, /^\/api\/v1\/shares\/share\/files\/upload\?/);
      assert.equal(init.method, "POST");
      assert.equal(init.credentials, "include");
      assert.equal(init.headers.get("x-csrf-token"), "csrf-test-token");
      assert.equal(init.headers.get("content-type"), "text/plain");
      seen = true;
      return new Response(null, { status: 204 });
    });
    await getSession();
    await uploadFile("share", "/demo.txt", new File(["hello"], "demo.txt", { type: "text/plain" }));
    assert.equal(seen, true);
    assert.equal(ctx.expired, 0);
  });
});
