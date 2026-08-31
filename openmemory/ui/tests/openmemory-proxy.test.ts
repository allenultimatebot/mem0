import assert from "node:assert/strict"
import { test } from "node:test"

const originalFetch = globalThis.fetch
const tokenKey = "OPENMEMORY_API_" + "TOKEN"
const apiUrlKey = "OPENMEMORY_API_URL"
const originalToken = process.env[tokenKey]
const originalApiUrl = process.env[apiUrlKey]
const routeUrl = new URL("../app/api/openmemory/[...path]/route.ts", import.meta.url).href

function request(url: string, init?: RequestInit): Request {
  return Object.assign(new Request(url, init), { nextUrl: new URL(url) })
}

function context(...path: string[]) {
  return { params: Promise.resolve({ path }) }
}

function loadRoute() {
  return import(routeUrl)
}

test("returns 503 without contacting upstream when the server token is missing", async () => {
  process.env[tokenKey] = ""
  let fetchCalls = 0
  globalThis.fetch = async () => {
    fetchCalls += 1
    return new Response("unexpected", { status: 500 })
  }

  const { GET } = await loadRoute()
  const response = await GET(
    request("http://localhost:3000/api/openmemory/api/v1/stats"),
    context("api", "v1", "stats"),
  )

  assert.equal(response.status, 503)
  assert.equal(fetchCalls, 0)
})

test("injects the server token and canonicalizes root paths", async () => {
  process.env[tokenKey] = "server-secret"
  process.env[apiUrlKey] = "http://upstream.test/"
  let upstreamRequest: Request | undefined
  globalThis.fetch = async (input, init) => {
    upstreamRequest = new Request(input, init)
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  }

  const { GET } = await loadRoute()
  const response = await GET(
    request("http://localhost:3000/api/openmemory/api/v1/stats?range=7d", {
      headers: {
        authorization: "Bearer browser-token",
        "x-openmemory-token": "spoofed-token",
        "x-request-id": "request-1",
      },
    }),
    context("api", "v1", "stats"),
  )

  assert.equal(response.status, 200)
  assert.equal(upstreamRequest?.url, "http://upstream.test/api/v1/stats/?range=7d")
  assert.equal(upstreamRequest?.headers.get("authorization"), "Bearer server-secret")
  assert.equal(upstreamRequest?.headers.get("x-openmemory-token"), null)
  assert.equal(upstreamRequest?.headers.get("x-request-id"), "request-1")
})

test("rejects cross-origin mutations before contacting upstream", async () => {
  process.env[tokenKey] = "server-secret"
  let fetchCalls = 0
  globalThis.fetch = async () => {
    fetchCalls += 1
    return new Response("unexpected", { status: 500 })
  }

  const { POST } = await loadRoute()
  const response = await POST(
    request("http://localhost:3000/api/openmemory/api/v1/memories", {
      method: "POST",
      headers: {
        host: "localhost:3000",
        origin: "https://attacker.test",
        "content-type": "application/json",
      },
      body: JSON.stringify({ text: "should not forward" }),
    }),
    context("api", "v1", "memories"),
  )

  assert.equal(response.status, 403)
  assert.equal(fetchCalls, 0)
})

test("forwards same-origin mutation bodies without browser credentials", async () => {
  process.env[tokenKey] = "server-secret"
  process.env[apiUrlKey] = "http://upstream.test"
  let upstreamRequest: Request | undefined
  globalThis.fetch = async (input, init) => {
    upstreamRequest = new Request(input, init)
    return new Response(null, { status: 204 })
  }

  const { POST } = await loadRoute()
  const response = await POST(
    request("http://localhost:3000/api/openmemory/api/v1/memories", {
      method: "POST",
      headers: {
        host: "localhost:3000",
        origin: "http://localhost:3000",
        authorization: "Bearer browser-token",
        cookie: "session=browser-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({ text: "forward this" }),
    }),
    context("api", "v1", "memories"),
  )

  assert.equal(response.status, 204)
  assert.equal(upstreamRequest?.headers.get("authorization"), "Bearer server-secret")
  assert.equal(upstreamRequest?.headers.get("cookie"), null)
  assert.equal(await upstreamRequest?.text(), JSON.stringify({ text: "forward this" }))
})

process.on("exit", () => {
  globalThis.fetch = originalFetch
  if (originalToken === undefined) delete process.env[tokenKey]
  else process.env[tokenKey] = originalToken
  if (originalApiUrl === undefined) delete process.env[apiUrlKey]
  else process.env[apiUrlKey] = originalApiUrl
})
