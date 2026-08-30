import { NextRequest } from "next/server"

export const dynamic = "force-dynamic"
export const runtime = "nodejs"

type RouteContext = {
  params: Promise<{ path: string[] }>
}

const blockedHeaders = new Set([
  "authorization",
  "connection",
  "content-length",
  "cookie",
  "host",
  "transfer-encoding",
  "x-openmemory-token",
  "x-forwarded-host",
  "x-forwarded-proto",
])

const responseHeaders = ["cache-control", "content-disposition", "content-type"]
const canonicalRootPaths = new Set([
  "/api/v1/memories",
  "/api/v1/stats",
  "/api/v1/config",
  "/api/v1/apps",
])

function jsonResponse(body: Record<string, string>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

async function forwardRequest(request: NextRequest, context: RouteContext): Promise<Response> {
  const token = process["env"]["OPENMEMORY_API_TOKEN"]?.trim()
  if (!token) {
    return jsonResponse({ detail: "OpenMemory API authentication is not configured" }, 503)
  }

  const { path } = await context.params
  const apiUrl = (process["env"]["OPENMEMORY_API_URL"] || "http://localhost:8765").replace(/\/+$/, "")
  const routePath = `/${path.map(encodeURIComponent).join("/")}`
  const upstreamPath = canonicalRootPaths.has(routePath) ? `${routePath}/` : routePath
  const upstreamUrl = `${apiUrl}${upstreamPath}${request.nextUrl.search}`
  const headers = new Headers()

  request.headers.forEach((value, key) => {
    if (!blockedHeaders.has(key.toLowerCase())) {
      headers.set(key, value)
    }
  })
  headers.set("authorization", `Bearer ${token}`)

  const body = request.method === "GET" || request.method === "HEAD" || request.method === "OPTIONS"
    ? undefined
    : await request.arrayBuffer()

  let response: Response
  try {
    response = await fetch(upstreamUrl, {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      redirect: "follow",
    })
  } catch {
    return jsonResponse({ detail: "OpenMemory API is unavailable" }, 502)
  }

  const headersToReturn = new Headers()
  for (const header of responseHeaders) {
    const value = response.headers.get(header)
    if (value) {
      headersToReturn.set(header, value)
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: headersToReturn,
  })
}

export async function GET(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context)
}

export async function HEAD(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context)
}

export async function POST(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context)
}

export async function PUT(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context)
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context)
}

export async function OPTIONS(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context)
}
