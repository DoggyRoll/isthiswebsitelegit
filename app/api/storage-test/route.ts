import { NextResponse } from "next/server";
import Redis from "ioredis";

export const runtime = "nodejs";

export async function GET() {
  const url = process.env.REDIS_URL;
  if (!url) return NextResponse.json({ error: "REDIS_URL not set" });

  const redis = new Redis(url, {
    tls: { rejectUnauthorized: false },
    connectTimeout: 8000,
    commandTimeout: 6000,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    lazyConnect: true,
  });

  try {
    await redis.connect();
    const ping = await redis.ping();
    await redis.set("test:connection", "ok");
    const val = await redis.get("test:connection");
    const count = await redis.get("scans:count");
    await redis.quit();
    return NextResponse.json({ ping, val, scansCount: count, url: url.replace(/:([^@]+)@/, ":***@") });
  } catch (e: unknown) {
    await redis.quit().catch(() => {});
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e), url: url.replace(/:([^@]+)@/, ":***@") });
  }
}
