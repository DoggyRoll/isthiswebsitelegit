import { NextResponse } from "next/server";
import { Redis } from "@upstash/redis";

export async function GET() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return NextResponse.json({ error: "env vars not set" });

  try {
    const redis = new Redis({ url, token });
    const ping = await redis.ping();
    await redis.set("test:connection", "ok");
    const val = await redis.get("test:connection");
    const count = await redis.get("scans:count");
    const recent = await redis.zrange("scans:recent", 0, 4, { rev: true });
    return NextResponse.json({ ping, val, scansCount: count, recent });
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) });
  }
}
