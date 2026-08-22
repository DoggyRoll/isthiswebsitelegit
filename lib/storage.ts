import Redis from "ioredis";
import type { SafetyReport } from "@/app/api/check/route";

export interface ScanRecord {
  domain: string;
  safetyScore: number;
  verdict: "safe" | "caution" | "danger";
  isMalware: boolean;
  isPhishing: boolean;
  hasSSL: boolean;
  isUp: boolean;
  domainAgeDays: number | null;
  vtMalicious: number | null;
  vtTotal: number | null;
  checkedAt: string;
}

// Singleton Redis client — reused across invocations in the same function instance
let _redis: Redis | null = null;

function getRedis(): Redis | null {
  const url = process.env.REDIS_URL;
  if (!url) return null;
  if (_redis && _redis.status === "ready") return _redis;

  _redis = new Redis(url, {
    maxRetriesPerRequest: 1,
    connectTimeout: 4000,
    commandTimeout: 3000,
    enableOfflineQueue: false,
    lazyConnect: false,
    tls: url.startsWith("rediss://") ? { rejectUnauthorized: false } : undefined,
  });

  _redis.on("error", () => {
    _redis = null;
  });

  return _redis;
}

/**
 * Persist a scan result. Called fire-and-forget — never throws to caller.
 *
 * Storage layout:
 *   scan:{domain}       → latest ScanRecord JSON
 *   scan:{domain}:full  → full SafetyReport JSON
 *   scans:recent        → sorted set of domains scored by Unix timestamp
 *   scans:count         → running total of all scans
 */
export async function saveScanResult(report: SafetyReport): Promise<void> {
  const redis = getRedis();
  if (!redis) return;

  try {
    const record: ScanRecord = {
      domain: report.domain,
      safetyScore: report.safetyScore,
      verdict: report.verdict,
      isMalware: report.isMalware,
      isPhishing: report.isPhishing,
      hasSSL: report.hasSSL,
      isUp: report.isUp,
      domainAgeDays: report.domainAgeDays,
      vtMalicious: report.vtStats?.malicious ?? null,
      vtTotal: report.vtStats?.total ?? null,
      checkedAt: new Date().toISOString(),
    };

    const now = Date.now();

    await Promise.all([
      redis.set(`scan:${report.domain}`, JSON.stringify(record)),
      redis.set(`scan:${report.domain}:full`, JSON.stringify(report)),
      redis.zadd("scans:recent", now, report.domain),
      redis.incr("scans:count"),
    ]);
  } catch {
    // Storage is non-critical — never break the scan response
  }
}

export async function getScanRecord(domain: string): Promise<ScanRecord | null> {
  const redis = getRedis();
  if (!redis) return null;
  try {
    const raw = await redis.get(`scan:${domain}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export async function getFullReport(domain: string): Promise<SafetyReport | null> {
  const redis = getRedis();
  if (!redis) return null;
  try {
    const raw = await redis.get(`scan:${domain}:full`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export async function getRecentScans(limit = 20): Promise<string[]> {
  const redis = getRedis();
  if (!redis) return [];
  try {
    return await redis.zrevrange("scans:recent", 0, limit - 1);
  } catch {
    return [];
  }
}

export async function getTotalScans(): Promise<number> {
  const redis = getRedis();
  if (!redis) return 0;
  try {
    const count = await redis.get("scans:count");
    return count ? parseInt(count, 10) : 0;
  } catch {
    return 0;
  }
}
