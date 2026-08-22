import { Redis } from "@upstash/redis";
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

function getRedis(): Redis | null {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return new Redis({ url, token });
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
      redis.set(`scan:${report.domain}`, record),
      redis.set(`scan:${report.domain}:full`, report),
      redis.zadd("scans:recent", { score: now, member: report.domain }),
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
    return await redis.get<ScanRecord>(`scan:${domain}`);
  } catch {
    return null;
  }
}

export async function getFullReport(domain: string): Promise<SafetyReport | null> {
  const redis = getRedis();
  if (!redis) return null;
  try {
    return await redis.get<SafetyReport>(`scan:${domain}:full`);
  } catch {
    return null;
  }
}

export async function getRecentScans(limit = 20): Promise<string[]> {
  const redis = getRedis();
  if (!redis) return [];
  try {
    return await redis.zrange("scans:recent", 0, limit - 1, { rev: true });
  } catch {
    return [];
  }
}

export async function getTotalScans(): Promise<number> {
  const redis = getRedis();
  if (!redis) return 0;
  try {
    return (await redis.get<number>("scans:count")) ?? 0;
  } catch {
    return 0;
  }
}
