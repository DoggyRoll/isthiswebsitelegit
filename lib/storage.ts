import { kv } from "@vercel/kv";
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
  // Full report stored separately for deep queries later
}

/**
 * Persist a scan result to KV. Called fire-and-forget — never throws to caller.
 *
 * Storage layout:
 *   scan:{domain}          → latest ScanRecord (JSON), no TTL
 *   scan:{domain}:full     → full SafetyReport (JSON), no TTL
 *   scans:recent           → sorted set of domains, scored by Unix timestamp
 *   scans:count            → running total of all scans
 */
export async function saveScanResult(report: SafetyReport): Promise<void> {
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
      // Latest scan summary for this domain
      kv.set(`scan:${report.domain}`, record),
      // Full report — kept for future queries without re-scanning
      kv.set(`scan:${report.domain}:full`, report),
      // Sorted set for recent scans (score = timestamp for range queries)
      kv.zadd("scans:recent", { score: now, member: report.domain }),
      // Running total
      kv.incr("scans:count"),
    ]);
  } catch {
    // Storage is non-critical — never break the scan response
  }
}

/**
 * Retrieve the latest scan record for a domain, or null if never scanned.
 */
export async function getScanRecord(domain: string): Promise<ScanRecord | null> {
  try {
    return await kv.get<ScanRecord>(`scan:${domain}`);
  } catch {
    return null;
  }
}

/**
 * Retrieve the full SafetyReport for a domain, or null if never scanned.
 */
export async function getFullReport(domain: string): Promise<SafetyReport | null> {
  try {
    return await kv.get<SafetyReport>(`scan:${domain}:full`);
  } catch {
    return null;
  }
}

/**
 * Get the N most recently scanned domains.
 */
export async function getRecentScans(limit = 20): Promise<string[]> {
  try {
    const results = await kv.zrange("scans:recent", 0, limit - 1, { rev: true });
    return results as string[];
  } catch {
    return [];
  }
}

/**
 * Total number of scans ever run.
 */
export async function getTotalScans(): Promise<number> {
  try {
    return (await kv.get<number>("scans:count")) ?? 0;
  } catch {
    return 0;
  }
}
