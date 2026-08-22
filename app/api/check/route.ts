import { NextRequest, NextResponse } from "next/server";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ThreatItem {
  id: string;
  label: string;
  explanation: string;
}

export interface SafetyReport {
  domain: string;
  safetyScore: number;
  verdict: "safe" | "caution" | "danger";
  isMalware: boolean;
  isPhishing: boolean;
  isUp: boolean;
  hasSSL: boolean;
  domainAgeDays: number | null;
  domainCreatedDate: string | null;
  registrar: string | null;
  vtStats: {
    malicious: number;
    suspicious: number;
    clean: number;
    total: number;
  } | null;
  threats: ThreatItem[];
  checksRun: {
    googleSafeBrowsing: "clean" | "flagged";
    virusTotal: "clean" | "flagged" | "unavailable";
    ssl: "valid" | "missing";
    domainAge: "established" | "recent" | "new" | "unknown";
  };
}

// ── URL Cleaning ───────────────────────────────────────────────────────────────

function extractDomain(raw: string): string | null {
  try {
    const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const parsed = new URL(withProto);
    return parsed.hostname.replace(/^www\./i, "").toLowerCase() || null;
  } catch {
    return null;
  }
}

function isValidDomain(domain: string): boolean {
  return /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/i.test(
    domain
  );
}

// ── Individual Checks ──────────────────────────────────────────────────────────

async function checkGoogleSafeBrowsing(
  domain: string
): Promise<{ isMalware: boolean; isPhishing: boolean }> {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!key) return { isMalware: false, isPhishing: false };

  const res = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "isthissitelegit", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: `https://${domain}` }],
        },
      }),
      signal: AbortSignal.timeout(8000),
    }
  );

  if (!res.ok) return { isMalware: false, isPhishing: false };

  const data = await res.json();
  const matches: Array<{ threatType: string }> = data.matches ?? [];

  const isMalware = matches.some((m) =>
    ["MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"].includes(
      m.threatType
    )
  );
  const isPhishing = matches.some((m) => m.threatType === "SOCIAL_ENGINEERING");

  return { isMalware, isPhishing };
}

async function checkVirusTotal(
  domain: string
): Promise<{ malicious: number; suspicious: number; clean: number; total: number } | null> {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return null;

  const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": key,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `url=${encodeURIComponent(domain)}`,
    signal: AbortSignal.timeout(10000),
  });

  if (!submitRes.ok) return null;

  const submitData = await submitRes.json();
  const analysisId: string | undefined = submitData?.data?.id;
  if (!analysisId) return null;

  const analysisRes = await fetch(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    {
      headers: { "x-apikey": key },
      signal: AbortSignal.timeout(10000),
    }
  );

  if (!analysisRes.ok) return null;

  const analysisData = await analysisRes.json();
  const stats = analysisData?.data?.attributes?.stats;
  if (!stats) return null;

  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const clean = (stats.harmless ?? 0) + (stats.undetected ?? 0);
  const total = malicious + suspicious + clean;

  return { malicious, suspicious, clean, total };
}

async function checkWhois(
  domain: string
): Promise<{ createdDate: string | null; registrar: string | null }> {
  const key = process.env.WHOIS_XML_API_KEY;
  if (!key) return { createdDate: null, registrar: null };

  const res = await fetch(
    `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${key}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`,
    { signal: AbortSignal.timeout(8000) }
  );

  if (!res.ok) return { createdDate: null, registrar: null };

  const data = await res.json();
  const record = data?.WhoisRecord;

  return {
    createdDate: record?.createdDate ?? null,
    registrar: record?.registrarName ?? null,
  };
}

async function checkHttp(
  domain: string
): Promise<{ isUp: boolean; hasSSL: boolean; statusCode: number | null }> {
  try {
    const res = await fetch(`https://${domain}`, {
      method: "HEAD",
      signal: AbortSignal.timeout(5000),
      redirect: "follow",
    });
    return { isUp: res.ok || res.status < 500, hasSSL: true, statusCode: res.status };
  } catch {
    try {
      const httpRes = await fetch(`http://${domain}`, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
        redirect: "follow",
      });
      return {
        isUp: httpRes.ok || httpRes.status < 500,
        hasSSL: false,
        statusCode: httpRes.status,
      };
    } catch {
      return { isUp: false, hasSSL: true, statusCode: null };
    }
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function getDomainAgeDays(createdDate: string | null): number | null {
  if (!createdDate) return null;
  try {
    const created = new Date(createdDate);
    if (isNaN(created.getTime())) return null;
    return Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}

function formatCreatedDate(createdDate: string | null): string | null {
  if (!createdDate) return null;
  try {
    const d = new Date(createdDate);
    if (isNaN(d.getTime())) return null;
    return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  } catch {
    return null;
  }
}

function calcScore(params: {
  isMalware: boolean;
  isPhishing: boolean;
  vtMalicious: number;
  domainAgeDays: number | null;
  hasSSL: boolean;
  isUp: boolean;
}): number {
  let score = 100;
  if (params.isMalware) score -= 60;
  if (params.isPhishing) score -= 60;
  if (params.vtMalicious >= 5) score -= 60;
  else if (params.vtMalicious >= 3) score -= 30;
  if (params.domainAgeDays !== null) {
    if (params.domainAgeDays < 7) score -= 40;
    else if (params.domainAgeDays < 30) score -= 20;
  }
  if (!params.hasSSL) score -= 15;
  if (!params.isUp) score -= 10;
  return Math.max(0, Math.min(100, score));
}

function calcVerdict(score: number): "safe" | "caution" | "danger" {
  if (score >= 80) return "safe";
  if (score >= 40) return "caution";
  return "danger";
}

// ── Route Handler ──────────────────────────────────────────────────────────────

export async function POST(req: NextRequest): Promise<NextResponse> {
  let body: { url?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (typeof body.url !== "string" || !body.url.trim()) {
    return NextResponse.json({ error: "url is required" }, { status: 400 });
  }

  const domain = extractDomain(body.url.trim());
  if (!domain || !isValidDomain(domain)) {
    return NextResponse.json(
      { error: "Could not parse a valid domain from the provided URL" },
      { status: 422 }
    );
  }

  const [gsbResult, vtResult, whoisResult, httpResult] = await Promise.allSettled([
    checkGoogleSafeBrowsing(domain),
    checkVirusTotal(domain),
    checkWhois(domain),
    checkHttp(domain),
  ]);

  const gsb =
    gsbResult.status === "fulfilled"
      ? gsbResult.value
      : { isMalware: false, isPhishing: false };

  const vt = vtResult.status === "fulfilled" ? vtResult.value : null;

  const whois =
    whoisResult.status === "fulfilled"
      ? whoisResult.value
      : { createdDate: null, registrar: null };

  const http =
    httpResult.status === "fulfilled"
      ? httpResult.value
      : { isUp: false, hasSSL: false, statusCode: null };

  const domainAgeDays = getDomainAgeDays(whois.createdDate);
  const domainCreatedDate = formatCreatedDate(whois.createdDate);

  // ── Build structured threats with plain-English explanations ────────────────

  const threats: ThreatItem[] = [];

  if (gsb.isMalware) {
    threats.push({
      id: "malware",
      label: "Malware Detected",
      explanation:
        "Google has confirmed this site spreads harmful software — just visiting it could silently infect your device.",
    });
  }

  if (gsb.isPhishing) {
    threats.push({
      id: "phishing",
      label: "Phishing Site",
      explanation:
        "This site is impersonating a trusted brand to steal your passwords, credit card numbers, or personal information.",
    });
  }

  if (vt && vt.malicious >= 3) {
    threats.push({
      id: "vt_malicious",
      label: `Flagged by ${vt.malicious} Security Engine${vt.malicious === 1 ? "" : "s"}`,
      explanation:
        `${vt.malicious} out of ${vt.total} independent antivirus tools identified this site as harmful — that's a serious warning.`,
    });
  } else if (vt && vt.suspicious >= 1) {
    threats.push({
      id: "vt_suspicious",
      label: `Marked Suspicious by ${vt.suspicious} Engine${vt.suspicious === 1 ? "" : "s"}`,
      explanation:
        "Some security tools have raised concerns about this site, though it hasn't been fully confirmed as harmful yet.",
    });
  }

  if (domainAgeDays !== null && domainAgeDays < 7) {
    threats.push({
      id: "new_domain_critical",
      label: `Brand New Domain (${domainAgeDays} day${domainAgeDays === 1 ? "" : "s"} old)`,
      explanation:
        "This domain was registered just days ago — scam sites are often created overnight to trick people before getting reported.",
    });
  } else if (domainAgeDays !== null && domainAgeDays < 30) {
    threats.push({
      id: "new_domain",
      label: `Very New Domain (${domainAgeDays} days old)`,
      explanation:
        "This domain is less than a month old — legitimate businesses usually have years of history behind them.",
    });
  }

  if (!http.hasSSL) {
    threats.push({
      id: "no_ssl",
      label: "No Security Certificate (SSL)",
      explanation:
        "Without SSL, anything you type on this site — passwords, payment details — travels unencrypted and can be intercepted.",
    });
  }

  if (!http.isUp) {
    threats.push({
      id: "offline",
      label: "Site Appears Offline",
      explanation:
        "We couldn't reach this site, which means it may be shut down, temporarily unavailable, or blocked.",
    });
  }

  // ── Determine check statuses for the "What We Checked" UI section ───────────

  const checksRun: SafetyReport["checksRun"] = {
    googleSafeBrowsing: gsb.isMalware || gsb.isPhishing ? "flagged" : "clean",
    virusTotal:
      vt === null
        ? "unavailable"
        : vt.malicious > 0
        ? "flagged"
        : "clean",
    ssl: http.hasSSL ? "valid" : "missing",
    domainAge:
      domainAgeDays === null
        ? "unknown"
        : domainAgeDays < 30
        ? "new"
        : domainAgeDays < 365
        ? "recent"
        : "established",
  };

  const safetyScore = calcScore({
    isMalware: gsb.isMalware,
    isPhishing: gsb.isPhishing,
    vtMalicious: vt?.malicious ?? 0,
    domainAgeDays,
    hasSSL: http.hasSSL,
    isUp: http.isUp,
  });

  const report: SafetyReport = {
    domain,
    safetyScore,
    verdict: calcVerdict(safetyScore),
    isMalware: gsb.isMalware,
    isPhishing: gsb.isPhishing,
    isUp: http.isUp,
    hasSSL: http.hasSSL,
    domainAgeDays,
    domainCreatedDate,
    registrar: whois.registrar,
    vtStats: vt,
    threats,
    checksRun,
  };

  return NextResponse.json(report);
}
