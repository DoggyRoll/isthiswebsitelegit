import { NextRequest, NextResponse } from "next/server";

// ── Types ─────────────────────────────────────────────────────────────────────

interface SafetyReport {
  domain: string;
  safetyScore: number;
  isMalware: boolean;
  isPhishing: boolean;
  isUp: boolean;
  hasSSL: boolean;
  domainAgeDays: number | null;
  registrar: string | null;
  vtStats: { malicious: number; suspicious: number; clean: number } | null;
  threats: string[];
}

// ── URL Cleaning ───────────────────────────────────────────────────────────────

function extractDomain(raw: string): string | null {
  try {
    // Prepend protocol if missing so URL constructor works
    const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const parsed = new URL(withProto);
    // Strip www.
    return parsed.hostname.replace(/^www\./i, "").toLowerCase() || null;
  } catch {
    return null;
  }
}

function isValidDomain(domain: string): boolean {
  // Must have at least one dot, no spaces, valid chars
  return /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/i.test(
    domain
  );
}

// ── Individual Checks ──────────────────────────────────────────────────────────

async function checkGoogleSafeBrowsing(
  domain: string
): Promise<{ isMalware: boolean; isPhishing: boolean; threats: string[] }> {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!key) return { isMalware: false, isPhishing: false, threats: [] };

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

  if (!res.ok) return { isMalware: false, isPhishing: false, threats: [] };

  const data = await res.json();
  const matches: Array<{ threatType: string }> = data.matches ?? [];

  const isMalware = matches.some((m) =>
    ["MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"].includes(
      m.threatType
    )
  );
  const isPhishing = matches.some((m) => m.threatType === "SOCIAL_ENGINEERING");

  const threats: string[] = [];
  if (isMalware) threats.push("Malware detected by Google Safe Browsing");
  if (isPhishing) threats.push("Phishing detected by Google Safe Browsing");

  return { isMalware, isPhishing, threats };
}

async function checkVirusTotal(
  domain: string
): Promise<{ malicious: number; suspicious: number; clean: number } | null> {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return null;

  // Step 1: submit URL
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

  // Step 2: fetch analysis result
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

  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    clean: (stats.harmless ?? 0) + (stats.undetected ?? 0),
  };
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

    // If we got here, HTTPS worked
    return { isUp: res.ok || res.status < 500, hasSSL: true, statusCode: res.status };
  } catch {
    // HTTPS failed — try HTTP
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
      // Both HTTPS and HTTP failed — site is blocking server pings.
      // Don't assume no SSL; mark as down but leave SSL unknown (true = no penalty).
      return { isUp: false, hasSSL: true, statusCode: null };
    }
  }
}

// ── Domain Age Helper ──────────────────────────────────────────────────────────

function getDomainAgeDays(createdDate: string | null): number | null {
  if (!createdDate) return null;
  try {
    const created = new Date(createdDate);
    if (isNaN(created.getTime())) return null;
    const ageMs = Date.now() - created.getTime();
    return Math.floor(ageMs / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
}

// ── Score Calculator ───────────────────────────────────────────────────────────

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

  if (params.vtMalicious >= 5) {
    score -= 60;
  } else if (params.vtMalicious >= 3) {
    score -= 30;
  }

  if (params.domainAgeDays !== null) {
    if (params.domainAgeDays < 7) {
      score -= 40;
    } else if (params.domainAgeDays < 30) {
      score -= 20;
    }
  }

  if (!params.hasSSL) score -= 15;
  if (!params.isUp) score -= 10;

  return Math.max(0, Math.min(100, score));
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

  // Fan out all checks in parallel — never throw
  const [gsbResult, vtResult, whoisResult, httpResult] =
    await Promise.allSettled([
      checkGoogleSafeBrowsing(domain),
      checkVirusTotal(domain),
      checkWhois(domain),
      checkHttp(domain),
    ]);

  // Unwrap settled results with safe fallbacks
  const gsb =
    gsbResult.status === "fulfilled"
      ? gsbResult.value
      : { isMalware: false, isPhishing: false, threats: [] as string[] };

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

  const threats: string[] = [...gsb.threats];
  if (vt && vt.malicious >= 3) {
    threats.push(`Flagged malicious by ${vt.malicious} VirusTotal engine(s)`);
  }
  if (vt && vt.suspicious >= 1) {
    threats.push(`Flagged suspicious by ${vt.suspicious} VirusTotal engine(s)`);
  }
  if (domainAgeDays !== null && domainAgeDays < 30) {
    threats.push(
      `Very new domain (registered ${domainAgeDays} day${domainAgeDays === 1 ? "" : "s"} ago)`
    );
  }
  if (!http.hasSSL) threats.push("No valid SSL certificate");
  if (!http.isUp) threats.push("Site appears to be down");

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
    isMalware: gsb.isMalware,
    isPhishing: gsb.isPhishing,
    isUp: http.isUp,
    hasSSL: http.hasSSL,
    domainAgeDays,
    registrar: whois.registrar,
    vtStats: vt,
    threats,
  };

  return NextResponse.json(report);
}
