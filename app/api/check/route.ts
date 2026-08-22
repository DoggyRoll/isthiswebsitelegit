import { NextRequest, NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";

export const maxDuration = 15;

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
    aiContent: "clean" | "flagged" | "unavailable";
  };
  aiAnalysis: { flags: string[]; summary: string } | null;
}

// ── AI Flag Definitions ────────────────────────────────────────────────────────

const AI_FLAG_COPY: Record<string, { label: string; explanation: string }> = {
  FAKE_URGENCY: {
    label: "Fake Urgency Tactics",
    explanation:
      "The page uses pressure phrases like 'limited time' or 'act now' to rush you into a decision — a classic scam technique.",
  },
  VAGUE_CONTACT: {
    label: "No Clear Contact Information",
    explanation:
      "Legitimate businesses make it easy to reach them; this site doesn't show a real address, phone number, or support email.",
  },
  GRAMMAR_ISSUES: {
    label: "Poor Grammar and Spelling",
    explanation:
      "Scam sites are often written hastily or translated poorly — consistent language errors are a warning sign.",
  },
  SUSPICIOUS_PRICING: {
    label: "Suspicious Pricing",
    explanation:
      "Prices that seem too good to be true usually are — this is a common lure used to steal payment details.",
  },
  FAKE_REVIEWS: {
    label: "Potentially Fake Reviews",
    explanation:
      "The reviews on this page show patterns common in fabricated testimonials rather than genuine customer feedback.",
  },
  UNREALISTIC_CLAIMS: {
    label: "Unrealistic Claims",
    explanation:
      "The site makes promises that no legitimate business could keep, which is a strong indicator of fraud.",
  },
  MISSING_LEGAL: {
    label: "Missing Legal Pages",
    explanation:
      "Trustworthy sites include a privacy policy and terms of service — their absence is a red flag.",
  },
  PRESSURE_TACTICS: {
    label: "High-Pressure Sales Tactics",
    explanation:
      "The site uses countdown timers, scarcity warnings, or other pressure techniques designed to stop you from thinking carefully.",
  },
  BRAND_IMPERSONATION: {
    label: "Possible Brand Impersonation",
    explanation:
      "The page appears to be imitating a well-known brand to gain your trust — check the URL carefully.",
  },
  CRYPTO_PAYMENT_PUSH: {
    label: "Cryptocurrency Payment Pressure",
    explanation:
      "Pushing crypto payments is a scammer's favorite move — transactions are untraceable and cannot be reversed.",
  },
};

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

  return {
    isMalware: matches.some((m) =>
      ["MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"].includes(m.threatType)
    ),
    isPhishing: matches.some((m) => m.threatType === "SOCIAL_ENGINEERING"),
  };
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

  return { malicious, suspicious, clean, total: malicious + suspicious + clean };
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

async function fetchPageText(domain: string): Promise<string | null> {
  try {
    const res = await fetch(`https://${domain}`, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
      },
      signal: AbortSignal.timeout(7000),
      redirect: "follow",
    });
    if (!res.ok) return null;
    const html = await res.text();
    // Strip tags, collapse whitespace, cap at 6000 chars
    return html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 6000);
  } catch {
    return null;
  }
}

async function analyzeWithClaude(
  domain: string,
  pageText: string
): Promise<{ riskScore: number; flags: string[]; summary: string }> {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return { riskScore: 0, flags: [], summary: "" };

  try {
    const client = new Anthropic({ apiKey: key });

    const message = await client.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 300,
      system:
        "You are a website safety analyst. Respond only with valid JSON, no markdown, no explanation.",
      messages: [
        {
          role: "user",
          content: `Analyze this page text from "${domain}" for scam and fraud signals.

Return exactly this JSON structure:
{
  "riskScore": <integer 0-30, where 0=no signals and 30=very high risk>,
  "flags": <array of applicable flags from this list only: FAKE_URGENCY, VAGUE_CONTACT, GRAMMAR_ISSUES, SUSPICIOUS_PRICING, FAKE_REVIEWS, UNREALISTIC_CLAIMS, MISSING_LEGAL, PRESSURE_TACTICS, BRAND_IMPERSONATION, CRYPTO_PAYMENT_PUSH>,
  "summary": <one sentence in plain English describing what you found, or empty string if nothing suspicious>
}

Page text:
${pageText}`,
        },
      ],
    });

    const raw = message.content[0].type === "text" ? message.content[0].text : "";
    const parsed = JSON.parse(raw);

    return {
      riskScore: Math.min(30, Math.max(0, Number(parsed.riskScore) || 0)),
      flags: Array.isArray(parsed.flags) ? parsed.flags.filter((f: unknown) => typeof f === "string" && f in AI_FLAG_COPY) : [],
      summary: typeof parsed.summary === "string" ? parsed.summary : "",
    };
  } catch {
    return { riskScore: 0, flags: [], summary: "" };
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
  aiRiskScore: number;
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
  score -= params.aiRiskScore;
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

  // Fan out all checks in parallel — fetchPageText runs alongside the others
  const [gsbResult, vtResult, whoisResult, httpResult, pageTextResult] =
    await Promise.allSettled([
      checkGoogleSafeBrowsing(domain),
      checkVirusTotal(domain),
      checkWhois(domain),
      checkHttp(domain),
      fetchPageText(domain),
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

  const pageText =
    pageTextResult.status === "fulfilled" ? pageTextResult.value : null;

  // AI analysis — only if we got page content
  const aiResult =
    pageText
      ? await analyzeWithClaude(domain, pageText)
      : { riskScore: 0, flags: [], summary: "" };

  const domainAgeDays = getDomainAgeDays(whois.createdDate);
  const domainCreatedDate = formatCreatedDate(whois.createdDate);

  // ── Build structured threats ─────────────────────────────────────────────────

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
      explanation: `${vt.malicious} out of ${vt.total} independent antivirus tools identified this site as harmful — that's a serious warning.`,
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

  // AI-detected flags — only push if riskScore meaningful or specific flags found
  for (const flag of aiResult.flags) {
    const copy = AI_FLAG_COPY[flag];
    if (copy) {
      threats.push({ id: `ai_${flag.toLowerCase()}`, ...copy });
    }
  }

  // ── checksRun ────────────────────────────────────────────────────────────────

  const checksRun: SafetyReport["checksRun"] = {
    googleSafeBrowsing: gsb.isMalware || gsb.isPhishing ? "flagged" : "clean",
    virusTotal:
      vt === null ? "unavailable" : vt.malicious > 0 ? "flagged" : "clean",
    ssl: http.hasSSL ? "valid" : "missing",
    domainAge:
      domainAgeDays === null
        ? "unknown"
        : domainAgeDays < 30
        ? "new"
        : domainAgeDays < 365
        ? "recent"
        : "established",
    aiContent:
      pageText === null
        ? "unavailable"
        : aiResult.flags.length > 0
        ? "flagged"
        : "clean",
  };

  const safetyScore = calcScore({
    isMalware: gsb.isMalware,
    isPhishing: gsb.isPhishing,
    vtMalicious: vt?.malicious ?? 0,
    domainAgeDays,
    hasSSL: http.hasSSL,
    isUp: http.isUp,
    aiRiskScore: aiResult.riskScore,
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
    aiAnalysis: pageText ? { flags: aiResult.flags, summary: aiResult.summary } : null,
  };

  return NextResponse.json(report);
}
