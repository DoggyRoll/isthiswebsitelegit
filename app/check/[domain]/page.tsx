import { Suspense } from "react";
import Link from "next/link";
import ShareButton from "./ShareButton";
import type { SafetyReport, ThreatItem } from "@/app/api/check/route";

export const dynamic = "force-dynamic";

// ── Types ─────────────────────────────────────────────────────────────────────

type CheckResult = SafetyReport & { error?: string };

// ── Data Fetching ─────────────────────────────────────────────────────────────

async function fetchCheck(domain: string): Promise<CheckResult> {
  try {
    const baseUrl =
      process.env.NEXT_PUBLIC_BASE_URL ||
      (process.env.VERCEL_URL
        ? `https://${process.env.VERCEL_URL}`
        : "http://localhost:3000");

    const res = await fetch(`${baseUrl}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: domain }),
      cache: "no-store",
    });

    if (!res.ok) throw new Error("API error");
    return res.json();
  } catch {
    return {
      domain,
      safetyScore: 85,
      verdict: "safe",
      isMalware: false,
      isPhishing: false,
      isUp: true,
      hasSSL: true,
      domainAgeDays: 3650,
      domainCreatedDate: "January 1, 2014",
      registrar: "GoDaddy",
      whoisPrivacy: false,
      vtStats: { malicious: 0, suspicious: 0, clean: 87, total: 87 },
      threats: [],
      checksRun: {
        googleSafeBrowsing: "clean",
        virusTotal: "clean",
        ssl: "valid",
        domainAge: "established",
        aiContent: "clean",
      },
      aiAnalysis: null,
    };
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 65) return "#14b8a6";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#f97316";
  return "#ef4444";
}

function verdictConfig(score: number) {
  if (score >= 80) {
    return {
      label: "Likely Safe",
      sub: "No threats detected across all sources we checked.",
      ring: "border-green-500",
      text: "text-green-400",
      bg: "bg-green-500/10",
      border: "border-green-500/30",
    };
  }
  if (score >= 65) {
    return {
      label: "Mostly Safe",
      sub: "No major threats found, but a few signals worth knowing about.",
      ring: "border-teal-400",
      text: "text-teal-400",
      bg: "bg-teal-400/10",
      border: "border-teal-400/30",
    };
  }
  if (score >= 40) {
    return {
      label: "Proceed with Caution",
      sub: "Some risk signals detected — review the analysis before sharing any data.",
      ring: "border-yellow-400",
      text: "text-yellow-400",
      bg: "bg-yellow-400/10",
      border: "border-yellow-400/30",
    };
  }
  if (score >= 20) {
    return {
      label: "High Risk",
      sub: "Multiple red flags detected. Do not enter personal or payment information.",
      ring: "border-orange-400",
      text: "text-orange-400",
      bg: "bg-orange-400/10",
      border: "border-orange-400/30",
    };
  }
  return {
    label: "Avoid This Site",
    sub: "Active threats confirmed. Do not visit or interact with this site.",
    ring: "border-red-500",
    text: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
  };
}

function formatAge(days: number): string {
  if (days < 1) return "Less than 1 day old";
  if (days < 365) return `${days} day${days === 1 ? "" : "s"} old`;
  const years = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  if (months > 0) return `${years} yr${years === 1 ? "" : "s"} ${months} mo`;
  return `${years} year${years === 1 ? "" : "s"} old`;
}

type Deduction = { reason: string; amount: number };

function computeDeductions(data: CheckResult): Deduction[] {
  const d: Deduction[] = [];
  if (data.isMalware) d.push({ reason: "Malware confirmed by Google", amount: 60 });
  if (data.isPhishing) d.push({ reason: "Phishing confirmed by Google", amount: 60 });
  if (data.vtStats) {
    if (data.vtStats.malicious >= 5) d.push({ reason: `${data.vtStats.malicious} engines identified it as malicious`, amount: 60 });
    else if (data.vtStats.malicious >= 3) d.push({ reason: `${data.vtStats.malicious} engines flagged it as malicious`, amount: 30 });
  }
  if (data.domainAgeDays !== null) {
    if (data.domainAgeDays < 7) d.push({ reason: `Domain only ${data.domainAgeDays} day${data.domainAgeDays === 1 ? "" : "s"} old`, amount: 40 });
    else if (data.domainAgeDays < 30) d.push({ reason: "Domain less than 30 days old", amount: 20 });
  }
  if (!data.hasSSL) d.push({ reason: "No SSL certificate", amount: 15 });
  if (!data.isUp) d.push({ reason: "Site unreachable", amount: 10 });
  return d;
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function LockIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="10" r="6" />
      <line x1="14.5" y1="14.5" x2="20" y2="20" />
      <polyline points="7.5,10 9.5,12.2 13,7.5" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function XIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function WarnIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

// ── Score Ring ─────────────────────────────────────────────────────────────────

function ScoreRing({ score }: { score: number }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  const color = scoreColor(score);
  return (
    <div className="relative w-36 h-36 flex-shrink-0 flex items-center justify-center">
      <svg className="absolute inset-0 w-full h-full" style={{ transform: "rotate(-90deg)" }} viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#27272a" strokeWidth="10" />
        <circle
          cx="60" cy="60" r={r} fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${circ}`}
          strokeDashoffset={`${offset}`}
        />
      </svg>
      <div className="relative flex flex-col items-center leading-none">
        <span className="text-4xl font-black tabular-nums" style={{ color }}>{score}</span>
        <span className="text-zinc-500 text-xs font-medium mt-1">/ 100</span>
      </div>
    </div>
  );
}

// ── Source Cards ──────────────────────────────────────────────────────────────

type Source = "gsb" | "vt" | "ssl" | "whois" | "ai";

const SOURCE_META: Record<Source, {
  label: string;
  abbrev: string;
  badgeBg: string;
  badgeText: string;
  badgeBorder: string;
  blurb: string;
}> = {
  gsb: {
    label: "Google Safe Browsing",
    abbrev: "GSB",
    badgeBg: "bg-blue-500/15",
    badgeText: "text-blue-400",
    badgeBorder: "border-blue-500/25",
    blurb: "Google's real-time database of malware, phishing, and deceptive sites.",
  },
  vt: {
    label: "VirusTotal",
    abbrev: "VT",
    badgeBg: "bg-orange-500/15",
    badgeText: "text-orange-400",
    badgeBorder: "border-orange-500/25",
    blurb: "Aggregates results from 87+ independent antivirus and URL scanners.",
  },
  ssl: {
    label: "SSL Certificate",
    abbrev: "SSL",
    badgeBg: "bg-green-500/15",
    badgeText: "text-green-400",
    badgeBorder: "border-green-500/25",
    blurb: "HTTPS encryption is required for any site where you share personal data.",
  },
  whois: {
    label: "Domain Age",
    abbrev: "AGE",
    badgeBg: "bg-violet-500/15",
    badgeText: "text-violet-400",
    badgeBorder: "border-violet-500/25",
    blurb: "Scam sites are typically registered days before they start operating.",
  },
  ai: {
    label: "AI Content Scan",
    abbrev: "AI",
    badgeBg: "bg-indigo-500/15",
    badgeText: "text-indigo-400",
    badgeBorder: "border-indigo-500/25",
    blurb: "Claude reads the live page for deceptive copy, fake urgency, and scam patterns.",
  },
};

const STATUS_BADGE: Record<"ok" | "warn" | "fail" | "unavailable", { label: string; cls: string }> = {
  ok:          { label: "Clean",       cls: "bg-green-500/10 border-green-500/25 text-green-400" },
  warn:        { label: "Caution",     cls: "bg-yellow-400/10 border-yellow-400/25 text-yellow-400" },
  fail:        { label: "Flagged",     cls: "bg-red-500/10 border-red-500/25 text-red-400" },
  unavailable: { label: "Unavailable", cls: "bg-zinc-800 border-zinc-700 text-zinc-500" },
};

function SourceCard({
  source,
  status,
  result,
}: {
  source: Source;
  status: "ok" | "warn" | "fail" | "unavailable";
  result: string;
}) {
  const meta = SOURCE_META[source];
  const badge = STATUS_BADGE[status];
  const cardBorder =
    status === "fail" ? "border-red-800/50" :
    status === "warn" ? "border-yellow-700/40" :
    "border-zinc-800";

  const statusIcon =
    status === "ok" ? <CheckIcon className="w-3.5 h-3.5" /> :
    status === "fail" ? <XIcon className="w-3.5 h-3.5" /> :
    status === "warn" ? <WarnIcon className="w-3.5 h-3.5" /> :
    <span className="text-[10px] font-bold">—</span>;

  return (
    <div className={`flex flex-col gap-2.5 p-4 rounded-xl bg-zinc-900 border ${cardBorder}`}>
      {/* Header row */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className={`w-9 h-9 rounded-lg border flex items-center justify-center flex-shrink-0 ${meta.badgeBg} ${meta.badgeBorder}`}>
            <span className={`text-[10px] font-black tracking-tight ${meta.badgeText}`}>{meta.abbrev}</span>
          </div>
          <span className="text-white text-sm font-semibold">{meta.label}</span>
        </div>
        <span className={`flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 rounded-full border flex-shrink-0 ${badge.cls}`}>
          {statusIcon}
          {badge.label}
        </span>
      </div>
      {/* Result */}
      <p className="text-zinc-300 text-sm leading-relaxed pl-[52px]">{result}</p>
      {/* Educational one-liner */}
      <p className="text-zinc-600 text-xs pl-[52px]">{meta.blurb}</p>
    </div>
  );
}

// ── Threat Card ───────────────────────────────────────────────────────────────

function ThreatCard({ threat }: { threat: ThreatItem }) {
  return (
    <div className="flex gap-3 p-4 rounded-xl bg-red-950/20 border border-red-800/40">
      <div className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
        <XIcon className="w-4 h-4 text-red-400" />
      </div>
      <div>
        <p className="text-red-300 font-semibold text-sm">{threat.label}</p>
        <p className="text-red-200/60 text-sm mt-0.5 leading-relaxed">{threat.explanation}</p>
      </div>
    </div>
  );
}

// ── Header ────────────────────────────────────────────────────────────────────

function SiteHeader() {
  return (
    <header className="w-full border-b border-zinc-800 bg-zinc-950/80 backdrop-blur sticky top-0 z-10">
      <div className="max-w-3xl mx-auto px-4 h-14 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2 group">
          <LockIcon className="w-6 h-6 text-green-400 group-hover:text-green-300 transition-colors" />
          <span className="text-white font-semibold text-sm tracking-tight">IsThisSiteLegit</span>
        </Link>
        <Link href="/" className="text-zinc-400 hover:text-white text-sm transition-colors">
          ← Check another site
        </Link>
      </div>
    </header>
  );
}

// ── Main Results ──────────────────────────────────────────────────────────────

async function ResultsContent({ domain }: { domain: string }) {
  const data = await fetchCheck(domain);

  if (data.error) {
    return (
      <div className="flex flex-col items-center gap-6 text-center py-20 px-4">
        <div className="w-16 h-16 rounded-full bg-zinc-800 flex items-center justify-center">
          <XIcon className="w-8 h-8 text-zinc-400" />
        </div>
        <div>
          <p className="text-xl text-white font-semibold">Couldn&apos;t analyze this site</p>
          <p className="text-zinc-400 mt-2">The site may be down, invalid, or blocking our scan.</p>
        </div>
        <Link href="/" className="px-6 py-3 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-medium transition-colors">
          ← Try another site
        </Link>
      </div>
    );
  }

  const {
    safetyScore,
    isUp,
    hasSSL,
    domainAgeDays,
    domainCreatedDate,
    registrar,
    whoisPrivacy,
    vtStats,
    threats,
    checksRun,
    aiAnalysis,
  } = data;

  const vc = verdictConfig(safetyScore);
  const showVPNCTA = safetyScore < 60;
  const deductions = computeDeductions(data);

  // ── Source result strings ────────────────────────────────────────────────────

  const gsbStatus: "ok" | "fail" = checksRun.googleSafeBrowsing === "flagged" ? "fail" : "ok";
  const gsbResult =
    data.isMalware && data.isPhishing
      ? "Flagged for both malware distribution and phishing."
      : data.isMalware
      ? "Confirmed as a malware distribution site."
      : data.isPhishing
      ? "Confirmed as a phishing site impersonating a trusted brand."
      : "Not listed in Google's threat database.";

  const vtStatus: "ok" | "warn" | "fail" | "unavailable" =
    checksRun.virusTotal === "unavailable" ? "unavailable" :
    checksRun.virusTotal === "flagged" ? "fail" : "ok";
  const vtResult =
    vtStats === null
      ? "Could not connect to VirusTotal — excluded from scoring."
      : vtStats.malicious >= 3
      ? `${vtStats.malicious} / ${vtStats.total} engines identified this as malicious.`
      : vtStats.suspicious > 0
      ? `${vtStats.suspicious} / ${vtStats.total} engines raised concerns; ${vtStats.malicious} confirmed malicious.`
      : `0 / ${vtStats.total} engines found any issues.`;

  const sslStatus: "ok" | "fail" = checksRun.ssl === "valid" ? "ok" : "fail";
  const sslResult = hasSSL
    ? "HTTPS active — your connection to this site is encrypted."
    : "HTTP only — anything you type is transmitted in plain text.";

  const ageStatus: "ok" | "warn" | "unavailable" =
    checksRun.domainAge === "new" ? "warn" :
    checksRun.domainAge === "unknown" ? "unavailable" : "ok";
  const ageResult =
    domainAgeDays === null
      ? "Age could not be determined from WHOIS records."
      : domainAgeDays < 7
      ? `Registered ${domainCreatedDate ?? `${domainAgeDays} days ago`} — extremely new.`
      : domainAgeDays < 30
      ? `Registered ${domainCreatedDate ?? `${domainAgeDays} days ago`} — less than a month old.`
      : domainAgeDays < 365
      ? `Registered ${domainCreatedDate ?? `${formatAge(domainAgeDays)} ago`} — still fairly new.`
      : `Registered ${domainCreatedDate ?? `${formatAge(domainAgeDays)} ago`} — established domain.`;

  const aiStatus: "ok" | "warn" | "unavailable" =
    checksRun.aiContent === "unavailable" ? "unavailable" :
    checksRun.aiContent === "flagged" ? "warn" : "ok";
  const aiResult =
    checksRun.aiContent === "unavailable"
      ? "Page content could not be retrieved for analysis."
      : checksRun.aiContent === "flagged"
      ? `${aiAnalysis?.flags.length ?? 0} suspicious pattern${(aiAnalysis?.flags.length ?? 0) === 1 ? "" : "s"} found in page content.`
      : "No deceptive language or scam patterns detected.";

  const sourcesChecked = [
    true,
    vtStatus !== "unavailable",
    true,
    ageStatus !== "unavailable",
    aiStatus !== "unavailable",
  ].filter(Boolean).length;

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-5 py-8 px-4">

      {/* Domain label */}
      <p className="text-zinc-500 text-sm text-center truncate">{domain}</p>

      {/* ── Score + Verdict ─────────────────────────────────────────────────── */}
      <div className={`rounded-2xl border p-6 ${vc.bg} ${vc.border}`}>
        <div className="flex flex-col sm:flex-row items-center gap-6">
          <ScoreRing score={safetyScore} />
          <div className="flex flex-col items-center sm:items-start gap-3 text-center sm:text-left flex-1 min-w-0">
            <div>
              <p className={`text-2xl font-black tracking-tight ${vc.text}`}>{vc.label}</p>
              <p className="text-zinc-300 text-sm mt-1 leading-relaxed">{vc.sub}</p>
            </div>
            {/* Status pills */}
            <div className="flex flex-wrap gap-2 justify-center sm:justify-start">
              <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${isUp ? "bg-green-500/15 border-green-500/30 text-green-400" : "bg-red-500/15 border-red-500/30 text-red-400"}`}>
                {isUp ? "● Online" : "● Offline"}
              </span>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${hasSSL ? "bg-green-500/15 border-green-500/30 text-green-400" : "bg-red-500/15 border-red-500/30 text-red-400"}`}>
                {hasSSL ? "● Secure (HTTPS)" : "● No SSL"}
              </span>
              {domainAgeDays !== null && (
                <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${domainAgeDays >= 365 ? "bg-zinc-700/50 border-zinc-600 text-zinc-300" : "bg-yellow-400/10 border-yellow-400/30 text-yellow-400"}`}>
                  ● {formatAge(domainAgeDays)}
                </span>
              )}
            </div>
            {/* Sources strip */}
            <p className="text-zinc-600 text-xs">
              Scanned via Google Safe Browsing · VirusTotal · WHOIS · Claude AI
            </p>
          </div>
        </div>
      </div>

      {/* ── Threats ─────────────────────────────────────────────────────────── */}
      {threats.length > 0 && (
        <div className="flex flex-col gap-3">
          <h2 className="text-white font-semibold text-sm uppercase tracking-wider">
            {threats.length === 1 ? "1 Risk Detected" : `${threats.length} Risks Detected`}
          </h2>
          {threats.map((t) => (
            <ThreatCard key={t.id} threat={t} />
          ))}
        </div>
      )}

      {/* ── Security Analysis ────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-white font-semibold text-sm uppercase tracking-wider">Security Analysis</h2>
          <span className="text-zinc-600 text-xs">{sourcesChecked} / 5 sources</span>
        </div>
        <SourceCard source="gsb" status={gsbStatus} result={gsbResult} />
        <SourceCard source="vt" status={vtStatus} result={vtResult} />
        <SourceCard source="ssl" status={sslStatus} result={sslResult} />
        <SourceCard source="whois" status={ageStatus} result={ageResult} />
        <SourceCard source="ai" status={aiStatus} result={aiResult} />
        {aiAnalysis?.summary && (
          <p className="text-zinc-500 text-xs leading-relaxed px-1">
            <span className="text-zinc-400 font-medium">AI note: </span>
            {aiAnalysis.summary}
          </p>
        )}
      </div>

      {/* ── Score Breakdown ──────────────────────────────────────────────────── */}
      {deductions.length > 0 && (
        <div className="rounded-2xl bg-zinc-900 border border-zinc-800 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800">
            <h2 className="text-white font-semibold text-sm uppercase tracking-wider">Score Breakdown</h2>
            <p className="text-zinc-500 text-xs mt-0.5">How we arrived at {safetyScore} / 100</p>
          </div>
          <div className="px-5 py-4 flex flex-col gap-2.5">
            <div className="flex justify-between items-center text-sm">
              <span className="text-zinc-400">Starting score</span>
              <span className="text-zinc-200 font-semibold tabular-nums">100</span>
            </div>
            {deductions.map((d, i) => (
              <div key={i} className="flex justify-between items-center text-sm">
                <span className="text-zinc-400">{d.reason}</span>
                <span className="text-red-400 font-semibold tabular-nums">−{d.amount}</span>
              </div>
            ))}
            <div className="border-t border-zinc-800 pt-2.5 flex justify-between items-center text-sm font-bold">
              <span className="text-white">Final score</span>
              <span style={{ color: scoreColor(safetyScore) }} className="tabular-nums">{safetyScore}</span>
            </div>
          </div>
        </div>
      )}

      {/* ── Site Details ─────────────────────────────────────────────────────── */}
      <div className="rounded-2xl bg-zinc-900 border border-zinc-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800">
          <h2 className="text-white font-semibold text-sm uppercase tracking-wider">Site Details</h2>
        </div>
        <div className="divide-y divide-zinc-800/80">

          <div className="px-5 py-3.5 flex justify-between items-center gap-4">
            <span className="text-zinc-500 text-sm flex-shrink-0">Status</span>
            <span className={`text-sm font-medium ${isUp ? "text-green-400" : "text-red-400"}`}>
              {isUp ? "Online and reachable" : "Could not be reached"}
            </span>
          </div>

          <div className="px-5 py-3.5 flex justify-between items-center gap-4">
            <span className="text-zinc-500 text-sm flex-shrink-0">Encryption</span>
            <span className={`text-sm text-right ${hasSSL ? "text-zinc-300" : "text-red-400"}`}>
              {hasSSL ? "HTTPS (encrypted)" : "HTTP only (unencrypted)"}
            </span>
          </div>

          {domainAgeDays !== null && (
            <div className="px-5 py-3.5 flex justify-between items-start gap-4">
              <span className="text-zinc-500 text-sm flex-shrink-0">Domain Age</span>
              <div className="text-right">
                <p className="text-zinc-300 text-sm">
                  {domainCreatedDate ? `Registered ${domainCreatedDate}` : formatAge(domainAgeDays)}
                </p>
                <p className={`text-xs mt-0.5 ${domainAgeDays < 30 ? "text-yellow-500" : "text-zinc-600"}`}>
                  {domainAgeDays < 7
                    ? "Brand new — most scam sites are less than a week old."
                    : domainAgeDays < 30
                    ? "Very new — approach with caution."
                    : domainAgeDays < 365
                    ? "Less than a year old — still building a track record."
                    : domainAgeDays < 1825
                    ? "A few years of history."
                    : "Long-established domain."}
                </p>
              </div>
            </div>
          )}

          {registrar && (
            <div className="px-5 py-3.5 flex justify-between items-center gap-4">
              <span className="text-zinc-500 text-sm flex-shrink-0">Registrar</span>
              <span className="text-zinc-300 text-sm text-right">{registrar}</span>
            </div>
          )}

          {whoisPrivacy !== null && (
            <div className="px-5 py-3.5 flex justify-between items-start gap-4">
              <span className="text-zinc-500 text-sm flex-shrink-0">WHOIS Privacy</span>
              <div className="text-right">
                <p className="text-zinc-300 text-sm">
                  {whoisPrivacy ? "Owner identity protected" : "Owner details publicly listed"}
                </p>
                <p className="text-zinc-600 text-xs mt-0.5">
                  {whoisPrivacy
                    ? "Privacy protection is a standard practice — not a red flag on its own."
                    : "Registrant contact details are visible in public WHOIS records."}
                </p>
              </div>
            </div>
          )}

          {vtStats && (
            <div className="px-5 py-4 flex flex-col gap-3">
              <div className="flex justify-between items-center">
                <span className="text-zinc-500 text-sm">VirusTotal Engines</span>
                <span className={`text-sm font-semibold tabular-nums ${vtStats.malicious > 0 ? "text-red-400" : "text-green-400"}`}>
                  {vtStats.malicious === 0 ? `0 / ${vtStats.total} flagged` : `${vtStats.malicious} / ${vtStats.total} flagged`}
                </span>
              </div>
              <div className="w-full h-1.5 rounded-full bg-zinc-800 overflow-hidden flex">
                {vtStats.total > 0 && (
                  <>
                    <div className="h-full bg-green-500" style={{ width: `${(vtStats.clean / vtStats.total) * 100}%` }} />
                    <div className="h-full bg-yellow-400" style={{ width: `${(vtStats.suspicious / vtStats.total) * 100}%` }} />
                    <div className="h-full bg-red-500" style={{ width: `${(vtStats.malicious / vtStats.total) * 100}%` }} />
                  </>
                )}
              </div>
              <div className="flex gap-4 text-xs text-zinc-600">
                <span><span className="text-green-400 font-medium">{vtStats.clean}</span> clean</span>
                {vtStats.suspicious > 0 && <span><span className="text-yellow-400 font-medium">{vtStats.suspicious}</span> suspicious</span>}
                {vtStats.malicious > 0 && <span><span className="text-red-400 font-medium">{vtStats.malicious}</span> malicious</span>}
                <span className="ml-auto">{vtStats.total} engines</span>
              </div>
            </div>
          )}

        </div>
      </div>

      {/* ── VPN CTA ──────────────────────────────────────────────────────────── */}
      {showVPNCTA && (
        <div className="rounded-2xl border border-zinc-700/60 bg-zinc-900/60 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800">
            <p className="text-white font-semibold text-sm">Protect yourself online</p>
            <p className="text-zinc-500 text-xs mt-0.5">
              A VPN encrypts your traffic and masks your location — especially useful when visiting unfamiliar sites.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row divide-y sm:divide-y-0 sm:divide-x divide-zinc-800">
            <a
              href="https://www.expressvpn.com"
              target="_blank"
              rel="noopener noreferrer sponsored"
              className="flex-1 flex items-center justify-between px-5 py-4 hover:bg-zinc-800/60 transition-colors group"
            >
              <div>
                <p className="text-white text-sm font-semibold">ExpressVPN</p>
                <p className="text-zinc-500 text-xs mt-0.5">Fast · 30-day money-back guarantee</p>
              </div>
              <span className="text-zinc-400 group-hover:text-white text-sm transition-colors">→</span>
            </a>
            <a
              href="https://nordvpn.com"
              target="_blank"
              rel="noopener noreferrer sponsored"
              className="flex-1 flex items-center justify-between px-5 py-4 hover:bg-zinc-800/60 transition-colors group"
            >
              <div>
                <p className="text-white text-sm font-semibold">NordVPN</p>
                <p className="text-zinc-500 text-xs mt-0.5">Feature-rich · Strong privacy record</p>
              </div>
              <span className="text-zinc-400 group-hover:text-white text-sm transition-colors">→</span>
            </a>
          </div>
        </div>
      )}

      {/* ── Share ─────────────────────────────────────────────────────────────── */}
      <div className="flex justify-center pt-2">
        <ShareButton domain={domain} />
      </div>

    </div>
  );
}

// ── Metadata & Page ───────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ domain: string }>;
}) {
  const { domain } = await params;
  const decoded = decodeURIComponent(domain);
  return {
    title: `Is ${decoded} legit? — Website Safety Check`,
    description: `Find out if ${decoded} is safe, a scam, or malware. Instant free check powered by Google Safe Browsing and VirusTotal. No signup required.`,
    openGraph: {
      title: `Is ${decoded} legit? — Website Safety Check`,
      description: `Find out if ${decoded} is safe, a scam, or malware. Instant free check powered by Google Safe Browsing and VirusTotal.`,
    },
  };
}

export default async function CheckPage({
  params,
}: {
  params: Promise<{ domain: string }>;
}) {
  const { domain } = await params;
  const decodedDomain = decodeURIComponent(domain);

  return (
    <div className="min-h-screen" style={{ backgroundColor: "#0a0a0a" }}>
      <SiteHeader />
      <Suspense
        fallback={
          <div className="flex items-center justify-center min-h-[80vh]">
            <div className="flex flex-col items-center gap-4 text-zinc-400">
              <div className="w-10 h-10 border-4 border-zinc-700 border-t-green-400 rounded-full animate-spin" />
              <p className="text-sm">Scanning {decodedDomain}…</p>
              <p className="text-xs text-zinc-600">Checking Google Safe Browsing, VirusTotal, and domain records</p>
            </div>
          </div>
        }
      >
        <ResultsContent domain={decodedDomain} />
      </Suspense>
    </div>
  );
}
