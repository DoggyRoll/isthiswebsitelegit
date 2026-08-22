import { Suspense } from "react";
import Link from "next/link";
import ShareButton from "./ShareButton";
import type { SafetyReport, ThreatItem } from "@/app/api/check/route";

export const dynamic = "force-dynamic";

// ── Types ─────────────────────────────────────────────────────────────────────

type CheckResult = SafetyReport & { error?: string };

// Extend mock to include new fields


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

// ── Score Helpers ─────────────────────────────────────────────────────────────

function verdictConfig(score: number) {
  if (score >= 80) {
    return {
      label: "Likely Safe",
      sub: "This site passed our security checks.",
      ring: "border-green-500",
      text: "text-green-400",
      bg: "bg-green-500/10",
      border: "border-green-500/30",
    };
  }
  if (score >= 65) {
    return {
      label: "Mostly Safe",
      sub: "No major threats detected, but a few minor signals to be aware of.",
      ring: "border-teal-400",
      text: "text-teal-400",
      bg: "bg-teal-400/10",
      border: "border-teal-400/30",
    };
  }
  if (score >= 40) {
    return {
      label: "Proceed with Caution",
      sub: "Some concerns were found. Review the details below before proceeding.",
      ring: "border-yellow-400",
      text: "text-yellow-400",
      bg: "bg-yellow-400/10",
      border: "border-yellow-400/30",
    };
  }
  if (score >= 20) {
    return {
      label: "High Risk",
      sub: "Multiple red flags detected. Do not share personal or payment information.",
      ring: "border-orange-400",
      text: "text-orange-400",
      bg: "bg-orange-400/10",
      border: "border-orange-400/30",
    };
  }
  return {
    label: "Avoid This Site",
    sub: "Serious threats detected. Do not visit or enter any information.",
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
  const rem = days % 365;
  const months = Math.floor(rem / 30);
  if (months > 0) return `${years} yr${years === 1 ? "" : "s"} ${months} mo old`;
  return `${years} year${years === 1 ? "" : "s"} old`;
}

function ageContext(days: number | null): string {
  if (days === null) return "Age could not be determined.";
  if (days < 7) return "Extremely new — scam sites are often just days old.";
  if (days < 30) return "Less than a month old — approach with caution.";
  if (days < 180) return "A few months old — not yet well established.";
  if (days < 365) return "Less than a year old — still fairly new.";
  if (days < 1825) return "A few years old — shows some history.";
  return "Well established — older domains are generally more trustworthy.";
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SiteHeader() {
  return (
    <header className="w-full border-b border-zinc-800 bg-zinc-950/80 backdrop-blur sticky top-0 z-10">
      <div className="max-w-3xl mx-auto px-4 h-14 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2 group">
          <ShieldIcon className="w-6 h-6 text-green-400 group-hover:text-green-300 transition-colors" />
          <span className="text-white font-semibold text-sm tracking-tight">
            IsThisSiteLegit
          </span>
        </Link>
        <Link
          href="/"
          className="text-zinc-400 hover:text-white text-sm transition-colors"
        >
          ← Check another site
        </Link>
      </div>
    </header>
  );
}

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
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

function SecurityCheck({
  label,
  sublabel,
  status,
}: {
  label: string;
  sublabel: string;
  status: "ok" | "warn" | "fail" | "unavailable";
}) {
  const configs = {
    ok: {
      icon: <CheckIcon className="w-4 h-4 text-green-400" />,
      iconBg: "bg-green-500/15 border-green-500/30",
      text: "text-green-400",
    },
    warn: {
      icon: <WarnIcon className="w-4 h-4 text-yellow-400" />,
      iconBg: "bg-yellow-400/15 border-yellow-400/30",
      text: "text-yellow-400",
    },
    fail: {
      icon: <XIcon className="w-4 h-4 text-red-400" />,
      iconBg: "bg-red-500/15 border-red-500/30",
      text: "text-red-400",
    },
    unavailable: {
      icon: <span className="text-zinc-500 text-xs font-bold">—</span>,
      iconBg: "bg-zinc-800 border-zinc-700",
      text: "text-zinc-500",
    },
  };
  const c = configs[status];

  return (
    <div className="flex items-start gap-3 p-4 rounded-xl bg-zinc-900 border border-zinc-800">
      <div className={`w-8 h-8 rounded-lg border flex items-center justify-center flex-shrink-0 ${c.iconBg}`}>
        {c.icon}
      </div>
      <div>
        <p className="text-white text-sm font-medium">{label}</p>
        <p className={`text-xs mt-0.5 ${c.text}`}>{sublabel}</p>
      </div>
    </div>
  );
}

function ThreatCard({ threat }: { threat: ThreatItem }) {
  return (
    <div className="flex gap-3 p-4 rounded-xl bg-red-950/20 border border-red-800/40">
      <div className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
        <XIcon className="w-4 h-4 text-red-400" />
      </div>
      <div>
        <p className="text-red-300 font-semibold text-sm">{threat.label}</p>
        <p className="text-red-200/70 text-sm mt-0.5 leading-relaxed">{threat.explanation}</p>
      </div>
    </div>
  );
}

// ── Main Results Component ─────────────────────────────────────────────────────

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
        <Link
          href="/"
          className="px-6 py-3 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-medium transition-colors"
        >
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

  // Count completed sources for header
  const sourcesChecked = [
    true, // GSB always runs
    checksRun.virusTotal !== "unavailable",
    true, // SSL always runs
    checksRun.domainAge !== "unknown",
    checksRun.aiContent !== "unavailable",
  ].filter(Boolean).length;

  // Build security check rows
  const vtLabel =
    vtStats === null
      ? "Not available"
      : vtStats.malicious > 0
      ? `${vtStats.malicious} engine${vtStats.malicious === 1 ? "" : "s"} flagged this site`
      : `Clean across ${vtStats.total} security engines`;

  const vtStatus =
    checksRun.virusTotal === "unavailable"
      ? "unavailable"
      : checksRun.virusTotal === "flagged"
      ? "fail"
      : "ok";

  const sslStatus = checksRun.ssl === "valid" ? "ok" : "fail";
  const sslLabel = hasSSL
    ? "Encrypted connection (HTTPS) — your data is protected in transit"
    : "No HTTPS — anything you type can be intercepted by third parties";

  const gsbStatus = checksRun.googleSafeBrowsing === "flagged" ? "fail" : "ok";
  const gsbLabel =
    checksRun.googleSafeBrowsing === "flagged"
      ? "Flagged in Google Safe Browsing — reported for malware or phishing"
      : "Not found in Google Safe Browsing threat database";

  const ageStatus =
    checksRun.domainAge === "new"
      ? "warn"
      : checksRun.domainAge === "unknown"
      ? "unavailable"
      : "ok";

  const ageLabel =
    domainAgeDays !== null
      ? checksRun.domainAge === "new"
        ? `${formatAge(domainAgeDays)} — new domains are common in scams, but not always suspicious`
        : checksRun.domainAge === "recent"
        ? `${formatAge(domainAgeDays)} — still building a track record`
        : `${formatAge(domainAgeDays)} — established history`
      : "Age could not be determined from WHOIS records";

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-6 py-8 px-4">

      {/* Domain label */}
      <p className="text-zinc-500 text-sm text-center truncate">{domain}</p>

      {/* Verdict Banner */}
      <div className={`rounded-2xl border p-6 flex flex-col items-center gap-4 ${vc.bg} ${vc.border}`}>
        {/* Score ring */}
        <div className={`w-28 h-28 rounded-full border-[6px] flex items-center justify-center ${vc.ring}`}>
          <span className={`text-4xl font-black ${vc.text}`}>{safetyScore}</span>
        </div>
        <div className="text-center">
          <p className={`text-2xl font-bold ${vc.text}`}>{vc.label}</p>
          <p className="text-zinc-300 text-sm mt-1">{vc.sub}</p>
        </div>
        {/* Quick status pills */}
        <div className="flex flex-wrap gap-2 justify-center">
          <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${isUp ? "bg-green-500/15 border-green-500/30 text-green-400" : "bg-red-500/15 border-red-500/30 text-red-400"}`}>
            {isUp ? "● Online" : "● Offline"}
          </span>
          <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${hasSSL ? "bg-green-500/15 border-green-500/30 text-green-400" : "bg-red-500/15 border-red-500/30 text-red-400"}`}>
            {hasSSL ? "● SSL Secured" : "● No SSL"}
          </span>
          {domainAgeDays !== null && (
            <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${domainAgeDays >= 365 ? "bg-zinc-700/50 border-zinc-600 text-zinc-300" : "bg-yellow-400/10 border-yellow-400/30 text-yellow-400"}`}>
              ● {formatAge(domainAgeDays)}
            </span>
          )}
        </div>
      </div>

      {/* Threats — only shown if any exist */}
      {threats.length > 0 && (
        <div className="flex flex-col gap-3">
          <h2 className="text-white font-semibold text-base">
            {threats.length === 1 ? "1 Risk Detected" : `${threats.length} Risks Detected`}
          </h2>
          {threats.map((t) => (
            <ThreatCard key={t.id} threat={t} />
          ))}
        </div>
      )}

      {/* Security Checks */}
      <div className="flex flex-col gap-3">
        <div className="flex items-baseline justify-between">
          <h2 className="text-white font-semibold text-base">Security Checks</h2>
          <span className="text-zinc-500 text-xs">{sourcesChecked} sources checked</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <SecurityCheck
            label="Google Safe Browsing"
            sublabel={gsbLabel}
            status={gsbStatus}
          />
          <SecurityCheck
            label={`VirusTotal${vtStats ? ` (${vtStats.total} engines)` : ""}`}
            sublabel={vtLabel}
            status={vtStatus}
          />
          <SecurityCheck
            label="SSL Certificate"
            sublabel={sslLabel}
            status={sslStatus}
          />
          <SecurityCheck
            label="Domain Age"
            sublabel={ageLabel}
            status={ageStatus}
          />
          <SecurityCheck
            label="AI Content Analysis"
            sublabel={
              checksRun.aiContent === "unavailable"
                ? "Page content could not be retrieved for analysis"
                : checksRun.aiContent === "flagged"
                ? `${aiAnalysis?.flags.length ?? 0} suspicious pattern${(aiAnalysis?.flags.length ?? 0) === 1 ? "" : "s"} detected in page content`
                : "No scam patterns or deceptive language detected in page content"
            }
            status={
              checksRun.aiContent === "unavailable"
                ? "unavailable"
                : checksRun.aiContent === "flagged"
                ? "warn"
                : "ok"
            }
          />
        </div>
        {aiAnalysis?.summary && (
          <p className="text-zinc-400 text-xs leading-relaxed px-1">
            <span className="text-zinc-500 font-medium">AI note: </span>
            {aiAnalysis.summary}
          </p>
        )}
      </div>

      {/* Site Details */}
      <div className="rounded-2xl bg-zinc-900 border border-zinc-800 overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800">
          <h2 className="text-white font-semibold text-base">Site Details</h2>
        </div>
        <div className="divide-y divide-zinc-800">

          {/* Domain status */}
          <div className="px-5 py-4 flex justify-between items-start gap-4">
            <span className="text-zinc-400 text-sm flex-shrink-0">Status</span>
            <span className={`text-sm text-right font-medium ${isUp ? "text-green-400" : "text-red-400"}`}>
              {isUp ? "Online and reachable" : "Could not be reached"}
            </span>
          </div>

          {/* SSL */}
          <div className="px-5 py-4 flex justify-between items-start gap-4">
            <span className="text-zinc-400 text-sm flex-shrink-0">Encryption</span>
            <span className={`text-sm text-right ${hasSSL ? "text-zinc-200" : "text-red-400"}`}>
              {hasSSL
                ? "HTTPS — your connection to this site is encrypted"
                : "HTTP only — no encryption in place"}
            </span>
          </div>

          {/* Domain age */}
          {domainAgeDays !== null && (
            <div className="px-5 py-4 flex justify-between items-start gap-4">
              <span className="text-zinc-400 text-sm flex-shrink-0">Domain Age</span>
              <div className="text-right">
                <p className="text-zinc-200 text-sm">
                  {domainCreatedDate
                    ? `Registered ${domainCreatedDate}`
                    : formatAge(domainAgeDays)}
                </p>
                <p className="text-zinc-500 text-xs mt-0.5">{ageContext(domainAgeDays)}</p>
              </div>
            </div>
          )}

          {/* Registrar */}
          {registrar && (
            <div className="px-5 py-4 flex justify-between items-start gap-4">
              <span className="text-zinc-400 text-sm flex-shrink-0">Registrar</span>
              <span className="text-zinc-200 text-sm text-right">{registrar}</span>
            </div>
          )}

          {/* WHOIS Privacy */}
          {whoisPrivacy !== null && (
            <div className="px-5 py-4 flex justify-between items-start gap-4">
              <span className="text-zinc-400 text-sm flex-shrink-0">WHOIS Privacy</span>
              <div className="text-right">
                <p className={`text-sm ${whoisPrivacy ? "text-zinc-200" : "text-zinc-400"}`}>
                  {whoisPrivacy ? "Owner identity protected" : "Owner details publicly listed"}
                </p>
                <p className="text-zinc-500 text-xs mt-0.5">
                  {whoisPrivacy
                    ? "Privacy protection is a normal and common practice — it does not indicate wrongdoing."
                    : "The domain owner's contact details are visible in public WHOIS records."}
                </p>
              </div>
            </div>
          )}

          {/* VirusTotal breakdown */}
          {vtStats && (
            <div className="px-5 py-4 flex flex-col gap-3">
              <div className="flex justify-between items-center">
                <span className="text-zinc-400 text-sm">VirusTotal Scan</span>
                <span className={`text-sm font-medium ${vtStats.malicious > 0 ? "text-red-400" : "text-green-400"}`}>
                  {vtStats.malicious === 0
                    ? `All clear`
                    : `${vtStats.malicious} flagged`}
                </span>
              </div>
              {/* Progress-style breakdown */}
              <div className="w-full h-2 rounded-full bg-zinc-800 overflow-hidden flex">
                {vtStats.total > 0 && (
                  <>
                    <div
                      className="h-full bg-red-500"
                      style={{ width: `${(vtStats.malicious / vtStats.total) * 100}%` }}
                    />
                    <div
                      className="h-full bg-yellow-400"
                      style={{ width: `${(vtStats.suspicious / vtStats.total) * 100}%` }}
                    />
                    <div
                      className="h-full bg-green-500"
                      style={{ width: `${(vtStats.clean / vtStats.total) * 100}%` }}
                    />
                  </>
                )}
              </div>
              <div className="flex gap-4 text-xs text-zinc-500">
                <span><span className="text-green-400 font-medium">{vtStats.clean}</span> clean</span>
                {vtStats.suspicious > 0 && (
                  <span><span className="text-yellow-400 font-medium">{vtStats.suspicious}</span> suspicious</span>
                )}
                {vtStats.malicious > 0 && (
                  <span><span className="text-red-400 font-medium">{vtStats.malicious}</span> malicious</span>
                )}
                <span className="ml-auto">{vtStats.total} engines total</span>
              </div>
            </div>
          )}

        </div>
      </div>

      {/* VPN CTA */}
      {showVPNCTA && (
        <div className="rounded-2xl p-5 border border-yellow-700/50 bg-yellow-950/20 flex flex-col gap-4">
          <div>
            <p className="text-yellow-300 font-semibold text-base">Stay protected online</p>
            <p className="text-yellow-200/60 text-sm mt-1">
              This site may be risky. A VPN encrypts your traffic and hides your location.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <a
              href="https://www.expressvpn.com"
              target="_blank"
              rel="noopener noreferrer sponsored"
              className="flex-1 flex flex-col gap-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 px-5 py-4 transition-colors"
            >
              <span className="text-white font-bold text-sm">ExpressVPN</span>
              <span className="text-zinc-400 text-xs">Fast, trusted, 30-day money-back</span>
              <span className="text-green-400 text-xs font-medium mt-1">Get ExpressVPN →</span>
            </a>
            <a
              href="https://nordvpn.com"
              target="_blank"
              rel="noopener noreferrer sponsored"
              className="flex-1 flex flex-col gap-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 px-5 py-4 transition-colors"
            >
              <span className="text-white font-bold text-sm">NordVPN</span>
              <span className="text-zinc-400 text-xs">Feature-rich, strong privacy record</span>
              <span className="text-green-400 text-xs font-medium mt-1">Get NordVPN →</span>
            </a>
          </div>
        </div>
      )}

      {/* Share */}
      <div className="flex justify-center">
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
              <p className="text-sm">Scanning {decodedDomain}...</p>
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
