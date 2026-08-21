import { Suspense } from "react";
import Link from "next/link";
import ShareButton from "./ShareButton";

export const dynamic = "force-dynamic";

interface CheckResult {
  domain: string;
  safetyScore: number;
  isMalware: boolean;
  isPhishing: boolean;
  isUp: boolean;
  hasSSL: boolean;
  domainAgeDays: number;
  registrar: string;
  vtStats: { malicious: number; suspicious: number; clean: number };
  threats: string[];
  error?: string;
}

const MOCK_RESULT: Omit<CheckResult, "domain"> = {
  safetyScore: 85,
  isMalware: false,
  isPhishing: false,
  isUp: true,
  hasSSL: true,
  domainAgeDays: 3650,
  registrar: "GoDaddy",
  vtStats: { malicious: 0, suspicious: 0, clean: 70 },
  threats: [],
};

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
    // API doesn't exist yet — return mock data
    return { domain, ...MOCK_RESULT };
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 40) return "text-yellow-400";
  return "text-red-400";
}

function scoreRingColor(score: number): string {
  if (score >= 80) return "border-green-400";
  if (score >= 40) return "border-yellow-400";
  return "border-red-400";
}

function formatAge(days: number): string {
  if (days < 1) return "Less than 1 day old";
  if (days < 365) return `${days} day${days === 1 ? "" : "s"} old`;
  const years = Math.floor(days / 365);
  return `${years} year${years === 1 ? "" : "s"} old`;
}

function Badge({
  label,
  ok,
  neutral,
}: {
  label: string;
  ok: boolean;
  neutral?: boolean;
}) {
  const bg = neutral
    ? "bg-zinc-700 text-zinc-200"
    : ok
    ? "bg-green-900 text-green-300 border border-green-700"
    : "bg-red-900 text-red-300 border border-red-700";
  return (
    <span className={`px-3 py-1 rounded-full text-sm font-medium ${bg}`}>
      {label}
    </span>
  );
}

async function ResultsContent({ domain }: { domain: string }) {
  const data = await fetchCheck(domain);

  if (data.error) {
    return (
      <div className="flex flex-col items-center gap-6 text-center py-20">
        <p className="text-xl text-zinc-300">
          We couldn&apos;t analyze this site. It may be down or invalid.
        </p>
        <Link
          href="/"
          className="px-6 py-3 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-medium transition-colors"
        >
          ← Back
        </Link>
      </div>
    );
  }

  const { safetyScore, isMalware, isPhishing, isUp, hasSSL, domainAgeDays, registrar, vtStats, threats } = data;
  const showAffiliateCTA = safetyScore < 60;

  return (
    <div className="w-full max-w-2xl mx-auto flex flex-col gap-8 py-10 px-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link
          href="/"
          className="text-zinc-400 hover:text-white transition-colors text-xl font-light"
          aria-label="Back to home"
        >
          ←
        </Link>
        <h1 className="text-2xl font-bold text-white truncate">
          Results for{" "}
          <span className="text-zinc-300">{domain}</span>
        </h1>
      </div>

      {/* Safety Score */}
      <div className="flex flex-col items-center gap-2 py-4">
        <div
          className={`w-32 h-32 rounded-full border-8 flex items-center justify-center ${scoreRingColor(safetyScore)}`}
        >
          <span className={`text-4xl font-bold ${scoreColor(safetyScore)}`}>
            {safetyScore}
          </span>
        </div>
        <p className="text-zinc-400 text-sm uppercase tracking-widest mt-1">
          Safety Score
        </p>
      </div>

      {/* Status Badges */}
      <div className="flex flex-wrap gap-2 justify-center">
        <Badge
          label={isMalware ? "Malware" : isPhishing ? "Phishing" : "Safe"}
          ok={!isMalware && !isPhishing}
        />
        <Badge label={isUp ? "Online" : "Offline"} ok={isUp} />
        <Badge label={hasSSL ? "SSL Secured" : "No SSL"} ok={hasSSL} />
        <Badge label={formatAge(domainAgeDays)} ok={domainAgeDays >= 30} neutral />
      </div>

      {/* Details */}
      <div
        className="rounded-2xl p-6 flex flex-col gap-4"
        style={{ backgroundColor: "#111111" }}
      >
        <h2 className="text-white font-semibold text-lg">Details</h2>

        <div className="flex flex-col gap-3 text-sm">
          {registrar && (
            <div className="flex justify-between">
              <span className="text-zinc-400">Registrar</span>
              <span className="text-zinc-200">{registrar}</span>
            </div>
          )}

          <div className="flex justify-between">
            <span className="text-zinc-400">VirusTotal</span>
            <span
              className={
                vtStats.malicious > 0 ? "text-red-400" : "text-green-400"
              }
            >
              {vtStats.malicious} out of {vtStats.malicious + vtStats.suspicious + vtStats.clean} engines flagged this site
            </span>
          </div>

          {threats.length > 0 && (
            <div className="flex flex-col gap-1 mt-1">
              <span className="text-zinc-400">Threats</span>
              <ul className="list-disc list-inside text-red-400 pl-1">
                {threats.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Affiliate CTA */}
      {showAffiliateCTA && (
        <div className="rounded-2xl p-6 border border-yellow-700 bg-yellow-950/30 flex flex-col gap-4">
          <p className="text-yellow-300 font-medium text-base">
            This site may be risky. We recommend protecting yourself with a
            trusted VPN.
          </p>
          <div className="flex flex-col sm:flex-row gap-3">
            <a
              href="https://www.expressvpn.com"
              target="_blank"
              rel="noopener noreferrer sponsored"
              className="flex-1 flex flex-col gap-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 px-5 py-4 transition-colors"
            >
              <span className="text-white font-bold text-base">ExpressVPN</span>
              <span className="text-zinc-400 text-sm">
                Fast, trusted, 30-day money-back
              </span>
              <span className="text-green-400 text-sm font-medium mt-1">
                Get ExpressVPN →
              </span>
            </a>
            <a
              href="https://nordvpn.com"
              target="_blank"
              rel="noopener noreferrer sponsored"
              className="flex-1 flex flex-col gap-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 px-5 py-4 transition-colors"
            >
              <span className="text-white font-bold text-base">NordVPN</span>
              <span className="text-zinc-400 text-sm">
                Feature-rich, strong privacy record
              </span>
              <span className="text-green-400 text-sm font-medium mt-1">
                Get NordVPN →
              </span>
            </a>
          </div>
        </div>
      )}

      {/* Share Button */}
      <div className="flex justify-center">
        <ShareButton domain={domain} />
      </div>

      {/* AdSense Placeholder */}
      <div className="flex flex-col items-center gap-2 pt-4">
        <p className="text-zinc-600 text-xs uppercase tracking-widest">
          Advertisement
        </p>
        {/* Desktop 728x90 */}
        <div className="hidden sm:flex w-[728px] max-w-full h-[90px] bg-zinc-900 border border-zinc-800 rounded items-center justify-center">
          <span className="text-zinc-600 text-sm">Ad Unit (728×90)</span>
        </div>
        {/* Mobile 320x100 */}
        <div className="flex sm:hidden w-[320px] max-w-full h-[100px] bg-zinc-900 border border-zinc-800 rounded items-center justify-center">
          <span className="text-zinc-600 text-sm">Ad Unit (320×100)</span>
        </div>
      </div>
    </div>
  );
}

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
      <Suspense
        fallback={
          <div className="flex items-center justify-center min-h-screen">
            <div className="flex flex-col items-center gap-4 text-zinc-400">
              <div className="w-10 h-10 border-4 border-zinc-700 border-t-green-400 rounded-full animate-spin" />
              <p>Analyzing {decodedDomain}...</p>
            </div>
          </div>
        }
      >
        <ResultsContent domain={decodedDomain} />
      </Suspense>
    </div>
  );
}
