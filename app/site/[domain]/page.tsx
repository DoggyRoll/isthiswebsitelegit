import Link from "next/link";
import type { Metadata } from "next";
import { getScanRecord } from "@/lib/storage";
import type { ScanRecord } from "@/lib/storage";

export const revalidate = 86400; // ISR: rebuild daily

// ── Seed list ─────────────────────────────────────────────────────────────────
// These are the domains people actually Google "is X safe / legit?"

export const TOP_DOMAINS = [
  // Frequently questioned shopping
  "temu.com", "shein.com", "wish.com", "aliexpress.com", "dhgate.com",
  "banggood.com", "gearbest.com", "joom.com", "lightinthebox.com", "rosegal.com",
  "zaful.com", "sammydress.com", "dresslily.com", "patpat.com", "romwe.com",
  "g2a.com", "kinguin.net", "eneba.com", "cdkeys.com",
  // Major e-commerce
  "amazon.com", "ebay.com", "etsy.com", "walmart.com", "target.com",
  "bestbuy.com", "costco.com", "newegg.com", "overstock.com", "wayfair.com",
  "chewy.com", "zappos.com", "poshmark.com", "mercari.com", "depop.com",
  "stockx.com", "vinted.com", "reverb.com", "swappa.com", "offerup.com",
  "letgo.com", "craigslist.org", "facebook.com",
  // Payments & fintech
  "paypal.com", "cashapp.com", "venmo.com", "zelle.com", "wise.com",
  "revolut.com", "chime.com", "sofi.com", "stripe.com", "square.com",
  "affirm.com", "klarna.com", "afterpay.com", "sezzle.com",
  // Crypto
  "coinbase.com", "binance.com", "kraken.com", "gemini.com", "crypto.com",
  "robinhood.com", "webull.com", "etrade.com", "opensea.io", "metamask.io",
  "uniswap.org", "pancakeswap.finance", "luno.com",
  // Social & communication
  "instagram.com", "tiktok.com", "twitter.com", "x.com", "snapchat.com",
  "pinterest.com", "youtube.com", "linkedin.com", "reddit.com", "discord.com",
  "telegram.org", "whatsapp.com", "tumblr.com", "threads.net",
  // Streaming & entertainment
  "netflix.com", "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com",
  "paramountplus.com", "spotify.com", "pandora.com", "soundcloud.com",
  "twitch.tv", "roblox.com", "steam.com", "epicgames.com",
  // Tech & cloud
  "google.com", "microsoft.com", "apple.com", "dropbox.com", "zoom.us",
  "slack.com", "notion.so", "canva.com", "adobe.com", "github.com",
  "cloudflare.com", "godaddy.com", "namecheap.com", "bluehost.com",
  // Shipping & government
  "usps.com", "fedex.com", "ups.com", "dhl.com", "irs.gov", "ssa.gov",
  // Dating
  "match.com", "tinder.com", "bumble.com", "hinge.co", "eharmony.com",
  "plentyoffish.com", "okcupid.com", "badoo.com", "zoosk.com",
  // Jobs
  "indeed.com", "glassdoor.com", "ziprecruiter.com", "monster.com",
  "careerbuilder.com", "flexjobs.com", "upwork.com", "fiverr.com",
  "freelancer.com", "toptal.com",
  // Travel
  "airbnb.com", "booking.com", "expedia.com", "tripadvisor.com",
  "kayak.com", "hotels.com", "vrbo.com", "agoda.com", "hotwire.com",
  "priceline.com",
  // Health & pharma
  "cvs.com", "walgreens.com", "goodrx.com", "hims.com", "ro.co",
  "webmd.com", "healthline.com", "1800petmeds.com",
  // Education
  "coursera.org", "udemy.com", "skillshare.com", "masterclass.com",
  "khanacademy.org", "duolingo.com", "chegg.com", "quizlet.com",
  // News
  "cnn.com", "foxnews.com", "bbc.com", "nytimes.com", "washingtonpost.com",
  "theguardian.com", "apnews.com", "huffpost.com",
  // VPN & security
  "nordvpn.com", "expressvpn.com", "surfshark.com", "protonvpn.com",
  "mullvad.net", "privateinternetaccess.com",
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 65) return "#14b8a6";
  if (score >= 40) return "#eab308";
  if (score >= 20) return "#f97316";
  return "#ef4444";
}

function verdictLabel(score: number): string {
  if (score >= 80) return "Likely Safe";
  if (score >= 65) return "Mostly Safe";
  if (score >= 40) return "Proceed with Caution";
  if (score >= 20) return "High Risk";
  return "Avoid This Site";
}

function verdictSentence(domain: string, record: ScanRecord): string {
  const score = record.safetyScore;
  if (score >= 80)
    return `${domain} passed all our checks — no malware, no phishing, valid SSL, and an established domain age.`;
  if (score >= 65)
    return `${domain} looks mostly safe, though a few minor signals are worth reviewing before sharing sensitive data.`;
  if (score >= 40)
    return `${domain} has some risk signals. Proceed carefully and avoid entering payment or personal information until you've reviewed the full report.`;
  if (score >= 20)
    return `${domain} has multiple red flags. We recommend not visiting or entering any information on this site.`;
  return `${domain} has confirmed threats. Do not visit, click, or interact with this site.`;
}

function ScoreRing({ score }: { score: number }) {
  const r = 40;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  const color = scoreColor(score);
  return (
    <div className="relative w-28 h-28 flex-shrink-0 flex items-center justify-center">
      <svg className="absolute inset-0 w-full h-full" style={{ transform: "rotate(-90deg)" }} viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#27272a" strokeWidth="8" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeLinecap="round" strokeDasharray={`${circ}`} strokeDashoffset={`${offset}`} />
      </svg>
      <div className="relative flex flex-col items-center leading-none">
        <span className="text-3xl font-black tabular-nums" style={{ color }}>{score}</span>
        <span className="text-zinc-500 text-[10px] font-medium mt-0.5">/ 100</span>
      </div>
    </div>
  );
}

function LockIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="9" r="7" />
      <line x1="14.5" y1="14.5" x2="21" y2="21" />
      <polyline points="6,9 8.5,11.5 13,6" />
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
      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

// ── Metadata ──────────────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ domain: string }>;
}): Promise<Metadata> {
  const { domain } = await params;
  const d = decodeURIComponent(domain);
  return {
    title: `Is ${d} Safe? — Free Website Safety Report`,
    description: `Is ${d} legit or a scam? We check it against Google Safe Browsing, VirusTotal's 90+ engines, and WHOIS. Free instant report — no signup required.`,
    openGraph: {
      title: `Is ${d} Safe? — Free Website Safety Report`,
      description: `Real-time safety check for ${d}. Google Safe Browsing + VirusTotal + WHOIS. Free, instant, no signup.`,
    },
  };
}

export async function generateStaticParams() {
  return TOP_DOMAINS.map((domain) => ({ domain }));
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function SitePage({
  params,
}: {
  params: Promise<{ domain: string }>;
}) {
  const { domain } = await params;
  const d = decodeURIComponent(domain);
  const record = await getScanRecord(d);

  const faqItems = [
    {
      q: `Is ${d} safe to visit?`,
      a: record
        ? verdictSentence(d, record)
        : `Use our free scanner to check ${d} right now. We run live checks against Google Safe Browsing and VirusTotal's 90+ antivirus engines — results in seconds.`,
    },
    {
      q: `Is ${d} a scam or legitimate?`,
      a: record
        ? `${d} received a safety score of ${record.safetyScore}/100. Our verdict: ${verdictLabel(record.safetyScore)}. ${record.isMalware ? "It was flagged for malware by Google Safe Browsing." : record.isPhishing ? "It was flagged for phishing by Google Safe Browsing." : "No malware or phishing was detected."}`
        : `We check domain age, SSL certificate validity, Google's threat database, and VirusTotal to determine if a site is legitimate. Run a free check on ${d} to see the full report.`,
    },
    {
      q: `Does ${d} have a valid SSL certificate?`,
      a: record
        ? record.hasSSL
          ? `Yes — ${d} uses HTTPS, meaning your connection is encrypted.`
          : `No — ${d} does not have a valid SSL certificate. Avoid entering any personal or payment information on this site.`
        : `An SSL certificate (HTTPS) is required for any site where you share data. Run our check to see if ${d} has one.`,
    },
    {
      q: `How old is ${d}?`,
      a: record?.domainAgeDays != null
        ? record.domainAgeDays < 30
          ? `${d} was registered ${record.domainAgeDays} days ago. Very new domains are a common warning sign for scam sites.`
          : `${d} was registered approximately ${Math.floor(record.domainAgeDays / 365)} years ago. Established domains are generally more trustworthy.`
        : `Domain age is one of the strongest indicators of legitimacy — scam sites are typically registered days before they go live. Run our check to see ${d}'s registration date.`,
    },
    {
      q: "How do you check if a website is safe?",
      a: "We query Google Safe Browsing (malware and phishing), VirusTotal (90+ antivirus engines), check the SSL certificate, and look up the domain registration date via WHOIS. Each source is listed individually so you can see exactly what was found.",
    },
  ];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: faqItems.map(({ q, a }) => ({
      "@type": "Question",
      name: q,
      acceptedAnswer: { "@type": "Answer", text: a },
    })),
  };

  return (
    <div className="min-h-screen flex flex-col" style={{ backgroundColor: "#0a0a0a" }}>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      {/* Header */}
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

      <main className="flex-1 w-full max-w-2xl mx-auto px-4 py-10 flex flex-col gap-8">

        {/* Heading */}
        <div className="text-center flex flex-col gap-2">
          <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
            Is <span className="text-green-400">{d}</span> safe?
          </h1>
          <p className="text-zinc-400 text-sm">
            Real-time check via Google Safe Browsing · VirusTotal · WHOIS
          </p>
        </div>

        {/* Score card — if cached data exists */}
        {record ? (
          <div className={`rounded-2xl border p-6 flex flex-col sm:flex-row items-center gap-6 ${
            record.safetyScore >= 80 ? "bg-green-500/10 border-green-500/30" :
            record.safetyScore >= 65 ? "bg-teal-400/10 border-teal-400/30" :
            record.safetyScore >= 40 ? "bg-yellow-400/10 border-yellow-400/30" :
            record.safetyScore >= 20 ? "bg-orange-400/10 border-orange-400/30" :
            "bg-red-500/10 border-red-500/30"
          }`}>
            <ScoreRing score={record.safetyScore} />
            <div className="flex flex-col gap-3 text-center sm:text-left flex-1">
              <div>
                <p className="text-2xl font-black tracking-tight" style={{ color: scoreColor(record.safetyScore) }}>
                  {verdictLabel(record.safetyScore)}
                </p>
                <p className="text-zinc-300 text-sm mt-1 leading-relaxed">{verdictSentence(d, record)}</p>
              </div>
              {/* Quick pills */}
              <div className="flex flex-wrap gap-2 justify-center sm:justify-start">
                <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${record.hasSSL ? "bg-green-500/15 border-green-500/30 text-green-400" : "bg-red-500/15 border-red-500/30 text-red-400"}`}>
                  {record.hasSSL ? "● SSL Valid" : "● No SSL"}
                </span>
                <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${record.isMalware || record.isPhishing ? "bg-red-500/15 border-red-500/30 text-red-400" : "bg-green-500/15 border-green-500/30 text-green-400"}`}>
                  {record.isMalware ? "● Malware Detected" : record.isPhishing ? "● Phishing Detected" : "● No Threats (Google)"}
                </span>
                {record.vtMalicious !== null && (
                  <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${record.vtMalicious > 0 ? "bg-red-500/15 border-red-500/30 text-red-400" : "bg-green-500/15 border-green-500/30 text-green-400"}`}>
                    {record.vtMalicious > 0 ? `● ${record.vtMalicious} engines flagged` : `● Clean (VirusTotal)`}
                  </span>
                )}
              </div>
              <p className="text-zinc-600 text-xs">
                Last scanned {new Date(record.checkedAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}
              </p>
            </div>
          </div>
        ) : (
          /* No cached data — prompt fresh scan */
          <div className="rounded-2xl border border-zinc-800 bg-zinc-900 p-8 flex flex-col items-center gap-4 text-center">
            <div className="w-14 h-14 rounded-full bg-zinc-800 flex items-center justify-center">
              <LockIcon className="w-7 h-7 text-zinc-400" />
            </div>
            <div>
              <p className="text-white font-semibold text-lg">No cached report yet</p>
              <p className="text-zinc-400 text-sm mt-1">Run a live scan — results in under 10 seconds.</p>
            </div>
          </div>
        )}

        {/* CTA */}
        <Link
          href={`/check/${encodeURIComponent(d)}`}
          className="w-full flex items-center justify-center gap-2 py-4 rounded-xl bg-green-500 hover:bg-green-400 text-black font-bold text-base transition-colors"
        >
          {record ? "Run a Fresh Real-Time Scan" : `Check ${d} Now`}
          <span className="text-lg">→</span>
        </Link>

        {/* What we check */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Google Safe Browsing", sub: "Malware & phishing" },
            { label: "VirusTotal", sub: "90+ AV engines" },
            { label: "SSL Certificate", sub: "HTTPS encryption" },
            { label: "WHOIS / Domain Age", sub: "Registration history" },
          ].map((item) => (
            <div key={item.label} className="flex flex-col gap-1.5 rounded-xl bg-zinc-900 border border-zinc-800 p-3 text-left">
              <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
              <span className="text-white text-xs font-semibold">{item.label}</span>
              <span className="text-zinc-500 text-xs">{item.sub}</span>
            </div>
          ))}
        </div>

        {/* FAQ */}
        <div className="flex flex-col gap-4">
          <h2 className="text-white font-bold text-lg">Frequently asked questions</h2>
          <div className="flex flex-col divide-y divide-zinc-800 rounded-2xl border border-zinc-800 overflow-hidden">
            {faqItems.map(({ q, a }) => (
              <div key={q} className="px-5 py-4 bg-zinc-900">
                <p className="text-white text-sm font-semibold">{q}</p>
                <p className="text-zinc-400 text-sm mt-1.5 leading-relaxed">{a}</p>
              </div>
            ))}
          </div>
        </div>

        {/* How scoring works */}
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
          <div className="px-5 py-4 border-b border-zinc-800">
            <h2 className="text-white font-semibold text-sm">How our safety score works</h2>
          </div>
          <div className="divide-y divide-zinc-800">
            {[
              { icon: <XIcon className="w-3.5 h-3.5 text-red-400" />, label: "Malware or phishing detected by Google", points: "−60 pts" },
              { icon: <XIcon className="w-3.5 h-3.5 text-red-400" />, label: "5+ VirusTotal engines flagged as malicious", points: "−60 pts" },
              { icon: <XIcon className="w-3.5 h-3.5 text-orange-400" />, label: "Domain registered less than 7 days ago", points: "−40 pts" },
              { icon: <XIcon className="w-3.5 h-3.5 text-yellow-400" />, label: "Domain registered less than 30 days ago", points: "−20 pts" },
              { icon: <XIcon className="w-3.5 h-3.5 text-yellow-400" />, label: "No SSL certificate (HTTP only)", points: "−15 pts" },
              { icon: <CheckIcon className="w-3.5 h-3.5 text-green-400" />, label: "No threats found across all sources", points: "100 pts" },
            ].map((row) => (
              <div key={row.label} className="px-5 py-3 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  {row.icon}
                  <span className="text-zinc-400 text-xs">{row.label}</span>
                </div>
                <span className="text-zinc-300 text-xs font-mono flex-shrink-0">{row.points}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom CTA */}
        <div className="text-center flex flex-col gap-3 pt-2">
          <p className="text-zinc-500 text-sm">Not what you were looking for?</p>
          <Link href="/" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white text-sm font-medium transition-colors">
            ← Check a different site
          </Link>
        </div>

      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800/60 py-6 px-4">
        <div className="max-w-3xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <LockIcon className="w-4 h-4 text-zinc-600" />
            <span className="text-zinc-600 text-xs">IsThisSiteLegit — Free website safety checker</span>
          </div>
          <span className="text-zinc-700 text-xs">
            Powered by Google Safe Browsing · VirusTotal · WHOIS
          </span>
        </div>
      </footer>
    </div>
  );
}
