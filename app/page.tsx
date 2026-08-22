"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

function ScanIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2" />
      <path d="M12 2a10 10 0 0 1 10 10" />
      <path d="M12 6a6 6 0 0 1 6 6" />
      <path d="M12 10a2 2 0 0 1 2 2" />
    </svg>
  );
}

function CheckCircleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  );
}

function XCircleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  );
}

export default function Home() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  function cleanDomain(raw: string): string | null {
    let input = raw.trim();
    if (!input) return null;
    if (!/^https?:\/\//i.test(input)) input = "https://" + input;
    try {
      const parsed = new URL(input);
      let hostname = parsed.hostname.toLowerCase();
      if (hostname.startsWith("www.")) hostname = hostname.slice(4);
      if (!hostname.includes(".")) return null;
      return hostname;
    } catch {
      return null;
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    const domain = cleanDomain(url);
    if (!domain) {
      setError("Please enter a valid website URL, e.g. amazon.com");
      return;
    }
    router.push(`/check/${domain}`);
  }

  return (
    <div className="min-h-screen flex flex-col" style={{ backgroundColor: "#0a0a0a" }}>

      {/* Header */}
      <header className="w-full border-b border-zinc-800/60">
        <div className="max-w-3xl mx-auto px-4 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <ScanIcon className="w-6 h-6 text-green-400" />
            <span className="text-white font-semibold text-sm tracking-tight">IsThisSiteLegit</span>
          </Link>
          <span className="text-zinc-600 text-xs hidden sm:block">Free · No signup · Instant results</span>
        </div>
      </header>

      {/* Hero */}
      <main className="flex-1 flex flex-col items-center justify-center px-4 py-16">
        <div className="w-full max-w-2xl flex flex-col items-center gap-10 text-center">

          {/* Trust badge */}
          <div className="flex items-center gap-2 px-4 py-2 rounded-full bg-green-500/10 border border-green-500/20">
            <CheckCircleIcon className="w-4 h-4 text-green-400" />
            <span className="text-green-400 text-xs font-medium">
              Real-time scans, not AI guesses
            </span>
          </div>

          {/* Heading */}
          <div className="flex flex-col gap-4">
            <h1 className="text-5xl sm:text-6xl font-black text-white tracking-tight leading-none">
              Is this website<br />
              <span className="text-green-400">safe to visit?</span>
            </h1>
            <p className="text-lg text-zinc-400 max-w-lg mx-auto leading-relaxed">
              Paste any URL. We run live checks against Google Safe Browsing, VirusTotal&apos;s 90+ engines, and WHOIS records — then show you every source, every result, and exactly what affected the score.
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="w-full flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter a website URL (e.g. amazon.com)"
              className="flex-1 px-5 py-4 rounded-xl bg-zinc-900 border border-zinc-700 text-white placeholder-zinc-500 text-base focus:outline-none focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
              autoFocus
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="submit"
              className="px-8 py-4 rounded-xl bg-green-500 hover:bg-green-400 text-black font-bold text-base transition-colors whitespace-nowrap"
            >
              Check Site
            </button>
          </form>

          {error && <p className="text-red-400 text-sm -mt-6">{error}</p>}

          {/* Differentiators */}
          <div className="w-full grid grid-cols-1 sm:grid-cols-3 gap-3">
            {[
              {
                good: true,
                title: "Live APIs, not AI guesses",
                body: "We query Google Safe Browsing and VirusTotal directly — no AI-generated summaries that can be months out of date.",
              },
              {
                good: true,
                title: "Every source named",
                body: "Each check shows which service ran it, what it found, and what it means. Nothing is hidden behind a single number.",
              },
              {
                good: true,
                title: "Score math shown",
                body: "We display exactly which factors reduced your score and by how much — so you understand the result, not just the verdict.",
              },
            ].map((item) => (
              <div
                key={item.title}
                className="flex flex-col gap-2 rounded-xl bg-zinc-900 border border-zinc-800 p-4 text-left"
              >
                <div className="flex items-center gap-2">
                  <CheckCircleIcon className="w-4 h-4 text-green-400 flex-shrink-0" />
                  <span className="text-white text-sm font-semibold">{item.title}</span>
                </div>
                <p className="text-zinc-500 text-xs leading-relaxed">{item.body}</p>
              </div>
            ))}
          </div>

          {/* What we check */}
          <div className="w-full flex flex-col gap-3">
            <p className="text-zinc-600 text-xs uppercase tracking-widest">What we check</p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: "Google Safe Browsing", sub: "Malware & phishing — live database" },
                { label: "VirusTotal", sub: "90+ antivirus engines, scanned simultaneously" },
                { label: "SSL Certificate", sub: "HTTPS encryption & certificate validity" },
                { label: "WHOIS Records", sub: "Domain age, registrar & privacy flags" },
              ].map((item) => (
                <div
                  key={item.label}
                  className="flex flex-col gap-1.5 rounded-xl bg-zinc-900 border border-zinc-800 p-4 text-left"
                >
                  <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
                  <span className="text-white text-xs font-semibold">{item.label}</span>
                  <span className="text-zinc-500 text-xs leading-relaxed">{item.sub}</span>
                </div>
              ))}
            </div>
          </div>

          {/* How it works */}
          <div className="w-full flex flex-col gap-4">
            <p className="text-zinc-600 text-xs uppercase tracking-widest">How it works</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-left">
              {[
                {
                  step: "1",
                  title: "Paste any URL",
                  body: "Enter a full URL or just the domain. No account needed.",
                },
                {
                  step: "2",
                  title: "We query live databases",
                  body: "Google, VirusTotal, and WHOIS are checked in parallel — real data, not cached summaries.",
                },
                {
                  step: "3",
                  title: "See the full breakdown",
                  body: "A safety score with every source named, every result explained, and a breakdown of what affected the number.",
                },
              ].map((item) => (
                <div key={item.step} className="flex gap-3 rounded-xl bg-zinc-900 border border-zinc-800 p-4">
                  <span className="text-green-400 font-black text-lg leading-none flex-shrink-0">{item.step}</span>
                  <div>
                    <p className="text-white text-sm font-semibold">{item.title}</p>
                    <p className="text-zinc-500 text-xs mt-1 leading-relaxed">{item.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* What others don't show */}
          <div className="w-full rounded-2xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
            <div className="px-5 py-4 border-b border-zinc-800">
              <p className="text-white text-sm font-semibold">What most checkers don&apos;t tell you</p>
            </div>
            <div className="divide-y divide-zinc-800">
              {[
                {
                  them: "A single score with no explanation",
                  us: "Score + breakdown showing every deduction and why",
                },
                {
                  them: "No indication of which sources were used",
                  us: "Every source named: Google, VirusTotal, WHOIS, Claude AI",
                },
                {
                  them: "AI-summarized web search results",
                  us: "Live API calls — data from the moment you run the check",
                },
                {
                  them: "Pass / fail with no context",
                  us: "Per-source verdict with a one-sentence explanation for each",
                },
              ].map((row, i) => (
                <div key={i} className="grid grid-cols-2 divide-x divide-zinc-800">
                  <div className="flex items-start gap-2.5 px-4 py-3">
                    <XCircleIcon className="w-4 h-4 text-zinc-600 flex-shrink-0 mt-0.5" />
                    <span className="text-zinc-500 text-xs leading-relaxed">{row.them}</span>
                  </div>
                  <div className="flex items-start gap-2.5 px-4 py-3">
                    <CheckCircleIcon className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                    <span className="text-zinc-300 text-xs leading-relaxed">{row.us}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800/60 py-6 px-4">
        <div className="max-w-3xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ScanIcon className="w-4 h-4 text-zinc-600" />
            <span className="text-zinc-600 text-xs">IsThisSiteLegit — Free website safety checker</span>
          </div>
          <span className="text-zinc-700 text-xs">
            Powered by Google Safe Browsing · VirusTotal · WHOIS · Claude AI
          </span>
        </div>
      </footer>

    </div>
  );
}
