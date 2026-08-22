"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

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

function CheckCircleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
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
            <ShieldIcon className="w-6 h-6 text-green-400" />
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
              Scans against Google Safe Browsing, VirusTotal &amp; 90+ engines
            </span>
          </div>

          {/* Heading */}
          <div className="flex flex-col gap-4">
            <h1 className="text-5xl sm:text-6xl font-black text-white tracking-tight leading-none">
              Is this website<br />
              <span className="text-green-400">safe to visit?</span>
            </h1>
            <p className="text-lg text-zinc-400 max-w-lg mx-auto leading-relaxed">
              Paste any URL and get an instant safety verdict — no technical knowledge needed.
              We&apos;ll tell you exactly what we found and what it means.
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

          {/* What we check */}
          <div className="w-full grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
            {[
              { label: "Google Safe Browsing", sub: "Malware & phishing" },
              { label: "VirusTotal", sub: "90+ security engines" },
              { label: "SSL Certificate", sub: "Encryption check" },
              { label: "WHOIS Records", sub: "Domain age & registrar" },
            ].map((item) => (
              <div
                key={item.label}
                className="flex flex-col gap-1 rounded-xl bg-zinc-900 border border-zinc-800 p-4 text-left"
              >
                <div className="flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full bg-green-400 flex-shrink-0" />
                  <span className="text-white text-xs font-semibold">{item.label}</span>
                </div>
                <span className="text-zinc-500 text-xs">{item.sub}</span>
              </div>
            ))}
          </div>

          {/* How it works */}
          <div className="w-full flex flex-col gap-4">
            <p className="text-zinc-600 text-xs uppercase tracking-widest">How it works</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-left">
              {[
                {
                  step: "1",
                  title: "Enter any URL",
                  body: "Paste the website address you want to check — full URL or just the domain.",
                },
                {
                  step: "2",
                  title: "We scan it instantly",
                  body: "We query multiple threat databases and run security checks simultaneously.",
                },
                {
                  step: "3",
                  title: "Get a clear verdict",
                  body: "A plain-English safety score with explanations — no jargon, no guessing.",
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

        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800/60 py-6 px-4">
        <div className="max-w-3xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldIcon className="w-4 h-4 text-zinc-600" />
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
