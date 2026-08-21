"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  function cleanDomain(raw: string): string | null {
    let input = raw.trim();
    if (!input) return null;

    // Add scheme if missing so URL() can parse it
    if (!/^https?:\/\//i.test(input)) {
      input = "https://" + input;
    }

    try {
      const parsed = new URL(input);
      // hostname strips port; remove www.
      let hostname = parsed.hostname.toLowerCase();
      if (hostname.startsWith("www.")) {
        hostname = hostname.slice(4);
      }
      // Must have at least one dot
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
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4"
      style={{ backgroundColor: "#0a0a0a" }}
    >
      <main className="w-full max-w-2xl flex flex-col items-center gap-8 text-center">
        {/* Heading */}
        <div className="flex flex-col gap-3">
          <h1 className="text-5xl font-bold text-white tracking-tight leading-tight">
            Is this site legit?
          </h1>
          <p className="text-lg text-zinc-400 max-w-xl mx-auto leading-relaxed">
            Find out if any website is safe, trustworthy, or a scam — instantly.
            No signup required.
          </p>
        </div>

        {/* Form */}
        <form
          onSubmit={handleSubmit}
          className="w-full flex flex-col sm:flex-row gap-3"
        >
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

        {/* Error */}
        {error && (
          <p className="text-red-400 text-sm -mt-4">{error}</p>
        )}

        {/* Footer */}
        <p className="text-zinc-600 text-sm mt-4">
          Powered by Google Safe Browsing, VirusTotal, and WHOIS data
        </p>
      </main>
    </div>
  );
}
