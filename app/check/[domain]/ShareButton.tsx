"use client";

import { useState } from "react";

export default function ShareButton({ domain }: { domain: string }) {
  const [copied, setCopied] = useState(false);

  async function handleShare() {
    const url = `${window.location.origin}/check/${domain}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback: select a temporary input
      const input = document.createElement("input");
      input.value = url;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      document.body.removeChild(input);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <button
      onClick={handleShare}
      className="px-6 py-3 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-white font-medium text-sm transition-colors"
    >
      {copied ? "Link copied!" : "Share this result"}
    </button>
  );
}
