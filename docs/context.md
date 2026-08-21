# Project Context — Site Legitimacy Checker

## What This Is

A fast, no-signup web tool. User pastes a URL, gets an instant report: is it safe, is it phishing, is it malware, how old is it, is it currently up, what is its reputation score. No account, no waiting, no noise.

## Who It Is For

Anyone who receives a suspicious link — in an email, a text, a Reddit post — and wants to know if it is safe before clicking. Also people shopping on unfamiliar sites who want to verify they are real.

## Competitors

- ScamAdviser (scamadviser.com) — 6.5M users/month, clunky UI, slow, lots of ads
- WOT Web of Trust (mywot.com) — browser extension focused, less web-first
- URLVoid, Norton Safe Web, VirusTotal — more technical, not consumer-friendly

## Our Edge

Cleaner, faster, mobile-friendly, instant results, no signup, no extension required.

## Tech Stack

- Frontend + API routes: Next.js on Vercel (free tier)
- No database — fully stateless, every check is live
- Styling: Tailwind CSS

## Data Sources (all free tier)

- Google Safe Browsing API — phishing and malware detection (free, requires Google Cloud account)
- VirusTotal API — reputation score from 70+ engines (free: 4 requests/minute)
- WHOIS XML API — domain age, registrar, creation date (free tier: 1000 lookups/month)
- URLScan.io — screenshot + detailed scan (free tier)
- HTTP fetch — is the site currently up or down (built-in, no API needed)
- SSL check — does it have a valid HTTPS certificate (built-in via Node)

## Monetization

- Google AdSense: applied for on launch, passive baseline
- ExpressVPN affiliate: 35% recurring commission, 90-day cookie — shown when site is flagged risky
- NordVPN affiliate: 100% first month / 40% recurring — backup or complement to ExpressVPN
- Contextual placement: "This site looks risky. Protect yourself with [VPN]" only on bad results

## SEO Strategy

- Every URL checked gets a shareable result page at /check/[domain]
- These pages get indexed by Google
- People searching "is [domain] legit" find our result page directly
- Programmatic SEO at scale — more checks = more indexed pages = more organic traffic

## Current State (2026-08-20)

- Idea validated — market exists (ScamAdviser 6.5M users/month)
- Domain not yet purchased — building prototype first on Vercel subdomain
- Project directory created at D:/site-checker
