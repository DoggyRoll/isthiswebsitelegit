# Build Plan — Site Legitimacy Checker

## Architecture

Fully stateless Next.js app on Vercel. User submits a URL → Next.js API route fans out to 4-5 external APIs in parallel → results aggregated → rendered on a shareable result page.

No database. No auth. No queue. Just fast parallel API calls.

## Pages

### / (Home)
- Large URL input box, centered
- "Check this site" button
- Brief tagline: "Find out if any website is safe, legit, or a scam — instantly"
- No login, no signup, no extension

### /check/[domain] (Results page)
- Shows: Safety score (0-100), threat status, domain age, site status (up/down), SSL status, reputation from VirusTotal
- Color coded: green (safe), yellow (unknown), red (danger)
- If red or yellow: affiliate CTA — "Protect yourself with [ExpressVPN/NordVPN]"
- Google AdSense ad unit below the fold
- Shareable URL — this is the SEO landing page

## API Route: /api/check

Accepts: POST { url: string }
Returns: aggregated result object

Fans out in parallel to:
1. Google Safe Browsing — threatMatches array
2. VirusTotal — POST URL for analysis, GET report
3. WHOIS XML — domain creation date, registrar
4. HTTP fetch — status code, response time
5. SSL check — certificate validity via Node https module

Returns unified object:
{
  domain: string,
  safetyScore: number (0-100),
  isMalware: boolean,
  isPhishing: boolean,
  isUp: boolean,
  hasSSL: boolean,
  domainAgeDays: number,
  registrar: string,
  vtStats: { malicious, suspicious, clean },
  threats: string[]
}

## Safety Score Logic

Start at 100, subtract points:
- Google flags as malware: -60
- Google flags as phishing: -60
- VirusTotal 1+ malicious engines: -30
- VirusTotal 3+ malicious engines: -60
- Domain age under 30 days: -20
- Domain age under 7 days: -40
- No SSL: -15
- Site is down: -10
- No registrar info: -5

## Build Order

1. Next.js project scaffold with Tailwind
2. Home page with URL input form
3. /api/check route with parallel API calls (mock data first)
4. Results page UI — score, badges, details
5. Wire real API keys (Google Safe Browsing, VirusTotal, WHOIS)
6. Affiliate CTA component — shown conditionally on risky results
7. AdSense placeholder (apply for approval after launch)
8. SEO: meta tags, sitemap, robots.txt, structured data
9. Deploy to Vercel free subdomain
10. Test with 10 real URLs

## Environment Variables Needed

GOOGLE_SAFE_BROWSING_API_KEY — free via Google Cloud Console
VIRUSTOTAL_API_KEY — free at virustotal.com
WHOIS_XML_API_KEY — free at whoisxmlapi.com

## MVP Scope (What to Skip for Now)

- No user accounts
- No history / saved checks
- No browser extension
- No bulk URL checking
- No API access tier
