import type { MetadataRoute } from "next";

const HIGH_VALUE_DOMAINS = [
  "amazon.com",
  "ebay.com",
  "aliexpress.com",
  "temu.com",
  "shein.com",
  "wish.com",
  "etsy.com",
  "paypal.com",
  "cashapp.com",
  "venmo.com",
  "coinbase.com",
  "binance.com",
  "robinhood.com",
  "facebook.com",
  "instagram.com",
  "tiktok.com",
  "telegram.org",
  "discord.com",
  "reddit.com",
  "craigslist.org",
];

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://isthissitelegit.net";

  const home: MetadataRoute.Sitemap = [
    {
      url: base,
      lastModified: new Date(),
      changeFrequency: "weekly",
      priority: 1,
    },
  ];

  const domainPages: MetadataRoute.Sitemap = HIGH_VALUE_DOMAINS.map((domain) => ({
    url: `${base}/check/${domain}`,
    lastModified: new Date(),
    changeFrequency: "daily" as const,
    priority: 0.8,
  }));

  return [...home, ...domainPages];
}
