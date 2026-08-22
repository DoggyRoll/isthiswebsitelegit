import type { MetadataRoute } from "next";
import { TOP_DOMAINS } from "./site/[domain]/page";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://isthiswebsitelegit.com";

  const home: MetadataRoute.Sitemap = [
    {
      url: base,
      lastModified: new Date(),
      changeFrequency: "weekly",
      priority: 1,
    },
  ];

  const sitePages: MetadataRoute.Sitemap = TOP_DOMAINS.map((domain) => ({
    url: `${base}/site/${domain}`,
    lastModified: new Date(),
    changeFrequency: "daily" as const,
    priority: 0.9,
  }));

  const checkPages: MetadataRoute.Sitemap = TOP_DOMAINS.map((domain) => ({
    url: `${base}/check/${domain}`,
    lastModified: new Date(),
    changeFrequency: "daily" as const,
    priority: 0.7,
  }));

  return [...home, ...sitePages, ...checkPages];
}
