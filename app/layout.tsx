import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Is This Site Legit? — Free Website Safety Checker",
  description:
    "Instantly check if any website is safe, legitimate, or a scam. No signup required. Powered by Google Safe Browsing and VirusTotal.",
  openGraph: {
    title: "Is This Site Legit? — Free Website Safety Checker",
    description:
      "Instantly check if any website is safe, legitimate, or a scam. No signup required. Powered by Google Safe Browsing and VirusTotal.",
  },
  verification: {
    google: "MzB7SexpKokxOBMQBW8iESdBxsxLGnG2cOl4ov37zTY",
  },
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔍</text></svg>",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <head>
        <script
          async
          src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-8236169200681018"
          crossOrigin="anonymous"
        />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
