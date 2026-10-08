import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { connection } from "next/server";
import { Toaster } from "sonner";
import "./globals.css";

// Self-hosted at build time: no runtime requests to third-party font CDNs (sovereign deployments).
const inter = Inter({ subsets: ["latin"], variable: "--font-inter", preload: false });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains", preload: false });

export const metadata: Metadata = {
  title: { default: "blakSOC", template: "%s · blakSOC" },
  description: "Sovereign-capable, multi-tenant Security Operations Centre by Yuma IT.",
  robots: { index: false, follow: false },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Every page renders per request so Next.js can stamp the CSP nonce from src/proxy.ts on its scripts.
  await connection();
  return (
    <html lang="en-AU" data-theme="dark" className={`${inter.variable} ${mono.variable}`}>
      <body className="min-h-screen antialiased">
        {children}
        {/* One toast region for the whole app; its colours come from the design tokens in globals.css. */}
        <Toaster position="bottom-right" theme="dark" richColors closeButton containerAriaLabel="Notifications" />
      </body>
    </html>
  );
}
