"use client";
import "./globals.css";
import { type BoundaryError, ErrorPanel } from "@/components/soc/error-panel";

/** Replaces the root layout when it fails, so it brings its own document, styles and theme. */
export default function GlobalError({ error, retry }: { error: BoundaryError; retry: () => void }) {
  return (
    <html lang="en-AU" data-theme="dark">
      <body className="min-h-screen px-4 antialiased">
        <title>Something went wrong · blakSOC</title>
        <ErrorPanel error={error} retry={retry} />
      </body>
    </html>
  );
}
