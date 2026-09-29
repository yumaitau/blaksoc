import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "blakSOC portal",
    short_name: "blakSOC",
    description: "Plain-language security updates for your organisation.",
    start_url: "/portal",
    scope: "/portal",
    display: "standalone",
    background_color: "#0d0f12",
    theme_color: "#0d0f12",
    lang: "en-AU",
    icons: [
      { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
  };
}
