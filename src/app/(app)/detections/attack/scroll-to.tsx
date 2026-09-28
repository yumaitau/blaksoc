"use client";
import { useEffect } from "react";

/** Scrolls the highlighted technique into view in both axes (the matrix scrolls horizontally). */
export function ScrollTo({ id }: { id: string }) {
  useEffect(() => {
    document.getElementById(id)?.scrollIntoView({ block: "center", inline: "center" });
  }, [id]);
  return null;
}
