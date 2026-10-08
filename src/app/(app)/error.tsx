"use client";
import { type BoundaryError, ErrorPanel } from "@/components/soc/error-panel";

export default function AppError({ error, retry }: { error: BoundaryError; retry: () => void }) {
  return <ErrorPanel error={error} retry={retry} />;
}
