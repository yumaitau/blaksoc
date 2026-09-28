export function BrandMark({ className = "size-6" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <path d="M16 4.5l9.5 4.2v6.8c0 5.9-4 10.9-9.5 12-5.5-1.1-9.5-6.1-9.5-12V8.7L16 4.5z" fill="none" stroke="var(--color-accent)" strokeWidth="2.2" strokeLinejoin="round" />
      <circle cx="16" cy="15.5" r="3.2" fill="var(--color-accent)" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2">
      <BrandMark />
      <span className="text-[15px] font-semibold tracking-tight">
        blak<span className="text-accent">SOC</span>
      </span>
    </span>
  );
}
