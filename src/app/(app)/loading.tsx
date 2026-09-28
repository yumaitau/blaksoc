export default function Loading() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-7 w-64 rounded bg-surface-2" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{Array.from({ length: 4 }, (_, i) => <div key={i} className="h-20 rounded-lg bg-surface" />)}</div>
      <div className="h-80 rounded-lg bg-surface" />
    </div>
  );
}
