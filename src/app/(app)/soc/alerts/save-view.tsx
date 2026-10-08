"use client";
import { Bookmark } from "lucide-react";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Label } from "@/components/ui/input";
import { saveAlertView } from "./actions";

export function SaveView({ filters }: { filters: Record<string, string> }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [shared, setShared] = useState(false);
  const { pending, error, run } = useAction();
  const empty = Object.keys(filters).length === 0;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="ghost" disabled={empty} title={empty ? "Apply a filter first" : undefined}>
          <Bookmark /> Save current view
        </Button>
      </DialogTrigger>
      <DialogContent title="Save queue view" description="Saves the current filters as a chip above the queue.">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => saveAlertView({ name, filters, shared }), () => {
              setOpen(false);
              setName("");
            }, { success: `View ${name.trim()} saved${shared ? " and shared with the SOC team" : ""}` });
          }}
        >
          <div>
            <Label htmlFor="view-name">Name</Label>
            <Input id="view-name" required maxLength={80} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Wattle high-risk identity" />
          </div>
          <div className="rounded-md border border-border bg-bg px-3 py-2 font-mono text-xs text-muted">
            {Object.entries(filters).map(([k, v]) => `${k}=${v}`).join("  ")}
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} className="accent-accent" />
            Share with the SOC team
          </label>
          <ActionError error={error} />
          <div className="flex justify-end">
            <Button type="submit" disabled={pending}>Save view</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
