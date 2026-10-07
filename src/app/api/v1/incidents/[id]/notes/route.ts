import { idParam, json, serviceCall, shape } from "@/lib/api/http";
import { IncidentNote, NoteCreate } from "@/lib/api/schemas";
import { addNote } from "@/lib/services/incidents";

export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  return serviceCall(req, "/incidents/{id}/notes", async (ctx) => {
    const id = idParam((await params).id);
    const input = NoteCreate.parse(await req.json());
    const note = await addNote(ctx, id, input.body, input.visibility);
    return json(201, shape(IncidentNote, { ...note, authorName: null }));
  });
}
