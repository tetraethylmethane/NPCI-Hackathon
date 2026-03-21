import { prisma } from "@/lib/prisma";
import { z } from "zod";
import { NextResponse } from "next/server";

const logSchema = z.object({
  userId: z.string(),
  projectId: z.string(),
  action: z.enum(["PROJECT_CREATED", "FILE_UPLOADED", "FILE_DELETED", "MEMBER_JOINED"]),
  description: z.string(),
});

export async function POST(req: Request) {
  try {
    const data = logSchema.parse(await req.json());
    const log = await prisma.activityLog.create({ data });
    return NextResponse.json({ success: true, id: log.id }, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: "Invalid Data Format" }, { status: 400 });
  }
}