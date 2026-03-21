import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { vectorizeUserBehavior } from "@/lib/analysis";

export async function POST() {
  console.log("⚡ Manual Audit Triggered via Dashboard...");
  
  try {
    const users = await prisma.user.findMany({ select: { id: true } });

    for (const user of users) {
      await vectorizeUserBehavior(user.id);
    }

    return NextResponse.json({ success: true, message: "Audit Complete" });
  } catch (error) {
    return NextResponse.json({ success: false, error: "Audit Failed" }, { status: 500 });
  }
}