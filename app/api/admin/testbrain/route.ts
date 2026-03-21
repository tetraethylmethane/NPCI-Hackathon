import { vectorizeUserBehavior } from "@/lib/analysis";
import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";

export async function GET() {
  try {
    // This manually runs the "Brain" for all users
    const users = await prisma.user.findMany();
    
    for (const user of users) {
      await vectorizeUserBehavior(user.id);
    }

    return NextResponse.json({ 
      status: "Success", 
      message: "Xcelit Brain is WORKING! Check your Database for Risk Scores." 
    });
  } catch (error) {
    return NextResponse.json({ status: "Error", error: String(error) }, { status: 500 });
  }
}