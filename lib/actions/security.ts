"use server";
import { prisma } from "../prisma";
import { revalidatePath } from "next/cache";

export async function handleSecurityAction(userId: string, actionType: "LOCK" | "UNLOCK") {
  const newStatus = actionType === "LOCK" ? "LOCKED" : "ACTIVE";
  const logAction = actionType === "LOCK" ? "ACCOUNT_LOCKOUT" : "ACCOUNT_RECOVERY";

  // 1. Update the User Status
  await prisma.user.update({
    where: { id: userId },
    data: { status: newStatus }
  });

  // 2. Find any existing project to satisfy the database requirement
  const anyProject = await prisma.project.findFirst();

  if (!anyProject) {
    console.error("No project found to attach the security log to.");
    return;
  }

  // 3. Create the Security Log connecting both User and Project
  await prisma.activityLog.create({
    data: {
      action: logAction as any,
      description: `Security Intervention: ${actionType} performed by system admin.`,
      user: {
        connect: { id: userId }
      },
      project: {
        connect: { id: anyProject.id }
      }
    }
  });

  revalidatePath("/(dashboard)");
}