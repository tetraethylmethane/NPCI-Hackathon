import { prisma } from "./prisma";
import { ActivityType } from "@prisma/client";

async function simulate() {
  console.log("💎 XCELIT INVESTOR DEMO: Generating Security Story...");

  // 1. Create the Lead Admin (Panchi) FIRST
  const panchi = await prisma.user.upsert({
    where: { email: "panchi@xcelit.com" },
    update: { name: "Panchi (Lead Admin)", riskScore: 15 },
    create: { 
      email: "panchi@xcelit.com", 
      name: "Panchi (Lead Admin)", 
      riskScore: 15 
    },
  });

  // 2. Create the Project OWNED by Panchi
  const project = await prisma.project.upsert({
    where: { id: "investor-demo-project" },
    update: { userId: panchi.id },
    create: {
      id: "investor-demo-project",
      name: "Xcelit AI Engine",
      githubUrl: "https://github.com/xcelit/engine",
      userId: panchi.id, // Now using a real, existing ID!
    },
  });

  // 3. Create the Intern (The Threat)
  const intern = await prisma.user.upsert({
    where: { email: "intern_threat@xcelit.com" },
    update: { name: "Temporary Intern", riskScore: 92 },
    create: { 
      email: "intern_threat@xcelit.com", 
      name: "Temporary Intern", 
      riskScore: 92 
    },
  });

  // 4. Add the "Evidence" logs for the Intern
  const internActions = [
    { type: ActivityType.FILE_DELETED, desc: "Deleted 'database_backup_march.sql'" },
    { type: ActivityType.FILE_DELETED, desc: "Deleted 'security_protocols.pdf'" },
    { type: ActivityType.MEMBER_LEFT, desc: "Revoked own access and left project" }
  ];

  for (const act of internActions) {
    await prisma.activityLog.create({
      data: {
        action: act.type,
        description: act.desc,
        userId: intern.id,
        projectId: project.id,
      }
    });
  }

  console.log("✅ DATA READY: Neon tables are now populated with a Security Story.");
}

simulate().catch(console.error);