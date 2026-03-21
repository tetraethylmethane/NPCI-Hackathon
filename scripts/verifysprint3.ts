import { prisma } from "../lib/prisma";
import { vectorizeUserBehavior } from "../lib/analysis";

async function verify() {
  console.log("🔍 [XCELIT VERIFICATION] Starting Sprint 3 Test...");

  // 1. Find the Intern
  const intern = await prisma.user.findUnique({
    where: { email: 'intern_threat@xcelit.com' }
  });

  if (!intern) {
    console.error("❌ Could not find intern_threat@xcelit.com. Please check your DB.");
    return;
  }

  // 2. Find ANY existing project to satisfy the Foreign Key
  const existingProject = await prisma.project.findFirst();

  if (!existingProject) {
    console.error("❌ No projects found in DB. Please create one project first in the UI!");
    return;
  }

  // 3. Create a "Suspicious" Activity Log
  console.log(`🚩 Step 1: Creating a suspicious log for Project: ${existingProject.name}...`);
  await prisma.activityLog.create({
    data: {
      userId: intern.id,
      action: 'FILE_DELETED',
      description: 'Intern attempted to delete production backups',
      projectId: existingProject.id // Using a REAL project ID now
    }
  });

  // 4. Trigger the AI Brain
  console.log("🧠 Step 2: Triggering the AI Detection Engine...");
  await vectorizeUserBehavior(intern.id);

  // 5. Check the Results
  const updatedUser = await prisma.user.findUnique({
    where: { id: intern.id },
    select: { riskScore: true, isFlagged: true }
  });

  console.log("-----------------------------------------");
  console.log("📊 SPRINT 3 VERIFICATION RESULTS:");
  console.log(`- Final Risk Score: ${updatedUser?.riskScore}`);
  console.log(`- Anomaly Flagged: ${updatedUser?.isFlagged ? "✅ YES (System detected the spike)" : "❌ NO"}`);
  console.log("-----------------------------------------");
}

verify()
  .catch(console.error)
  .finally(() => prisma.$disconnect());