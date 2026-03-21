// scripts/seed-ml.ts
import { PrismaClient } from "@prisma/client";

// We initialize a fresh client here to ensure it runs 
// smoothly as a standalone script.
const prisma = new PrismaClient();

async function seedHistoricalData() {
  console.log("🚀 [XCELIT AI] Starting Historical Data Seeding...");

  // 1. Fetch all users currently in your database
  const users = await prisma.user.findMany();

  if (users.length === 0) {
    console.log("⚠️ No users found in the database. Please create a user first!");
    return;
  }

  const now = new Date();

  for (const user of users) {
    console.log(`📊 Generating 7-day baseline for: ${user.email}`);
    
    // 2. Loop back 7 days
    for (let i = 7; i >= 1; i--) {
      // Create a date for 'i' days ago
      const historicalDate = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      
      // LOGIC: Create "Normal" behavior
      // Low risk (5-15) and low activity (2-5 actions per day)
      // This tells the AI: "This is what a safe employee looks like."
      const baseRisk = Math.floor(Math.random() * 10) + 5;
      const baseActions = Math.floor(Math.random() * 3) + 2;

      await prisma.userSnapshot.create({
        data: {
          userId: user.id,
          riskScore: baseRisk,
          baseline: baseActions,
          createdAt: historicalDate,
          vectorData: { 
            hour: 10, 
            actions: baseActions, 
            status: "synthetic_baseline",
            isAnomaly: false 
          }
        }
      });
    }
  }

  console.log("✅ SUCCESS: 7-day history created for all users.");
  console.log("💡 Now, when you run an 'Audit' today, the AI will see a clear contrast!");
}

seedHistoricalData()
  .catch((e) => {
    console.error("❌ Seeding failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });