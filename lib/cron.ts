import cron from "node-cron";
import { prisma } from "./prisma";
import { vectorizeUserBehavior } from "./analysis";

export function initSecurityCron() {
  // Runs every day at midnight (00:00)
  cron.schedule("0 0 * * *", async () => {
    console.log("⚡ Xcelit Security: Starting Nightly Behavioral Baselining...");
    
    const users = await prisma.user.findMany({
      select: { id: true }
    });

    for (const user of users) {
      try {
        await vectorizeUserBehavior(user.id);
      } catch (err) {
        console.error(`Failed to analyze user ${user.id}:`, err);
      }
    }
  });
}