import { prisma } from "./prisma";
import { zScore, mean, standardDeviation } from "simple-statistics";

export async function vectorizeUserBehavior(userId: string) {
  // 1. DATA INGESTION
  const history = await prisma.userSnapshot.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: 10
  });

  const logs = await prisma.activityLog.findMany({
    where: { userId, createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }
  });

  if (logs.length === 0) return;

  // 2. FEATURE EXTRACTION
  const currentRisk = (logs.length * 1) + (logs.filter(l => l.action.includes("DELETE")).length * 25);
  
  // Initialize these so they are accessible outside the IF block
  let finalScoreZ = 0;
  let isAnomaly = false;

  // 3. ML MODEL CALCULATION
  if (history.length >= 3) {
    const historicalScores = history.map(h => h.riskScore);
    
    const avgScore = mean(historicalScores);
    const stdDev = standardDeviation(historicalScores);

    // Calculate and assign to our higher-scope variable
    finalScoreZ = zScore(currentRisk, avgScore, stdDev);
    isAnomaly = finalScoreZ > 2.0;

    // 4. UPDATE DASHBOARD
    await prisma.user.update({
      where: { id: userId },
      data: {
        riskScore: Math.round(currentRisk),
        isFlagged: isAnomaly,
        lastAnalyzed: new Date()
      }
    });

    console.log(`🤖 [ML ENGINE] Z-Score: ${finalScoreZ.toFixed(2)} | Outlier: ${isAnomaly}`);
  }

  // 5. SAVE SNAPSHOT (Using finalScoreZ which is now defined)
  await prisma.userSnapshot.create({
    data: {
      userId: userId,
      riskScore: Math.round(currentRisk),
      baseline: logs.length,
      vectorData: {
        mlModel: "Z-Score Analysis",
        zScore: finalScoreZ.toFixed(2),
        isAnomaly: isAnomaly,
        timestamp: new Date().toISOString()
      }
    }
  });
}