export async function register() {
  // Move the log OUTSIDE the if-statement so it shows up no matter what
  console.log("------------------------------------------");
  console.log("🔍 XCELIT SYSTEM CHECK: Waking up the Brain...");
  console.log("------------------------------------------");

  if (process.env.NEXT_RUNTIME === "nodejs") {
    try {
      const { initSecurityCron } = await import("./lib/cron");
      if (initSecurityCron) {
        initSecurityCron();
        console.log("✅ SUCCESS: Behavioral Engine is LIVE");
      }
    } catch (error) {
      console.log("❌ CRITICAL ERROR: Brain failed to start", error);
    }
  }
}