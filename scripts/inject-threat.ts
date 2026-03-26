/**
 * scripts/inject-threat.ts
 * =========================
 * Injects a synthetic insider-threat burst for demo purposes.
 *
 * Sends 50 FILE_COPY events in rapid succession for a target user
 * (default: first flagged user, or ACM2278 if found).
 * This spikes the file_access_volume feature far beyond the 30-day baseline
 * and should produce a CRITICAL alert within seconds.
 *
 * Usage:
 *   DATABASE_URL="..." KAFKA_BOOTSTRAP_SERVERS="..." \
 *   KAFKA_API_KEY="..." KAFKA_API_SECRET="..." \
 *   npx ts-node scripts/inject-threat.ts [--user ACM2278] [--events 50]
 */

import { Kafka, Partitioners } from "kafkajs";
import { PrismaClient } from "@prisma/client";
import { parseArgs } from "util";

const prisma = new PrismaClient();

const { values: args } = parseArgs({
  options: {
    user:   { type: "string", default: "" },
    events: { type: "string", default: "50" },
  },
});

const EVENT_COUNT = parseInt(args.events as string, 10);
const RAW_TOPIC   = process.env.KAFKA_RAW_LOGS_TOPIC ?? "xcelit.raw-logs";

async function resolveTargetUser(hint: string): Promise<string> {
  if (hint) return hint;
  // Try to find ACM2278 (canonical CERT insider)
  const acm = await prisma.user.findFirst({ where: { email: { contains: "ACM2278" } } });
  if (acm) return acm.id;
  // Fall back to highest-risk flagged user
  const flagged = await prisma.user.findFirst({
    where: { isFlagged: true },
    orderBy: { riskScore: "desc" },
  });
  if (flagged) return flagged.id;
  // Fall back to any user
  const any = await prisma.user.findFirst({ orderBy: { createdAt: "asc" } });
  if (any) return any.id;
  throw new Error("No users found in database. Run the ETL seed first.");
}

async function main() {
  const targetUserId = await resolveTargetUser(args.user as string);
  console.log(`Injecting ${EVENT_COUNT} FILE_COPY events for user: ${targetUserId}`);

  const kafka = new Kafka({
    clientId: "threat-injector",
    brokers: [process.env.KAFKA_BOOTSTRAP_SERVERS!],
    ssl: true,
    sasl: {
      mechanism: "plain",
      username: process.env.KAFKA_API_KEY!,
      password: process.env.KAFKA_API_SECRET!,
    },
  });

  const producer = kafka.producer({ createPartitioner: Partitioners.DefaultPartitioner });
  await producer.connect();

  const now = new Date();
  const messages = Array.from({ length: EVENT_COUNT }, (_, i) => {
    const ts = new Date(now.getTime() - (EVENT_COUNT - i) * 3600); // 1 event every 3.6s
    return {
      key: targetUserId,
      value: JSON.stringify({
        event_id: `threat-inject-${Date.now()}-${i}`,
        user_id:  targetUserId,
        pc:       "PC-THREAT-001",
        timestamp: ts.toISOString(),
        source:   "file",
        action_type: "Copy",
        metadata: {
          filename: `/sensitive/payroll/q4_salaries_${i}.xlsx`,
          to_device: "USB_DRIVE",
        },
      }),
    };
  });

  await producer.send({ topic: RAW_TOPIC, messages });
  await producer.disconnect();

  console.log(`✓ ${EVENT_COUNT} events sent to ${RAW_TOPIC}`);
  console.log(`  Watch the dashboard for a CRITICAL alert for user: ${targetUserId}`);
  await prisma.$disconnect();
}

main().catch((e) => { console.error(e); process.exit(1); });
