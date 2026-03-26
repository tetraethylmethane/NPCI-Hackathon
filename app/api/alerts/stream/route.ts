/**
 * GET /api/alerts/stream
 * =======================
 * Server-Sent Events endpoint. Listens on the Postgres pg_notify channel
 * 'new_alert' (fired by the Kafka alert consumer) and streams alert payloads
 * to connected dashboard clients.
 *
 * The client receives events in the format:
 *   data: {"alertId":"...","userId":"...","severity":"CRITICAL",...}\n\n
 *
 * Connection lifecycle:
 *   - On connect: send a heartbeat every 25s to keep the connection alive
 *     through Vercel's 30s serverless timeout.
 *   - On disconnect (req.signal abort): unlisten + close the pg client.
 */

import { Client } from "pg";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const client = new Client({ connectionString: process.env.DATABASE_URL });

      const send = (data: string) => {
        controller.enqueue(encoder.encode(`data: ${data}\n\n`));
      };

      try {
        await client.connect();
        await client.query("LISTEN new_alert");

        // Heartbeat to prevent Vercel / proxy timeouts
        const heartbeat = setInterval(() => {
          try {
            controller.enqueue(encoder.encode(": heartbeat\n\n"));
          } catch {
            clearInterval(heartbeat);
          }
        }, 25_000);

        client.on("notification", (msg) => {
          if (msg.channel === "new_alert" && msg.payload) {
            send(msg.payload);
          }
        });

        // Clean up when the client disconnects
        req.signal.addEventListener("abort", async () => {
          clearInterval(heartbeat);
          try {
            await client.query("UNLISTEN new_alert");
            await client.end();
          } catch {}
          controller.close();
        });
      } catch (err) {
        console.error("[SSE] pg connection failed:", err);
        send(JSON.stringify({ error: "stream unavailable" }));
        controller.close();
        await client.end().catch(() => {});
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
