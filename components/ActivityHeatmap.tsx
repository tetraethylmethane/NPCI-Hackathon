"use client";

/**
 * ActivityHeatmap
 * ===============
 * Renders a 24-column (hour 0–23) × 7-row (Mon–Sun) grid.
 * Cell colour is proportional to the number of events in that slot.
 * Accepts an array of { createdAt: string } records and computes
 * the matrix client-side — no server round-trip required.
 */

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

// Color scale: empty → light → NPCI navy
function cellColor(count: number, max: number): string {
  if (count === 0 || max === 0) return "#f0f4fa";
  const ratio = count / max;
  if (ratio < 0.2) return "#dce8f7";
  if (ratio < 0.4) return "#a8c8ed";
  if (ratio < 0.6) return "#6baed6";
  if (ratio < 0.8) return "#2171b5";
  return "#003478";
}

function textColor(count: number, max: number): string {
  if (max === 0) return "transparent";
  return count / max >= 0.6 ? "#fff" : "transparent";
}

interface Props {
  logs: { createdAt: string; action?: string }[];
}

export default function ActivityHeatmap({ logs }: Props) {
  // Build 7×24 matrix  (day index 0=Mon, hour 0–23)
  const matrix: number[][] = Array.from({ length: 7 }, () =>
    new Array(24).fill(0),
  );

  for (const log of logs) {
    const d = new Date(log.createdAt);
    const dow = (d.getDay() + 6) % 7; // JS: 0=Sun → 0=Mon
    const hour = d.getHours();
    matrix[dow][hour]++;
  }

  const max = Math.max(...matrix.flat(), 1);

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-2">
        <p className="text-[10px] font-bold text-[#003478]/50 uppercase tracking-widest">
          Activity Heatmap (hour × weekday)
        </p>
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] text-[#003478]/30">Low</span>
          {["#dce8f7", "#a8c8ed", "#6baed6", "#2171b5", "#003478"].map((c) => (
            <div
              key={c}
              className="w-3 h-3 rounded-sm"
              style={{ backgroundColor: c }}
            />
          ))}
          <span className="text-[9px] text-[#003478]/30">High</span>
        </div>
      </div>

      <div className="overflow-x-auto">
        <div
          className="grid gap-[2px]"
          style={{ gridTemplateColumns: `28px repeat(24, minmax(0, 1fr))` }}
        >
          {/* Hour labels row */}
          <div /> {/* empty corner */}
          {HOURS.map((h) => (
            <div
              key={h}
              className="text-center text-[8px] text-[#003478]/30 font-mono pb-1"
            >
              {h.toString().padStart(2, "0")}
            </div>
          ))}

          {/* Day rows */}
          {DAYS.map((day, di) => (
            <>
              <div
                key={`label-${day}`}
                className="flex items-center justify-end pr-1 text-[9px] text-[#003478]/40 font-semibold"
              >
                {day}
              </div>
              {HOURS.map((h) => {
                const count = matrix[di][h];
                const bg = cellColor(count, max);
                const fg = textColor(count, max);
                return (
                  <div
                    key={`${di}-${h}`}
                    title={`${day} ${h.toString().padStart(2, "0")}:00 — ${count} event${count !== 1 ? "s" : ""}`}
                    className="aspect-square rounded-sm flex items-center justify-center text-[7px] font-mono transition-opacity hover:opacity-80"
                    style={{ backgroundColor: bg, color: fg }}
                  >
                    {count > 0 ? count : ""}
                  </div>
                );
              })}
            </>
          ))}
        </div>
      </div>

      {logs.length === 0 && (
        <p className="text-center text-[11px] text-[#003478]/30 italic mt-2">
          No activity data for this user.
        </p>
      )}
    </div>
  );
}
