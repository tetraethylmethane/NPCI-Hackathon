"use client";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Area, AreaChart
} from 'recharts';

export default function RiskTrendChart({ snapshots }: { snapshots: any[] }) {
  // Format and sort data (Oldest to Newest)
  const chartData = snapshots
    .map(s => ({
      date: new Date(s.createdAt).toLocaleTimeString('en-US', { hour: 'numeric', hour12: true }),
      score: s.riskScore,
      fullDate: new Date(s.createdAt).toLocaleString()
    }))
    .reverse();

  return (
    <div className="w-full h-[250px] bg-[#e8f1fb]/50 p-4 rounded-xl border border-[#003478]/10 mt-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-sm font-bold text-[#003478] uppercase tracking-wider">
          Behavioral Trend (Last 7 Days)
        </h3>
        <span className="text-[10px] bg-[#f7941d]/10 text-[#f7941d] px-2 py-1 rounded-full font-bold border border-[#f7941d]/20">
          NPCI AI INSIGHTS ACTIVE
        </span>
      </div>

      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData}>
          <defs>
            <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#003478" stopOpacity={0.25}/>
              <stop offset="95%" stopColor="#003478" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#003478" strokeOpacity={0.08} />
          <XAxis
            dataKey="date"
            fontSize={10}
            tickLine={false}
            axisLine={false}
            tick={{ fill: '#0066b3', opacity: 0.7 }}
          />
          <YAxis
            fontSize={10}
            tickLine={false}
            axisLine={false}
            domain={[0, 100]}
            tick={{ fill: '#0066b3', opacity: 0.7 }}
          />
          <Tooltip
            contentStyle={{
              borderRadius: '10px',
              border: '1px solid #003478',
              borderOpacity: 0.15,
              boxShadow: '0 10px 15px -3px rgba(0,52,120,0.1)',
              backgroundColor: '#fff',
              color: '#003478',
              fontSize: '12px',
            }}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="#003478"
            strokeWidth={2.5}
            fillOpacity={1}
            fill="url(#colorScore)"
            dot={{ fill: '#f7941d', strokeWidth: 0, r: 3 }}
            activeDot={{ fill: '#f7941d', stroke: '#003478', strokeWidth: 2, r: 5 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
