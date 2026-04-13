import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import type { EventsBucket } from '../../lib/types';
import { format, parseISO } from 'date-fns';

interface EventsTimelineProps {
  data: EventsBucket[];
}

export default function EventsTimeline({ data }: EventsTimelineProps) {
  const formatted = data.map((d) => ({
    ...d,
    label: format(parseISO(d.time), 'HH:mm'),
  }));

  return (
    <ResponsiveContainer width="100%" height={250}>
      <LineChart data={formatted} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
        <XAxis dataKey="label" tick={{ fill: '#9CA3AF', fontSize: 11 }} />
        <YAxis tick={{ fill: '#9CA3AF', fontSize: 11 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }}
          labelStyle={{ color: '#F9FAFB' }}
        />
        <Legend />
        <Line type="monotone" dataKey="events" stroke="#3B82F6" strokeWidth={2} dot={false} name="Events" />
        <Line type="monotone" dataKey="threats" stroke="#F59E0B" strokeWidth={2} dot={false} name="Threats" />
        <Line type="monotone" dataKey="blocked" stroke="#EF4444" strokeWidth={2} dot={false} name="Blocked" />
      </LineChart>
    </ResponsiveContainer>
  );
}
