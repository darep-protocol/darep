import { z } from 'zod';

function formatter(zone) {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: zone, weekday: 'short', year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'shortOffset',
  });
}
export const timeZone = z.string().min(1).max(100).refine(value => {
  try { formatter(value); return true; } catch { return false; }
}, 'Expected a time zone, e.g. Europe/London');
export const displayZone = timeZone.optional().describe('Only set when the user explicitly requests this time zone. Otherwise use the owner’s saved preference.');

// These labels are local MCP presentation data. They never become part of a signed event or a grant.
export function withDisplayTimes(result, zone) {
  const format = formatter(zone);
  const label = value => format.format(new Date(value)) + ' [' + zone + ']';
  function display(record) {
    return { ...record, display: {
      timeZone: zone, originalStart: label(record.originalStart),
      slots: record.slots.map(label), selectedSlot: record.selectedSlot ? label(record.selectedSlot) : null,
    } };
  }
  if (result.occurrences) return { ...result, occurrences: result.occurrences.map(display) };
  if (result.threads) return { ...result, threads: result.threads.map(display) };
  return display(result);
}
