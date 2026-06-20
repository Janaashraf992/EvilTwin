const CAIRO_TZ = "Africa/Cairo";

const TIME_OPTS: Intl.DateTimeFormatOptions = {
  timeZone: CAIRO_TZ,
  hour12: false,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
};

const DATETIME_OPTS: Intl.DateTimeFormatOptions = {
  timeZone: CAIRO_TZ,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
};

const DATE_OPTS: Intl.DateTimeFormatOptions = {
  timeZone: CAIRO_TZ,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
};

const TZ_OFFSET_RE = /[+-]\d{2}:\d{2}$/;

function parseAsCairo(input: string | Date): Date {
  if (input instanceof Date) return input;
  if (input.endsWith("Z") || TZ_OFFSET_RE.test(input)) {
    return new Date(input);
  }
  return new Date(input + "+02:00");
}

export function formatTime(input: string | Date): string {
  return new Intl.DateTimeFormat("en-US", TIME_OPTS).format(parseAsCairo(input));
}

export function formatDateTime(input: string | Date): string {
  return new Intl.DateTimeFormat("en-US", DATETIME_OPTS).format(parseAsCairo(input));
}

export function formatDate(input: string | Date): string {
  return new Intl.DateTimeFormat("en-US", DATE_OPTS).format(parseAsCairo(input));
}

export function getRelativeTime(input: string | Date): string {
  const parsed = parseAsCairo(input);
  const diffInSeconds = Math.floor((Date.now() - parsed.getTime()) / 1000);
  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours < 24) return `${diffInHours}h ago`;
  return formatDate(input);
}
