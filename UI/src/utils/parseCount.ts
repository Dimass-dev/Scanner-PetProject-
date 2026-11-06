// Keep the previous value when the input holds a partial or non-numeric string
// (Number('-') or Number('1e') is NaN, and NaN silently defeats range checks).
export function parseCount(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}
