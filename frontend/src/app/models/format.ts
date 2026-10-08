const UNITS = ['o', 'Ko', 'Mo', 'Go', 'To'];

// Volume lisible, au format français (« 61,8 Mo »).
export function formatBytes(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = unit === 0 ? 0 : 1;
  const text = value.toLocaleString('fr-FR', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
  return `${text} ${UNITS[unit]}`;
}
