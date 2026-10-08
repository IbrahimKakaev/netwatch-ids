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

const SPARK_BLOCKS = '▁▂▃▄▅▆▇█';

// Mini-graphique en caractères, à la manière des outils en terminal : chaque
// valeur devient un bloc dont la hauteur est proportionnelle au maximum.
export function sparkline(values: number[]): string {
  const max = Math.max(...values, 1);
  return values
    .map((value) => SPARK_BLOCKS[Math.min(SPARK_BLOCKS.length - 1, Math.floor((value / max) * SPARK_BLOCKS.length))])
    .join('');
}
