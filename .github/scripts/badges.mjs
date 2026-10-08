// Génère les fichiers lus par les badges du README (format « endpoint » de
// shields.io) à partir des résultats de tests et de couverture de la CI.
// Usage : node badges.mjs <dossier de sortie>
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const outputDir = process.argv[2];
mkdirSync(outputDir, { recursive: true });

function color(percent) {
  if (percent >= 80) return 'brightgreen';
  if (percent >= 70) return 'green';
  if (percent >= 60) return 'yellowgreen';
  if (percent >= 50) return 'yellow';
  return 'orange';
}

function write(name, label, message, badgeColor) {
  const badge = { schemaVersion: 1, label, message, color: badgeColor };
  writeFileSync(join(outputDir, `${name}.json`), JSON.stringify(badge));
  console.log(`${label} : ${message}`);
}

function coverage(name, label, percent) {
  if (!Number.isFinite(percent)) {
    throw new Error(`Couverture illisible pour ${label}`);
  }
  write(name, label, `${Math.round(percent)} %`, color(percent));
}

const ansi = /\u001b\[[0-9;]*m/g;
const log = (path) => readFileSync(path, 'utf8').replace(ansi, '');

// Couverture des lignes.
const frontend = JSON.parse(readFileSync('frontend/coverage/frontend/coverage-summary.json', 'utf8'));
coverage('coverage-frontend', 'couverture Angular', frontend.total.lines.pct);

const backend = JSON.parse(readFileSync('backend-coverage.json', 'utf8'));
coverage('coverage-backend', 'couverture Rust', backend.data[0].totals.lines.percent);

// Nombre de tests réussis, lu dans la sortie des deux lanceurs.
const frontendTests = Number(log('frontend-tests.log').match(/Tests\s+(\d+) passed/)?.[1]);
const backendTests = [...log('backend-tests.log').matchAll(/test result: ok\. (\d+) passed/g)]
  .reduce((sum, match) => sum + Number(match[1]), 0);
if (!frontendTests || !backendTests) {
  throw new Error('Nombre de tests illisible');
}
write('tests', 'tests', `${frontendTests + backendTests} réussis`, 'brightgreen');
