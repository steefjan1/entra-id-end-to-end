/**
 * Which control reaches which surface.
 *
 * This is the "which slice never gets the same rigor" answer in table form. It
 * is static: no tenant is queried, nothing is inferred from your configuration.
 * That is deliberate. The reach of a control is a property of the protocol, not
 * of your tenant, and pretending to measure it would be worse than stating it.
 *
 * Everything follows from one sentence: Conditional Access is a token issuance
 * time control. Where Microsoft Entra ID issues no token, no policy runs. Rows
 * that say "no" are not gaps in your configuration, they are the shape of the
 * protocol, and the only fixes are to put an Entra decision point in the path
 * (Application Proxy, Private Access) or to move the workload.
 *
 * The matrix lives in config/coverage.json so you can adapt it. Add your own
 * surfaces, add rows for the controls your auditor asks about, and keep it next
 * to the code rather than in a slide nobody can diff.
 *
 *   npm run coverage
 *   npm run coverage -- --notes
 *   npm run coverage -- --surface kerberos
 *   npm run coverage -- --control conditionalAccess
 *   npm run coverage -- --json
 *
 * https://learn.microsoft.com/entra/global-secure-access/how-to-configure-domain-controllers
 * https://learn.microsoft.com/entra/identity/app-proxy/concept-continuous-access-evaluation
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { printTable } from '../../../shared/js/graph.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const configFile = process.env.COVERAGE_FILE || join(here, '..', 'config', 'coverage.json');

const { values: args } = parseArgs({
  options: {
    surface: { type: 'string' },
    control: { type: 'string' },
    notes: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (args.help) {
  console.log(
    'Usage: node src/control-coverage.mjs [options]\n' +
      '\n' +
      '  --surface <key>  show one surface only, with every note in full.\n' +
      '  --control <key>  show one control only, across every surface.\n' +
      '  --notes          print the note for every cell, not just the grid.\n' +
      '  --json           emit the matrix as JSON.\n' +
      '\n' +
      'The matrix is read from config/coverage.json. Override the path with\n' +
      'COVERAGE_FILE. No tenant is contacted.\n',
  );
  process.exit(0);
}

let config;
try {
  config = JSON.parse(await readFile(configFile, 'utf8'));
} catch (error) {
  console.error(`Could not read ${configFile}: ${error.message}`);
  process.exit(1);
}

const surfaces = config.surfaces || [];
const controls = config.controls || [];
const matrix = config.matrix || {};

const selectedSurfaces = args.surface
  ? surfaces.filter((surface) => surface.key === args.surface.toLowerCase())
  : surfaces;
const selectedControls = args.control
  ? controls.filter((control) => control.key.toLowerCase() === args.control.toLowerCase())
  : controls;

if (selectedSurfaces.length === 0) {
  console.error(`No surface matched "${args.surface}". Known: ${surfaces.map((s) => s.key).join(', ')}`);
  process.exit(1);
}
if (selectedControls.length === 0) {
  console.error(`No control matched "${args.control}". Known: ${controls.map((c) => c.key).join(', ')}`);
  process.exit(1);
}

if (args.json) {
  console.log(
    JSON.stringify(
      {
        title: config.title,
        lastReviewed: config.lastReviewed,
        surfaces: selectedSurfaces,
        controls: selectedControls,
        matrix: Object.fromEntries(
          selectedControls.map((control) => [
            control.key,
            Object.fromEntries(
              selectedSurfaces.map((surface) => [surface.key, cell(control.key, surface.key)]),
            ),
          ]),
        ),
        footnotes: config.footnotes || [],
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

console.log(`${config.title || 'Control coverage'}\n`);
if (config.subtitle) console.log(`${config.subtitle}\n`);

console.log('Surfaces\n');
selectedSurfaces.forEach((surface) => {
  console.log(`  ${surface.column.padEnd(12)}${surface.label}`);
  wrap(surface.description, 74).forEach((line) => console.log(`              ${line}`));
  console.log('');
});

console.log('Matrix\n');
printTable(
  selectedControls.map((control) => {
    const row = { control: control.label };
    selectedSurfaces.forEach((surface) => {
      row[surface.column] = cell(control.key, surface.key).value;
    });
    return row;
  }),
  ['control', ...selectedSurfaces.map((surface) => surface.column)],
);

console.log(
  '\n  yes          the control applies to this surface as a matter of course\n' +
    '  conditional  it applies, but only with a specific configuration, licence or\n' +
    '               client. Read the note. This is where audits go wrong.\n' +
    '  no           the control does not reach this surface at all\n',
);

const wantNotes = args.notes || Boolean(args.surface) || Boolean(args.control);

if (wantNotes) {
  console.log('Notes\n');
  selectedControls.forEach((control) => {
    console.log(`${control.label}`);
    if (control.summary) {
      wrap(control.summary, 76).forEach((line) => console.log(`  ${line}`));
    }
    selectedSurfaces.forEach((surface) => {
      const entry = cell(control.key, surface.key);
      console.log(`  ${entry.value.toUpperCase().padEnd(12)}${surface.column}`);
      wrap(entry.note, 70).forEach((line) => console.log(`              ${line}`));
    });
    console.log('');
  });
} else {
  console.log('Run with --notes for the one line reason behind every cell.\n');
}

if ((config.footnotes || []).length > 0) {
  console.log('Footnotes\n');
  config.footnotes.forEach((note, index) => {
    const lines = wrap(note, 76);
    console.log(`  ${index + 1}. ${lines[0]}`);
    lines.slice(1).forEach((line) => console.log(`     ${line}`));
    console.log('');
  });
}

const noCells = selectedControls.flatMap((control) =>
  selectedSurfaces
    .filter((surface) => cell(control.key, surface.key).value === 'no')
    .map((surface) => `${control.label} on ${surface.label}`),
);

console.log(
  `${noCells.length} cell(s) in this view say no outright. Every one of them is a place\n` +
    'where a control your security review believes is universal simply is not present.\n' +
    'The honest move is not to argue about it, it is to write down which applications\n' +
    'sit on those surfaces and how many people reach them.\n' +
    `\nMatrix last reviewed ${config.lastReviewed || 'unknown'}. ` +
    'It is a text file. Keep it current.\n',
);

function cell(controlKey, surfaceKey) {
  const entry = matrix[controlKey]?.[surfaceKey];
  if (!entry) return { value: 'unknown', note: 'not defined in config/coverage.json' };
  return entry;
}

function wrap(text, width) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  if (words.length === 0) return [''];
  const lines = [];
  let line = '';
  for (const word of words) {
    if (line.length === 0) line = word;
    else if (line.length + 1 + word.length <= width) line += ` ${word}`;
    else {
      lines.push(line);
      line = word;
    }
  }
  lines.push(line);
  return lines;
}
