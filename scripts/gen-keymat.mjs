#!/usr/bin/env node
// Regenerate the embedded keymat for every language port from
// assets/*.bin:
//
//   src/keymat.ts                        (JS/TS package)
//   python/incy_link_encoder/_keymat.py  (Python port)
//   php/src/Keymat.php                   (PHP port)
//   go/keymat.go                         (Go port)
//
// Run this whenever the keymat asset bytes change — for example,
// when rotating to a new scheme (`crypt2/...`). Every distribution
// embeds these bytes as base64, so a stale keymat file means that
// port's output no longer matches what the iOS/Android/Desktop
// clients expect.
//
// Usage:
//   npm run gen-keymat
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const a = readFileSync(resolve(root, 'assets/incy_assets_a.bin')).toString('base64');
const b = readFileSync(resolve(root, 'assets/incy_assets_b.bin')).toString('base64');

const targets = [
  [
    'src/keymat.ts',
    `// Auto-generated from assets/*.bin. Run \`npm run gen-keymat\` to refresh.
// shellcheck disable=all
export const KEYMAT_A_B64 = '${a}';
export const KEYMAT_B_B64 = '${b}';
`,
  ],
  [
    'python/incy_link_encoder/_keymat.py',
    `# Auto-generated from assets/*.bin. Run \`npm run gen-keymat\` to refresh.
KEYMAT_A_B64 = "${a}"
KEYMAT_B_B64 = "${b}"
`,
  ],
  [
    'php/src/Keymat.php',
    `<?php

declare(strict_types=1);

namespace Incy\\LinkEncoder;

// Auto-generated from assets/*.bin. Run \`npm run gen-keymat\` to refresh.
final class Keymat
{
    public const KEYMAT_A_B64 = '${a}';
    public const KEYMAT_B_B64 = '${b}';
}
`,
  ],
  [
    'go/keymat.go',
    `package incylink

// Auto-generated from assets/*.bin. Run \`npm run gen-keymat\` to refresh.
const keymatAB64 = "${a}"
const keymatBB64 = "${b}"
`,
  ],
];

for (const [rel, content] of targets) {
  writeFileSync(resolve(root, rel), content);
  console.log(`wrote ${rel}`);
}
console.log(`keymat: ${a.length} + ${b.length} bytes base64`);
