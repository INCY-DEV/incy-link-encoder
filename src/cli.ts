#!/usr/bin/env node
// @incy/link-encoder CLI — encode/decode incy://crypt1/ links from
// the terminal. Thin wrapper over the Node entry; no extra deps.
//
//   npx @incy/link-encoder --url https://sub.example/token --name "My VPN"
//   npx @incy/link-encoder --decode incy://crypt1/AAEC...
//   echo "https://sub.example/token" | npx @incy/link-encoder

import { encryptLink, decryptLink, VERSION, KEY_FINGERPRINT } from './index.js';

const HELP = `@incy/link-encoder v${VERSION}

Encode subscription URLs into incy://crypt1/<payload> deep links.

Usage:
  incy-link-encoder --url <url> [--name <name>]   Encrypt a URL to a link
  incy-link-encoder --decode <link>               Decrypt a link back to its URL
  incy-link-encoder <url>                          Shorthand for --url <url>
  echo <url> | incy-link-encoder                   Read the URL/link from stdin

Options:
  -u, --url <url>      Subscription URL to encrypt (http/https)
  -n, --name <name>    Optional display name (max 128 chars)
  -d, --decode <link>  Decrypt an incy://crypt1/... link instead
      --json           Print machine-readable JSON
  -h, --help           Show this help
  -v, --version        Print version and key fingerprint

This is obfuscation, not secrecy — the key is public. See the README.`;

interface Args {
  url?: string;
  name?: string;
  decode?: string;
  json: boolean;
  help: boolean;
  version: boolean;
  positional: string[];
}

function parseArgs(argv: string[]): Args {
  const args: Args = { json: false, help: false, version: false, positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-u':
      case '--url':
        args.url = argv[++i];
        break;
      case '-n':
      case '--name':
        args.name = argv[++i];
        break;
      case '-d':
      case '--decode':
        args.decode = argv[++i];
        break;
      case '--json':
        args.json = true;
        break;
      case '-h':
      case '--help':
        args.help = true;
        break;
      case '-v':
      case '--version':
        args.version = true;
        break;
      default:
        if (a.startsWith('-')) {
          throw new Error(`unknown option: ${a}`);
        }
        args.positional.push(a);
    }
  }
  return args;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data.trim()));
  });
}

function fail(msg: string): never {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  let args: Args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    fail((e as Error).message);
  }

  if (args.help) {
    process.stdout.write(HELP + '\n');
    return;
  }
  if (args.version) {
    process.stdout.write(`@incy/link-encoder v${VERSION}\nK1 fingerprint: ${KEY_FINGERPRINT}\n`);
    return;
  }

  // Resolve the operand: explicit flag, positional, or stdin.
  let input = args.decode ?? args.url ?? args.positional[0];
  if (input === undefined && !process.stdin.isTTY) {
    input = await readStdin();
  }
  if (!input) {
    fail('no input — pass a URL, --decode <link>, or pipe via stdin (see --help)');
  }

  // Decode mode is chosen by --decode or by an input that already
  // looks like a link.
  const isDecode = args.decode !== undefined || input.startsWith('incy://');

  try {
    if (isDecode) {
      const decoded = decryptLink(input);
      if (args.json) {
        process.stdout.write(JSON.stringify(decoded) + '\n');
      } else {
        process.stdout.write(decoded.url + '\n');
        if (decoded.name) process.stderr.write(`name: ${decoded.name}\n`);
      }
    } else {
      const link = encryptLink(input, args.name ? { name: args.name } : {});
      if (args.json) {
        process.stdout.write(JSON.stringify({ link }) + '\n');
      } else {
        process.stdout.write(link + '\n');
      }
    }
  } catch (e) {
    fail((e as Error).message);
  }
}

main();
