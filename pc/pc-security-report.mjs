#!/usr/bin/env node
// The nethersec PC scanner. The scheduled task runs this file; everything else is in
// pc-security-run.mjs (probes, glue, sending) and pc-security-lib.mjs (decisions).
// See docs/pc/README.md.
//
// Usage: node pc-security-report.mjs [--dry-run] [--ignore-grace] [--json] [--help]
//          [--dir <folder>] [--config <file>] [--watch <file>] [--state <file>]
//        node pc-security-report.mjs --new-key [--hub-url <url>] [--dm <Discord user ID>]
//        node pc-security-report.mjs --set-webhook   (reads the URL from stdin)

import { cli } from './pc-security-run.mjs'

cli(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code
  },
  (e) => {
    console.error(`pc-security-report crashed: ${e && e.stack ? e.stack : e}`)
    process.exitCode = 1
  },
)
