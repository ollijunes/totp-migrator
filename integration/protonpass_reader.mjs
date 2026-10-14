// Replays the Proton Pass "Generic CSV" import on a file written by totp-migrator.
//
// Proton Pass (ProtonMail/WebClients, packages/pass/lib/import) reads the CSV
// with papaparse, then stores the `totp` column as `URI.parse(totp).toString()`
// from the `otpauth` package. This script does the same with the same packages
// and prints one JSON line per row: the stored URI's parameters and the code
// for the timestamp given in argv, so a Python driver can compare them with
// totp-migrator's own TOTP. Run by integration/protonpass_import.py.
//
//   node protonpass_reader.mjs <csv file> <unix seconds>

import { readFileSync } from "node:fs";
import Papa from "papaparse";
import { URI } from "otpauth";

const [, , csvPath, unixSeconds] = process.argv;
const timestamp = Number(unixSeconds) * 1000;

// Same parser options as Proton's readCSV helper.
const { data, errors } = Papa.parse(readFileSync(csvPath, "utf8"), {
  header: true,
  transformHeader: (h) => h.trim(),
  skipEmptyLines: true,
  delimiter: ",",
  newline: "\n",
  transform: (value) => value.replaceAll("\r", ""),
});
if (errors.length > 0) {
  console.error("papaparse:", errors);
  process.exit(1);
}

// Proton verifies these when the file is imported as a Proton Pass CSV.
const expectedHeaders = ["name", "url", "username", "password", "note", "totp"];
for (const row of data) {
  const missing = expectedHeaders.filter((h) => !(h in row));
  if (missing.length > 0) {
    console.error("missing headers:", missing);
    process.exit(1);
  }
  const stored = URI.parse(row.totp).toString(); // what Proton Pass keeps as totpUri
  const totp = URI.parse(stored);
  console.log(
    JSON.stringify({
      name: row.name,
      username: row.username,
      issuer: totp.issuer,
      label: totp.label,
      algorithm: totp.algorithm,
      digits: totp.digits,
      period: totp.period,
      code: totp.generate({ timestamp }),
    }),
  );
}
