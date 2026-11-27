import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const SERVICE = "passwd.team";
const TIMEOUT = 10_000;

type Backend = "security" | "secret-tool" | "dpapi" | "none";
let _backend: Backend | null = null; // null = not yet checked

function run(cmd: string, args: string[], stdin?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile(cmd, args, { timeout: TIMEOUT }, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
    if (stdin !== undefined && child.stdin) {
      child.stdin.end(stdin);
    }
  });
}

async function detectBackend(): Promise<Backend> {
  if (_backend !== null) return _backend;

  if (process.platform === "darwin") {
    try {
      await run("security", ["default-keychain"]);
      _backend = "security";
    } catch {
      _backend = "none";
    }
  } else if (process.platform === "linux") {
    try {
      await run("which", ["secret-tool"]);
      _backend = "secret-tool";
    } catch {
      _backend = "none";
    }
  } else if (process.platform === "win32") {
    try {
      await run(POWERSHELL, [...PS_ARGS, `${DPAPI_LOAD}; [void][Security.Cryptography.ProtectedData]`]);
      _backend = "dpapi";
    } catch {
      _backend = "none";
    }
  } else {
    _backend = "none";
  }

  return _backend;
}

// Windows has no keychain CLI like `security` or `secret-tool`. The value is
// protected with DPAPI for the current user (Windows PowerShell 5.1, present on
// every supported Windows) and the encrypted blob is kept in a file only that
// user can decrypt. Value and blob travel over stdin, never in argv.
const POWERSHELL = "powershell.exe";
const PS_ARGS = ["-NoProfile", "-NonInteractive", "-Command"];
const DPAPI_LOAD = "Add-Type -AssemblyName System.Security";
const DPAPI_PROTECT =
  `${DPAPI_LOAD}; $v = [Console]::In.ReadToEnd(); ` +
  "[Console]::Out.Write([Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect(" +
  "[Text.Encoding]::UTF8.GetBytes($v), $null, 'CurrentUser')))";
const DPAPI_UNPROTECT =
  `${DPAPI_LOAD}; $b = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); ` +
  "[Console]::Out.Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect(" +
  "$b, $null, 'CurrentUser')))";

/** The file that holds the DPAPI blob of an account. */
export function dpapiFile(account: string, dir = join(homedir(), ".passwd", "keychain")): string {
  return join(dir, `${SERVICE}-${encodeURIComponent(account)}.dpapi`);
}

async function dpapiSave(file: string, value: string): Promise<void> {
  const blob = (await run(POWERSHELL, [...PS_ARGS, DPAPI_PROTECT], value)).trim();
  if (!blob) throw new Error("DPAPI returned no data");
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await writeFile(file, blob, { encoding: "utf-8", mode: 0o600 });
}

async function dpapiLoad(file: string): Promise<string | null> {
  let blob: string;
  try {
    blob = (await readFile(file, "utf-8")).trim();
  } catch {
    return null;
  }
  if (!blob) return null;
  return (await run(POWERSHELL, [...PS_ARGS, DPAPI_UNPROTECT], blob)).trim() || null;
}

/** Exported for tests: the DPAPI round trip on a given file. */
export const dpapi = { save: dpapiSave, load: dpapiLoad };

function securityQuote(arg: string): string {
  if (/[\r\n\0]/.test(arg)) {
    throw new Error("Keychain arguments must not contain line breaks or NUL characters");
  }
  return `"${arg.replace(/[\\"]/g, "\\$&")}"`;
}

/**
 * Build the `security -i` input line that stores a generic password. The
 * value travels over stdin instead of argv, so it never shows up in the
 * process list.
 */
export function securityAddCommand(service: string, account: string, value: string): string {
  const args = ["-s", service, "-a", account, "-w", value].map((a, i) =>
    i % 2 === 0 ? a : securityQuote(a),
  );
  return `add-generic-password ${args.join(" ")} -U\n`;
}

export async function isKeychainAvailable(): Promise<boolean> {
  return (await detectBackend()) !== "none";
}

export async function keychainSave(account: string, value: string): Promise<boolean> {
  const backend = await detectBackend();
  if (backend === "none") return false;
  try {
    if (backend === "security") {
      // `security -i` reads the command from stdin (no process list exposure)
      await run("security", ["-i"], securityAddCommand(SERVICE, account, value));
    } else if (backend === "dpapi") {
      await dpapiSave(dpapiFile(account), value);
    } else {
      // secret-tool reads the value from stdin (no process list exposure)
      await run("secret-tool", [
        "store",
        "--label", SERVICE,
        "service", SERVICE,
        "account", account,
      ], value);
    }
    return true;
  } catch {
    return false;
  }
}

export async function keychainLoad(account: string): Promise<string | null> {
  const backend = await detectBackend();
  if (backend === "none") return null;
  try {
    if (backend === "security") {
      const result = await run("security", [
        "find-generic-password",
        "-s", SERVICE,
        "-a", account,
        "-w",
      ]);
      return result.trim() || null;
    } else if (backend === "dpapi") {
      return await dpapiLoad(dpapiFile(account));
    } else {
      const result = await run("secret-tool", [
        "lookup",
        "service", SERVICE,
        "account", account,
      ]);
      return result.trim() || null;
    }
  } catch {
    return null;
  }
}

export function resetKeychainCache(): void {
  _backend = null;
}
