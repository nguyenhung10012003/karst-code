/**
 * PowerShell, on Windows, beside Bash (which there is Git Bash): PowerShell for what Windows does
 * its own way, Bash for POSIX tools.
 *
 * Each command goes in a script file that a short bootstrap reads and runs as a script block.
 * Passed with -EncodedCommand instead, errors come back as CLIXML; run with -File, it can be
 * refused by an execution policy that Group Policy sets. A script block is subject to neither,
 * and the bootstrap holds nothing but a quoted path, so no quoting can go wrong.
 */
import { randomUUID } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import {
  BLOCKED_SLEEP_MESSAGE,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  MIN_BLOCKED_SLEEP_SECONDS,
  commandEnvironment,
  foregroundTimeout,
  runInForeground,
  startInBackground,
} from './bash.ts';
import type { ShellTarget } from './bash.ts';
import { withProcessGroup } from './tasks.ts';
import type { Tool, ToolContext } from './types.ts';

export interface PowerShellInstall {
  file: string;
  /** `pwsh` is PowerShell 7 or later; `powershell` is Windows PowerShell 5.1. */
  edition: 'pwsh' | 'powershell';
}

/** PowerShell 7 when it is installed, which has `&&` and UTF-8 by default, else Windows PowerShell. */
export function findPowerShell(env: NodeJS.ProcessEnv, exists: (path: string) => boolean = existsSync): PowerShellInstall | null {
  const path = (env.PATH ?? env.Path ?? '').split(';').filter(Boolean);
  const onPath = (name: string): string | undefined => path.map((dir) => win32.join(dir, name)).find(exists);
  const pwsh = onPath('pwsh.exe') ?? [env.ProgramFiles, env.ProgramW6432].filter(Boolean).map((base) => win32.join(base!, 'PowerShell', '7', 'pwsh.exe')).find(exists);
  if (pwsh) return { file: pwsh, edition: 'pwsh' };
  const system = env.SystemRoot ?? env.windir;
  const windows = (system ? [win32.join(system, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')] : []).find(exists) ?? onPath('powershell.exe');
  return windows ? { file: windows, edition: 'powershell' } : null;
}

let found: PowerShellInstall | null | undefined;

function powerShell(): PowerShellInstall | null {
  if (found === undefined) found = findPowerShell(process.env);
  return found;
}

function quote(text: string): string {
  return `'${text.replaceAll("'", "''")}'`;
}

/**
 * The script around a command. It removes its own file once read, makes output UTF-8, and exits
 * with the status of the command's last statement: a program's exit code, else 1 if it failed.
 * In the foreground it also records the directory it ended in, as Bash does.
 *
 * The command's output goes through Out-Default before the script exits: PowerShell holds
 * objects back for a moment to lay out a table, and `exit` would drop what it still holds.
 */
export function powerShellScript(command: string, scriptFile: string, cwdFile: string | null): string {
  return [
    `Remove-Item -LiteralPath ${quote(scriptFile)} -Force -ErrorAction SilentlyContinue`,
    "$ProgressPreference = 'SilentlyContinue'",
    'try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch {}',
    '$OutputEncoding = [System.Text.UTF8Encoding]::new($false)',
    '. {',
    command,
    '$global:__karst_ok = $?; $global:__karst_code = $global:LASTEXITCODE',
    '} | Out-Default',
    ...(cwdFile ? [`try { [System.IO.File]::WriteAllText(${quote(cwdFile)}, (Get-Location -PSProvider FileSystem).ProviderPath) } catch {}`] : []),
    'if ($global:__karst_ok) { exit 0 } elseif ($global:__karst_code) { exit $global:__karst_code } else { exit 1 }',
  ].join('\n');
}

function target(install: PowerShellInstall, scriptFile: string, ctx: ToolContext): ShellTarget {
  const bootstrap = `. ([ScriptBlock]::Create([System.IO.File]::ReadAllText(${quote(scriptFile)}, [System.Text.Encoding]::UTF8)))`;
  return {
    file: install.file,
    args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', bootstrap],
    env: withProcessGroup(commandEnvironment(ctx)),
  };
}

const SLEEP = /^\s*(?:start-sleep|sleep)\b/i;

/** A bare `Start-Sleep N` as the whole command, refused in the foreground as Bash refuses `sleep`. */
function blockedSleep(command: string): boolean {
  const match = /^\s*(?:start-sleep|sleep)\s+(?:-(s|seconds|m|milliseconds)\s+)?(\d+(?:\.\d+)?)\s*;?\s*$/i.exec(command);
  if (!match) return false;
  const unitMs = match[1]?.toLowerCase().startsWith('m') ? 1 : 1000;
  return Number(match[2]) * unitMs >= MIN_BLOCKED_SLEEP_SECONDS * 1000;
}

function description(): string {
  const install = powerShell();
  const which = install?.edition === 'pwsh' ? 'PowerShell 7' : 'Windows PowerShell 5.1';
  return `Executes a ${which} command on Windows and returns its output.

- Use this for what Windows does its own way: Windows paths, services, processes, the registry, \`.ps1\` scripts, and tools such as \`winget\` or \`dotnet\`. Use Bash for POSIX tools, shell scripts and git.
- Each call is a new session started with -NoProfile. \`cd\` (Set-Location) carries to the next call only in the main session, if the command succeeds and ends inside the working directories. Variables, functions and imported modules do not persist.${install?.edition === 'pwsh' ? '' : '\n- Windows PowerShell 5.1 has no `&&` or `||`: join commands with `;`, or check `$?` and `$LASTEXITCODE`.'}
- Nothing can answer a prompt: Read-Host, Get-Credential and confirmation prompts fail. Pass \`-Confirm:$false\` or \`-Force\` where a cmdlet would ask.
- Commands with literal arguments that only read, such as \`Get-ChildItem src -Recurse -Filter *.ts\`, can run without asking the user. Variables, \`$(...)\`, script blocks and redirection to a file always need approval.
- Avoid using this tool to read, search or edit files: Read, Grep, Glob and Edit do that better.
- Command output is displayed to you, not reliably to the user.
- \`timeout\` is in milliseconds: default ${DEFAULT_TIMEOUT_MS}, max ${MAX_TIMEOUT_MS} for a foreground command.
- \`run_in_background\` runs the command detached: it keeps running across turns and re-invokes you when it exits. You will be notified when it exits — do not poll its output file while waiting. Foreground \`Start-Sleep\` is blocked.`;
}

export const powerShellTool: Tool = {
  name: 'PowerShell',
  get description() {
    return description();
  },
  inputSchema: {
    type: 'object',
    properties: {
      command: { description: 'The PowerShell command to execute', type: 'string' },
      timeout: { description: `Optional timeout in milliseconds (max ${MAX_TIMEOUT_MS} for a foreground command)`, type: 'number' },
      description: {
        description: `Clear, concise description of what this command does in active voice, in 5-10 words for simple commands. Say what it does in plain words: do not echo the command's text, its flags, or file paths.
- Get-Service -Name w* → "List services whose names start with w"
- Get-ChildItem -Recurse -Filter *.log | Remove-Item → "Delete all .log files below this folder"`,
        type: 'string',
      },
      run_in_background: { description: 'Set to true to run this command in the background.', type: 'boolean' },
    },
    required: ['command'],
    additionalProperties: false,
  },
  isReadOnly: () => false,
  access: (input) => ({ kind: 'powershell', command: input.command as string }),
  async execute(input, ctx) {
    const install = powerShell();
    if (!install) return { content: 'PowerShell was not found: neither pwsh.exe nor powershell.exe is installed.', isError: true };
    const command = input.command as string;
    const descriptionText = input.description as string | undefined;
    const requested = input.timeout as number | undefined;
    const scriptFile = join(tmpdir(), `karst-ps-${randomUUID()}.ps1`);

    if (input.run_in_background === true) {
      writeFileSync(scriptFile, powerShellScript(command, scriptFile, null), { mode: 0o600 });
      const result = startInBackground(command, target(install, scriptFile, ctx), requested, descriptionText, ctx);
      if (result.isError) rmSync(scriptFile, { force: true });
      return result;
    }
    if (blockedSleep(command)) return { content: BLOCKED_SLEEP_MESSAGE, isError: true };
    const cwdFile = join(tmpdir(), `karst-cwd-${randomUUID()}`);
    writeFileSync(scriptFile, powerShellScript(command, scriptFile, cwdFile), { mode: 0o600 });
    return runInForeground(
      {
        command,
        timeoutMs: foregroundTimeout(requested),
        target: target(install, scriptFile, ctx),
        cwdFile,
        mayMoveToBackground: !SLEEP.test(command),
        scratch: [scriptFile],
        ...(descriptionText ? { description: descriptionText } : {}),
      },
      ctx,
    );
  },
};
