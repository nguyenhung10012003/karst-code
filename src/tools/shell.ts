/**
 * The shell that runs commands: `$SHELL`, else `/bin/sh`. Windows has neither as a rule, so there
 * it is Git Bash, found next to `git.exe` on the PATH or where Git for Windows installs itself.
 */
import { existsSync } from 'node:fs';
import { win32 } from 'node:path';

let gitBash: string | null | undefined;

export function shell(): string {
  if (process.env.SHELL) return process.env.SHELL;
  if (process.platform !== 'win32') return '/bin/sh';
  gitBash ??= findGitBash(process.env);
  return gitBash ?? '/bin/sh';
}

/** Its file name, for showing: `bash` for `/bin/bash` and `C:\Program Files\Git\bin\bash.exe` alike. */
export function shellName(file: string = shell()): string {
  return win32.basename(file).replace(/\.exe$/i, '');
}

/**
 * `bin\bash.exe` rather than `usr\bin\bash.exe`: it puts Git's tools on the PATH before starting
 * bash. A `bash.exe` found on the PATH itself is not used, since `System32` and `WindowsApps` hold
 * WSL's, which runs commands in Linux with Linux paths.
 */
export function findGitBash(env: NodeJS.ProcessEnv, exists: (path: string) => boolean = existsSync): string | null {
  const roots: string[] = [];
  for (const dir of (env.PATH ?? env.Path ?? '').split(';').filter(Boolean)) {
    if (!exists(win32.join(dir, 'git.exe'))) continue;
    // `<root>\cmd\git.exe`, `<root>\bin\git.exe` or `<root>\mingw64\bin\git.exe`.
    roots.push(win32.dirname(dir), win32.dirname(win32.dirname(dir)));
  }
  for (const base of [env.ProgramFiles, env.ProgramW6432, env['ProgramFiles(x86)']]) if (base) roots.push(win32.join(base, 'Git'));
  if (env.LOCALAPPDATA) roots.push(win32.join(env.LOCALAPPDATA, 'Programs', 'Git'));
  for (const root of roots) {
    const bash = win32.join(root, 'bin', 'bash.exe');
    if (exists(bash)) return bash;
  }
  return null;
}
