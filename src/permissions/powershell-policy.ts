/**
 * Permission analysis for PowerShell commands. It never executes anything.
 *
 * PowerShell's grammar is far larger than POSIX shell's, so this does not try to parse all of
 * it. It reads a plain subset: commands whose arguments are bare words or quoted strings, joined
 * by `;`, `|`, `&&`, `||` or newlines. Variables, subexpressions, script blocks, escapes, the
 * call operator, splatting and redirection to a file all make a command unanalyzable, which
 * means it is never approved without a prompt. Commands found along the way are still reported,
 * so deny and ask rules keep working on a best-effort basis.
 */
import { homedir } from 'node:os';
import { basename, dirname, join, parse, resolve } from 'node:path';
import type { BashContext } from './bash-policy.ts';
import { isReadOnlyCommand, readPaths } from './bash-policy.ts';
import { canonicalize, isInside, isProtectedPath } from './rules.ts';
import type { SimpleCommand, Word } from './shell.ts';

export interface PsWord {
  /** Source text, including any quotes. */
  raw: string;
  /** Text after quote removal. Meaningless where `dynamic` is true. */
  value: string;
  quoted: boolean;
  /** Holds something only known when it runs: a variable, subexpression, script block or escape. */
  dynamic: boolean;
  /** Holds an unquoted wildcard. */
  glob: boolean;
}

export interface PsCommand {
  words: PsWord[];
  /** Files output is redirected to. */
  redirects: PsWord[];
}

export interface PsAnalysis {
  parseable: boolean;
  reason?: string;
  commands: PsCommand[];
}

const MAX_ANALYZED_LENGTH = 10_000;
/** PowerShell reads these as quotes, the same as ' and ". */
const SINGLE_QUOTES = /[‘’‚‛]/;
const DOUBLE_QUOTES = /[“”„]/;
/** Literal values, not variables: `-Recurse:$false`, `2>$null`. */
const CONSTANTS = /^\$(?:null|true|false)(?![\w:])/i;

function newWord(): PsWord {
  return { raw: '', value: '', quoted: false, dynamic: false, glob: false };
}

export function analyzePowerShell(source: string): PsAnalysis {
  const commands: PsCommand[] = [];
  let parseable = true;
  let reason: string | undefined;
  const fail = (why: string): void => {
    if (!parseable) return;
    parseable = false;
    reason = why;
  };
  if (source.length > MAX_ANALYZED_LENGTH) fail('too long to analyze');

  let current: PsCommand = { words: [], redirects: [] };
  let word: PsWord | null = null;
  /** The next word is where output goes. */
  let redirectPending = false;
  const w = (): PsWord => (word ??= newWord());
  const endWord = (): void => {
    if (!word) return;
    if (redirectPending) {
      redirectPending = false;
      // `> $null` discards output, the one target that writes nothing.
      if (word.dynamic || word.value.toLowerCase() !== '$null') {
        current.redirects.push(word);
        fail('redirects output to a file');
      }
    } else {
      current.words.push(word);
    }
    word = null;
  };
  const endCommand = (): void => {
    endWord();
    if (redirectPending) {
      redirectPending = false;
      fail('redirects output without a target');
    }
    if (current.words.length > 0 || current.redirects.length > 0) commands.push(current);
    current = { words: [], redirects: [] };
  };
  /** What follows starts a nested command, whose value the outer one only gets when it runs. */
  const openNested = (raw: string, why: string): void => {
    fail(why);
    endWord();
    current.words.push({ raw, value: raw, quoted: false, dynamic: true, glob: false });
    endCommand();
  };

  let i = 0;
  while (i < source.length) {
    const c = source[i]!;
    const next = source[i + 1];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\f' || c === '\v') {
      endWord();
      i++;
    } else if (c === '\n' || c === ';') {
      endCommand();
      i++;
    } else if (c === '|') {
      endCommand();
      i += next === '|' ? 2 : 1;
    } else if (c === '&') {
      if (next !== '&') fail('uses the & call operator or a background job');
      endCommand();
      i += next === '&' ? 2 : 1;
    } else if (c === '#' && !word) {
      while (i < source.length && source[i] !== '\n') i++;
    } else if (c === '<' && next === '#') {
      fail('has a block comment');
      endWord();
      const close = source.indexOf('#>', i + 2);
      i = close === -1 ? source.length : close + 2;
    } else if (c === "'") {
      const part = w();
      part.quoted = true;
      let j = i + 1;
      let closed = false;
      while (j < source.length) {
        const ch = source[j]!;
        if (SINGLE_QUOTES.test(ch)) fail('has a curly quote');
        if (ch === "'") {
          if (source[j + 1] === "'") {
            part.value += "'";
            j += 2;
            continue;
          }
          closed = true;
          break;
        }
        part.value += ch;
        j++;
      }
      if (!closed) fail('has an unterminated string');
      part.raw += source.slice(i, j + 1);
      i = j + 1;
    } else if (c === '"') {
      const part = w();
      part.quoted = true;
      let j = i + 1;
      let closed = false;
      while (j < source.length) {
        const ch = source[j]!;
        if (DOUBLE_QUOTES.test(ch)) fail('has a curly quote');
        if (ch === '$' || ch === '`') {
          // A variable, a subexpression or an escape: its value is only known when it runs.
          fail('expands a variable or escape inside double quotes');
          part.dynamic = true;
        }
        if (ch === '"') {
          if (source[j + 1] === '"') {
            part.value += '"';
            j += 2;
            continue;
          }
          closed = true;
          break;
        }
        part.value += ch;
        j++;
      }
      if (!closed) fail('has an unterminated string');
      part.raw += source.slice(i, j + 1);
      i = j + 1;
    } else if (c === '$') {
      const constant = CONSTANTS.exec(source.slice(i));
      const part = w();
      if (constant) {
        part.raw += constant[0];
        part.value += constant[0];
        i += constant[0].length;
      } else {
        fail('uses a variable or subexpression');
        part.dynamic = true;
        part.raw += c;
        part.value += c;
        i++;
      }
    } else if (c === '`') {
      fail('uses a backtick escape');
      const part = w();
      part.dynamic = true;
      part.raw += source.slice(i, i + 2);
      i += 2;
    } else if (c === '(' || c === '{') {
      openNested(c, 'uses a subexpression or script block');
      i++;
    } else if (c === ')' || c === '}') {
      endCommand();
      i++;
    } else if (c === '@' && !word) {
      if (next === '(' || next === '{') {
        openNested(`@${next}`, 'uses an array or hashtable expression');
        i += 2;
      } else if (next === "'" || next === '"') {
        fail('uses a here-string');
        const close = source.indexOf(`\n${next}@`, i + 2);
        const part = w();
        part.dynamic = true;
        const end = close === -1 ? source.length : close + 3;
        part.raw += source.slice(i, end);
        i = end;
      } else {
        fail('uses splatting');
        const part = w();
        part.dynamic = true;
        part.raw += c;
        i++;
      }
    } else if (c === '[' && !word) {
      fail('uses a type or attribute');
      const part = w();
      part.dynamic = true;
      part.raw += c;
      i++;
    } else if (c === ',') {
      // An array: each element is its own argument.
      endWord();
      i++;
    } else if (c === '>' || ((c === '*' || (c >= '1' && c <= '6')) && next === '>' && !word)) {
      // `>`, `>>`, `2>`, `*>>`, and `2>&1`, which only merges streams.
      endWord();
      let j = c === '>' ? i + 1 : i + 2;
      if (source[j] === '>') j++;
      if (source[j] === '&' && source[j + 1] !== undefined && /[1-6]/.test(source[j + 1]!)) {
        j += 2;
      } else {
        redirectPending = true;
      }
      i = j;
    } else if (c === '<') {
      fail('uses <, which PowerShell reserves');
      endWord();
      i++;
    } else if (c === '-' && next === '-' && source[i + 2] === '%' && !word) {
      fail('uses the stop-parsing token');
      const part = w();
      part.dynamic = true;
      while (i < source.length && source[i] !== '\n') part.raw += source[i++];
    } else if (c.charCodeAt(0) > 0x7e || c.charCodeAt(0) < 0x20) {
      // PowerShell takes some of these as dashes, quotes or spaces.
      fail('has characters outside plain ASCII outside quotes');
      const part = w();
      part.raw += c;
      part.value += c;
      i++;
    } else {
      const part = w();
      if (c === '*' || c === '?' || c === '[' || c === ']') part.glob = true;
      part.raw += c;
      part.value += c;
      i++;
    }
  }
  endCommand();
  return { parseable, ...(reason ? { reason } : {}), commands };
}

type CmdletKind =
  /** Reads only, and its arguments are not paths. */
  | 'read'
  /** Reads only the paths it is given. */
  | 'read-paths'
  | 'location'
  | 'remove'
  /** Creates, copies, moves or renames: approved by acceptEdits inside the working directories. */
  | 'edit'
  /** Writes to the paths it is given. */
  | 'write';

const CMDLETS: Record<string, CmdletKind> = {
  'Get-ChildItem': 'read-paths',
  'Get-Content': 'read-paths',
  'Select-String': 'read-paths',
  'Get-Item': 'read-paths',
  'Get-ItemProperty': 'read-paths',
  'Get-ItemPropertyValue': 'read-paths',
  'Test-Path': 'read-paths',
  'Resolve-Path': 'read-paths',
  'Get-FileHash': 'read-paths',
  'Format-Hex': 'read-paths',
  'Get-Acl': 'read-paths',
  'Get-Location': 'read',
  'Write-Output': 'read',
  'Write-Host': 'read',
  'Get-Date': 'read',
  'Get-Process': 'read',
  'Get-Service': 'read',
  'Select-Object': 'read',
  'Where-Object': 'read',
  'Sort-Object': 'read',
  'Group-Object': 'read',
  'Measure-Object': 'read',
  'Format-Table': 'read',
  'Format-List': 'read',
  'Format-Wide': 'read',
  'Out-String': 'read',
  'Out-Null': 'read',
  'Out-Host': 'read',
  'ConvertTo-Json': 'read',
  'ConvertFrom-Json': 'read',
  'ConvertTo-Csv': 'read',
  'ConvertFrom-Csv': 'read',
  'Get-Unique': 'read',
  'Compare-Object': 'read',
  'Get-Member': 'read',
  'Get-Command': 'read',
  'Get-Alias': 'read',
  'Get-Culture': 'read',
  'Get-Host': 'read',
  'Get-PSDrive': 'read',
  'Get-Module': 'read',
  'Get-TimeZone': 'read',
  'Get-Uptime': 'read',
  'Split-Path': 'read',
  'Join-Path': 'read',
  'Set-Location': 'location',
  'Push-Location': 'location',
  'Pop-Location': 'location',
  'Remove-Item': 'remove',
  'New-Item': 'edit',
  'Copy-Item': 'edit',
  'Move-Item': 'edit',
  'Rename-Item': 'edit',
  'Set-Content': 'write',
  'Add-Content': 'write',
  'Clear-Content': 'write',
  'Out-File': 'write',
  'Tee-Object': 'write',
  'Set-Item': 'write',
  'Export-Csv': 'write',
  'Export-Clixml': 'write',
};

/** The aliases a session started with -NoProfile has on Windows, in PowerShell 5.1 and 7. */
const ALIASES: Record<string, string> = {
  gci: 'Get-ChildItem', ls: 'Get-ChildItem', dir: 'Get-ChildItem',
  gc: 'Get-Content', cat: 'Get-Content', type: 'Get-Content',
  sls: 'Select-String', gi: 'Get-Item', gp: 'Get-ItemProperty', gpv: 'Get-ItemPropertyValue',
  rvpa: 'Resolve-Path', fhx: 'Format-Hex', gl: 'Get-Location', pwd: 'Get-Location',
  echo: 'Write-Output', write: 'Write-Output', gps: 'Get-Process', ps: 'Get-Process', gsv: 'Get-Service',
  select: 'Select-Object', where: 'Where-Object', '?': 'Where-Object', sort: 'Sort-Object', group: 'Group-Object',
  measure: 'Measure-Object', ft: 'Format-Table', fl: 'Format-List', fw: 'Format-Wide', oh: 'Out-Host',
  gu: 'Get-Unique', compare: 'Compare-Object', diff: 'Compare-Object', gm: 'Get-Member', gcm: 'Get-Command',
  gal: 'Get-Alias', gdr: 'Get-PSDrive', gmo: 'Get-Module',
  sl: 'Set-Location', cd: 'Set-Location', chdir: 'Set-Location', pushd: 'Push-Location', popd: 'Pop-Location',
  ri: 'Remove-Item', rm: 'Remove-Item', rmdir: 'Remove-Item', del: 'Remove-Item', erase: 'Remove-Item', rd: 'Remove-Item',
  ni: 'New-Item', mkdir: 'New-Item', md: 'New-Item', cpi: 'Copy-Item', cp: 'Copy-Item', copy: 'Copy-Item',
  mi: 'Move-Item', mv: 'Move-Item', move: 'Move-Item', rni: 'Rename-Item', ren: 'Rename-Item',
  ac: 'Add-Content', clc: 'Clear-Content', tee: 'Tee-Object', si: 'Set-Item',
};

const CMDLET_BY_LOWER = new Map(Object.keys(CMDLETS).map((name) => [name.toLowerCase(), name]));

/** Programs, not cmdlets, that are read-only as the bash rules judge them. Names PowerShell aliases are left out. */
const NATIVE_READ_ONLY = new Set([
  'git', 'rg', 'grep', 'egrep', 'fgrep', 'wc', 'head', 'tail', 'which', 'whoami', 'uname', 'stat', 'file', 'cut',
  'tr', 'uniq', 'basename', 'dirname', 'realpath', 'md5sum', 'sha256sum', 'shasum', 'cmp', 'comm', 'nl', 'tac',
  'rev', 'seq', 'du', 'df', 'tree',
]);

/** Reach another computer or run as someone else. Matched by prefix, as PowerShell does. */
const REMOTE_PARAMETERS = ['computername', 'cn', 'session', 'cimsession', 'credential'];

/** `Microsoft.PowerShell.Management\Remove-Item` names the same cmdlet as `Remove-Item`. */
function withoutModule(name: string): string {
  const match = /^Microsoft\.PowerShell\.[A-Za-z.]+\\(.+)$/i.exec(name);
  return match ? match[1]! : name;
}

/** The cmdlet a command name runs, through an alias, if it is one this file knows. */
function cmdletOf(name: string): string | undefined {
  const bare = withoutModule(name).toLowerCase();
  return ALIASES[bare] ?? CMDLET_BY_LOWER.get(bare);
}

/** A program's name without its directory or `.exe`, as rules name it. */
function programName(name: string): string {
  return basename(name.replaceAll('\\', '/')).replace(/\.(exe|cmd|bat|com)$/i, '').toLowerCase();
}

function parameterName(word: PsWord): string | null {
  if (word.quoted || !/^-[A-Za-z]/.test(word.value)) return null;
  return word.value.slice(1).split(':')[0]!.toLowerCase();
}

/** Values that may name a path: every argument, and what follows `-Param:`. Parameter names are skipped. */
function pathValues(args: PsWord[]): PsWord[] {
  return args.flatMap((arg) => {
    if (parameterName(arg) === null) return [arg];
    const colon = arg.value.indexOf(':');
    return colon === -1 ? [] : [{ ...arg, value: arg.value.slice(colon + 1) }];
  });
}

/**
 * The file a value names, or null when that cannot be told: a value only known at run time, or
 * one with a colon anywhere but after a drive letter. That covers provider paths such as `env:`,
 * `HKLM:\` and `Microsoft.PowerShell.Core\FileSystem::C:\`, which PowerShell resolves on its own
 * and `resolve` would wrongly place under `cwd`, as well as `\\?\C:\` and alternate data streams.
 * Wildcards are kept as written, so `..` after one still leaves the directory.
 */
function pathOf(word: PsWord, cwd: string): string | null {
  if (word.dynamic) return null;
  const value = word.value;
  if (value.includes(':') && !/^[A-Za-z]:[^:]*$/.test(value)) return null;
  if (value === '~' || value.startsWith('~\\') || value.startsWith('~/')) return join(homedir(), value.slice(2));
  return resolve(cwd, value);
}

function insideWorkingDirs(path: string, ctx: BashContext): boolean {
  const real = canonicalize(path);
  return ctx.workingDirs.some((dir) => isInside(real, dir));
}

function pathsInside(args: PsWord[], ctx: BashContext): boolean {
  return pathValues(args).every((word) => {
    const path = pathOf(word, ctx.cwd);
    return path !== null && insideWorkingDirs(path, ctx);
  });
}

/** For the bash rules, which judge a program's flags and paths. */
function asSimpleCommand(name: string, args: PsWord[]): SimpleCommand {
  const words: Word[] = [
    { raw: name, value: name, dynamic: false, glob: false, quoted: false },
    ...args.map((a) => ({ raw: a.raw, value: a.value, dynamic: a.dynamic, glob: a.glob, quoted: a.quoted })),
  ];
  return { assignments: [], words, redirects: [], nested: false };
}

export function isReadOnlyPowerShell(cmd: PsCommand, ctx: BashContext): boolean {
  if (cmd.redirects.length > 0) return false;
  const [first, ...args] = cmd.words;
  if (!first || first.quoted || cmd.words.some((w) => w.dynamic)) return false;
  const cmdlet = cmdletOf(first.value);
  if (cmdlet) {
    const kind = CMDLETS[cmdlet]!;
    if (kind !== 'read' && kind !== 'read-paths' && kind !== 'location') return false;
    const parameters = args.map(parameterName).filter((name): name is string => name !== null);
    if (parameters.some((given) => REMOTE_PARAMETERS.some((name) => name.startsWith(given)))) return false;
    return kind === 'read' || pathsInside(args, ctx);
  }
  const program = programName(first.value);
  if (!NATIVE_READ_ONLY.has(program) || first.value.includes('\\') || first.value.includes('/')) return false;
  return isReadOnlyCommand(asSimpleCommand(program, args), ctx);
}

/** In acceptEdits mode: creating, copying, moving or renaming inside the working directories. */
export function isAcceptEditsPowerShell(cmd: PsCommand, ctx: BashContext): boolean {
  const [first, ...args] = cmd.words;
  if (!first || cmd.redirects.length > 0 || cmd.words.some((w) => w.dynamic)) return false;
  const cmdlet = cmdletOf(first.value);
  if (!cmdlet || CMDLETS[cmdlet] !== 'edit') return false;
  return pathValues(args).every((word) => {
    const path = pathOf(word, ctx.cwd);
    return path !== null && insideWorkingDirs(path, ctx) && !isProtectedPath(canonicalize(path));
  });
}

function isLocationChange(cmd: PsCommand): boolean {
  const name = cmd.words[0]?.value;
  return name !== undefined && CMDLETS[cmdletOf(name) ?? ''] === 'location';
}

/** Moving somewhere, then running git or writing there, could run what that directory configures. */
export function hasRiskyLocationChange(commands: PsCommand[]): boolean {
  if (!commands.some(isLocationChange)) return false;
  return commands.some((cmd) => {
    const name = cmd.words[0]?.value;
    if (!name) return false;
    const kind = CMDLETS[cmdletOf(name) ?? ''];
    return cmd.redirects.length > 0 || programName(name) === 'git' || kind === 'write' || kind === 'edit' || kind === 'remove';
  });
}

/** Removing a drive, a top-level folder, home, or the working directory or one above it. */
export function isCriticalRemovalPowerShell(cmd: PsCommand, ctx: BashContext): boolean {
  const [first, ...args] = cmd.words;
  if (!first) return false;
  const removes = cmdletOf(first.value) === 'Remove-Item' || ['rm', 'rmdir'].includes(programName(first.value));
  if (!removes) return false;
  const home = homedir();
  return pathValues(args).some((target) => {
    if (target.dynamic) return true;
    const value = target.value;
    // Everything in a directory: `*`, `*.*`, `C:\*`, `~\*`.
    if (/^(?:[A-Za-z]:)?(?:[\\/]|~[\\/]|\.[\\/])?[*?.]*\*[*?.]*$/.test(value)) return true;
    const path = pathOf(target, ctx.cwd);
    // A provider path: the registry, environment variables, certificates.
    if (path === null) return true;
    const { root } = parse(path);
    return path === root || dirname(path) === root || path === home || path === ctx.cwd || isInside(ctx.cwd, path);
  });
}

/** Files a command visibly reads, for Read deny rules. */
export function powerShellReadPaths(cmd: PsCommand, cwd: string): string[] {
  const [first, ...args] = cmd.words;
  if (!first) return [];
  const cmdlet = cmdletOf(first.value);
  if (cmdlet) {
    if (CMDLETS[cmdlet] !== 'read-paths') return [];
    return pathValues(args).flatMap((word) => {
      const path = pathOf(word, cwd);
      return path === null ? [] : [path];
    });
  }
  const program = programName(first.value);
  return NATIVE_READ_ONLY.has(program) ? readPaths(asSimpleCommand(program, args), cwd) : [];
}

/** Files a command visibly writes, for Edit deny rules. */
export function powerShellWritePaths(cmd: PsCommand, cwd: string): string[] {
  const targets = [...cmd.redirects];
  const [first, ...args] = cmd.words;
  const kind = first ? CMDLETS[cmdletOf(first.value) ?? ''] : undefined;
  if (kind === 'write' || kind === 'edit' || kind === 'remove') targets.push(...pathValues(args));
  return targets.flatMap((word) => {
    const path = pathOf(word, cwd);
    return path === null ? [] : [path];
  });
}

/**
 * The texts deny and ask rules are matched against, lowercased: PowerShell ignores case, and
 * `rm`, `del` and `Remove-Item` all name the same cmdlet.
 */
export function powerShellForms(cmd: PsCommand): string[] {
  const [first, ...rest] = cmd.words;
  if (!first) return [];
  const forms = new Set<string>();
  const add = (name: string): void => {
    forms.add([name, ...rest.map((w) => w.raw)].join(' ').toLowerCase());
    forms.add([name, ...rest.map((w) => w.value)].join(' ').toLowerCase());
  };
  add(first.raw);
  add(first.value);
  const cmdlet = cmdletOf(first.value);
  if (cmdlet) add(cmdlet);
  else add(programName(first.value));
  return [...forms];
}

/** The text an allow rule for this command is saved as, or null when it cannot be one. */
export function powerShellAllowForm(cmd: PsCommand): string | null {
  if (cmd.words.length === 0 || cmd.words.some((w) => w.dynamic) || cmd.redirects.length > 0) return null;
  return cmd.words.map((w) => w.raw).join(' ');
}
