/**
 * Commands running in the background: those started with `run_in_background`, and those moved
 * there when they outlast their timeout. Output goes to a log file the model can Read.
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { appendFileSync, closeSync, createWriteStream, mkdirSync, openSync, statSync, truncateSync } from 'node:fs';
import type { WriteStream } from 'node:fs';
import { join } from 'node:path';
import type { Reaper } from './reaper.ts';
import { shell } from './shell.ts';
import type { Tool } from './types.ts';

const KILL_GRACE_MS = 2_000;
const MAX_LIMIT_MS = 2 * 60 * 60 * 1000;
/** A running command's log is cleared when it grows past this, so a chatty command cannot fill the disk. */
export const MAX_LOG_BYTES = 100 * 1024 * 1024;
const LOG_CHECK_MS = 2_000;

export type TaskStatus = 'running' | 'exited' | 'stopped' | 'timed_out';

export interface BackgroundTask {
  id: string;
  /** -1 for work the registry tracks but did not spawn, such as a monitor. */
  pid: number;
  command: string;
  description?: string;
  logPath: string;
  startedAt: number;
  status: TaskStatus;
  exitCode?: number | null;
  kind?: 'command' | 'monitor';
}

export interface TaskRegistryOptions {
  logDir: string;
  /** How long a background command may run. Undefined: no limit, as in an interactive session. */
  defaultLimitMs?: number;
  /** Tells the conversation that a command stopped. */
  onFinished?: (task: BackgroundTask, message: string) => void;
  /** Stops what is still running if Karst's process ends without doing so. Shared by a session's registries. */
  reaper?: Reaper;
  /** The size at which a running command's log is cleared. */
  maxLogBytes?: number;
}

/**
 * Commands run in process groups of their own, so a timeout can end everything they started.
 * Windows has no process groups. There a command gets a hidden console of its own instead
 * (`windowsHide` without `detached`): with none at all, PowerShell prints nothing, and sharing
 * Karst's would let it draw over the screen.
 */
export const DETACH_COMMANDS = process.platform !== 'win32';

/** When each process was ended on Windows, so the KILL that follows a TERM is not sent too. */
const endedOnWindows = new Map<number, number>();
const WINDOWS_REUSE_GUARD_MS = 10_000;
/** Set in a command's environment on Windows, so every process it starts can be found again. */
const WINDOWS_GROUP_VAR = 'KARST_PROCESS_GROUP';
const windowsGroups = new Map<number, string>();

/** On Windows, marks a command's environment with a group of its own. Elsewhere it is unchanged. */
export function withProcessGroup(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return process.platform === 'win32' ? { ...env, [WINDOWS_GROUP_VAR]: randomBytes(8).toString('hex') } : env;
}

/** Ties a started command to the group in its environment, for `killTree`. Cleared when it exits. */
export function rememberProcessGroup(child: ChildProcess, env: NodeJS.ProcessEnv | undefined): void {
  const group = env?.[WINDOWS_GROUP_VAR];
  const pid = child.pid;
  if (process.platform !== 'win32' || !group || pid === undefined) return;
  windowsGroups.set(pid, group);
  child.once('exit', () => setTimeout(() => windowsGroups.delete(pid), WINDOWS_REUSE_GUARD_MS).unref());
}

export function killTree(pid: number, signal: NodeJS.Signals): void {
  if (process.platform === 'win32') {
    killTreeOnWindows(pid, signal);
    return;
  }
  try {
    process.kill(-pid, signal);
  } catch {
    // The process group has already gone.
  }
}

/**
 * Prints the Windows pid of every MSYS process whose environment holds the group, using only
 * bash builtins: a fork costs tens of milliseconds on Windows.
 */
const FIND_GROUP = `
for d in /proc/[0-9]*; do
  while IFS= read -r -d '' entry; do
    if [ "$entry" = "$1" ]; then read -r w < "$d/winpid" && echo "$w"; break; fi
  done < "$d/environ"
done 2>/dev/null`;

/**
 * Windows has neither process groups nor TERM, so `process.kill(-pid)` does nothing there.
 * taskkill ends a process and its descendants, but only those Windows still sees as such: an
 * MSYS program Git Bash started with `&` or in a pipeline has lost its parent, so it is found
 * by the group in its environment instead. A second, forced call shortly after would find the
 * process gone, or its pid reused by an unrelated one, so it is skipped.
 */
function killTreeOnWindows(pid: number, signal: NodeJS.Signals): void {
  const now = Date.now();
  for (const [ended, at] of endedOnWindows) if (now - at > WINDOWS_REUSE_GUARD_MS) endedOnWindows.delete(ended);
  if (signal === 'SIGKILL' && endedOnWindows.has(pid)) return;
  endedOnWindows.set(pid, now);
  const taskkill = (pids: number[]): void => {
    try {
      const child = spawn('taskkill', [...pids.flatMap((p) => ['/pid', String(p)]), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      child.on('error', () => {});
      child.unref();
    } catch {
      // taskkill could not start; there is nothing else to try.
    }
  };
  taskkill([pid]);
  const group = windowsGroups.get(pid);
  if (!group) return;
  // Orphans outlive the process tree's end, so they can be looked for meanwhile.
  let found = '';
  try {
    const finder = spawn(shell(), ['-c', FIND_GROUP, 'find-group', `${WINDOWS_GROUP_VAR}=${group}`], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    finder.stdout.on('data', (chunk: Buffer) => (found += chunk.toString()));
    finder.on('error', () => {});
    finder.on('close', () => {
      const orphans = found.split(/\s+/).filter(Boolean).map(Number).filter((p) => p > 0 && p !== pid);
      if (orphans.length > 0) taskkill(orphans);
    });
    finder.unref();
  } catch {
    // No shell to look with; the tree itself has been ended.
  }
}

/** Copies a running command's pipes to its log, after `soFar`. */
function copyToLog(child: ChildProcess, logPath: string, soFar: string): void {
  const log: WriteStream = createWriteStream(logPath, { flags: 'a', mode: 0o600 });
  if (soFar) log.write(soFar);
  // The session must be able to exit while this runs. It is stopped at shutdown.
  child.unref();
  let open = 2;
  for (const stream of [child.stdout, child.stderr]) {
    (stream as unknown as { unref?: () => void } | null)?.unref?.();
    stream?.on('data', (chunk: Buffer) => log.write(chunk));
    stream?.once('close', () => {
      if (--open === 0) log.end();
    });
  }
}

function label(task: BackgroundTask): string {
  return task.description ?? task.command.split('\n')[0]!.slice(0, 80);
}

export class TaskRegistry {
  private readonly tasks = new Map<string, BackgroundTask>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly settled = new Set<() => void>();
  private readonly stoppers = new Map<string, () => void>();
  readonly logDir: string;
  private readonly defaultLimitMs: number | undefined;
  private readonly onFinished: TaskRegistryOptions['onFinished'];
  private readonly reaper: Reaper | undefined;
  private readonly maxLogBytes: number;
  private logCheck: NodeJS.Timeout | undefined;

  constructor(options: TaskRegistryOptions) {
    this.logDir = options.logDir;
    this.defaultLimitMs = options.defaultLimitMs;
    this.onFinished = options.onFinished;
    this.reaper = options.reaper;
    this.maxLogBytes = options.maxLogBytes ?? MAX_LOG_BYTES;
  }

  /**
   * Keeps a detached process group from outliving Karst's process, until the returned function
   * is called once it has exited. For foreground commands too, which are detached so a timeout
   * can end everything they started.
   */
  guard(pid: number | undefined): () => void {
    this.reaper?.add(pid);
    return () => this.reaper?.remove(pid);
  }

  /**
   * Logs are written in append mode, so emptying one leaves the command writing at its new end.
   * Checked on a timer while anything runs, since the command writes to the file directly.
   */
  private watchLogs(): void {
    if (this.logCheck) return;
    this.logCheck = setInterval(() => {
      const running = this.running();
      if (running.length === 0) {
        clearInterval(this.logCheck);
        this.logCheck = undefined;
        return;
      }
      for (const task of running) {
        try {
          if (statSync(task.logPath).size <= this.maxLogBytes) continue;
          truncateSync(task.logPath, 0);
          const size = this.maxLogBytes >= 1024 * 1024 ? `${Math.round(this.maxLogBytes / (1024 * 1024))} MB` : `${this.maxLogBytes} bytes`;
          appendFileSync(task.logPath, `[${new Date().toISOString()}: this log passed ${size}, so Karst emptied it. The command is still running; what it printed before this line is gone.]\n`);
        } catch {
          // The log was removed, as by karst purge. There is nothing to bound.
        }
      }
    }, LOG_CHECK_MS);
    this.logCheck.unref();
  }

  list(): BackgroundTask[] {
    return [...this.tasks.values()];
  }

  get(id: string): BackgroundTask | undefined {
    return this.tasks.get(id);
  }

  running(): BackgroundTask[] {
    return this.list().filter((task) => task.status === 'running');
  }

  /** Only an unattended session has a limit. Someone at a terminal can stop a command themselves. */
  private limitFor(requestedMs: number | undefined): number | undefined {
    if (this.defaultLimitMs === undefined) return undefined;
    return Math.min(requestedMs ?? this.defaultLimitMs, MAX_LIMIT_MS);
  }

  newLogPath(id: string): string {
    mkdirSync(this.logDir, { recursive: true, mode: 0o700 });
    return join(this.logDir, `${id}.log`);
  }

  private register(child: ChildProcess, command: string, logPath: string, id: string, description: string | undefined, limitMs: number | undefined): BackgroundTask {
    const task: BackgroundTask = { id, pid: child.pid!, command, logPath, startedAt: Date.now(), status: 'running', ...(description ? { description } : {}) };
    this.tasks.set(id, task);
    const release = this.guard(child.pid);
    this.watchLogs();
    if (limitMs !== undefined) {
      const timer = setTimeout(() => this.finishByLimit(task), limitMs);
      timer.unref();
      this.timers.set(id, timer);
    }
    child.once('exit', (code) => {
      clearTimeout(this.timers.get(id));
      release();
      if (task.status === 'running') {
        task.status = 'exited';
        task.exitCode = code;
        this.onFinished?.(task, `Background command "${label(task)}" (task ${id}) exited with code ${code}. Output: ${logPath}`);
      }
      for (const wake of [...this.settled]) wake();
    });
    return task;
  }

  private finishByLimit(task: BackgroundTask): void {
    if (task.status !== 'running') return;
    task.status = 'timed_out';
    this.terminate(task);
    this.onFinished?.(task, `Background command "${label(task)}" was stopped after reaching its background time limit. Output: ${task.logPath}`);
  }

  private terminate(task: BackgroundTask): void {
    killTree(task.pid, 'SIGTERM');
    setTimeout(() => killTree(task.pid, 'SIGKILL'), KILL_GRACE_MS).unref();
  }

  /** Runs a new detached command with its output in a log file. */
  start(file: string, args: string[], options: { command: string; description?: string; cwd: string; env: NodeJS.ProcessEnv; limitMs?: number }): BackgroundTask | null {
    const id = randomBytes(4).toString('hex');
    const logPath = this.newLogPath(id);
    if (process.platform === 'win32') {
      // Windows opens a file for appending with append-only access, which Git Bash cannot write
      // to, so the output comes through pipes and is copied to the log here.
      const child = spawn(file, args, { cwd: options.cwd, detached: DETACH_COMMANDS, stdio: ['ignore', 'pipe', 'pipe'], env: options.env, windowsHide: true });
      child.on('error', () => {});
      if (child.pid === undefined) return null;
      rememberProcessGroup(child, options.env);
      copyToLog(child, logPath, '');
      return this.register(child, options.command, logPath, id, options.description, this.limitFor(options.limitMs));
    }
    const fd = openSync(logPath, 'a', 0o600);
    try {
      const child = spawn(file, args, { cwd: options.cwd, detached: true, stdio: ['ignore', fd, fd], env: options.env });
      child.on('error', () => {});
      child.unref();
      if (child.pid === undefined) return null;
      return this.register(child, options.command, logPath, id, options.description, this.limitFor(options.limitMs));
    } finally {
      closeSync(fd);
    }
  }

  /**
   * Takes over a running foreground command. It keeps its pipes, so they are copied to the log
   * from here on, after what it has already printed.
   */
  adopt(child: ChildProcess, options: { command: string; description?: string; soFar: string }): BackgroundTask {
    const id = randomBytes(4).toString('hex');
    const logPath = this.newLogPath(id);
    copyToLog(child, logPath, options.soFar);
    return this.register(child, options.command, logPath, id, options.description, this.limitFor(undefined));
  }

  /** Work the registry did not start itself, such as a monitor: listed, stoppable and waited for. */
  track(options: { command: string; description?: string; stop: () => void }): BackgroundTask {
    const id = randomBytes(4).toString('hex');
    const task: BackgroundTask = {
      id,
      pid: -1,
      command: options.command,
      logPath: this.newLogPath(id),
      startedAt: Date.now(),
      status: 'running',
      kind: 'monitor',
      ...(options.description ? { description: options.description } : {}),
    };
    this.tasks.set(id, task);
    this.stoppers.set(id, options.stop);
    this.watchLogs();
    return task;
  }

  /** Records how tracked work ended. Has no effect once it has already ended. */
  settle(id: string, status: Exclude<TaskStatus, 'running'>, exitCode?: number | null): void {
    const task = this.tasks.get(id);
    if (!task || task.status !== 'running') return;
    task.status = status;
    if (exitCode !== undefined) task.exitCode = exitCode;
    this.stoppers.delete(id);
    for (const wake of [...this.settled]) wake();
  }

  stop(id: string): BackgroundTask | undefined {
    const task = this.tasks.get(id);
    if (!task || task.status !== 'running') return task;
    const stopper = this.stoppers.get(id);
    if (stopper) {
      stopper();
      this.settle(id, 'stopped');
      return task;
    }
    task.status = 'stopped';
    clearTimeout(this.timers.get(id));
    this.terminate(task);
    return task;
  }

  stopAll(): void {
    for (const task of this.running()) this.stop(task.id);
  }

  /** Resolves when no command is left running, or the signal fires. */
  async waitForAll(signal?: AbortSignal): Promise<void> {
    while (this.running().length > 0 && !signal?.aborted) await this.waitForChange(signal);
  }

  /** Resolves when the next task ends, however it ends, or the signal fires. */
  waitForChange(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.resolve();
    return new Promise<void>((resolve) => {
      // The commands are unref'd, so nothing else would keep the process alive to see them exit.
      const keepAlive = setInterval(() => {}, 1_000);
      const wake = (): void => {
        clearInterval(keepAlive);
        this.settled.delete(wake);
        signal?.removeEventListener('abort', wake);
        resolve();
      };
      this.settled.add(wake);
      signal?.addEventListener('abort', wake, { once: true });
    });
  }
}

export const taskStopTool: Tool = {
  name: 'TaskStop',
  description: `
- Stops a running background task by its ID
- Takes a task_id parameter identifying the task to stop
- To stop a background agent, pass its agent ID as task_id
- Returns a success or failure status
- Use this tool when you need to terminate a long-running task
`,
  inputSchema: {
    type: 'object',
    properties: {
      task_id: { description: 'The ID of the background task to stop. Background agents are also accepted by agent ID.', type: 'string' },
      shell_id: { description: 'Deprecated: use task_id instead', type: 'string' },
    },
    additionalProperties: false,
  },
  isReadOnly: () => false,
  access: () => ({ kind: 'none' }),
  async execute(input, ctx) {
    const id = ((input.task_id ?? input.shell_id) as string | undefined)?.trim();
    if (!id) return { content: 'Give the task_id of the task to stop.', isError: true };
    const task = ctx.tasks.get(id);
    if (!task) {
      const agent = ctx.agents?.stop(id);
      if (agent) return { content: agent.status === 'stopped' ? `Stopped agent ${agent.id}.` : `Agent ${agent.id} is not running (${agent.status}).`, display: `stopped ${agent.id}` };
      return { content: `No background task ${id}.`, isError: true };
    }
    if (task.status !== 'running') return { content: `Task ${id} is not running (${task.status}).` };
    ctx.tasks.stop(id);
    return { content: `Stopped task ${id}. Its output is in ${task.logPath}.`, display: `stopped ${id}` };
  },
};
