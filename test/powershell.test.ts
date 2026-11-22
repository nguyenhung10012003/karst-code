import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'bun:test';
import { PermissionEngine } from '../src/permissions/engine.ts';
import type { PermissionMode } from '../src/permissions/engine.ts';
import { analyzePowerShell } from '../src/permissions/powershell-policy.ts';
import { parseRule } from '../src/permissions/rules.ts';
import type { RuleBehavior } from '../src/permissions/rules.ts';
import { findPowerShell, powerShellTool } from '../src/tools/powershell.ts';
import { TaskRegistry } from '../src/tools/tasks.ts';
import type { ToolContext } from '../src/tools/types.ts';

const windows = process.platform === 'win32';

function tempProject(): string {
  return realpathSync(mkdtempSync(join(tmpdir(), 'karst-ps-')));
}

function engine(cwd: string, mode: PermissionMode = 'default', rules: Partial<Record<RuleBehavior, string[]>> = {}): PermissionEngine {
  const parsed = (['allow', 'ask', 'deny'] as const).flatMap((behavior) =>
    (rules[behavior] ?? []).map((text) => parseRule(text, behavior, 'project', cwd)!),
  );
  return new PermissionEngine({ mode, rules: parsed, workingDirs: [cwd], cwd: () => cwd });
}

const ps = (e: PermissionEngine, command: string) => e.check('PowerShell', { kind: 'powershell', command });

describe('PowerShell analysis', () => {
  const commandsOf = (src: string): string[] => analyzePowerShell(src).commands.map((c) => c.words.map((w) => w.value).join(' '));

  it('splits on every separator, and keeps quoted text whole', () => {
    assert.deepEqual(commandsOf("a; b | c && d || e\nf"), ['a', 'b', 'c', 'd', 'e', 'f']);
    assert.deepEqual(commandsOf(`Write-Output 'a; b' "c | d" 'it''s'`), ["Write-Output a; b c | d it's"]);
    assert.equal(analyzePowerShell('Get-ChildItem -Name # a comment; Remove-Item x').commands.length, 1);
  });

  it('reads an array as separate arguments', () => {
    assert.deepEqual(commandsOf('Get-Content a,b'), ['Get-Content a b']);
  });

  it('cannot analyze what is only known when it runs', () => {
    for (const command of [
      'Get-Content $file',
      'Write-Output "$(Remove-Item x)"',
      'Get-ChildItem | ForEach-Object { Remove-Item $_ }',
      '& Remove-Item x',
      'Remove-Item (Get-Item x)',
      'Get-Content `x',
      '@args',
      "Write-Output @'\nx\n'@",
      '[IO.File]::Delete("x")',
      'Get-Content x > out.txt',
      'Get-Content x 2> err.txt',
      'cmd --% /c del x',
      // PowerShell takes curly quotes as quotes, so "…” would end where this file's reader would not expect.
      'Write-Output "a” ; Remove-Item x ; “b"',
      'Write-Output a–b',
    ]) {
      assert.equal(analyzePowerShell(command).parseable, false, command);
    }
  });

  it('still finds the commands inside, for deny and ask rules', () => {
    assert.ok(commandsOf('Get-ChildItem | ForEach-Object { Remove-Item $_ }').includes('Remove-Item $_'));
    assert.ok(commandsOf('& Remove-Item x').includes('Remove-Item x'));
    assert.ok(commandsOf('Write-Output (Remove-Item x)').includes('Remove-Item x'));
  });

  it('allows discarding output and merging streams', () => {
    for (const command of ['git status 2>&1', 'Get-Item x 2>$null', 'Get-Item x > $null', 'Get-Item x *>&1', 'Get-ChildItem -Recurse:$false']) {
      assert.equal(analyzePowerShell(command).parseable, true, command);
    }
  });
});

describe('PowerShell permissions', () => {
  it('runs read-only commands inside the working directories without asking', () => {
    const cwd = tempProject();
    const e = engine(cwd);
    for (const command of [
      'Get-ChildItem',
      'Get-ChildItem src -Recurse -Filter *.ts | Select-Object -First 5',
      'ls; pwd',
      'Get-Content package.json | ConvertFrom-Json | Select-Object name',
      'Select-String -Path *.md -Pattern TODO',
      'cat README.md | Measure-Object -Line',
      'Test-Path node_modules',
      'git status',
      'git log -5 --oneline',
      'git.exe diff HEAD~1 --stat',
      'Get-Process | Sort-Object CPU | Select-Object -Last 3',
    ]) {
      assert.equal(ps(e, command).behavior, 'allow', command);
    }
  });

  it('asks for paths outside the working directories, and for other drives and providers', () => {
    const e = engine(tempProject());
    for (const command of ['Get-Content ../secret.txt', 'Get-ChildItem ~/.ssh', 'Get-Content -Path:../x', 'Get-Content env:API_KEY', 'Get-ChildItem HKLM:/SOFTWARE', 'Get-Content */../../x']) {
      assert.equal(ps(e, command).behavior, 'ask', command);
    }
  });

  it('asks for provider paths, however they are qualified', () => {
    const e = engine(tempProject());
    for (const command of [
      'Get-Content Microsoft.PowerShell.Core\\FileSystem::C:\\Windows\\win.ini',
      'Get-ChildItem Microsoft.PowerShell.Core\\Environment::',
      'gc -LiteralPath Microsoft.PowerShell.Core\\Environment::API_KEY',
      'Get-ChildItem Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE',
      'Get-Content -Path:Microsoft.PowerShell.Core\\FileSystem::C:\\x',
      'Select-String -Path FileSystem::C:\\x -Pattern y',
      'Get-Content \\\\?\\C:\\secret',
      'Get-Content x.txt:hidden',
    ]) {
      assert.equal(ps(e, command).behavior, 'ask', command);
    }
    const remove = ps(engine(tempProject(), 'default', { allow: ['PowerShell(Remove-Item *)'] }), 'Remove-Item Microsoft.PowerShell.Core\\FileSystem::C:\\ -Recurse');
    assert.equal(remove.behavior, 'ask');
    assert.equal(remove.forced, true);
  });

  it.skipIf(!windows)('asks for Windows paths outside the working directories', () => {
    const e = engine(tempProject());
    for (const command of ['Get-Content C:\\Windows\\win.ini', 'Get-ChildItem \\\\server\\share', 'Get-Content ..\\x']) {
      assert.equal(ps(e, command).behavior, 'ask', command);
    }
  });

  it('asks for anything that writes, runs code, or reaches other computers', () => {
    const e = engine(tempProject());
    for (const command of [
      'Remove-Item build -Recurse',
      'Set-Content x.txt hi',
      'Get-Content a | Out-File b',
      'Invoke-WebRequest https://example.com',
      'Invoke-Expression x',
      'Start-Process notepad',
      'Get-ChildItem | ForEach-Object Delete',
      'Get-Service -ComputerName other',
      'Get-Process -Comp other',
      'npm install',
      'git push',
      'git -C ../other status',
      '.\\build.ps1',
      'Get-Content $env:USERPROFILE\\x',
    ]) {
      assert.notEqual(ps(e, command).behavior, 'allow', command);
    }
  });

  it('applies deny rules through aliases, module names and case', () => {
    const e = engine(tempProject(), 'default', { deny: ['PowerShell(Remove-Item *)'] });
    for (const command of ['Remove-Item x', 'rm x', 'del x', 'REMOVE-ITEM x', 'Microsoft.PowerShell.Management\\Remove-Item x', 'Get-ChildItem | ForEach-Object { rm $_ }', 'Write-Output hi; ri x']) {
      assert.equal(ps(e, command).behavior, 'deny', command);
    }
    assert.equal(ps(e, 'Get-ChildItem').behavior, 'allow');
  });

  it("keeps Bash's deny and ask rules, but not its allow rules", () => {
    const cwd = tempProject();
    const e = engine(cwd, 'default', { deny: ['Bash(curl *)'], ask: ['Bash(git push *)'], allow: ['Bash(npm test *)'] });
    assert.equal(ps(e, 'curl https://example.com').behavior, 'deny');
    const push = ps(e, 'git push origin main');
    assert.equal(push.behavior, 'ask');
    assert.equal(push.forced, true);
    assert.equal(ps(e, 'npm test').behavior, 'ask');
    assert.equal(engine(cwd, 'default', { deny: ['Bash'] }).isToolRemoved('PowerShell'), true);
    assert.equal(engine(cwd, 'default', { deny: ['PowerShell'] }).isToolRemoved('Bash'), false);
  });

  it('lets an allow rule approve its command, and nothing joined to it', () => {
    const e = engine(tempProject(), 'default', { allow: ['PowerShell(npm test *)'] });
    assert.equal(ps(e, 'npm test').behavior, 'allow');
    assert.equal(ps(e, 'npm test -- --watch=false; git status').behavior, 'allow');
    assert.equal(ps(e, 'npm test; Remove-Item x').behavior, 'ask');
    assert.equal(ps(e, 'npm test > out.txt').behavior, 'ask');
    assert.equal(ps(e, 'npm test $args').behavior, 'ask');
  });

  it('offers to save the command as a rule', () => {
    const decision = ps(engine(tempProject()), 'npm run build');
    assert.deepEqual(decision.suggestions, [{ rule: 'PowerShell(npm run build)', persist: true }]);
  });

  it('always prompts before removing a critical path', () => {
    const cwd = tempProject();
    const critical = ['Remove-Item -Recurse -Force ~', 'rm -r .', 'del *', 'Remove-Item *.*','Remove-Item $dir -Recurse', 'rd ../..', 'Remove-Item env:PATH', 'Get-ChildItem | ForEach-Object { Remove-Item $_ }'];
    if (windows) critical.push('Remove-Item -Recurse -Force C:\\', 'Remove-Item C:\\Windows -Recurse', 'rm.exe -rf C:\\Users');
    for (const command of critical) {
      for (const e of [engine(cwd, 'default', { allow: ['PowerShell'] }), engine(cwd, 'bypassPermissions')]) {
        const decision = ps(e, command);
        assert.equal(decision.behavior, 'ask', command);
        assert.equal(decision.forced, true, command);
      }
    }
    assert.equal(ps(engine(cwd), 'Remove-Item build -Recurse').forced, undefined);
  });

  it('keeps plan mode to read-only commands', () => {
    const e = engine(tempProject(), 'plan');
    assert.equal(ps(e, 'Get-ChildItem').behavior, 'allow');
    assert.equal(ps(e, 'New-Item x.txt').behavior, 'deny');
  });

  it('accepts creating, copying and moving inside the working directories in acceptEdits mode', () => {
    const cwd = tempProject();
    const e = engine(cwd, 'acceptEdits');
    assert.equal(ps(e, 'New-Item -ItemType Directory build').behavior, 'allow');
    assert.equal(ps(e, 'mkdir out; Copy-Item a.txt out').behavior, 'allow');
    assert.equal(ps(e, 'Copy-Item ../secret.txt .').behavior, 'ask');
    assert.equal(ps(e, 'Move-Item a.txt .git/hooks/pre-commit').behavior, 'ask');
    assert.equal(ps(e, 'Remove-Item a.txt').behavior, 'ask');
  });

  it('asks when it changes directory before running git', () => {
    const e = engine(tempProject());
    assert.equal(ps(e, 'cd sub; Get-ChildItem').behavior, 'allow');
    assert.equal(ps(e, 'cd sub; git status').behavior, 'ask');
  });

  it('applies Read and Edit deny rules to the files a command names', () => {
    const cwd = tempProject();
    const e = engine(cwd, 'default', { deny: ['Read(.env)', 'Edit(/locked/**)'] });
    assert.equal(ps(e, 'Get-Content .env').behavior, 'deny');
    assert.equal(ps(e, 'type .env').behavior, 'deny');
    assert.equal(ps(e, 'Set-Content locked/a.txt hi').behavior, 'deny');
  });
});

describe('finding PowerShell', () => {
  const installed = (...files: string[]) => (path: string) => files.includes(path);

  it('prefers PowerShell 7, and falls back to Windows PowerShell', () => {
    const env = { PATH: 'C:\\Tools', SystemRoot: 'C:\\Windows', ProgramFiles: 'C:\\Program Files' };
    const system = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    assert.deepEqual(findPowerShell(env, installed('C:\\Tools\\pwsh.exe', system)), { file: 'C:\\Tools\\pwsh.exe', edition: 'pwsh' });
    assert.deepEqual(findPowerShell(env, installed('C:\\Program Files\\PowerShell\\7\\pwsh.exe', system)), { file: 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', edition: 'pwsh' });
    assert.deepEqual(findPowerShell(env, installed(system)), { file: system, edition: 'powershell' });
    assert.equal(findPowerShell(env, installed()), null);
  });
});

function setup(overrides: Partial<ToolContext> = {}): { dir: string; ctx: ToolContext } {
  const dir = tempProject();
  let cwd = dir;
  const ctx = {
    cwd: () => cwd,
    setCwd: (next: string) => {
      cwd = next;
    },
    workingDirs: () => [dir],
    secretEnvVars: ['KARST_TEST_SECRET'],
    tasks: new TaskRegistry({ logDir: join(dir, '.tasks') }),
    signal: new AbortController().signal,
    ...overrides,
  } as unknown as ToolContext;
  return { dir, ctx };
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe.skipIf(!windows)('PowerShell tool', () => {
  it('returns output, UTF-8 intact, and exit codes as errors', async () => {
    const { ctx } = setup();
    assert.equal((await powerShellTool.execute({ command: 'Write-Output "xin chào"' }, ctx)).content, 'xin chào');
    const failed = await powerShellTool.execute({ command: 'cmd /c "exit 5"' }, ctx);
    assert.equal(failed.isError, true);
    assert.equal(failed.exitCode, 5);
    const exited = await powerShellTool.execute({ command: 'Write-Output before; exit 3' }, ctx);
    assert.equal(exited.exitCode, 3);
    assert.match(exited.content, /before/);
  });

  it('prints objects as PowerShell formats them, even as a table', async () => {
    const { dir, ctx } = setup();
    assert.match((await powerShellTool.execute({ command: 'Get-Location' }, ctx)).content, new RegExp(`Path\\s+-+\\s+${dir.replaceAll('\\', '\\\\')}`));
    assert.match((await powerShellTool.execute({ command: 'Get-Item . | Select-Object Name, Mode' }, ctx)).content, /Name\s+Mode/);
  });

  it('reports errors as text, not CLIXML', async () => {
    const { ctx } = setup();
    const result = await powerShellTool.execute({ command: 'Get-Item does-not-exist' }, ctx);
    assert.equal(result.isError, true);
    assert.match(result.content, /Cannot find path/);
    assert.doesNotMatch(result.content, /CLIXML/);
  });

  it('carries the working directory across calls, within the working directories', async () => {
    const { dir, ctx } = setup();
    mkdirSync(join(dir, 'sub'));
    await powerShellTool.execute({ command: 'Set-Location sub; $x = 1' }, ctx);
    assert.equal(ctx.cwd(), join(dir, 'sub'));
    assert.equal((await powerShellTool.execute({ command: '(Get-Location).Path; "[$x]"' }, ctx)).content, `${join(dir, 'sub')}\r\n[]`);
    const outside = await powerShellTool.execute({ command: 'Set-Location ..\\..' }, ctx);
    assert.equal(ctx.cwd(), dir);
    assert.match(outside.content, /outside the working directories/);
  });

  it('hides credentials and leaves no script behind', async () => {
    const { ctx } = setup();
    const scripts = (): string[] => readdirSync(tmpdir()).filter((name) => name.startsWith('karst-ps-') && name.endsWith('.ps1'));
    const before = scripts();
    process.env.KARST_TEST_SECRET = 'super-secret-value';
    try {
      const output = (await powerShellTool.execute({ command: 'Get-ChildItem env: | Out-String -Width 400' }, ctx)).content;
      assert.doesNotMatch(output, /super-secret-value/);
    } finally {
      delete process.env.KARST_TEST_SECRET;
    }
    assert.deepEqual(scripts().filter((name) => !before.includes(name)), []);
  });

  it('enforces a timeout and ends what the command started', async () => {
    const { dir, ctx } = setup();
    const pidFile = join(dir, 'pid');
    const started = Date.now();
    const result = await powerShellTool.execute(
      { command: `$p = Start-Process -PassThru -WindowStyle Hidden ping -ArgumentList '-n','60','127.0.0.1'; [IO.File]::WriteAllText('${pidFile}', $p.Id); ping -n 60 127.0.0.1 > $null`, timeout: 3000 },
      ctx,
    );
    assert.equal(result.isError, true);
    assert.match(result.content, /timed out/);
    assert.ok(Date.now() - started < 10_000);
    assert.ok(existsSync(pidFile));
    const pid = Number(readFileSync(pidFile, 'utf8'));
    for (let waited = 0; waited < 3000 && isAlive(pid); waited += 100) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(isAlive(pid), false);
  });

  it('refuses a foreground Start-Sleep', async () => {
    const { ctx } = setup();
    assert.match((await powerShellTool.execute({ command: 'Start-Sleep -Seconds 30' }, ctx)).content, /sleep is blocked/);
  });

  it('runs background commands, logs their output and can stop them', async () => {
    const { ctx } = setup();
    const result = await powerShellTool.execute({ command: 'Write-Output from-bg; Start-Sleep 30', run_in_background: true }, ctx);
    assert.match(result.content, /task [0-9a-f]{8}/);
    const { pid, logPath } = ctx.tasks.list()[0]!;
    for (let waited = 0; waited < 5000 && !(existsSync(logPath) && readFileSync(logPath, 'utf8').includes('from-bg')); waited += 100) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.match(readFileSync(logPath, 'utf8'), /from-bg/);
    ctx.tasks.stopAll();
    for (let waited = 0; waited < 3000 && isAlive(pid); waited += 100) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(isAlive(pid), false);
  });
});

describe('PowerShell in the tool list', () => {
  it('is offered on Windows only', async () => {
    const { builtinTools } = await import('../src/tools/index.ts');
    assert.equal(builtinTools().some((tool) => tool.name === 'PowerShell'), windows);
  });

  it('describes the edition it runs', () => {
    if (!windows) return;
    assert.match(powerShellTool.description, /PowerShell (7|5\.1)/);
  });
});
