// Template file: identical in every repository that adopts repo-policy. Change
// it in shockstruck/agent-platform, not here. Everything repository-specific is
// `repository` and `probity` in .claude/hooks/policy.json.
//
// Probity carries the one rule that needs a judge: commit scope. Everything
// deterministic — blocked executables, unsafe Git and gh forms, added
// commentary, the validation gate — stays in the sibling hooks, where it costs
// no tokens and cannot be argued with.
import { defineConfig } from '@nizos/probity'
import type { Action, RuleContext, RuleResult, SessionEvent } from '@nizos/probity'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// The repository the agent is editing, which is not necessarily the directory
// this file sits in: the dispatcher runs merged policy out of a pinned cache.
// CLAUDE_PROJECT_DIR is the checkout root and is always set by the dispatcher;
// the fallback covers running this config from the tree directly.
const ROOT = process.env.CLAUDE_PROJECT_DIR
  ? path.resolve(process.env.CLAUDE_PROJECT_DIR)
  : path.dirname(fileURLToPath(import.meta.url))

type Policy = { repository?: string; probity?: { extraInstructions?: string } }

/** The repository's slots. Policy comes from the pinned copy when there is one. */
function loadPolicy(): Policy {
  const candidates = [
    process.env.MULTICA_POLICY_DIR
      ? path.join(process.env.MULTICA_POLICY_DIR, '.claude', 'hooks', 'policy.json')
      : undefined,
    path.join(ROOT, '.claude', 'hooks', 'policy.json'),
  ].filter((candidate): candidate is string => Boolean(candidate))
  for (const candidate of candidates) {
    try {
      return JSON.parse(fs.readFileSync(candidate, 'utf8')) as Policy
    } catch {
      continue
    }
  }
  return {}
}

const POLICY = loadPolicy()
const REPOSITORY = POLICY.repository?.trim() || 'this repository'
const EXTRA_INSTRUCTIONS = POLICY.probity?.extraInstructions?.trim() ?? ''

// The built-in maxEvents / maxContentChars options belong to enforceTdd, which
// this config does not use. The custom rule windows its own history; these are
// the equivalents, sized so a commit prompt stays well inside a single turn.
/** Session events carry the agent's raw `file_path`, which may be absolute. */
function repoRelativePath(candidate: string): string {
  return path.relative(ROOT, path.resolve(ROOT, candidate))
}

function insideRepo(candidate: string): boolean {
  const relative = repoRelativePath(candidate)
  return !relative.startsWith('..') && !path.isAbsolute(relative)
}

const MAX_WRITE_EVENTS = 40
const MAX_PROMPT_EVENTS = 8
const MAX_CONTENT_CHARS = 800
const MAX_OUTCOME_CHARS = 300
const MAX_DIFF_STAT_CHARS = 1000
const MAX_DIFF_CHARS = 4000

const RESPONSE_SPEC = `## Response format

Respond with a single JSON object of exactly this shape:
{"kind":"pass"|"violation","reason":"<short explanation>"}
On "pass", leave reason an empty string (""); only a "violation" needs an explanation.
Return JSON only. No prose, no code fences.`

// A commit is what the session is about to record, so the whole session's writes
// are the unit of judgement — not the pending command text. The diff the commit
// will record is what settles which of those writes are in it: an Edit event only
// carries the tool's replacement text, which repeats whatever unchanged text the
// edit was anchored on, so the writes alone overstate what changed.
const COMMIT_INSTRUCTIONS = `## Role

You are reviewing the scope of a commit an agent is about to make in ${REPOSITORY}.
You judge scope only. Another gate already checks that validation ran and that the
command itself is safe.

## What you judge

The commit diff is authoritative for what the commit contains: a file or hunk that is
not in it is not part of this commit. The operator prompt and the session's writes are
context for what the change was for; use them to decide whether every hunk in the diff
serves that one outcome. A write shows the text the tool put in place, which repeats
the unchanged text it was anchored on (inserting before a block re-emits that block),
so text a write shows that the diff does not add is pre-existing, never bundled scope.

When the commit diff section is empty or unavailable, judge the writes as the commit's
content instead.

## What you block

**Bundled scope.** The commit mixes the change the operator asked for with
unrelated work: an incidental cleanup, a version bump, a refactor, a rename, or a
second component's configuration carried along with a fix. The rule is the smallest
reversible change per commit.

## What you must not block

- A change that is large but coherent: every hunk serves the one stated outcome.
- Edits that are mechanically required by the asked-for change (a new file plus the
  manifest entry that wires it, a value plus the schema that validates it, code plus
  its test).
- Repository housekeeping the operator asked for directly.
- Missing evidence. When the writes or the operator prompt are absent, do not infer
  a violation from the absence.
- A partial commit. A commit is complete when what it records belongs together;
  work the session did that this diff does not carry is not missing from it, and a
  fix-up to a change already landed needs no tests, docs or changelog of its own to
  be in scope.
- A multi-part outcome the operator named as one: an adoption, a migration, a
  template sync, a repository-wide scrub. Each part that serves that one outcome
  belongs, whatever else it also touches.
- Where an insertion sits. The pre-existing text a hunk is anchored on or sits next
  to is never scope — only the diff's own added or removed lines are.

Each write shows the outcome the agent got back. A write whose outcome records a
denial or an error never landed: it is not part of this commit, and it is not bundled
scope. Judge the writes that succeeded.

Judge only what the inputs show. Do not speculate about files you were not given.`

type Verdict = { kind: 'pass' | 'violation'; reason: string }

// Every refusal ends on the step that is allowed, so the agent can carry on.
const SPLIT_COMMIT =
  'Allowed next step: unstage what does not serve the asked-for outcome ' +
  '(`git restore --staged <path>`), commit the rest, then commit any in-scope remainder ' +
  'separately; leave unrelated work intact for its owner.'
const RETRY_OR_REPORT =
  'Allowed next step: report the unavailable validator or transcript for runtime repair, ' +
  'preserve the change uncommitted and continue independent work; retry the commit only ' +
  'after the validator and readable session history are restored.'

function truncate(text: string, limit = MAX_CONTENT_CHARS): string {
  if (text.length <= limit) return text
  return `${text.slice(0, limit)}\n… (${text.length - limit} more characters)`
}

async function readHistory(ctx?: RuleContext): Promise<SessionEvent[] | undefined> {
  if (!ctx?.history) return undefined
  try {
    return await ctx.history()
  } catch {
    return undefined
  }
}

function formatEvent(event: SessionEvent): string {
  switch (event.kind) {
    case 'prompt':
      return `Operator: ${truncate(event.text)}`
    case 'command':
      return `Ran: ${truncate(event.command)}`
    // The outcome matters as much as the attempt: a write a hook denied left
    // nothing behind, and must not be judged as part of the change.
    case 'write':
      return `Wrote ${event.path} → ${truncate(event.output, MAX_OUTCOME_CHARS)}\n${truncate(event.content)}`
    case 'other':
      return `${event.tool}: ${truncate(String(event.output))}`
  }
}

const HOOK_LIB = path.join(ROOT, '.claude', 'hooks', 'lib')
// What the commit records: `none` when the command is not a commit, `index`
// for the staged changes, `all` when `-a`/`--all` stages every tracked change
// at commit time. The short-flag grammar is the one block-git-unsafe.sh applies
// to the same command, so `-am msg` and `-m -a` read the same way in both.
const GIT_COMMIT_PROBE = [
  'import sys',
  `sys.path.insert(0, ${JSON.stringify(HOOK_LIB)})`,
  'from git_command import invocations, parse',
  "commits = [i for i in invocations(sys.stdin.read(), strict=False) if i.subcommand == 'commit']",
  'mode = "none"',
  'for invocation in commits:',
  '    flags, longs, _ = parse(invocation.arguments, "mFCct")',
  '    mode = "all" if "a" in flags or "--all" in longs else "index"',
  '    if mode == "all":',
  '        break',
  'print(mode)',
].join('\n')

type CommitMode = 'none' | 'index' | 'all'

/**
 * Whether the command actually runs `git commit`, and what it records, via the
 * same tokenizer `block-git-unsafe.sh` and `require-validation-before-git.sh`
 * use: it unwraps `bash -c`, `xargs` and clause chains, and strips heredoc
 * bodies, so a command that merely quotes the words "git commit" is not
 * mistaken for one. A word check first keeps the interpreter off the path of
 * every other Bash call.
 */
function commitMode(command: string): CommitMode {
  if (!/\bcommit\b/.test(command)) return 'none'
  try {
    const stdout = execFileSync('python3', ['-c', GIT_COMMIT_PROBE], {
      input: command,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    const mode = stdout.trim()
    return mode === 'index' || mode === 'all' ? mode : 'none'
  } catch {
    // The deterministic Git hooks already deny a command they cannot tokenize,
    // so an unparseable one never reaches a commit worth judging here.
    return 'none'
  }
}

function git(...args: string[]): string {
  return execFileSync('git', args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
}

/**
 * The tree Git's own merge would have produced when a merge is in progress:
 * every change the incoming side brings is already in it, and a conflict it
 * could not settle is in it with its markers. Undefined outside a merge, and
 * when `merge-tree --write-tree` (Git 2.38) is missing or fails, so an older
 * Git degrades to judging the whole incoming side rather than to silence.
 */
function autoMergeTree(): string | undefined {
  try {
    git('rev-parse', '-q', '--verify', 'MERGE_HEAD')
  } catch {
    return undefined
  }
  const result = spawnSync('git', ['merge-tree', '--write-tree', 'HEAD', 'MERGE_HEAD'], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  // Exit 1 is a merge with conflicts, and the first line is still the tree.
  if (result.error || (result.status !== 0 && result.status !== 1)) return undefined
  const tree = result.stdout.split('\n', 1)[0].trim()
  return /^[0-9a-f]{40,64}$/.test(tree) ? tree : undefined
}

/** The `git diff` range the commit will record, shared by every reader of it. */
function commitRange(mode: Exclude<CommitMode, 'none'>, mergeTree: string | undefined): string[] {
  if (mergeTree) return mode === 'all' ? [mergeTree] : ['--cached', mergeTree]
  return mode === 'all' ? ['HEAD'] : ['--cached']
}

/**
 * The diff the commit will record: the index, or every tracked change against
 * HEAD when the command stages at commit time. During a merge the base is the
 * auto-merge tree instead, so the diff is only what the session resolved by
 * hand and the incoming side's own commits are not judged as this commit's
 * scope. Undefined when Git cannot say, so the judge falls back to the writes
 * rather than reading silence as an empty commit. The patch is hunks only
 * (`-U0`): the judge needs what changed, not the context around it, and the
 * stat lists every file even when the patch is cut.
 */
function commitDiff(
  mode: Exclude<CommitMode, 'none'>,
  mergeTree: string | undefined,
): string | undefined {
  const range = commitRange(mode, mergeTree)
  try {
    const stat = git('diff', ...range, '--stat=200,160', '--no-color').trim()
    if (!stat) return ''
    const patch = git('diff', ...range, '-U0', '--no-color', '--no-ext-diff').trim()
    return `${truncate(stat, MAX_DIFF_STAT_CHARS)}\n\n${truncate(patch, MAX_DIFF_CHARS)}`
  } catch {
    return undefined
  }
}

/**
 * The repository-relative paths the commit will record, from the same range
 * `commitDiff` reads. Undefined when Git cannot say, so the caller falls back
 * to showing every write rather than trusting an empty filter it cannot verify.
 */
function commitFiles(
  mode: Exclude<CommitMode, 'none'>,
  mergeTree: string | undefined,
): string[] | undefined {
  const range = commitRange(mode, mergeTree)
  try {
    const names = git('diff', ...range, '--name-only', '--no-color').trim()
    return names ? names.split('\n') : []
  } catch {
    return undefined
  }
}

/**
 * AI-judged commit scope. One model call per `git commit`, and none at all when
 * the session recorded no writes.
 */
async function commitScope(action: Action, ctx?: RuleContext): Promise<RuleResult> {
  if (action.kind !== 'command') return { kind: 'pass' }
  const mode = commitMode(action.command)
  if (mode === 'none') return { kind: 'pass' }
  if (!ctx?.agent) {
    return {
      kind: 'violation',
      reason: `commit scope: no AI validator available to judge this commit. ${RETRY_OR_REPORT}`,
    }
  }

  const history = await readHistory(ctx)
  if (history === undefined) {
    return {
      kind: 'violation',
      reason:
        'commit scope: the session transcript could not be read, so the commit scope cannot be ' +
        `judged. ${RETRY_OR_REPORT}`,
    }
  }

  // Only a write inside this repository can be part of this commit. A session
  // that also edited another checkout is not bundling scope here, so writes
  // outside ROOT are dropped before the judge sees them. A tool call the model
  // issued without a path was refused before it ran and wrote nothing.
  const writes = history.flatMap((event) =>
    event.kind === 'write' && typeof event.path === 'string' && insideRepo(event.path)
      ? [event]
      : [],
  )
  if (writes.length === 0) return { kind: 'pass' }

  const prompts = history
    .filter((event): event is Extract<SessionEvent, { kind: 'prompt' }> => event.kind === 'prompt')
    .slice(-MAX_PROMPT_EVENTS)
  const mergeTree = autoMergeTree()
  const diff = commitDiff(mode, mergeTree)
  // Nothing staged yet is what `git add … && git commit …` looks like before it
  // runs: the add stages at run time, so the writes are the commit's content.
  const stagedByCommand = diff === '' && !mergeTree
  // Only a write whose path the commit diff actually carries can be part of
  // this commit; everything else in the session — an earlier landed unit, a
  // scratch file, a re-emitted anchor — is bundled scope only in appearance.
  // Filtering is skipped, not emptied, when Git could not report the diff or
  // the command stages its own changes.
  const filesInCommit =
    diff === undefined || stagedByCommand ? undefined : commitFiles(mode, mergeTree)
  const scopedWrites =
    filesInCommit === undefined
      ? writes
      : writes.filter((event) => filesInCommit.includes(repoRelativePath(event.path)))
  const recentWrites = scopedWrites.slice(-MAX_WRITE_EVENTS)

  const prompt = [
    EXTRA_INSTRUCTIONS ? `${COMMIT_INSTRUCTIONS}\n\n${EXTRA_INSTRUCTIONS}` : COMMIT_INSTRUCTIONS,
    `## What the operator asked for\n\n${
      prompts.length
        ? prompts.map(formatEvent).join('\n\n')
        : '(no operator prompt in the transcript)'
    }`,
    `${filesInCommit === undefined ? '## Writes in this session' : '## Writes in this session that touch files in this commit'}\n\n${
      recentWrites.length
        ? recentWrites.map(formatEvent).join('\n')
        : '(none of this session\'s writes touches a file in this commit)'
    }`,
    `## Commit diff\n\n${
      mergeTree
        ? '(a merge is in progress: the diff is against the automatic merge of HEAD and ' +
          'MERGE_HEAD, so it shows only what the session resolved by hand)\n\n'
        : ''
    }${
      diff === undefined
        ? '(unavailable: Git could not report the diff)'
        : diff ||
          (mergeTree
            ? '(empty: the merge resolved every change automatically)'
            : '(empty: nothing is staged yet; the command stages its changes when it runs, ' +
              'so judge the writes as the commit\'s content)')
    }`,
    `## Pending command\n\n${truncate(action.command, 2000)}`,
    RESPONSE_SPEC,
  ].join('\n\n')

  const verdict: Verdict = await ctx.agent.reason(prompt)
  if (verdict.kind === 'violation') {
    return { kind: 'violation', reason: `commit scope: ${verdict.reason} ${SPLIT_COMMIT}` }
  }
  return { kind: 'pass' }
}

export default defineConfig({
  rules: [commitScope],
})
