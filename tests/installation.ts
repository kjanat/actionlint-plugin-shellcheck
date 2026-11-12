import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

interface Context {
	directory: string;
	run: (args: string[], expected?: number) => Promise<string>;
	runResult: (args: string[], expected?: number) => Promise<{ stdout: string; stderr: string }>;
}

const workflow = `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          . ./values.sh
          echo $FLAGS
          echo $STABLE
        working-directory: scripts
permissions: {}
`;
const source = "FLAGS='one two'\nSTABLE=one\n";
const directives = `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: leading
        # shellcheck disable=SC2086
        run: echo $LEADING
      - run: echo $TRAILING # shellcheck disable=SC2086
      - run: | # shellcheck disable=SC2086
          echo $BLOCK
      - run: echo $VISIBLE # shellcheck disable=SC2034
permissions: {}
`;
const invalidDirective = `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok # shellcheck shell=unknown
permissions: {}
`;

export async function prepare({
	directory,
}: Pick<Context, 'directory'>): Promise<void> {
	await mkdir(join(directory, '.github'), { recursive: true });
	await mkdir(join(directory, 'scripts'), { recursive: true });
	await writeFile(join(directory, 'workflow.yml'), workflow);
	await writeFile(join(directory, 'directives.yml'), directives);
	await writeFile(join(directory, 'invalid-directive.yml'), invalidDirective);
	await writeFile(join(directory, 'scripts', 'values.sh'), source);
	await writeFile(
		join(directory, '.github', 'actionlint.yaml'),
		`tools:
  ruff: false
  shellcheck:
    config:
      external-sources: true
      source-path: [scripts]
`,
	);
}

function object(value: unknown): Record<string, unknown> {
	assert.ok(
		typeof value === 'object' && value !== null && !Array.isArray(value),
	);
	return Object.fromEntries(Object.entries(value));
}

export async function verify({
	directory,
	run,
	runResult,
}: Context): Promise<{ checks: string[]; probe: string[] }> {
	const probe = ['check', '--json', '--no-tool', 'ruff', 'workflow.yml'];
	const result = object(JSON.parse(await run(probe, 1)));
	assert.equal(result.completed, true);
	assert.equal(result.exit_code, 1);
	assert.ok(Array.isArray(result.diagnostics));
	assert.equal(result.diagnostics.length, 1);
	const diagnostic = object(result.diagnostics[0]);
	assert.equal(diagnostic.rule, 'shellcheck');
	assert.equal(diagnostic.code, 'SC2086');
	assert.equal(diagnostic.message, 'Double quote to prevent globbing and word splitting');
	assert.deepEqual(diagnostic.start, { line: 8, column: 16 });
	assert.deepEqual(diagnostic.end, { line: 8, column: 22 });
	const path = join(directory, 'scripts', 'values.sh');
	await writeFile(path, 'FLAGS=one\nSTABLE=one\n');
	try {
		const changed = object(JSON.parse(await run(probe)));
		assert.equal(changed.completed, true);
		assert.equal(changed.exit_code, 0);
		assert.deepEqual(changed.diagnostics, []);
	} finally {
		await writeFile(path, source);
	}
	const blocked = await runResult(
		['check', '--no-tool', 'ruff', '--output-file', path, '--yes', 'workflow.yml'],
		3,
	);
	assert.match(blocked.stderr, /also an input/);
	assert.equal(await readFile(path, 'utf8'), source);
	const annotated = object(JSON.parse(await run(['check', '--json', '--no-tool', 'ruff', 'directives.yml'], 1)));
	assert.equal(annotated.completed, true);
	assert.equal(annotated.exit_code, 1);
	assert.ok(Array.isArray(annotated.diagnostics));
	assert.equal(annotated.diagnostics.length, 1);
	const remaining = object(annotated.diagnostics[0]);
	assert.equal(remaining.rule, 'shellcheck');
	assert.equal(remaining.code, 'SC2086');
	assert.deepEqual(remaining.start, { line: 12, column: 19 });
	assert.deepEqual(remaining.end, { line: 12, column: 27 });
	assert.ok(Array.isArray(remaining.fixes));
	assert.equal(remaining.fixes.length, 1);
	const edits = object(remaining.fixes[0]).edits;
	assert.ok(Array.isArray(edits));
	assert.equal(edits.length, 2);
	for (const [index, column] of [19, 27].entries()) {
		const edit = object(edits[index]);
		assert.ok(typeof edit.path === 'string');
		assert.equal(resolve(directory, edit.path), join(directory, 'directives.yml'));
		assert.deepEqual(edit.start, { line: 12, column });
		assert.deepEqual(edit.end, edit.start);
		assert.equal(edit.replacement, '"');
	}
	assert.equal(await readFile(join(directory, 'directives.yml'), 'utf8'), directives);
	const invalid = object(JSON.parse(await run(['check', '--json', '--no-tool', 'ruff', 'invalid-directive.yml'], 1)));
	assert.equal(invalid.completed, true);
	assert.equal(invalid.exit_code, 1);
	assert.ok(Array.isArray(invalid.diagnostics));
	assert.equal(invalid.diagnostics.length, 1);
	const directiveError = object(invalid.diagnostics[0]);
	assert.equal(directiveError.rule, 'shellcheck');
	assert.equal(directiveError.code, 'SC1103');
	assert.deepEqual(directiveError.start, { line: 6, column: 41 });
	assert.deepEqual(directiveError.fixes ?? [], []);
	return {
		checks: [
			'SC2086 position',
			'source following',
			'source edits change findings',
			'source overwrite rejected',
			'leading and trailing YAML directives suppress SC2086',
			'block header YAML directive suppresses SC2086',
			'remaining diagnostic and quote edits keep source positions',
			'invalid YAML directive reports comment position',
		],
		probe,
	};
}
