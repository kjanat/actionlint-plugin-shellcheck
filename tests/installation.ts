import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

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
`;
const source = "FLAGS='one two'\nSTABLE=one\n";

export async function prepare({
	directory,
}: Pick<Context, 'directory'>): Promise<void> {
	await mkdir(join(directory, '.github'), { recursive: true });
	await mkdir(join(directory, 'scripts'), { recursive: true });
	await writeFile(join(directory, 'workflow.yml'), workflow);
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

// Source edits must change findings; output protection must prevent overwriting
// the dependency read through the installed plugin's filesystem grants.
export async function verify({
	directory,
	run,
	runResult,
}: Context): Promise<{ checks: string[]; probe: string[] }> {
	const probe = ['check', '--json', '--no-ruff', 'workflow.yml'];
	const result = object(JSON.parse(await run(probe, 1)));
	assert.equal(result.completed, true);
	assert.equal(result.exit_code, 1);
	assert.ok(Array.isArray(result.diagnostics));
	assert.equal(result.diagnostics.length, 1);
	const diagnostic = object(result.diagnostics[0]);
	assert.equal(diagnostic.rule, 'shellcheck');
	assert.equal(diagnostic.code, 'SC2086');
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
		['check', '--no-ruff', '--output-file', path, '--yes', 'workflow.yml'],
		3,
	);
	assert.match(blocked.stderr, /also an input/);
	assert.equal(await readFile(path, 'utf8'), source);
	return {
		checks: [
			'SC2086 position',
			'source following',
			'source edits change findings',
			'source overwrite rejected',
		],
		probe,
	};
}
