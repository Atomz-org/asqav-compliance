import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { analyzeFile, generateReport, globToRegExp, loadConfig, parseConfig, scanDirectory, EMPTY_CONFIG } from './scanner';

let passed: number = 0;
let failed: number = 0;

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`  PASS  ${name}`);
    passed++;
  } catch (err: unknown) {
    const message: string = err instanceof Error ? err.message : String(err);
    console.log(`  FAIL  ${name}`);
    console.log(`        ${message}`);
    failed++;
  }
}

console.log('\nRunning scanner tests...\n');

// === analyzeFile: framework detection ===

test('detects langchain import', () => {
  const content: string = `import langchain\nfrom langchain.agents import AgentExecutor\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.frameworks.includes('langchain'), 'Should detect langchain');
});

test('detects crewai from-import', () => {
  const content: string = `from crewai import Agent, Task, Crew\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.frameworks.includes('crewai'), 'Should detect crewai');
});

test('detects openai import', () => {
  const content: string = `import openai\nclient = openai.OpenAI()\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.frameworks.includes('openai'), 'Should detect openai');
});

test('detects anthropic import', () => {
  const content: string = `from anthropic import Anthropic\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.frameworks.includes('anthropic'), 'Should detect anthropic');
});

test('detects autogen import', () => {
  const content: string = `import autogen\nassistant = autogen.AssistantAgent("assistant")\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.frameworks.includes('autogen'), 'Should detect autogen');
});

test('detects google.generativeai import', () => {
  const content: string = `import google.generativeai as genai\nmodel = genai.GenerativeModel("gemini-pro")\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.frameworks.includes('google.generativeai'), 'Should detect google.generativeai');
});

// === analyzeFile: audit trail ===

test('detects asqav audit trail', () => {
  const content: string = `import openai\nimport asqav\nasqav.sign(action)\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.auditTrail.pass, 'Should detect asqav audit trail');
});

test('detects logging as audit trail', () => {
  const content: string = `import openai\nimport logging\nlogger = logging.getLogger(__name__)\nlogger.info("action taken")\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.auditTrail.pass, 'Should detect logging as audit trail');
});

test('detects action_log as audit trail', () => {
  const content: string = `import openai\naction_log.append({"action": "search"})\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.auditTrail.pass, 'Should detect action_log');
});

test('flags missing audit trail', () => {
  const content: string = `import openai\nclient = openai.OpenAI()\nresult = client.chat.completions.create()\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(!result.auditTrail.pass, 'Should flag missing audit trail');
});

// === analyzeFile: policy enforcement ===

test('detects rate_limit policy', () => {
  const content: string = `import openai\nrate_limit = 10\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.policyEnforcement.pass, 'Should detect rate_limit');
});

test('detects allowed_actions policy', () => {
  const content: string = `import openai\nallowed_actions = ["search", "email"]\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.policyEnforcement.pass, 'Should detect allowed_actions');
});

test('detects max_iterations policy', () => {
  const content: string = `from langchain import agents\nagent = agents.create(max_iterations=5)\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.policyEnforcement.pass, 'Should detect max_iterations');
});

test('flags missing policy enforcement', () => {
  const content: string = `import openai\nclient = openai.OpenAI()\nresult = client.chat.completions.create()\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(!result.policyEnforcement.pass, 'Should flag missing policy enforcement');
});

// === analyzeFile: revocation ===

test('detects kill_switch', () => {
  const content: string = `import openai\nif kill_switch:\n    sys.exit(1)\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.revocation.pass, 'Should detect kill_switch');
});

test('detects revoke pattern', () => {
  const content: string = `import openai\ndef revoke_agent(agent_id):\n    pass\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.revocation.pass, 'Should detect revoke');
});

test('flags missing revocation', () => {
  const content: string = `import openai\nclient = openai.OpenAI()\nresult = client.chat.completions.create()\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(!result.revocation.pass, 'Should flag missing revocation');
});

// === analyzeFile: human oversight ===

test('detects human_in_the_loop', () => {
  const content: string = `import openai\nhuman_in_the_loop = True\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.humanOversight.pass, 'Should detect human_in_the_loop');
});

test('detects require_approval', () => {
  const content: string = `import openai\n@require_approval\ndef dangerous_action():\n    pass\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.humanOversight.pass, 'Should detect require_approval');
});

test('detects hitl abbreviation', () => {
  const content: string = `import openai\nhitl_enabled = True\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.humanOversight.pass, 'Should detect hitl');
});

test('flags missing human oversight', () => {
  const content: string = `import openai\nclient = openai.OpenAI()\nresult = client.chat.completions.create()\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(!result.humanOversight.pass, 'Should flag missing human oversight');
});

// === analyzeFile: error handling ===

test('detects try/except error handling', () => {
  const content: string = `import openai\ntry:\n    result = openai.chat()\nexcept Exception as e:\n    handle(e)\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(result.errorHandling.pass, 'Should detect try/except');
});

test('flags missing error handling', () => {
  const content: string = `import openai\nresult = openai.chat()\n`;
  const result = analyzeFile('test.py', content);
  assert.ok(!result.errorHandling.pass, 'Should flag missing error handling');
});

// === analyzeFile: fully compliant file ===

test('fully compliant file scores all PASS', () => {
  const content: string = `
import openai
import asqav
import logging

logger = logging.getLogger(__name__)

rate_limit = 10
allowed_actions = ["search"]
kill_switch = False
human_in_the_loop = True

try:
    client = openai.OpenAI()
    asqav.sign(result)
    logger.info("Agent action completed")
except Exception as e:
    logger.error(f"Agent error: {e}")
`;
  const result = analyzeFile('compliant.py', content);
  assert.ok(result.auditTrail.pass, 'Audit trail should pass');
  assert.ok(result.policyEnforcement.pass, 'Policy enforcement should pass');
  assert.ok(result.revocation.pass, 'Revocation should pass');
  assert.ok(result.humanOversight.pass, 'Human oversight should pass');
  assert.ok(result.errorHandling.pass, 'Error handling should pass');
});

// === generateReport: empty results ===

test('generates report for no agent files', () => {
  const report: string = generateReport([]);
  assert.ok(report.includes('No AI agent framework usage detected'), 'Should mention no agent files');
  assert.ok(report.includes('asqav'), 'Should mention asqav');
});

// === generateReport: gaps ===

test('generates report with gaps', () => {
  const results = [
    analyzeFile('agent.py', `import openai\nclient = openai.OpenAI()\n`),
  ];
  const report: string = generateReport(results);
  assert.ok(report.includes('Compliance Score'), 'Should include compliance score');
  assert.ok(report.includes('GAP'), 'Should include GAP markers');
  assert.ok(report.includes('Recommendations'), 'Should include recommendations');
  assert.ok(report.includes('agent.py'), 'Should reference the file');
});

// === generateReport: compliant file ===

test('generates report with all PASS for compliant file', () => {
  const content: string = `
import openai
import asqav
rate_limit = 10
kill_switch = False
human_in_the_loop = True
try:
    openai.chat()
    asqav.sign(result)
except Exception as e:
    pass
`;
  const results = [analyzeFile('good.py', content)];
  const report: string = generateReport(results);
  assert.ok(report.includes('100'), 'Score should be 100');
  assert.ok(report.includes('PASS'), 'Should include PASS markers');
  assert.ok(!report.includes('Recommendations'), 'Should not include recommendations');
});

// === generateReport: score calculation ===

test('score is 0 when all checks fail', () => {
  const results = [
    analyzeFile('bad.py', `import openai\nclient = openai.OpenAI()\n`),
  ];
  const report: string = generateReport(results);
  assert.ok(report.includes('0/100'), 'Score should be 0/100');
});

test('score is partial when some checks pass', () => {
  const content: string = `import openai\nimport asqav\nasqav.sign(x)\nrate_limit = 5\n`;
  const results = [analyzeFile('partial.py', content)];
  const report: string = generateReport(results);
  assert.ok(report.includes('40/100'), 'Score should be 40/100 (audit + policy = 40)');
});

// === repository config (.asqav.json) ===

const TRACED: string = `from anthropic import Anthropic\nfrom pf import trace\n\ndef call():\n    tr = trace.get()\n    tr.intent('x')\n`;

test('without a config the built-in vocabulary decides', () => {
  assert.ok(!analyzeFile('agent.py', TRACED).auditTrail.pass, 'pf.trace is not a built-in audit pattern');
});

test('a repo pattern teaches the scanner how the codebase spells a control', () => {
  const config = parseConfig({ version: 1, patterns: { auditTrail: ['\\btrace\\.get\\(\\)'] } }, '.asqav.json');
  const result = analyzeFile('agent.py', TRACED, config);
  assert.ok(result.auditTrail.pass, 'the declared pattern satisfies the audit trail');
  assert.ok(result.auditTrail.matches.includes('trace.get()'), 'the match is reported');
});

test('repo patterns only add: built-in patterns still apply and nothing is switched off', () => {
  const config = parseConfig({ patterns: { auditTrail: ['never_matches_anything_zz'] } }, '.asqav.json');
  const content: string = `import openai\nimport logging\nlogger = logging.getLogger(__name__)\n`;
  assert.ok(analyzeFile('a.py', content, config).auditTrail.pass, 'logging still counts');
});

test('error handling accepts a repo pattern as an alternative to try/except', () => {
  const config = parseConfig({ patterns: { errorHandling: ['NoCredentials'] } }, '.asqav.json');
  const content: string = `import anthropic\nraise NoCredentials('no key')\n`;
  assert.ok(analyzeFile('b.py', content, config).errorHandling.pass);
  assert.ok(!analyzeFile('b.py', content).errorHandling.pass);
});

test('a broken config never breaks the scan: every problem is a warning', () => {
  const c = parseConfig({ exclude: 'tests', patterns: { auditTrail: ['(unclosed'], nonsense: ['x'], humanOversight: 'x' } }, '.asqav.json');
  assert.strictEqual(c.exclude.length, 0);
  assert.ok(!c.patterns.auditTrail, 'an invalid regex is skipped');
  assert.strictEqual(c.warnings.length, 4, c.warnings.join(' | '));
  const v = parseConfig({ version: 2 }, '.asqav.json');
  assert.ok(v.warnings[0].includes('unsupported version') && !v.source, 'an unknown version falls back to defaults');
  assert.ok(parseConfig([1, 2], 'x').warnings.length === 1);
});

test('globs: ** crosses directories, * does not', () => {
  assert.ok(globToRegExp('**/tests/**').test('platform/tests/gate/test_loops.py'));
  assert.ok(globToRegExp('**/tests/**').test('tests/a.py'));
  assert.ok(globToRegExp('**/test_*.py').test('pkg/test_x.py'));
  assert.ok(!globToRegExp('src/*.py').test('src/a/b.py'));
  assert.ok(globToRegExp('src/*.py').test('src/a.py'));
  assert.ok(globToRegExp('docs/v1.0/**').test('docs/v1.0/x.py') && !globToRegExp('docs/v1.0/**').test('docs/v100/x.py'), 'dots are literal');
});

test('excluded paths are not scanned; the rest are, from the repository root', () => {
  const root: string = fs.mkdtempSync(path.join(os.tmpdir(), 'asqav-'));
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'platform', 'tests'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'agent.py'), 'import anthropic\n');
  fs.writeFileSync(path.join(root, 'platform', 'tests', 'test_agent.py'), 'import anthropic\n');
  fs.writeFileSync(path.join(root, '.asqav.json'), JSON.stringify({ version: 1, exclude: ['**/tests/**'] }));
  const config = loadConfig(root);
  assert.strictEqual(config.source, '.asqav.json');
  const all = scanDirectory(root).map((f) => path.relative(root, f.filePath)).sort();
  const scoped = scanDirectory(root, config, root).map((f) => path.relative(root, f.filePath)).sort();
  assert.deepStrictEqual(all, [path.join('platform', 'tests', 'test_agent.py'), path.join('src', 'agent.py')]);
  assert.deepStrictEqual(scoped, [path.join('src', 'agent.py')]);
});

test('no config file is not an error; an explicit missing one is a warning; bad JSON falls back', () => {
  const root: string = fs.mkdtempSync(path.join(os.tmpdir(), 'asqav-'));
  assert.strictEqual(loadConfig(root), EMPTY_CONFIG);
  assert.ok(loadConfig(root, 'governance/asqav.json').warnings[0].includes('not found'));
  fs.writeFileSync(path.join(root, '.asqav.json'), '{ not json');
  const bad = loadConfig(root);
  assert.ok(!bad.source && bad.warnings[0].includes('not valid JSON'));
});

test('the report says when a repository config extended the vocabulary', () => {
  const config = parseConfig({ patterns: { auditTrail: ['trace\\.get'] }, exclude: ['**/tests/**'] }, '.asqav.json');
  const report: string = generateReport([analyzeFile('agent.py', TRACED, config)], config);
  assert.ok(report.includes('Repository config `.asqav.json`'), 'config named');
  assert.ok(report.includes('Audit Trail +1') && report.includes('`**/tests/**`'), 'what it added');
  assert.ok(report.includes('Built-in patterns still apply'));
  assert.ok(!generateReport([analyzeFile('agent.py', TRACED)]).includes('Repository config'), 'silent without one');
});

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);

if (failed > 0) {
  process.exit(1);
}
