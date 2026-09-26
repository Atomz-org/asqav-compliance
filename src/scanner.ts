// Static-pattern scanner for AI agent governance gaps in Python agent files.

import * as fs from 'fs';
import * as path from 'path';

export interface FileResult {
  filePath: string;
  content: string;
}

interface GovCheck {
  pass: boolean;
  matches: string[];
}

export interface AnalysisResult {
  filePath: string;
  frameworks: string[];
  auditTrail: GovCheck;
  policyEnforcement: GovCheck;
  revocation: GovCheck;
  humanOversight: GovCheck;
  errorHandling: GovCheck;
}

export type CategoryKey = 'auditTrail' | 'policyEnforcement' | 'revocation' | 'humanOversight' | 'errorHandling';

const CATEGORY_KEYS: CategoryKey[] = ['auditTrail', 'policyEnforcement', 'revocation', 'humanOversight', 'errorHandling'];

/**
 * A repository's own vocabulary, read from `.asqav.json` at the scan root (or
 * the `config` input). It can only *add*: extra patterns per category, and
 * paths to leave out (tests, fixtures, examples). The built-in patterns always
 * apply, so a config cannot switch a check off — it can only teach the scanner
 * how this codebase spells a control it already has.
 */
export interface ScanConfig {
  source: string | null;
  exclude: string[];
  excludeRes: RegExp[];
  patterns: Partial<Record<CategoryKey, RegExp[]>>;
  warnings: string[];
}

export const EMPTY_CONFIG: ScanConfig = { source: null, exclude: [], excludeRes: [], patterns: {}, warnings: [] };

export const CONFIG_FILE = '.asqav.json';

/** A path glob as a regex over `/`-separated relative paths: `**` crosses directories, `*` and `?` do not. */
export function globToRegExp(glob: string): RegExp {
  let out: string = '';
  for (let i = 0; i < glob.length; i++) {
    const c: string = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') {
        i++;
        out += '(?:.*/)?';
      } else {
        out += '.*';
      }
    } else if (c === '*') {
      out += '[^/]*';
    } else if (c === '?') {
      out += '[^/]';
    } else {
      out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${out}$`);
}

/** Parse a config object; problems become warnings and the scan falls back to defaults. */
export function parseConfig(raw: unknown, source: string): ScanConfig {
  const config: ScanConfig = { source, exclude: [], excludeRes: [], patterns: {}, warnings: [] };
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    config.warnings.push(`${source}: expected a JSON object; ignored`);
    return { ...EMPTY_CONFIG, warnings: config.warnings };
  }
  const obj = raw as Record<string, unknown>;
  if (obj.version !== undefined && obj.version !== 1) {
    config.warnings.push(`${source}: unsupported version ${String(obj.version)}; ignored`);
    return { ...EMPTY_CONFIG, warnings: config.warnings };
  }
  if (obj.exclude !== undefined) {
    if (!Array.isArray(obj.exclude)) {
      config.warnings.push(`${source}: "exclude" must be a list of globs; ignored`);
    } else {
      for (const g of obj.exclude) {
        if (typeof g === 'string' && g.trim()) {
          config.exclude.push(g.trim());
          config.excludeRes.push(globToRegExp(g.trim().replace(/^\.\//, '')));
        } else {
          config.warnings.push(`${source}: exclude entry ${JSON.stringify(g)} is not a glob; skipped`);
        }
      }
    }
  }
  const patterns = obj.patterns;
  if (patterns !== undefined) {
    if (typeof patterns !== 'object' || patterns === null || Array.isArray(patterns)) {
      config.warnings.push(`${source}: "patterns" must map a category to a list of regexes; ignored`);
    } else {
      for (const [key, list] of Object.entries(patterns as Record<string, unknown>)) {
        if (!CATEGORY_KEYS.includes(key as CategoryKey)) {
          config.warnings.push(`${source}: unknown category "${key}" (expected one of ${CATEGORY_KEYS.join(', ')}); skipped`);
          continue;
        }
        if (!Array.isArray(list)) {
          config.warnings.push(`${source}: patterns.${key} must be a list; skipped`);
          continue;
        }
        const compiled: RegExp[] = [];
        for (const p of list) {
          try {
            if (typeof p !== 'string' || !p) throw new Error('not a string');
            compiled.push(new RegExp(p));
          } catch (e) {
            config.warnings.push(`${source}: patterns.${key} entry ${JSON.stringify(p)} is not a valid regex; skipped`);
          }
        }
        if (compiled.length) config.patterns[key as CategoryKey] = compiled;
      }
    }
  }
  return config;
}

/** The repository config at `explicit` (relative to root) or `<root>/.asqav.json`; none is not an error. */
export function loadConfig(root: string, explicit: string = ''): ScanConfig {
  const file: string = path.resolve(root, explicit || CONFIG_FILE);
  if (!fs.existsSync(file)) {
    return explicit ? { ...EMPTY_CONFIG, warnings: [`config ${explicit} not found; scanning with defaults`] } : EMPTY_CONFIG;
  }
  const source: string = path.relative(root, file) || CONFIG_FILE;
  try {
    return parseConfig(JSON.parse(fs.readFileSync(file, 'utf-8')), source);
  } catch (e) {
    const message: string = e instanceof Error ? e.message : String(e);
    return { ...EMPTY_CONFIG, warnings: [`${source}: not valid JSON (${message}); scanning with defaults`] };
  }
}

export function isExcluded(relativePath: string, config: ScanConfig): boolean {
  const rel: string = relativePath.split(path.sep).join('/');
  return config.excludeRes.some((re: RegExp) => re.test(rel));
}

export function extraPatternCount(config: ScanConfig): number {
  return Object.values(config.patterns).reduce((n: number, list?: RegExp[]) => n + (list ? list.length : 0), 0);
}

const AGENT_FRAMEWORK_PATTERNS: RegExp[] = [
  /^\s*(?:import\s+(?:langchain|crewai|openai|anthropic|autogen|google\.generativeai|smolagents|llama_index|haystack|semantic_kernel|dspy|pydantic_ai))/m,
  /^\s*(?:from\s+(?:langchain|crewai|openai|anthropic|autogen|google\.generativeai|smolagents|llama_index|haystack|semantic_kernel|dspy|pydantic_ai)[\s.])/m,
];

const AUDIT_TRAIL_PATTERNS: RegExp[] = [
  /import\s+asqav/,
  /from\s+asqav\s+import/,
  /asqav\./,
  /\.sign\s*\(/,
  /audit_trail/i,
  /log_action/i,
  /action_log/i,
  /audit_log/i,
  /logging\.getLogger/,
  /logger\.\w+\(/,
];

const POLICY_PATTERNS: RegExp[] = [
  /rate_limit/i,
  /ratelimit/i,
  /policy/i,
  /\bscope\b/i,
  /allowed_actions/i,
  /action_gate/i,
  /\bguard\b/i,
  /permission/i,
  /restrict/i,
  /whitelist/i,
  /allowlist/i,
  /max_iterations/i,
  /max_steps/i,
  /\btimeout\b/i,
];

const REVOCATION_PATTERNS: RegExp[] = [
  /revoke/i,
  /\bdisable[d]?\b/i,
  /kill_switch/i,
  /killswitch/i,
  /suspend/i,
  /shutdown/i,
  /terminate/i,
  /emergency_stop/i,
  /circuit_breaker/i,
];

const HUMAN_OVERSIGHT_PATTERNS: RegExp[] = [
  /human_in_the_loop/i,
  /human_in_loop/i,
  /hitl/i,
  /\bapproval\b/i,
  /approve/i,
  /multi_party/i,
  /require_approval/i,
  /manual_review/i,
  /human_review/i,
  /confirm_action/i,
  /await_confirmation/i,
  /human_oversight/i,
];

const ERROR_HANDLING_PATTERN: RegExp = /try\s*:/;
const EXCEPT_PATTERN: RegExp = /except\s*(?:\w|[:(])/;

// Skips build/venv dirs, symlinks, and files over 1 MiB.
export function scanDirectory(dirPath: string, config: ScanConfig = EMPTY_CONFIG, root: string = dirPath): FileResult[] {
  const results: FileResult[] = [];

  function walk(currentPath: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch (err) {
      return;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const fullPath: string = path.join(currentPath, entry.name);

      if (isExcluded(path.relative(root, fullPath), config)) continue;

      if (entry.isDirectory()) {
        const skip: string[] = [
          'node_modules', '.git', '__pycache__', '.venv', 'venv',
          'env', '.env', '.tox', '.mypy_cache', '.pytest_cache',
          'dist', 'build', '.eggs',
        ];
        if (!skip.includes(entry.name)) {
          walk(fullPath);
        }
        continue;
      }

      if (!entry.name.endsWith('.py')) continue;

      const stat: fs.Stats = fs.statSync(fullPath);
      if (stat.size > 1024 * 1024) continue;

      let content: string;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch (err) {
        continue;
      }

      const usesAgent: boolean = AGENT_FRAMEWORK_PATTERNS.some((pat: RegExp) => pat.test(content));
      if (usesAgent) {
        results.push({ filePath: fullPath, content });
      }
    }
  }

  walk(dirPath);
  return results;
}

function checkPatterns(patterns: RegExp[], content: string): GovCheck {
  return {
    pass: patterns.some((p: RegExp) => p.test(content)),
    matches: patterns
      .filter((p: RegExp) => p.test(content))
      .map((p: RegExp) => {
        const m: RegExpMatchArray | null = content.match(p);
        return m ? m[0].trim() : null;
      })
      .filter((v): v is string => v !== null),
  };
}

export function analyzeFile(filePath: string, content: string, config: ScanConfig = EMPTY_CONFIG): AnalysisResult {
  const withRepo = (key: CategoryKey, builtin: RegExp[]): RegExp[] => [...builtin, ...(config.patterns[key] || [])];
  const detectedFrameworks: string[] = [];
  for (const pat of AGENT_FRAMEWORK_PATTERNS) {
    const match: RegExpMatchArray | null = content.match(pat);
    if (match) {
      const line: string = match[0].trim();
      const fwMatch: RegExpMatchArray | null = line.match(/(?:import|from)\s+([\w.]+)/);
      if (fwMatch && !detectedFrameworks.includes(fwMatch[1].replace(/\.$/, ''))) {
        detectedFrameworks.push(fwMatch[1].replace(/\.$/, ''));
      }
    }
  }

  const auditTrail: GovCheck = checkPatterns(withRepo('auditTrail', AUDIT_TRAIL_PATTERNS), content);
  const policyEnforcement: GovCheck = checkPatterns(withRepo('policyEnforcement', POLICY_PATTERNS), content);
  const revocation: GovCheck = checkPatterns(withRepo('revocation', REVOCATION_PATTERNS), content);
  const humanOversight: GovCheck = checkPatterns(withRepo('humanOversight', HUMAN_OVERSIGHT_PATTERNS), content);

  const hasTry: boolean = ERROR_HANDLING_PATTERN.test(content);
  const hasExcept: boolean = EXCEPT_PATTERN.test(content);
  const repoErrors: GovCheck = checkPatterns(config.patterns.errorHandling || [], content);
  const errorHandling: GovCheck = {
    pass: (hasTry && hasExcept) || repoErrors.pass,
    matches: [...(hasTry && hasExcept ? ['try/except'] : []), ...repoErrors.matches],
  };

  return {
    filePath,
    frameworks: detectedFrameworks,
    auditTrail,
    policyEnforcement,
    revocation,
    humanOversight,
    errorHandling,
  };
}

interface CategoryDef {
  key: CategoryKey;
  label: string;
}

interface CategoryTotal {
  pass: number;
  gap: number;
  files: string[];
}

// Canonical ordered list of governance categories; single source for keys + labels.
const GOVERNANCE_CATEGORIES: CategoryDef[] = [
  { key: 'auditTrail', label: 'Audit Trail' },
  { key: 'policyEnforcement', label: 'Policy Enforcement' },
  { key: 'revocation', label: 'Revocation Capability' },
  { key: 'humanOversight', label: 'Human Oversight' },
  { key: 'errorHandling', label: 'Error Handling' },
];

// Weight each category equally toward a 0-100 compliance score (empty category counts as full).
export function computeScore(results: AnalysisResult[]): number {
  let score: number = 0;
  for (const { key } of GOVERNANCE_CATEGORIES) {
    const total: number = results.length;
    const passCount: number = results.filter((r: AnalysisResult) => r[key].pass).length;
    score += total > 0 ? (passCount / total) * 20 : 20;
  }
  return Math.round(score);
}

function configNote(config: ScanConfig): string[] {
  if (!config.source) return [];
  const parts: string[] = [];
  const n: number = extraPatternCount(config);
  if (n) {
    const per: string = (Object.entries(config.patterns) as [CategoryKey, RegExp[]][])
      .map(([k, v]) => `${GOVERNANCE_CATEGORIES.find((c) => c.key === k)?.label ?? k} +${v.length}`).join(', ');
    parts.push(`${n} extra pattern(s) (${per})`);
  }
  if (config.exclude.length) parts.push(`${config.exclude.length} excluded path(s): ${config.exclude.map((e) => `\`${e}\``).join(', ')}`);
  return parts.length
    ? [`> Repository config \`${config.source}\`: ${parts.join('; ')}. Built-in patterns still apply.`, '']
    : [];
}

export function generateReport(results: AnalysisResult[], config: ScanConfig = EMPTY_CONFIG): string {
  if (results.length === 0) {
    return [
      '## :shield: AI Agent Governance Report',
      '',
      ...configNote(config),
      '**No AI agent framework usage detected.** No Python files importing known agent frameworks (LangChain, CrewAI, OpenAI, Anthropic, AutoGen, etc.) were found in the scanned path.',
      '',
      '---',
      '*Powered by [Asqav](https://asqav.com) - AI agent governance made simple.*',
    ].join('\n');
  }

  const totals: Record<CategoryKey, CategoryTotal> = {
    auditTrail: { pass: 0, gap: 0, files: [] },
    policyEnforcement: { pass: 0, gap: 0, files: [] },
    revocation: { pass: 0, gap: 0, files: [] },
    humanOversight: { pass: 0, gap: 0, files: [] },
    errorHandling: { pass: 0, gap: 0, files: [] },
  };

  const categories: CategoryDef[] = GOVERNANCE_CATEGORIES;

  for (const result of results) {
    for (const { key } of categories) {
      if (result[key].pass) {
        totals[key].pass += 1;
      } else {
        totals[key].gap += 1;
        totals[key].files.push(result.filePath);
      }
    }
  }

  const score: number = computeScore(results);

  let badge: string;
  if (score >= 80) {
    badge = ':white_check_mark:';
  } else if (score >= 50) {
    badge = ':warning:';
  } else {
    badge = ':x:';
  }

  const lines: string[] = [];
  lines.push(`## :shield: AI Agent Governance Report`);
  lines.push('');
  lines.push(...configNote(config));
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| **Compliance Score** | ${badge} **${score}/100** |`);
  lines.push(`| **Agent files scanned** | ${results.length} |`);
  lines.push(`| **Frameworks detected** | ${[...new Set(results.flatMap((r: AnalysisResult) => r.frameworks))].join(', ') || 'N/A'} |`);
  lines.push('');

  lines.push('### Governance Checks');
  lines.push('');
  lines.push('| Category | Status | Details |');
  lines.push('|----------|--------|---------|');

  const recommendations: Record<CategoryKey, string> = {
    auditTrail:
      'Add `import asqav` and use `asqav.sign()` to create tamper-proof audit trails for agent actions. [Learn more](https://asqav.com/docs/sessions)',
    policyEnforcement:
      'Implement rate limits, scope restrictions, or action gating to control agent behavior. [Learn more](https://asqav.com/docs/agents)',
    revocation:
      'Add a kill switch or revocation mechanism so agents can be disabled in an emergency. [Learn more](https://asqav.com/docs/agents)',
    humanOversight:
      'Add human-in-the-loop approval flows for high-risk agent actions. [Learn more](https://asqav.com/docs/signing-groups)',
    errorHandling:
      'Wrap agent calls in try/except blocks with proper error handling and fallback behavior. [Learn more](https://asqav.com/docs/)',
  };

  for (const { key, label } of categories) {
    const t: CategoryTotal = totals[key];
    const total: number = t.pass + t.gap;
    if (t.gap === 0) {
      lines.push(`| ${label} | :white_check_mark: PASS | ${t.pass}/${total} files covered |`);
    } else {
      lines.push(`| ${label} | :x: GAP | ${t.gap}/${total} files missing coverage |`);
    }
  }

  lines.push('');

  const gapCategories: CategoryDef[] = categories.filter(({ key }: CategoryDef) => totals[key].gap > 0);
  if (gapCategories.length > 0) {
    lines.push('### Recommendations');
    lines.push('');
    for (const { key, label } of gapCategories) {
      lines.push(`- **${label}**: ${recommendations[key]}`);
    }
    lines.push('');
  }

  lines.push('<details>');
  lines.push('<summary>Per-file breakdown</summary>');
  lines.push('');

  for (const result of results) {
    const checks: string[] = categories.map(({ key, label }: CategoryDef) => {
      const status: string = result[key].pass ? ':white_check_mark:' : ':x:';
      return `${status} ${label}`;
    });
    lines.push(`**\`${result.filePath}\`**`);
    lines.push(`- Frameworks: ${result.frameworks.join(', ')}`);
    lines.push(`- ${checks.join(' | ')}`);
    lines.push('');
  }

  lines.push('</details>');
  lines.push('');
  lines.push('---');
  lines.push('*Powered by [Asqav](https://asqav.com) - AI agent governance made simple. Get the full platform for automated compliance, audit trails, and policy enforcement.*');

  return lines.join('\n');
}
