const fs = require('fs');
const path = require('path');
const {
  extractHttpUrls,
  parseCvssFromText,
  hasConfirmedExploitation,
  rssToIntel,
  normalizeSentinelApexRecord,
  qualityGate,
  genBusinessImpact,
  genAttackChain,
  generatePostHTML,
  correlateAndMerge,
} = require('../fetch-live-intel');

describe('SENTINEL APEX evidence-integrity controls', () => {
  test('extracts only valid HTTP references from free-form CISA notes', () => {
    const refs = extractHttpUrls(
      'See vendor guidance; https://example.com/advisory; https://github.com/org/repo/security/advisories/GHSA-1234. Additional text'
    );
    expect(refs).toEqual([
      'https://example.com/advisory',
      'https://github.com/org/repo/security/advisories/GHSA-1234',
    ]);
    refs.forEach(ref => expect(() => new URL(ref)).not.toThrow());
  });

  test('does not invent CVSS from severity, CVE presence, or source type', () => {
    expect(parseCvssFromText('Critical CVE with public exploit')).toBeNull();
    expect(parseCvssFromText('CVSS 9.8 remote code execution')).toBe(9.8);

    const rss = rssToIntel({
      title: 'Critical CVE-2026-99999 exploit released',
      desc: 'Researchers published a proof of concept.',
      link: 'https://example.org/research',
      pubDate: '2026-08-12T00:00:00Z',
    }, 'unit42');
    expect(rss.cvss).toBeNull();

    const native = normalizeSentinelApexRecord({
      id: 'native-1', title: 'Critical security advisory', severity: 'critical',
      description: 'A public exploit proof of concept is available.',
      url: 'https://example.org/advisory',
    }, 'latest');
    expect(native.cvss).toBeNull();
  });

  test('requires explicit observed-exploitation language', () => {
    expect(hasConfirmedExploitation('Exploit proof of concept available for Active Directory')).toBe(false);
    expect(hasConfirmedExploitation('A zero-day vulnerability was disclosed')).toBe(false);
    expect(hasConfirmedExploitation('CISA reports this is actively exploited')).toBe(true);
    expect(hasConfirmedExploitation('Observed exploitation in the wild')).toBe(true);
  });

  test('preserves unknown CVSS through correlation', () => {
    const [merged] = correlateAndMerge([[
      { id: 'CVE-2026-11111', source: 'cisa_kev', title: 'CISA KEV record', desc: 'Confirmed exploitation.', cvss: null, cisaKev: true, refs: ['https://cisa.gov/example'] },
      { id: 'CVE-2026-11111', source: 'unit42', title: 'Coverage without a score', desc: 'Reporting without numeric severity.', cvss: null, refs: ['https://example.org/report'] },
    ]]);
    expect(merged.cvss).toBeNull();
  });

  test('rejects malformed reference-only records', () => {
    const result = qualityGate({
      id: 'TEST-1', title: 'Substantive intelligence title',
      desc: 'A sufficiently long description for validation.',
      source: 'unit42', type: 'ADVISORY', threatLevel: 'MEDIUM',
      priority: 50, refs: ['This vulnerability affects users; https://example.com'],
    });
    // Embedded notes are normalized into a valid URL, so this passes.
    expect(result.pass).toBe(true);

    const invalid = qualityGate({
      id: 'REAL-1', title: 'Substantive intelligence title',
      desc: 'A sufficiently long description for validation.',
      source: 'unit42', type: 'ADVISORY', threatLevel: 'MEDIUM',
      priority: 50, refs: ['not a URL'],
    });
    expect(invalid.pass).toBe(false);
    expect(invalid.reasons).toContain('Missing/invalid: references / link');
  });

  test('does not fabricate an attack chain or complete compromise', () => {
    const item = {
      id: 'CVE-2026-48027', vendor: 'Nx', product: 'Nx Console',
      title: 'Malicious extension harvested credentials',
      desc: 'A supply-chain compromise harvested credentials from developer systems.',
      cisaKev: true, exploited: true,
    };
    const impact = genBusinessImpact(item).join(' ');
    const chain = genAttackChain(item);
    expect(impact).not.toMatch(/complete system compromise|full server takeover/i);
    expect(chain).toEqual(expect.arrayContaining([
      expect.objectContaining({ phase: 'Evidence boundary', tactic: 'Not assigned' }),
    ]));
    expect(JSON.stringify(chain)).not.toMatch(/Shodan|scheduled task|command & control|Mimikatz/i);
  });

  test('renders unknown CVSS and honest commercial/evidence language', () => {
    const { html } = generatePostHTML({
      id: 'CVE-2026-99999', title: 'Example source-attributed advisory',
      desc: 'The primary source describes a vulnerability with prerequisites still under review.',
      source: 'cisa_kev', _sources: ['cisa_kev'], sourceCount: 1,
      refs: ['https://example.org/advisory'], pubDate: '2026-08-12',
      vendor: 'Example', product: 'Example Product', type: 'CVE_REPORT',
      cvss: null, cisaKev: true, exploited: true, ransomware: false,
      iocs: [], cves: ['CVE-2026-99999'], priority: 50, threatLevel: 'MEDIUM',
    });
    expect(html).toContain('CVSS Not assigned');
    expect(html).toContain('Evidence boundary');
    expect(html).toContain('reference draft');
    expect(html).not.toMatch(/10,000\+|48hr pre-disclosure|PRIVATE LIMITED|FP-validated|production-ready/i);
  });
});

describe('publication and acquisition workflow regressions', () => {
  const root = path.join(__dirname, '..');

  test('staged change detection uses valid Git commands', () => {
    const workflow = fs.readFileSync(path.join(root, '.github/workflows/sentinel-apex.yml'), 'utf8');
    expect(workflow).not.toContain('git status --cached');
    expect(workflow).toContain('git diff --cached --name-status');
  });

  test('runtime and customer publication freshness use separate controlled recovery paths', () => {
    const workflow = fs.readFileSync(path.join(root, '.github/workflows/freshness-check.yml'), 'utf8');
    const classifier = fs.readFileSync(path.join(root, 'scripts/check-intel-freshness.js'), 'utf8');

    // Classification belongs in a testable script. The workflow maps the
    // classifier's dedicated runtime-outage exit code (2) to recovery while
    // preserving exit 1 as a fail-closed monitor/feed-integrity failure.
    expect(workflow).toContain('node scripts/check-intel-freshness.js live-intel.json intel-state.json');

    const classifierStep = workflow.split('- name: "Classify runtime and content freshness"')[1]
      .split('- name: "Dispatch recovery and wait for completion"')[0];
    expect(classifierStep).toBeDefined();
    expect(classifierStep).toContain('case "$CHECK_EXIT" in');

    const shellCaseBody = (text, caseValue) => {
      const marker = new RegExp(`^\\s*${caseValue}\\)\\s*$`, 'm');
      const match = marker.exec(text);
      expect(match).not.toBeNull();
      const afterMarker = text.slice(match.index + match[0].length);
      return afterMarker.split(/^\s*;;\s*$/m)[0];
    };

    const monitorErrorCase = shellCaseBody(classifierStep, 1);
    const runtimeOutageCase = shellCaseBody(classifierStep, 2);
    expect(monitorErrorCase).toContain('recovery_required=false');
    expect(monitorErrorCase).toContain('exit 1');
    expect(runtimeOutageCase).toContain('recovery_required=true');
    expect(runtimeOutageCase).not.toContain('exit 2');

    // Runtime recovery is authorized only by the explicit output produced by
    // the internal freshness classifier's exit code 2.
    const recoveryStep = workflow.split('- name: "Dispatch recovery and wait for completion"')[1]
      .split('- name: "Re-verify production after recovery"')[0];
    expect(recoveryStep).toBeDefined();
    expect(recoveryStep).toContain("if: steps.freshness.outputs.recovery_required == 'true'");
    expect(recoveryStep).not.toContain('if: failure()');
    expect(recoveryStep).toContain("const workflowId = 'sentinel-apex.yml';");
    expect(recoveryStep).toContain('createWorkflowDispatch');
    expect(recoveryStep).toContain("current.conclusion !== 'success'");

    // Customer-facing Blogger freshness is an independent delivery SLO. Its
    // recovery may dispatch only when the internal generator is not already in
    // recovery, must retain the bounded four-post public write cap, and must suppress
    // duplicate dispatches while a recent/active Blogger run exists.
    const bloggerRecoveryStep = workflow.split('- name: "Dispatch Blogger publication recovery when customer feed is stale"')[1]
      .split('- name: "Dispatch recovery and wait for completion"')[0];
    expect(bloggerRecoveryStep).toBeDefined();
    expect(bloggerRecoveryStep).toContain("steps.freshness.outputs.recovery_required != 'true'");
    expect(bloggerRecoveryStep).toContain("steps.blogger_freshness.outputs.recovery_required == 'true'");
    expect(bloggerRecoveryStep).toContain("const workflowId = 'blogger-syndication.yml';");
    expect(bloggerRecoveryStep).toContain("max_posts: '4'");
    expect(bloggerRecoveryStep).toContain('45 * 60 * 1000');
    expect(bloggerRecoveryStep).toContain("latest.status !== 'completed'");
    expect(bloggerRecoveryStep).toContain('createWorkflowDispatch');

    // Exactly two self-healing dispatch sites are permitted: one for the
    // internal generator and one for the customer-facing Blogger delivery
    // lane. Any third dispatch path is a regression.
    expect((workflow.match(/github\.rest\.actions\.createWorkflowDispatch\s*\(/g) || [])).toHaveLength(2);

    // A successful recovery is not enough by itself. The monitor must refresh
    // the canonical main branch and run the same classifier again; unresolved
    // post-recovery failure remains red rather than being masked as healed.
    const postRecoveryStep = workflow.split('- name: "Re-verify production after recovery"')[1]
      .split('- name: "Monitor result summary"')[0];
    expect(postRecoveryStep).toBeDefined();
    expect(postRecoveryStep).toContain("if: steps.freshness.outputs.recovery_required == 'true'");
    expect(postRecoveryStep).toContain('git fetch --depth=1 origin main');
    expect(postRecoveryStep).toContain('git reset --hard origin/main');
    expect(postRecoveryStep).toContain('POST_OUTPUT=$(node scripts/check-intel-freshness.js live-intel.json intel-state.json 2>&1)');
    expect(postRecoveryStep).toContain('if [ "$POST_EXIT" -ne 0 ]; then');
    expect(postRecoveryStep).toContain('exit "$POST_EXIT"');

    // The monitor is deliberately staggered ten minutes behind the generator
    // (sentinel-apex.yml: :03/:33) to avoid a same-boundary read/write race.
    // Runtime timestamps remain the authority, so this cadence change is
    // optimization rather than truth. Minutes shifted from :10/:40 to
    // :13/:43 (preserving the same 10-minute offset) after a repo-wide
    // GitHub Actions scheduled-trigger stall on 2026-09-03, traced to 6+
    // cron schedules clustered on :00/:15/:30/:40 — see sentinel-apex.yml.
    expect(workflow).toContain("- cron: '13,43 * * * *'");

    // The CLI returns the classifier result from main() and binds that exact
    // return value to process.exitCode. Dedicated classifier tests exercise
    // 0/1/2 semantics; this regression guard verifies the executable wiring.
    expect(classifier).toContain('return result.exitCode;');
    expect(classifier).toContain('process.exitCode = main();');
  });

  test('newsletter uses the first-party endpoint before fallback', () => {
    const engine = fs.readFileSync(path.join(root, 'email-engine.js'), 'utf8');
    const page = fs.readFileSync(path.join(root, 'newsletter.html'), 'utf8');
    expect(engine).toContain("provider: 'resend'");
    expect(engine).toContain("fetch('/api/v1/newsletter'");
    expect(page).not.toMatch(/2,000\+|47%|\d{1,3},\d{3} readers/);
  });
});
