'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const wf=fs.readFileSync(path.join(__dirname,'..','.github/workflows/blogger-syndication.yml'),'utf8');

test('P0 Blogger publication limit is bounded and never interpolated directly into Bash',()=>{
  assert.match(wf,/MAX_POSTS_PER_RUN:\s*\$\{\{\s*github\.event\.inputs\.max_posts\s*\|\|\s*'4'\s*\}\}/);
  assert.match(wf,/case "\$\{MAX_POSTS_PER_RUN\}" in\s*\n\s*1\|2\|3\|4\)/);
  assert.match(wf,/--max-posts "\$\{MAX_POSTS_PER_RUN\}"/);
  assert.doesNotMatch(wf,/--max-posts\s+\$\{\{/,'manual input must not become shell source');
  const limit=wf.indexOf('case "'+'$'+'{MAX_POSTS_PER_RUN}" in');
  const python=wf.indexOf('python -m automation.premium_main');
  assert(limit>0&&python>limit,'reject invalid limit before calling external publisher');
});

test('P0 live Blogger publishing requires main, no untrusted ref text reaches Git shell',()=>{
  assert.match(wf,/if: \$\{\{ github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(wf,/\[ "\$\{GITHUB_REF\}" != "refs\/heads\/main" \]/);
  assert.doesNotMatch(wf,/DRY_RUN_FLAG\}" != "--dry-run"/);
  assert.match(wf,/Unauthorized Blogger branch::Live publication requires main/);
  assert.match(wf,/git pull --rebase origin main --quiet/);
  assert.match(wf,/git push origin main/);
  assert.doesNotMatch(wf,/\$\{\{\s*github\.ref_name\s*\}\}/);
  assert.match(wf,/if \[ "\$\{GITHUB_REF\}" != "refs\/heads\/main" \]; then\s*\n\s*echo "No publication-state commit outside main"/);
});

test('bounded hourly Blogger cadence and fail-closed publication outcomes remain unchanged',()=>{
  assert.match(wf,/cron: "17 \* \* \* \*"/);
  assert.match(wf,/cancel-in-progress: false/);
  assert.match(wf,/PIPELINE_EXIT=\$\{PIPESTATUS\[0\]\}/);
  assert.match(wf,/exit \$PIPELINE_EXIT/);
  assert.match(wf,/permissions:\s*\n  contents: write/);
});
