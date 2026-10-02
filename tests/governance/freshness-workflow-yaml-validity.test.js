const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const ROOT = path.resolve(__dirname, '../..');
const WORKFLOW = path.join(ROOT, '.github/workflows/freshness-check.yml');

describe('freshness-check workflow YAML integrity', () => {
  test('parses as valid YAML and exposes the expected jobs', () => {
    const source = fs.readFileSync(WORKFLOW, 'utf8');

    expect(() => yaml.load(source)).not.toThrow();

    const doc = yaml.load(source);
    expect(doc).toBeTruthy();
    expect(doc.jobs).toBeTruthy();
    expect(doc.jobs['public-delivery-canary']).toBeTruthy();
    expect(doc.jobs['freshness-check']).toBeTruthy();
  });

  test('keeps the Blogger 429 state observable without multiline YAML hazards', () => {
    const source = fs.readFileSync(WORKFLOW, 'utf8');

    expect(source).toContain('BLOGGER_PUBLIC_RATE_LIMITED');
    expect(source).toContain('Provider returned HTTP 429');
    expect(source).toContain("sed -n 's/.*\"status\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p'");
    expect(source).not.toContain("python3 -c 'import json,sys\\ntry:");
  });
});
