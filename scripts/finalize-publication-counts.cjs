'use strict';
const fs = require('node:fs');

function assessPublicationCounts(state, widget, api) {
  const total = state?.totalPublished;
  const generated = state?.lastIngestion?.reportsGenerated;
  if (!Number.isSafeInteger(total) || total < 0 || !Number.isSafeInteger(generated) || generated < 0 || generated > total) {
    throw new Error('REPORT_LEDGER_INVALID');
  }
  if (!widget || !Array.isArray(widget.items) || !Number.isSafeInteger(widget.totalPublished) || widget.totalPublished < 0 ||
      !api || !Array.isArray(api.items) || !Number.isSafeInteger(api.total_published) || api.total_published < 0) {
    throw new Error('SOURCE_FEED_SHAPE_INVALID');
  }
  const counts = [widget.totalPublished, api.total_published];
  if (counts.every(value => value === total)) return {status:'ALREADY_FINAL', total};
  const before = total - generated;
  if (!counts.every(value => value === before)) {
    throw new Error(`SOURCE_FEED_COUNT_DRIFT: ledger=${total}, generated=${generated}, widget=${counts[0]}, api=${counts[1]}`);
  }
  return {status:'RECONCILE', total};
}

function atomicWrite(filePath, content) {
  const tmp = `${filePath}.publication-count.tmp`;
  try {
    fs.writeFileSync(tmp, content, 'utf8');
    fs.renameSync(tmp, filePath);
  } catch (error) {
    try { fs.unlinkSync(tmp); } catch (_) {}
    throw error;
  }
}

// Called only after the real report ledger is persisted. Does not generate reports,
// change rolling-window items, or advance any source/feed freshness timestamps.
function finalizePublicationCounts(state, widgetPath, apiPath) {
  const widget = JSON.parse(fs.readFileSync(widgetPath, 'utf8'));
  const api = JSON.parse(fs.readFileSync(apiPath, 'utf8'));
  const verdict = assessPublicationCounts(state, widget, api);
  if (verdict.status === 'ALREADY_FINAL') return verdict;
  widget.totalPublished = verdict.total;
  api.total_published = verdict.total;
  atomicWrite(widgetPath, JSON.stringify(widget, null, 2));
  atomicWrite(apiPath, JSON.stringify(api, null, 2));
  const verifiedWidget = JSON.parse(fs.readFileSync(widgetPath, 'utf8'));
  const verifiedApi = JSON.parse(fs.readFileSync(apiPath, 'utf8'));
  if (verifiedWidget.totalPublished !== verdict.total || verifiedApi.total_published !== verdict.total) {
    throw new Error('SOURCE_FEED_FINALIZATION_VERIFY_FAILED');
  }
  return {status:'RECONCILED', total:verdict.total};
}

module.exports = {assessPublicationCounts, finalizePublicationCounts};
