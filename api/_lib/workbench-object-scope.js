'use strict';

/**
 * Internal SOC analyst ownership checks. There is currently no customer
 * tenant registry or tenant membership mapping in this workbench; a role
 * called "lead" is an INTERNAL queue permission, never customer RBAC.
 *
 * Fail closed on incomplete records and unrecognized roles. Callers must
 * check this server side on every record read or mutation, including nested
 * case/evidence/graph/summary endpoints.
 */
const LEAD_ROLES = new Set(['lead_analyst', 'soc_admin']);
const ID_RE = /^[a-zA-Z0-9_-]{1,100}$/;

function isInternalLead(caller) {
  return Boolean(caller && typeof caller.id === 'string' && caller.id &&
    LEAD_ROLES.has(caller.role));
}

function isValidObjectId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

function canAccessInvestigation(caller, investigation) {
  return Boolean(caller && typeof caller.id === 'string' && caller.id &&
    investigation && typeof investigation === 'object' &&
    isValidObjectId(investigation.id) &&
    (isInternalLead(caller) || investigation.assignee === caller.id));
}

function canAssignInvestigation(caller, assignee) {
  return Boolean(caller && typeof caller.id === 'string' && caller.id &&
    isValidObjectId(assignee) &&
    (isInternalLead(caller) || assignee === caller.id));
}

module.exports = {
  isInternalLead, isValidObjectId, canAccessInvestigation, canAssignInvestigation,
};
