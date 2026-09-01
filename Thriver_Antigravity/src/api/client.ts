import { IncidentSummary, IncidentDetailData, PairwiseExplanation, AnalyticsSummary } from '../types';

const API_BASE = '/api/v1';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchIncidents(params?: { status?: string; priority?: string; search?: string }): Promise<IncidentSummary[]> {
  const query = new URLSearchParams();
  if (params?.status) query.append('status', params.status);
  if (params?.priority) query.append('priority', params.priority);
  if (params?.search) query.append('search', params.search);

  const res = await fetch(`${API_BASE}/incidents?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch incidents');
  return res.json();
}

export async function fetchIncidentDetail(incidentId: string): Promise<IncidentDetailData> {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}`);
  if (!res.ok) throw new Error(`Failed to fetch incident ${incidentId}`);
  return res.json();
}

export async function fetchWhyNumberOne(incidentId: string) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/explanation`);
  if (!res.ok) throw new Error('Failed to fetch explanation');
  return res.json();
}

export async function fetchCompareNext(incidentId: string): Promise<PairwiseExplanation> {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/compare-next`);
  if (!res.ok) throw new Error('Failed to fetch pairwise comparison');
  return res.json();
}

export async function fetchTimeline(incidentId: string) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/timeline`);
  if (!res.ok) throw new Error('Failed to fetch timeline');
  return res.json();
}

export async function fetchEvidence(incidentId: string) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}/evidence`);
  if (!res.ok) throw new Error('Failed to fetch evidence');
  return res.json();
}

export async function updateCaseStatus(caseId: string, status: string, analyst: string, notes?: string) {
  const res = await fetch(`${API_BASE}/cases/${caseId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, analyst, notes }),
  });
  return res.json();
}

export async function submitFeedback(caseId: string, decision: string, analyst: string, notes?: string) {
  const res = await fetch(`${API_BASE}/cases/${caseId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision, analyst, notes }),
  });
  return res.json();
}

export async function fetchPlaybook(caseId: string) {
  const res = await fetch(`${API_BASE}/cases/${caseId}/playbook`);
  return res.json();
}

export async function simulatePlaybookAction(caseId: string, playbookId: string, actionName: string, approved: boolean) {
  const res = await fetch(`${API_BASE}/cases/${caseId}/playbook/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ playbook_id: playbookId, action_name: actionName, approved }),
  });
  return res.json();
}

export async function fetchAnalytics(): Promise<AnalyticsSummary> {
  const res = await fetch(`${API_BASE}/analytics/summary`);
  if (!res.ok) throw new Error('Failed to fetch analytics summary');
  return res.json();
}

export async function fetchSectors() {
  const res = await fetch(`${API_BASE}/sectors`);
  if (!res.ok) throw new Error('Failed to fetch sectors');
  return res.json();
}

export async function activateSector(sectorId: string, weights?: any, versionName?: string) {
  const res = await fetch(`${API_BASE}/sectors/activate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sector_id: sectorId, weights, version_name: versionName }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to activate sector');
  }
  return res.json();
}

export async function fetchScoringConfig() {
  const res = await fetch(`${API_BASE}/config/scoring`);
  if (!res.ok) throw new Error('Failed to fetch scoring config');
  return res.json();
}

export async function updateScoringConfig(versionName: string, weights: any, thresholds: any, sectorId?: string) {
  const res = await fetch(`${API_BASE}/config/scoring`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ version_name: versionName, weights, thresholds, sector_id: sectorId }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Failed to update scoring configuration');
  }
  return res.json();
}

export async function resetScoringConfig() {
  const res = await fetch(`${API_BASE}/config/reset`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reset scoring config');
  return res.json();
}

export async function triggerScenario(scenarioKey: string) {
  const res = await fetch(`${API_BASE}/simulator/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario_key: scenarioKey }),
  });
  return res.json();
}

export async function loadDemoData() {
  const res = await fetch(`${API_BASE}/demo/load`, { method: 'POST' });
  return res.json();
}

export async function resetDemoData() {
  const res = await fetch(`${API_BASE}/demo/reset`, { method: 'POST' });
  return res.json();
}

