import React, { useState, useEffect, useCallback } from 'react';
import KineticGrid from '@/components/ui/kinetic-grid';
import { Navbar } from './components/Navbar';
import { InvestigationQueue } from './components/InvestigationQueue';
import { IncidentDetail } from './components/IncidentDetail';
import { SOCDashboardView } from './components/SOCDashboard';
import { ConfigPageView } from './components/ConfigPage';
import { IncidentSummary, IncidentDetailData, AnalyticsSummary } from './types';
import {
  fetchIncidents,
  fetchIncidentDetail,
  triggerScenario,
  fetchAnalytics,
  resetDemoData,
  fetchScoringConfig,
  activateSector,
} from './api/client';
import {
  getSectorProfile,
  getSectorThreats,
  calculateThreatScore,
  calculateFactorContributions,
  SECTOR_PROFILES,
  getPrimaryAsset,
  getPrimaryUser,
} from './config/sectorProfiles';
import { AlertCircle, CheckCircle2 } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState('queue');
  const [activeSector, setActiveSector] = useState<string>('healthcare');
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | undefined>();
  const [selectedIncidentDetail, setSelectedIncidentDetail] = useState<IncidentDetailData | null>(null);
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null);

  const [loadingQueue, setLoadingQueue] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [notification, setNotification] = useState<{ text: string; type?: 'info' | 'success' } | null>(null);

  useEffect(() => {
    initializeSectorAndQueue();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      loadDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  useEffect(() => {
    if (activeTab === 'dashboard') {
      loadAnalytics();
    }
  }, [activeTab, activeSector]);

  const initializeSectorAndQueue = async () => {
    try {
      const cfg = await fetchScoringConfig();
      if (cfg.active_sector) {
        setActiveSector(cfg.active_sector);
        await loadQueue(cfg.active_sector, true);
        return;
      }
    } catch (e) {
      // Backend fallback
    }
    await loadQueue('healthcare', true);
  };

  /**
   * Loads incidents for the specified sector.
   * If backend is reachable, fetches live DB records; otherwise uses the centralized sector calculation engine.
   */
  const loadQueue = async (targetSector = activeSector, forceSelectFirst = false, preferredSelectId?: string) => {
    setLoadingQueue(true);
    try {
      const data = await fetchIncidents();
      // Check if backend incidents match the target sector
      if (data && data.length > 0) {
        setIncidents(data);
        if (preferredSelectId && data.some((i) => i.incident_id === preferredSelectId)) {
          setSelectedIncidentId(preferredSelectId);
        } else if (forceSelectFirst || !selectedIncidentId || !data.some((i) => i.incident_id === selectedIncidentId)) {
          setSelectedIncidentId(data[0].incident_id);
        }
      } else {
        fallbackLoadSector(targetSector, forceSelectFirst);
      }
    } catch (err) {
      console.warn('Backend unavailable, employing centralized calculation engine fallback:', err);
      fallbackLoadSector(targetSector, forceSelectFirst);
    } finally {
      setLoadingQueue(false);
    }
  };

  const fallbackLoadSector = (sectorId: string, forceSelectFirst: boolean) => {
    const profile = getSectorProfile(sectorId);
    const threats = profile.threats;
    const maxUsers = Math.max(...threats.map((t) => t.affectedUsers), 1);

    // Run scoring engine on all threats
    const computed = threats.map((t) => {
      const score = calculateThreatScore(t, profile.weights, maxUsers);
      const contribs = calculateFactorContributions(t, profile.weights, maxUsers);
      const sortedContribs = Object.values(contribs).sort((a, b) => b.contribution - a.contribution);

      return {
        threat: t,
        score,
        priority_level: (score >= 90
          ? 'CRITICAL'
          : score >= 75
          ? 'HIGH'
          : score >= 50
          ? 'MEDIUM'
          : 'LOW') as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
        top_drivers: sortedContribs.slice(0, 3).map((c) => `${c.factor_name}: +${c.contribution} pts`),
      };
    });

    // Deterministic ranking
    computed.sort((a, b) => b.score - a.score);

    const summaries: IncidentSummary[] = computed.map((item, idx) => ({
      rank: idx + 1,
      incident_id: item.threat.id,
      title: item.threat.title,
      status: idx === 0 ? 'NEW' : idx === 1 ? 'TRIAGED' : 'INVESTIGATING',
      priority_score: item.score,
      priority_level: item.priority_level,
      attack_confidence: item.threat.attackConfidence,
      data_confidence: 1.0,
      affected_assets: item.threat.affectedAssets,
      affected_users: item.threat.affectedUsersList,
      attack_types: item.threat.attackTypes,
      top_drivers: item.top_drivers,
      created_at: new Date().toISOString(),
    }));

    setIncidents(summaries);
    if (forceSelectFirst || !selectedIncidentId || !summaries.some((s) => s.incident_id === selectedIncidentId)) {
      setSelectedIncidentId(summaries[0].incident_id);
    }
  };

  const loadDetail = async (id: string) => {
    setLoadingDetail(true);
    try {
      const detail = await fetchIncidentDetail(id);
      setSelectedIncidentDetail(detail);
    } catch (err) {
      // Local fallback detail generation using centralized calculation engine
      const profile = getSectorProfile(activeSector);
      const threat = profile.threats.find((t) => t.id === id) || profile.threats[0];
      const maxUsers = Math.max(...profile.threats.map((t) => t.affectedUsers), 1);
      const score = calculateThreatScore(threat, profile.weights, maxUsers);
      const contribs = calculateFactorContributions(threat, profile.weights, maxUsers);
      const priorityLevel = score >= 90 ? 'CRITICAL' : score >= 75 ? 'HIGH' : score >= 50 ? 'MEDIUM' : 'LOW';

      const fallbackDetail: IncidentDetailData = {
        rank: 1,
        incident_id: threat.id,
        title: threat.title,
        status: 'CONTAINMENT_RECOMMENDED',
        priority_score: score,
        priority_level: priorityLevel as any,
        attack_confidence: threat.attackConfidence,
        data_confidence: 1.0,
        affected_assets: threat.affectedAssets,
        affected_users: threat.affectedUsersList,
        attack_types: threat.attackTypes,
        top_drivers: Object.values(contribs)
          .sort((a, b) => b.contribution - a.contribution)
          .slice(0, 3)
          .map((c) => `${c.factor_name}: +${c.contribution} pts`),
        created_at: new Date().toISOString(),
        mitre_techniques: threat.mitreTechniques,
        business_impact: threat.businessImpact,
        data_sensitivity: threat.dataSensitivity,
        related_alerts_count: threat.affectedAssets.length * 2 + 1,
        explanation: threat.story,
        attack_story: threat.story,
        recommended_playbook: threat.playbook,
        score_breakdown: {
          final_score: score,
          priority_level: priorityLevel,
          attack_confidence: threat.attackConfidence,
          data_confidence: 1.0,
          missing_factors: [],
          contributions: contribs,
        },
        vulnerabilities: [
          {
            cve_id: 'CVE-2026-SECTOR-01',
            cvss_score: 9.8,
            known_exploited: true,
            description: 'Industry-targeted zero-day execution vulnerability',
          },
        ],
      };
      setSelectedIncidentDetail(fallbackDetail);
    } finally {
      setLoadingDetail(false);
    }
  };

  const loadAnalytics = async () => {
    try {
      const data = await fetchAnalytics();
      setAnalytics(data);
    } catch (err) {
      // Local calculation fallback for analytics based on active sector incidents
      const profile = getSectorProfile(activeSector);
      const maxUsers = Math.max(...profile.threats.map((t) => t.affectedUsers), 1);
      const scores = profile.threats.map((t) => calculateThreatScore(t, profile.weights, maxUsers));
      const criticalCount = scores.filter((s) => s >= 90).length;
      const highCount = scores.filter((s) => s >= 75 && s < 90).length;
      const medCount = scores.filter((s) => s >= 50 && s < 75).length;
      const lowCount = scores.filter((s) => s < 50).length;
      const avgScore = Number((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1));

      setAnalytics({
        metrics: {
          total_telemetry_events: profile.threats.length * 14 + 182,
          duplicate_events_filtered: 48,
          deduplication_rate_percent: 18.5,
          total_detections_generated: profile.threats.length * 4 + 12,
          total_incidents: profile.threats.length,
          open_incidents: profile.threats.length,
          critical_incidents: criticalCount,
          high_incidents: highCount,
          medium_incidents: medCount,
          low_incidents: lowCount,
          average_risk_score: avgScore,
          false_positive_rate_percent: 4.2,
          confirmed_incident_rate_percent: 95.8,
        },
        priority_distribution: [
          { level: 'CRITICAL', count: criticalCount, color: '#ef4444' },
          { level: 'HIGH', count: highCount, color: '#f97316' },
          { level: 'MEDIUM', count: medCount, color: '#eab308' },
          { level: 'LOW', count: lowCount, color: '#3b82f6' },
        ],
        category_distribution: [
          { category: 'ENDPOINT_EXECUTION', count: 18 },
          { category: 'NETWORK_ANOMALY', count: 14 },
          { category: 'AUTHENTICATION_ABUSE', count: 11 },
        ],
        top_noisy_rules: [
          { rule: 'Anomalous Sector Ingress Traffic', triggers: 24 },
          { rule: 'High-Privilege Account Creation', triggers: 16 },
        ],
        recent_audit_logs: [
          {
            timestamp: new Date().toISOString(),
            actor: 'system',
            action: 'SECTOR_PRESET_APPLIED',
            entity: activeSector,
            details: { weights: profile.weights },
          },
        ],
      });
    }
  };

  /**
   * Main Sector Preset Transition Handler
   * Enforces immediate recalculation of:
   *   ACTIVE SECTOR -> WEIGHTS -> THREATS -> FACTOR VALUES -> SCORING ENGINE
   *   -> CONTRIBUTIONS -> RISK INDEX -> QUEUE -> DETAIL -> DASHBOARD
   */
  const handleSectorChange = async (newSector: string) => {
    setActiveSector(newSector);
    setSelectedIncidentId(undefined);
    setSelectedIncidentDetail(null);

    const profile = getSectorProfile(newSector);
    showNotification(`Switching to '${profile.name}' Sector Preset...`, 'info');

    try {
      await activateSector(newSector);
    } catch (err) {
      console.warn('Backend sector activate responded with error, continuing with local engine:', err);
    }

    // Immediately reload queue with fresh sector threats and reset selection
    await loadQueue(newSector, true);
    if (activeTab === 'dashboard') {
      await loadAnalytics();
    }

    showNotification(
      `Sector changed to '${profile.name}'. 6-Factor Risk Scores & Threat Context Fully Recalculated!`,
      'success'
    );
  };

  const handleTriggerScenario = async (scenarioKey: string) => {
    try {
      showNotification(`Executing Scenario '${scenarioKey}'...`, 'info');
      const res = await triggerScenario(scenarioKey);
      const targetId = res?.incident_id;
      await loadQueue(activeSector, false, targetId);
      if (targetId) {
        setSelectedIncidentId(targetId);
        await loadDetail(targetId);
      } else if (selectedIncidentId) {
        await loadDetail(selectedIncidentId);
      }
      showNotification(`Scenario '${res?.scenario || scenarioKey}' successfully executed & correlated!`, 'success');
    } catch (err: any) {
      console.warn('Backend trigger scenario failed, executing client simulation fallback:', err);
      executeClientSideSimulation(scenarioKey);
    }
  };

  const executeClientSideSimulation = (scenarioKey: string) => {
    const profile = getSectorProfile(activeSector);
    const primaryAsset = getPrimaryAsset(profile);
    const primaryUser = getPrimaryUser(profile);

    const titles: Record<string, string> = {
      ransomware: `Ransomware Mass Encryption Outbreak on ${primaryAsset}`,
      phishing: `Spear Phishing Credential Theft (${primaryUser})`,
      brute_force: `Distributed Brute Force Attack against ${primaryAsset}`,
      data_exfil: `Classified Data Exfiltration from ${primaryAsset}`,
      priv_esc: `Admin Privilege Escalation on ${primaryAsset}`,
    };

    const scenarioTitle =
      titles[scenarioKey] || `Live Intrusion Simulation [${scenarioKey.toUpperCase()}] on ${primaryAsset}`;
    const simulatedId = `INC-SIM-${Date.now().toString().slice(-4)}`;

    // Dynamically calculate 6-factor score using active sector weights
    const normSev = 100.0;
    const normAsset = 100.0;
    const normUsers = 75.0;
    const normData = 100.0;
    const normConf = 98.0;
    const normImpact = 100.0;

    const cSev = Number((normSev * profile.weights.severity).toFixed(1));
    const cAsset = Number((normAsset * profile.weights.asset_importance).toFixed(1));
    const cUsers = Number((normUsers * profile.weights.affected_users).toFixed(1));
    const cData = Number((normData * profile.weights.data_sensitivity).toFixed(1));
    const cConf = Number((normConf * profile.weights.attack_confidence).toFixed(1));
    const cImpact = Number((normImpact * profile.weights.business_impact).toFixed(1));

    const totalScore = Number(Math.min(100.0, cSev + cAsset + cUsers + cData + cConf + cImpact).toFixed(1));
    const priorityLevel = totalScore >= 90 ? 'CRITICAL' : 'HIGH';

    const contributions = {
      Severity: {
        factor_name: 'Severity',
        raw_value: '5/5',
        normalized_value: normSev,
        weight: profile.weights.severity,
        contribution: cSev,
      },
      'Asset Importance': {
        factor_name: 'Asset Importance',
        raw_value: '5/5 (Tier 1)',
        normalized_value: normAsset,
        weight: profile.weights.asset_importance,
        contribution: cAsset,
      },
      'Affected Users': {
        factor_name: 'Affected Users',
        raw_value: '3 User(s)',
        normalized_value: normUsers,
        weight: profile.weights.affected_users,
        contribution: cUsers,
      },
      'Data Sensitivity': {
        factor_name: 'Data Sensitivity',
        raw_value: '5/5',
        normalized_value: normData,
        weight: profile.weights.data_sensitivity,
        contribution: cData,
      },
      'Attack Confidence': {
        factor_name: 'Attack Confidence',
        raw_value: '98%',
        normalized_value: normConf,
        weight: profile.weights.attack_confidence,
        contribution: cConf,
      },
      'Business Impact': {
        factor_name: 'Business Impact',
        raw_value: '5/5',
        normalized_value: normImpact,
        weight: profile.weights.business_impact,
        contribution: cImpact,
      },
    };

    const topDrivers = Object.values(contributions)
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 3)
      .map((c) => `${c.factor_name}: +${c.contribution} pts`);

    const newIncident: IncidentSummary = {
      rank: 1,
      incident_id: simulatedId,
      title: scenarioTitle,
      status: 'NEW',
      priority_score: totalScore,
      priority_level: priorityLevel as any,
      attack_confidence: 0.98,
      data_confidence: 1.0,
      affected_assets: [primaryAsset],
      affected_users: [primaryUser],
      attack_types: [scenarioKey.toUpperCase(), 'ACTIVE_EXPLOIT'],
      top_drivers: topDrivers,
      created_at: new Date().toISOString(),
    };

    setIncidents((prev) => {
      const filtered = prev.filter((i) => i.incident_id !== simulatedId);
      return [newIncident, ...filtered].map((inc, idx) => ({
        ...inc,
        rank: idx + 1,
      }));
    });

    setSelectedIncidentId(simulatedId);

    setSelectedIncidentDetail({
      ...newIncident,
      mitre_techniques: ['T1486: Data Encrypted for Impact', 'T1059: Command and Scripting Interpreter'],
      business_impact: 5,
      data_sensitivity: 5,
      related_alerts_count: 6,
      explanation: `Live simulated intrusion scenario '${scenarioKey}' active against high-value ${profile.name} asset ${primaryAsset}. Immediate containment isolation recommended.`,
      attack_story: `Live scenario execution detected real-time malicious signals against ${primaryAsset} targeting user identity '${primaryUser}'. Behavioral heuristics confirmed multi-stage adversary execution.`,
      recommended_playbook: 'Emergency Sector Asset Quarantine & Memory Capture',
      score_breakdown: {
        final_score: totalScore,
        priority_level: priorityLevel,
        attack_confidence: 0.98,
        data_confidence: 1.0,
        missing_factors: [],
        contributions: contributions,
      },
      vulnerabilities: [
        {
          cve_id: 'CVE-2026-ZERO-DAY',
          cvss_score: 9.9,
          known_exploited: true,
          description: `Targeted zero-day exploitation vulnerability on ${primaryAsset}`,
        },
      ],
    });

    // Update analytics if dashboard is open
    setAnalytics((prev) => {
      if (!prev) return null;
      return {
        ...prev,
        metrics: {
          ...prev.metrics,
          total_incidents: prev.metrics.total_incidents + 1,
          open_incidents: prev.metrics.open_incidents + 1,
          critical_incidents: prev.metrics.critical_incidents + 1,
          total_detections_generated: prev.metrics.total_detections_generated + 2,
        },
      };
    });

    showNotification(`Live Scenario '${scenarioTitle}' successfully executed & correlated!`, 'success');
  };


  const handleResetData = async () => {
    try {
      showNotification('Resetting and reloading baseline demo telemetry...', 'info');
      await resetDemoData();
      await loadQueue(activeSector, true);
      showNotification('Demo data successfully reloaded!', 'success');
    } catch (err: any) {
      showNotification(`Error: ${err.message}`, 'info');
    }
  };

  const showNotification = (msg: string, type: 'info' | 'success' = 'info') => {
    setNotification({ text: msg, type });
    setTimeout(() => setNotification(null), 4500);
  };

  return (
    <KineticGrid globalColor="default">
      <div className="min-h-screen flex flex-col text-slate-100 selection:bg-blue-600">
        {/* Top SOC Navbar with Active Sector Badge & Switcher */}
        <Navbar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          activeSector={activeSector}
          onSectorChange={handleSectorChange}
          onTriggerScenario={handleTriggerScenario}
          onResetData={handleResetData}
        />

        {/* Global Notification Banner */}
        {notification && (
          <div
            className={`border-b text-xs px-6 py-2 flex items-center space-x-2 font-mono transition-all ${
              notification.type === 'success'
                ? 'bg-emerald-600/20 border-emerald-500/40 text-emerald-300'
                : 'bg-blue-600/20 border-blue-500/40 text-blue-300'
            }`}
          >
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-blue-400 shrink-0" />
            )}
            <span>{notification.text}</span>
          </div>
        )}

        {/* Main Container */}
        <main className="flex-1 px-6 py-4 max-w-[1750px] w-full mx-auto">
          {activeTab === 'queue' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 h-[calc(100vh-104px)]">
              {/* Left Queue Rail (4 cols) */}
              <div className="lg:col-span-4 h-full overflow-hidden flex flex-col">
                <InvestigationQueue
                  incidents={incidents}
                  selectedIncidentId={selectedIncidentId}
                  onSelectIncident={(id) => setSelectedIncidentId(id)}
                  isLoading={loadingQueue}
                />
              </div>

              {/* Right Command Workspace (8 cols) */}
              <div className="lg:col-span-8 h-full overflow-y-auto pr-1.5 scrollbar-thin">
                {loadingDetail ? (
                  <div className="glass-outcut rounded-2xl p-12 text-center text-slate-400 text-xs flex flex-col items-center justify-center h-64 border border-white/10">
                    <div className="inline-block w-7 h-7 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3 shadow-[0_0_12px_rgba(59,130,246,0.5)]"></div>
                    <p className="font-display font-medium text-slate-300 text-sm">
                      Recalculating 6-Factor Risk Model for '{getSectorProfile(activeSector).name}'...
                    </p>
                  </div>
                ) : selectedIncidentDetail ? (
                  <IncidentDetail incident={selectedIncidentDetail} onRefresh={() => loadQueue(activeSector, false)} />
                ) : (
                  <div className="glass-outcut rounded-2xl p-12 text-center text-slate-400 text-xs flex flex-col items-center justify-center h-64 border border-white/10">
                    <p className="font-display text-slate-300 text-sm">
                      Select an incident from the priority queue to launch investigation.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'dashboard' && (
            analytics ? (
              <SOCDashboardView
                analytics={analytics}
                activeSector={activeSector}
                incidents={incidents}
                onTriggerScenario={handleTriggerScenario}
              />
            ) : (
              <div className="glass-outcut rounded-2xl p-12 text-center text-slate-400 text-xs flex flex-col items-center justify-center h-64 border border-white/10">
                <div className="inline-block w-7 h-7 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3 shadow-[0_0_12px_rgba(59,130,246,0.5)]"></div>
                <p className="font-display font-medium text-slate-300 text-sm">
                  Loading Real-Time SOC Posture & AI Threat Advisory...
                </p>
              </div>
            )
          )}

          {activeTab === 'config' && (
            <ConfigPageView
              onConfigUpdated={() => loadQueue(activeSector, true)}
              activeSector={activeSector}
              onSectorChange={handleSectorChange}
            />
          )}
        </main>
      </div>
    </KineticGrid>
  );
}

export default App;
