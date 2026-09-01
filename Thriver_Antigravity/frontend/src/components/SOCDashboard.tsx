import React, { useState } from 'react';
import { AnalyticsSummary, IncidentSummary } from '../types';
import { LiquidCard, AppleGlassStack } from './ui/liquid-glass-card';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import {
  Shield,
  AlertTriangle,
  Activity,
  CheckCircle2,
  Volume2,
  History,
  Cpu,
  Zap,
  Lock,
  Sparkles,
  Terminal,
  Copy,
  Check,
  Radio,
  TrendingDown,
  Sliders,
  ExternalLink,
  Target,
  ArrowRight,
  RefreshCw,
  Server,
  Layers
} from 'lucide-react';
import { getSectorProfile } from '../config/sectorProfiles';

interface SOCDashboardProps {
  analytics: AnalyticsSummary;
  activeSector?: string;
  incidents?: IncidentSummary[];
  onTriggerScenario?: (scenario: string) => void;
}

export const SOCDashboardView: React.FC<SOCDashboardProps> = ({
  analytics,
  activeSector = 'healthcare',
  incidents = [],
  onTriggerScenario,
}) => {
  const profile = getSectorProfile(activeSector);
  const assetCount = (profile as any).assets?.length || profile.threats?.reduce((acc, t) => acc + (t.affectedAssets?.length || 1), 0) || 6;
  const userCount = (profile as any).users?.length || profile.threats?.reduce((acc, t) => acc + (t.affectedUsersList?.length || 1), 0) || 8;

  const metrics = analytics?.metrics || {
    total_telemetry_events: 500,
    duplicate_events_filtered: 48,
    deduplication_rate_percent: 18.5,
    total_detections_generated: 120,
    total_incidents: incidents.length || 4,
    open_incidents: incidents.length || 4,
    critical_incidents: 1,
    high_incidents: 2,
    medium_incidents: 1,
    low_incidents: 0,
    average_risk_score: 74.2,
    false_positive_rate_percent: 4.2,
    confirmed_incident_rate_percent: 95.8,
  };

  const priority_distribution = analytics?.priority_distribution || [
    { level: 'CRITICAL', count: 1, color: '#ef4444' },
    { level: 'HIGH', count: 2, color: '#f97316' },
    { level: 'MEDIUM', count: 1, color: '#eab308' },
    { level: 'LOW', count: 0, color: '#3b82f6' },
  ];
  const category_distribution = analytics?.category_distribution || [];
  const top_noisy_rules = analytics?.top_noisy_rules || [];
  const recent_audit_logs = analytics?.recent_audit_logs || [];
  const posture_metrics = analytics?.posture_metrics;
  const mitre_matrix = analytics?.mitre_matrix;
  const ai_recommendations = analytics?.ai_recommendations || [];

  const [activeSubTab, setActiveSubTab] = useState<'telemetry' | 'mitre' | 'advisory' | 'audit'>('advisory');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Mitigation Simulator State
  const [simulatedControls, setSimulatedControls] = useState<{ [key: string]: boolean }>({
    edr_quarantine: true,
    fido2_mfa: true,
    db_microseg: false,
    powershell_lock: false,
  });

  // Copy automation script helper
  const handleCopyScript = (id: string, script: string) => {
    navigator.clipboard.writeText(script);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  // Toggle control for Threat Avoidance Simulator
  const toggleControl = (key: string) => {
    setSimulatedControls((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  // Calculate dynamic avoided risk
  const baselineRisk = metrics.average_risk_score || 84.5;
  let simulatedReduction = 0;
  if (simulatedControls.edr_quarantine) simulatedReduction += 34.5;
  if (simulatedControls.fido2_mfa) simulatedReduction += 26.8;
  if (simulatedControls.db_microseg) simulatedReduction += 22.4;
  if (simulatedControls.powershell_lock) simulatedReduction += 18.2;

  const projectedRisk = Math.max(12.0, +(baselineRisk - simulatedReduction).toFixed(1));
  const avoidedPercent = Math.min(100, Math.round(((baselineRisk - projectedRisk) / baselineRisk) * 100));

  // Fallback Posture Metrics if not populated by backend
  const posture = posture_metrics || {
    defcon_level: metrics.critical_incidents > 0 ? 'DEFCON 2 — ELEVATED SECTOR RISK' : 'DEFCON 4 — NOMINAL MONITORING',
    defcon_badge: metrics.critical_incidents > 0 ? 'CRITICAL' : 'NOMINAL',
    mttd_minutes: 11.8,
    mttr_minutes: 26.4,
    zero_trust_coverage_percent: 94.6,
    active_playbook_coverage_percent: 92.0,
    attack_surface_exposure_index: Math.min(100, Math.round(baselineRisk * 0.95)),
    telemetry_ingest_rate_eps: 42.8,
  };

  // Fallback MITRE techniques if not present
  const defaultMitreMatrix = [
    { technique_id: 'T1486', technique_name: 'Data Encrypted for Impact', tactic: 'Impact', count: 4, raw: 'T1486: Data Encrypted for Impact' },
    { technique_id: 'T1566', technique_name: 'Phishing', tactic: 'Initial Access', count: 3, raw: 'T1566: Phishing' },
    { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution', count: 5, raw: 'T1059: Command and Scripting' },
    { technique_id: 'T1110', technique_name: 'Brute Force', tactic: 'Credential Access', count: 3, raw: 'T1110: Brute Force' },
    { technique_id: 'T1048', technique_name: 'Exfiltration Over Alt Protocol', tactic: 'Exfiltration', count: 2, raw: 'T1048: Exfiltration' },
    { technique_id: 'T1078', technique_name: 'Valid Accounts Abuse', tactic: 'Defense Evasion', count: 4, raw: 'T1078: Valid Accounts' },
  ];
  const activeMitre = (mitre_matrix && mitre_matrix.length > 0) ? mitre_matrix : defaultMitreMatrix;

  // Format category data for bar chart
  const categoryChartData = (category_distribution && category_distribution.length > 0)
    ? category_distribution.map((c) => ({
        category: c.category.replace('_', ' '),
        count: c.count,
      }))
    : [
        { category: 'ENDPOINT', count: 18 },
        { category: 'NETWORK', count: 24 },
        { category: 'AUTH', count: 15 },
        { category: 'FILE SYS', count: 12 },
        { category: 'CLOUD', count: 9 },
      ];

  return (
    <div className="space-y-6">
      {/* 1. Executive Cyber Threat Posture Strip */}
      <LiquidCard borderRadius={20} className="p-4 border border-white/10 shadow-2xl bg-slate-950/80">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="relative flex items-center justify-center">
              <span className="w-3.5 h-3.5 rounded-full bg-red-500 animate-ping absolute opacity-75"></span>
              <span className="w-3 h-3 rounded-full bg-red-500 relative"></span>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono font-bold tracking-widest text-slate-400 uppercase">
                  ACTIVE SECTOR POSTURE
                </span>
                <span className="bg-red-500/20 text-red-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-red-500/30">
                  {posture.defcon_level}
                </span>
              </div>
              <p className="text-xs text-slate-300 font-sans mt-0.5">
                Monitoring <strong>{profile.name}</strong> infrastructure • Active Heuristic Context Prioritization Engine
              </p>
            </div>
          </div>

          {/* Quick Real-Time Posture Telemetry Gauges */}
          <div className="flex items-center space-x-6 text-xs font-mono">
            <div className="text-right">
              <span className="text-[10px] text-slate-400 block uppercase">MTTD</span>
              <span className="text-white font-bold">{posture.mttd_minutes}m</span>
            </div>
            <div className="text-right border-l border-white/10 pl-6">
              <span className="text-[10px] text-slate-400 block uppercase">MTTR</span>
              <span className="text-emerald-400 font-bold">{posture.mttr_minutes}m</span>
            </div>
            <div className="text-right border-l border-white/10 pl-6">
              <span className="text-[10px] text-slate-400 block uppercase">Zero-Trust Coverage</span>
              <span className="text-blue-400 font-bold">{posture.zero_trust_coverage_percent}%</span>
            </div>
            <div className="text-right border-l border-white/10 pl-6">
              <span className="text-[10px] text-slate-400 block uppercase">Ingestion</span>
              <span className="text-purple-400 font-bold">{posture.telemetry_ingest_rate_eps} EPS</span>
            </div>
          </div>
        </div>
      </LiquidCard>

      {/* 2. Primary KPI Telemetry Cards with Apple Glass 3D Tilt */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <LiquidCard enableTilt={true} hoverLift={6} borderRadius={20} className="p-5 border border-white/10 shadow-2xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-sans font-medium">Telemetry Signals Ingested</span>
            <Activity className="w-4 h-4 text-blue-400 drop-shadow-[0_0_6px_rgba(59,130,246,0.5)]" />
          </div>
          <p className="text-3xl font-extrabold text-white font-mono mt-2 tracking-tight">
            {metrics.total_telemetry_events}
          </p>
          <span className="text-[11px] text-emerald-400 font-mono mt-1.5 flex items-center space-x-1">
            <TrendingDown className="w-3 h-3" />
            <span>Noise Filtered: {metrics.deduplication_rate_percent}% Duplicates</span>
          </span>
        </LiquidCard>

        <LiquidCard enableTilt={true} hoverLift={6} borderRadius={20} className="p-5 border border-white/10 shadow-2xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-sans font-medium">Correlated Incidents</span>
            <Shield className="w-4 h-4 text-orange-400 drop-shadow-[0_0_6px_rgba(249,115,22,0.5)]" />
          </div>
          <p className="text-3xl font-extrabold text-white font-mono mt-2 tracking-tight">{metrics.open_incidents}</p>
          <span className="text-[11px] text-red-400 font-mono mt-1.5 block">
            {metrics.critical_incidents} Critical / {metrics.high_incidents} High Severity
          </span>
        </LiquidCard>

        <LiquidCard enableTilt={true} hoverLift={6} borderRadius={20} className="p-5 border border-white/10 shadow-2xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-sans font-medium">Avg Contextual Risk Index</span>
            <AlertTriangle className="w-4 h-4 text-yellow-400 drop-shadow-[0_0_6px_rgba(234,179,8,0.5)]" />
          </div>
          <p className="text-3xl font-extrabold text-white font-mono mt-2 tracking-tight">{metrics.average_risk_score}</p>
          <span className="text-[11px] text-slate-400 font-mono mt-1.5 block">
            Calibrated for {profile.name} Assets
          </span>
        </LiquidCard>

        <LiquidCard enableTilt={true} hoverLift={6} borderRadius={20} className="p-5 border border-white/10 shadow-2xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-sans font-medium">Triage Precision & Confidence</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400 drop-shadow-[0_0_6px_rgba(16,185,129,0.5)]" />
          </div>
          <p className="text-3xl font-extrabold text-white font-mono mt-2 tracking-tight">
            {metrics.confirmed_incident_rate_percent || 94.2}%
          </p>
          <span className="text-[11px] text-emerald-400 font-mono mt-1.5 block">
            False Positive Suppression: {metrics.false_positive_rate_percent}%
          </span>
        </LiquidCard>
      </div>

      {/* 3. Dashboard View Tabs */}
      <div className="flex items-center space-x-2 border-b border-white/10 pb-3">
        <button
          onClick={() => setActiveSubTab('advisory')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-display font-semibold transition-all ${
            activeSubTab === 'advisory'
              ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-lg shadow-indigo-500/25 border border-indigo-400/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <Sparkles className="w-4 h-4 text-amber-300 animate-pulse" />
          <span>AI Threat Advisory & Avoidance Engine</span>
          <span className="bg-amber-400/20 text-amber-300 text-[10px] px-2 py-0.2 rounded-full font-mono font-bold">
            PROACTIVE
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('telemetry')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-display font-semibold transition-all ${
            activeSubTab === 'telemetry'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>SOC Command & Telemetry</span>
        </button>

        <button
          onClick={() => setActiveSubTab('mitre')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-display font-semibold transition-all ${
            activeSubTab === 'mitre'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <Target className="w-4 h-4" />
          <span>MITRE ATT&CK Matrix Defense</span>
        </button>

        <button
          onClick={() => setActiveSubTab('audit')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-display font-semibold transition-all ${
            activeSubTab === 'audit'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <History className="w-4 h-4" />
          <span>Live Audit & Compliance Stream</span>
        </button>
      </div>

      {/* 4. Tab 1: AI Threat Advisory & Avoidance Engine (PRIMARY USER FOCUS) */}
      {activeSubTab === 'advisory' && (
        <div className="space-y-6">
          {/* Sector AI Advisory Strategy Callout */}
          <LiquidCard borderRadius={20} className="p-6 border border-indigo-500/30 bg-gradient-to-br from-indigo-950/40 via-slate-950/80 to-blue-950/30 shadow-2xl space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-1.5 max-w-3xl">
                <div className="flex items-center space-x-2">
                  <Sparkles className="w-5 h-5 text-amber-400" />
                  <h2 className="font-display font-bold text-white text-base tracking-tight">
                    Autonomous AI Threat Avoidance Advisory — {profile.name} Sector
                  </h2>
                </div>
                <p className="text-xs text-slate-300 font-sans leading-relaxed">
                  The RiskIQX Advisory Engine evaluates telemetry anomalies against your active asset inventory (
                  <strong>{assetCount} Tier-1 Assets</strong>, <strong>{userCount} Monitored Identities</strong>) and produces verifiable, step-by-step mitigation blueprints designed to avert intrusions before lateral propagation.
                </p>
              </div>

              {/* Quick Preset Threat Avoidance Trigger */}
              <div className="bg-slate-900/90 border border-white/10 p-3 rounded-xl flex items-center space-x-3">
                <Shield className="w-5 h-5 text-emerald-400" />
                <div>
                  <span className="text-[10px] text-slate-400 block font-mono">SECTOR RISK SHIELD</span>
                  <span className="text-emerald-300 font-bold font-mono text-xs">
                    {profile.name.toUpperCase()} ZERO-TRUST ACTIVE
                  </span>
                </div>
              </div>
            </div>

            {/* Interactive Threat Avoidance Simulator Widget */}
            <div className="mt-4 pt-4 border-t border-white/10 bg-slate-950/60 p-4 rounded-xl border border-white/5">
              <div className="flex flex-wrap items-center justify-between gap-4 mb-3">
                <div className="flex items-center space-x-2">
                  <Sliders className="w-4 h-4 text-indigo-400" />
                  <h3 className="font-display font-bold text-white text-xs uppercase tracking-wider">
                    Interactive Risk Mitigation Simulator (What-If Analysis)
                  </h3>
                </div>
                <div className="flex items-center space-x-4 font-mono text-xs">
                  <div>
                    <span className="text-slate-500 text-[10px] block">Baseline Risk</span>
                    <span className="text-red-400 font-bold text-sm">{baselineRisk.toFixed(1)}</span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-600" />
                  <div>
                    <span className="text-slate-500 text-[10px] block">Projected Avoided Risk</span>
                    <span className="text-emerald-400 font-bold text-sm">{projectedRisk.toFixed(1)} / 100</span>
                  </div>
                  <div className="bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-bold px-3 py-1 rounded-lg">
                    -{avoidedPercent}% Threat Exposure
                  </div>
                </div>
              </div>

              {/* 4 Interactive Mitigation Toggle Controls */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                <button
                  type="button"
                  onClick={() => toggleControl('edr_quarantine')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    simulatedControls.edr_quarantine
                      ? 'bg-blue-600/20 border-blue-500/50 text-white shadow-inner'
                      : 'bg-slate-900/60 border-white/10 text-slate-400 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold font-display text-[11px]">Auto EDR Host Containment</span>
                    <span className="text-blue-400 font-mono text-[10px] font-bold">-34.5 pts</span>
                  </div>
                  <p className="text-[10px] text-slate-400">Isolates infected endpoints on ransomware payload discovery.</p>
                </button>

                <button
                  type="button"
                  onClick={() => toggleControl('fido2_mfa')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    simulatedControls.fido2_mfa
                      ? 'bg-indigo-600/20 border-indigo-500/50 text-white shadow-inner'
                      : 'bg-slate-900/60 border-white/10 text-slate-400 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold font-display text-[11px]">Hardware FIDO2 MFA</span>
                    <span className="text-indigo-400 font-mono text-[10px] font-bold">-26.8 pts</span>
                  </div>
                  <p className="text-[10px] text-slate-400">Eliminates 99.8% of phishing & password spray breaches.</p>
                </button>

                <button
                  type="button"
                  onClick={() => toggleControl('db_microseg')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    simulatedControls.db_microseg
                      ? 'bg-emerald-600/20 border-emerald-500/50 text-white shadow-inner'
                      : 'bg-slate-900/60 border-white/10 text-slate-400 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold font-display text-[11px]">Database Egress DLP Lock</span>
                    <span className="text-emerald-400 font-mono text-[10px] font-bold">-22.4 pts</span>
                  </div>
                  <p className="text-[10px] text-slate-400">Strict egress whitelisting blocks unauthorized exfiltration.</p>
                </button>

                <button
                  type="button"
                  onClick={() => toggleControl('powershell_lock')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    simulatedControls.powershell_lock
                      ? 'bg-purple-600/20 border-purple-500/50 text-white shadow-inner'
                      : 'bg-slate-900/60 border-white/10 text-slate-400 hover:border-white/20'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold font-display text-[11px]">Constrained PowerShell</span>
                    <span className="text-purple-400 font-mono text-[10px] font-bold">-18.2 pts</span>
                  </div>
                  <p className="text-[10px] text-slate-400">Neutralizes Living-off-the-Land obfuscated script execution.</p>
                </button>
              </div>
            </div>
          </LiquidCard>

          {/* AI Avoidance Recommendation Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {(ai_recommendations || []).map((rec, idx) => (
              <LiquidCard
                key={rec.id || idx}
                borderRadius={18}
                className="p-5 border border-white/10 bg-slate-950/70 shadow-2xl space-y-4 hover:border-blue-500/40 transition-colors flex flex-col justify-between"
              >
                <div className="space-y-3">
                  {/* Card Header: Urgency Badge, Target & Risk Impact */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-md border tracking-wider ${
                          rec.urgency === 'IMMEDIATE'
                            ? 'bg-red-500/20 text-red-400 border-red-500/30 animate-pulse'
                            : rec.urgency === 'TACTICAL'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                        }`}
                      >
                        {rec.urgency} DEFENSE
                      </span>
                      <span className="text-slate-400 font-mono text-[10px]">{rec.id}</span>
                    </div>

                    <span className="bg-emerald-500/10 text-emerald-400 font-mono text-xs font-bold px-2.5 py-0.5 rounded border border-emerald-500/20">
                      -{rec.risk_reduction_points} pts Risk
                    </span>
                  </div>

                  {/* Title & Threat Vector */}
                  <div>
                    <h3 className="font-display font-bold text-white text-sm tracking-tight">{rec.title}</h3>
                    <div className="flex items-center space-x-2 mt-1 text-[11px] font-mono text-slate-400">
                      <span className="text-amber-400">Target Vector:</span>
                      <span className="text-slate-300">{rec.threat_vector}</span>
                    </div>
                  </div>

                  {/* Summary */}
                  <p className="text-xs text-slate-300 font-sans leading-relaxed">{rec.summary}</p>

                  {/* Mitigation Action Steps */}
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
                      Enforcement Steps:
                    </span>
                    <ul className="space-y-1 text-xs text-slate-300 font-sans">
                      {rec.mitigation_steps.map((step, sIdx) => (
                        <li key={sIdx} className="flex items-start space-x-2">
                          <Check className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Copyable Automation Script */}
                  {rec.automation_script && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span className="flex items-center space-x-1">
                          <Terminal className="w-3 h-3 text-emerald-400" />
                          <span>Automation Script / CLI Command:</span>
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopyScript(rec.id, rec.automation_script)}
                          className="flex items-center space-x-1 text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          {copiedId === rec.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400 font-bold">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy Script</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="bg-black/70 p-2.5 rounded-lg text-[10px] font-mono text-emerald-400 overflow-x-auto border border-white/10 whitespace-pre-wrap leading-relaxed">
                        {rec.automation_script}
                      </pre>
                    </div>
                  )}
                </div>

                {/* Footer Badges */}
                <div className="pt-3 mt-2 border-t border-white/10 flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <div className="flex items-center space-x-2">
                    <Target className="w-3.5 h-3.5 text-blue-400" />
                    <span>{rec.mitre_technique}</span>
                  </div>
                  <span className="text-slate-300 font-sans text-[11px]">{rec.implementation_effort}</span>
                </div>
              </LiquidCard>
            ))}
          </div>
        </div>
      )}

      {/* 5. Tab 2: SOC Command & Telemetry Breakdown */}
      {activeSubTab === 'telemetry' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Priority Level Breakdown Donut */}
            <LiquidCard borderRadius={18} className="p-5 space-y-4 border border-white/10 shadow-2xl bg-slate-950/70">
              <div className="flex items-center justify-between">
                <h3 className="font-display font-bold text-white text-sm">Incident Priority Distribution</h3>
                <span className="text-[10px] font-mono text-slate-400">{metrics.total_incidents} Total Incidents</span>
              </div>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={priority_distribution}
                      dataKey="count"
                      nameKey="level"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      innerRadius={50}
                      paddingAngle={3}
                    >
                      {priority_distribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#090d16',
                        borderColor: 'rgba(255,255,255,0.15)',
                        borderRadius: '12px',
                        color: '#fff',
                        fontSize: '12px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Custom Legend */}
              <div className="grid grid-cols-4 gap-2 pt-2 border-t border-white/10 text-center font-mono text-xs">
                {priority_distribution.map((p, idx) => (
                  <div key={idx} className="bg-slate-900/60 p-2 rounded-lg border border-white/5">
                    <span className="text-[10px] text-slate-400 block">{p.level}</span>
                    <span className="font-bold text-white" style={{ color: p.color }}>
                      {p.count}
                    </span>
                  </div>
                ))}
              </div>
            </LiquidCard>

            {/* Attack Kill-Chain Category Breakdown */}
            <LiquidCard borderRadius={18} className="p-5 space-y-4 border border-white/10 shadow-2xl bg-slate-950/70">
              <div className="flex items-center justify-between">
                <h3 className="font-display font-bold text-white text-sm">Kill-Chain Telemetry by Category</h3>
                <span className="text-[10px] font-mono text-slate-400">Events Ingested</span>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryChartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                    <XAxis dataKey="category" stroke="#94a3b8" fontSize={10} tickLine={false} />
                    <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#090d16',
                        borderColor: 'rgba(255,255,255,0.15)',
                        borderRadius: '12px',
                        color: '#fff',
                        fontSize: '12px',
                      }}
                    />
                    <Bar dataKey="count" fill="#3b82f6" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </LiquidCard>
          </div>

          {/* Top Noisy Rules & Triage Velocity */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <LiquidCard borderRadius={18} className="p-5 space-y-3 border border-white/10 shadow-2xl bg-slate-950/70">
              <div className="flex items-center space-x-2">
                <Volume2 className="w-4 h-4 text-yellow-400" />
                <h3 className="font-display font-bold text-white text-sm">Noisiest Detection Rules (Auto-Suppressed)</h3>
              </div>
              <div className="space-y-2 text-xs">
                {top_noisy_rules.map((rule, rIdx) => (
                  <div
                    key={rIdx}
                    className="bg-slate-950/70 p-3 rounded-xl border border-white/10 flex justify-between items-center hover:border-blue-500/40 transition-colors"
                  >
                    <span className="font-medium text-slate-200 font-sans">{rule.rule}</span>
                    <span className="bg-blue-500/15 text-blue-400 font-mono px-2.5 py-0.5 rounded-md font-bold border border-blue-500/20">
                      {rule.triggers} triggers
                    </span>
                  </div>
                ))}
              </div>
            </LiquidCard>

            <LiquidCard borderRadius={18} className="p-5 space-y-3 border border-white/10 shadow-2xl bg-slate-950/70">
              <div className="flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <h3 className="font-display font-bold text-white text-sm">Active Threat Engines & Defense Stack</h3>
              </div>
              <div className="space-y-2 text-xs">
                <div className="bg-slate-900/60 p-3 rounded-xl border border-white/10 flex justify-between items-center">
                  <span className="font-medium text-slate-200">Real-Time Event Normalization Engine</span>
                  <span className="bg-emerald-500/15 text-emerald-400 font-mono px-2 py-0.5 rounded text-[10px] font-bold">
                    ACTIVE (0.4ms)
                  </span>
                </div>
                <div className="bg-slate-900/60 p-3 rounded-xl border border-white/10 flex justify-between items-center">
                  <span className="font-medium text-slate-200">Temporal Sliding-Window Deduplication (300s)</span>
                  <span className="bg-emerald-500/15 text-emerald-400 font-mono px-2 py-0.5 rounded text-[10px] font-bold">
                    ENFORCED
                  </span>
                </div>
                <div className="bg-slate-900/60 p-3 rounded-xl border border-white/10 flex justify-between items-center">
                  <span className="font-medium text-slate-200">6-Factor Contextual Risk Prioritizer</span>
                  <span className="bg-blue-500/15 text-blue-400 font-mono px-2 py-0.5 rounded text-[10px] font-bold">
                    CALIBRATED
                  </span>
                </div>
                <div className="bg-slate-900/60 p-3 rounded-xl border border-white/10 flex justify-between items-center">
                  <span className="font-medium text-slate-200">Automated Reversible Playbook Isolation</span>
                  <span className="bg-indigo-500/15 text-indigo-400 font-mono px-2 py-0.5 rounded text-[10px] font-bold">
                    STANDBY
                  </span>
                </div>
              </div>
            </LiquidCard>
          </div>
        </div>
      )}

      {/* 6. Tab 3: MITRE ATT&CK Matrix Defense */}
      {activeSubTab === 'mitre' && (
        <LiquidCard borderRadius={20} className="p-6 border border-white/10 shadow-2xl bg-slate-950/70 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-display font-bold text-white text-base">MITRE ATT&CK Enterprise Matrix Coverage</h3>
              <p className="text-xs text-slate-400 font-sans mt-0.5">
                Real-time mapping of active intruder techniques detected across your {profile.name} endpoints.
              </p>
            </div>
            <span className="bg-blue-500/20 text-blue-300 font-mono text-xs px-3 py-1 rounded-lg border border-blue-500/30 font-bold">
              {activeMitre.length} Techniques Mapped
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
            {activeMitre.map((item, idx) => (
              <div
                key={idx}
                className="bg-slate-900/80 p-4 rounded-xl border border-white/10 hover:border-blue-500/40 transition-colors space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono bg-blue-600/30 text-blue-300 px-2 py-0.5 rounded font-bold border border-blue-500/30">
                    {item.technique_id}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">{item.tactic}</span>
                </div>
                <h4 className="font-bold text-white text-xs font-display">{item.technique_name}</h4>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1 border-t border-white/5">
                  <span>Detections:</span>
                  <span className="text-amber-400 font-bold">{item.count} hits</span>
                </div>
              </div>
            ))}
          </div>
        </LiquidCard>
      )}

      {/* 7. Tab 4: Live Security Audit Stream */}
      {activeSubTab === 'audit' && (
        <LiquidCard borderRadius={18} className="p-5 space-y-3 border border-white/10 shadow-2xl bg-slate-950/70">
          <div className="flex items-center space-x-2">
            <History className="w-4 h-4 text-blue-400" />
            <h3 className="font-display font-bold text-white text-sm">Immutable Security & Calibration Audit Log</h3>
          </div>

          <div className="divide-y divide-white/5 max-h-80 overflow-y-auto font-mono text-xs text-slate-300 scrollbar-thin">
            {recent_audit_logs.map((log, aIdx) => (
              <div key={aIdx} className="py-2.5 flex items-center justify-between hover:bg-slate-900/40 px-2 rounded-lg transition-colors">
                <div className="flex items-center space-x-3">
                  <span className="text-slate-500 text-[10px]">
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'N/A'}
                  </span>
                  <span className="text-blue-400 font-bold">[{log.action}]</span>
                  <span className="font-sans text-xs">
                    Actor: <span className="font-mono text-slate-200">{log.actor}</span>
                  </span>
                </div>
                <span className="text-slate-500 text-[10px]">{log.entity}</span>
              </div>
            ))}
          </div>
        </LiquidCard>
      )}

      {/* 8. Active Cyber Defense Capability Cards (Always present at bottom) */}
      <div className="space-y-3 pt-2">
        <h3 className="font-display font-bold text-white text-sm tracking-tight">Enterprise Defensive Capability Stack</h3>
        <AppleGlassStack
          direction="horizontal"
          gap={16}
          borderRadius={20}
          padding={20}
          hoverLift={6}
          items={[
            {
              title: "MITRE ATT&CK Matrix Correlation",
              body: "Real-time behavioral heuristics mapping active multi-stage intrusions to adversary techniques.",
              badge: "HEURISTICS ACTIVE",
              icon: <Cpu className="w-5 h-5 text-blue-400 drop-shadow-[0_0_8px_rgba(59,130,246,0.6)]" />,
            },
            {
              title: "6-Factor Dynamic Risk Prioritization",
              body: "Sub-second triage ranking factoring in asset criticality tier, data classification, and attack confidence.",
              badge: "MATHEMATICALLY FORMULATED",
              icon: <Zap className="w-5 h-5 text-amber-400 drop-shadow-[0_0_8px_rgba(251,191,36,0.6)]" />,
            },
            {
              title: "Zero-Trust Safe Playbook Automation",
              body: "Semi-automated containment workflows with immutable analyst audit logging and one-click rollback.",
              badge: "PROTECTED",
              icon: <Lock className="w-5 h-5 text-emerald-400 drop-shadow-[0_0_8px_rgba(16,185,129,0.6)]" />,
            },
          ]}
          boxWidth="calc(33.333% - 11px)"
        />
      </div>
    </div>
  );
};
