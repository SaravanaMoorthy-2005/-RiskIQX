import React, { useState, useEffect } from 'react';
import { IncidentDetailData, PairwiseExplanation, TimelineItem } from '../types';
import { ScoreBreakdownView } from './ScoreBreakdown';
import { PairwiseCompareView } from './PairwiseCompare';
import { PlaybookModal } from './PlaybookModal';
import { AppleGlassCard } from './ui/liquid-glass-card';
import {
  fetchWhyNumberOne,
  fetchCompareNext,
  fetchTimeline,
  fetchEvidence,
  submitFeedback,
  fetchPlaybook,
  simulatePlaybookAction,
} from '../api/client';
import {
  ShieldAlert,
  GitCompare,
  Clock,
  FileText,
  Play,
  CheckCircle,
  Zap,
  Server,
  Shield,
  Layers,
  ArrowUpRight,
} from 'lucide-react';

interface IncidentDetailProps {
  incident: IncidentDetailData;
  onRefresh: () => void;
}

export const IncidentDetail: React.FC<IncidentDetailProps> = ({ incident, onRefresh }) => {
  const [activeTab, setActiveTab] = useState<'why1' | 'compare' | 'timeline' | 'evidence'>('why1');
  const [why1Data, setWhy1Data] = useState<any>(null);
  const [pairwiseData, setPairwiseData] = useState<PairwiseExplanation | null>(null);
  const [timelineData, setTimelineData] = useState<TimelineItem[]>([]);
  const [evidenceData, setEvidenceData] = useState<any>(null);

  const [feedbackDecision, setFeedbackDecision] = useState<string>('CONFIRMED_INCIDENT');
  const [feedbackNotes, setFeedbackNotes] = useState<string>('');
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState(false);

  const [playbookModalOpen, setPlaybookModalOpen] = useState(false);
  const [playbookData, setPlaybookData] = useState<any>(null);

  useEffect(() => {
    loadTabContent();
  }, [incident.incident_id, activeTab]);

  const loadTabContent = async () => {
    try {
      if (activeTab === 'why1' && !why1Data) {
        const data = await fetchWhyNumberOne(incident.incident_id);
        setWhy1Data(data);
      } else if (activeTab === 'compare' && !pairwiseData) {
        const data = await fetchCompareNext(incident.incident_id);
        setPairwiseData(data);
      } else if (activeTab === 'timeline' && timelineData.length === 0) {
        const data = await fetchTimeline(incident.incident_id);
        setTimelineData(data.timeline || []);
      } else if (activeTab === 'evidence' && !evidenceData) {
        const data = await fetchEvidence(incident.incident_id);
        setEvidenceData(data);
      }
    } catch (err) {
      console.error('Error loading tab content:', err);
    }
  };

  const handleOpenPlaybook = async () => {
    try {
      const pb = await fetchPlaybook(incident.incident_id);
      setPlaybookData(pb);
      setPlaybookModalOpen(true);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSimulateAction = async (actionName: string, approved: boolean) => {
    return await simulatePlaybookAction(incident.incident_id, playbookData.id, actionName, approved);
  };

  const handleSubmitFeedback = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedbackSubmitting(true);
    try {
      await submitFeedback(incident.incident_id, feedbackDecision, 'analyst@soc.local', feedbackNotes);
      setFeedbackSuccess(true);
      setTimeout(() => setFeedbackSuccess(false), 4000);
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setFeedbackSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Precision Header Command Banner */}
      <AppleGlassCard
        borderRadius={20}
        hoverLift={3}
        className="p-5 border border-white/10 shadow-2xl relative overflow-hidden"
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5 flex-1">
            {/* Top Telemetry Meta Bar */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-mono text-[11px] font-semibold text-blue-400 bg-blue-500/10 px-2.5 py-0.5 rounded-md border border-blue-500/30 tracking-wide">
                {incident.incident_id}
              </span>

              <div className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded-md bg-slate-900 border border-white/10">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="font-mono text-[11px] text-slate-300 font-semibold">{incident.status}</span>
              </div>

              <span className="text-[11px] text-slate-400 font-mono">
                Assets: <strong className="text-slate-200">{incident.affected_assets?.length || 0}</strong>
              </span>

              <span className="text-slate-600">•</span>

              <span className="text-[11px] text-slate-400 font-mono">
                Confidence: <strong className="text-emerald-400">{Math.round((incident.score_breakdown?.attack_confidence ?? incident.attack_confidence ?? 0.8) * 100)}%</strong>
              </span>
            </div>

            {/* Title */}
            <h1 className="font-display text-xl md:text-2xl font-bold text-white tracking-tight leading-snug">
              {incident.title}
            </h1>

            {/* Attack Narrative */}
            <p className="text-xs text-slate-300 font-sans max-w-4xl leading-relaxed">
              {incident.attack_story}
            </p>
          </div>

          {/* Action Button */}
          <div className="flex items-center space-x-3 shrink-0 self-start md:self-center">
            <button
              onClick={handleOpenPlaybook}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-display font-semibold text-xs px-4 py-2.5 rounded-xl transition-all flex items-center space-x-2 shadow-[0_0_20px_rgba(16,185,129,0.35)] hover:shadow-[0_0_25px_rgba(16,185,129,0.5)] active:scale-95"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Execute Playbook</span>
            </button>
          </div>
        </div>
      </AppleGlassCard>

      {/* Symmetrical Dual-Column Layout: Left Intelligence Workspace (7 cols) / Right Score Architecture (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {/* Left Column: Segmented Switcher & Active Intelligence View */}
        <div className="lg:col-span-7 space-y-4">
          {/* macOS / Linear-Style Glass Segmented Pill Switcher */}
          <div className="p-1 bg-slate-950/70 backdrop-blur-xl border border-white/10 rounded-2xl flex items-center gap-1 shadow-inner">
            <button
              onClick={() => setActiveTab('why1')}
              className={`flex-1 py-2 px-3 rounded-xl flex items-center justify-center space-x-1.5 text-xs font-display font-semibold transition-all ${
                activeTab === 'why1'
                  ? 'bg-blue-600 text-white shadow-[0_2px_12px_rgba(59,130,246,0.4)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Score Rationale</span>
            </button>

            <button
              onClick={() => setActiveTab('compare')}
              className={`flex-1 py-2 px-3 rounded-xl flex items-center justify-center space-x-1.5 text-xs font-display font-semibold transition-all ${
                activeTab === 'compare'
                  ? 'bg-blue-600 text-white shadow-[0_2px_12px_rgba(59,130,246,0.4)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Pairwise Matrix</span>
            </button>

            <button
              onClick={() => setActiveTab('timeline')}
              className={`flex-1 py-2 px-3 rounded-xl flex items-center justify-center space-x-1.5 text-xs font-display font-semibold transition-all ${
                activeTab === 'timeline'
                  ? 'bg-blue-600 text-white shadow-[0_2px_12px_rgba(59,130,246,0.4)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              <span>Attack Timeline</span>
            </button>

            <button
              onClick={() => setActiveTab('evidence')}
              className={`flex-1 py-2 px-3 rounded-xl flex items-center justify-center space-x-1.5 text-xs font-display font-semibold transition-all ${
                activeTab === 'evidence'
                  ? 'bg-blue-600 text-white shadow-[0_2px_12px_rgba(59,130,246,0.4)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Telemetry Evidence</span>
            </button>
          </div>

          {/* Tab 1: Dynamic "Why #1?" Explanation */}
          {activeTab === 'why1' && (
            <AppleGlassCard borderRadius={18} hoverLift={2} className="p-5 space-y-4 border border-white/10 shadow-xl">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center space-x-2">
                  <div className="p-1 rounded bg-amber-500/15 text-amber-400">
                    <Zap className="w-3.5 h-3.5 drop-shadow-[0_0_6px_rgba(251,191,36,0.6)]" />
                  </div>
                  <h3 className="font-display font-bold text-white text-sm">Dynamic Risk Driver Analysis</h3>
                </div>
                <span className="text-[10px] font-mono bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded border border-blue-500/20 font-bold">
                  RANK #1 RATIONALE
                </span>
              </div>

              {/* Executive Summary Callout */}
              <div className="bg-gradient-to-r from-blue-950/40 via-indigo-950/30 to-slate-900/80 border border-blue-500/30 p-4 rounded-xl text-xs text-slate-200 leading-relaxed font-sans shadow-inner">
                <span className="text-blue-400 font-bold block mb-1 uppercase tracking-wider text-[10px] font-display">
                  Contextual Risk Summary
                </span>
                {why1Data?.narrative || 'Evaluating automated contextual narrative from telemetry weights...'}
              </div>

              {/* Structured Driver Highlights List */}
              {why1Data?.driver_highlights && (
                <div className="space-y-2.5">
                  <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider font-display">
                    Top Contributing Risk Drivers
                  </h4>
                  <div className="grid grid-cols-1 gap-2">
                    {why1Data.driver_highlights.map((driver: any, dIdx: number) => (
                      <div
                        key={dIdx}
                        className="bg-slate-900/80 border border-white/10 rounded-xl p-3 flex items-start justify-between text-xs hover:border-blue-500/40 transition-colors"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="bg-blue-600/30 text-blue-400 font-mono text-[10px] font-bold px-1.5 py-0.5 rounded border border-blue-500/30">
                              #{driver.rank} DRIVER
                            </span>
                            <span className="font-bold text-white font-display">{driver.factor}</span>
                            <span className="text-slate-400 font-mono text-[11px]">({driver.raw_value})</span>
                          </div>
                          <p className="text-slate-300 text-[11px] font-sans leading-normal">{driver.impact_statement}</p>
                        </div>
                        <span className="font-mono text-xs font-bold text-amber-400 bg-amber-500/10 px-2.5 py-0.5 rounded border border-amber-500/20 shrink-0 ml-3 tabular-nums">
                          {String(driver.contribution).includes('pts') ? driver.contribution : `+${driver.contribution} pts`}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Asset & Exposure Footprint */}
              {why1Data?.context_assessment && (
                <div className="space-y-2 pt-2 border-t border-white/10">
                  <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider font-display">
                    Target & Identity Exposure Footprint
                  </h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs bg-slate-950/50 p-3 rounded-xl border border-white/10">
                    <div>
                      <span className="text-slate-400 text-[10px] block">Criticality Tier</span>
                      <span className="font-mono font-bold text-red-400">{why1Data.context_assessment.criticality_tier}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">Financial Exposure</span>
                      <span className="font-mono text-slate-200">{why1Data.context_assessment.financial_impact}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">Data Sensitivity</span>
                      <span className="font-mono text-amber-400">{why1Data.context_assessment.data_classification}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">Network Surface</span>
                      <span className="font-mono text-slate-300">{why1Data.context_assessment.internet_facing}</span>
                    </div>
                  </div>
                </div>
              )}
            </AppleGlassCard>
          )}

          {/* Tab 2: Pairwise Compare ("Why Above #2?") */}
          {activeTab === 'compare' && (
            <div>
              {pairwiseData ? (
                <PairwiseCompareView comparison={pairwiseData} />
              ) : (
                <div className="p-8 text-center text-slate-500 text-xs font-sans">
                  Computing pairwise delta matrix...
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Chronological Attack Timeline */}
          {activeTab === 'timeline' && (
            <AppleGlassCard borderRadius={18} hoverLift={2} className="p-5 space-y-4 border border-white/10 shadow-xl">
              <h3 className="font-display font-bold text-white text-sm flex items-center space-x-2">
                <Clock className="w-4 h-4 text-blue-400" />
                <span>Chronological Attack Progression Timeline</span>
              </h3>

              <div className="relative border-l-2 border-slate-800 ml-4 space-y-5 py-2">
                {timelineData.map((item, idx) => (
                  <div key={idx} className="ml-6 relative">
                    <div className="absolute -left-[31px] top-0 w-3 h-3 rounded-full bg-blue-500 border-2 border-slate-950 shadow-[0_0_8px_rgba(59,130,246,0.8)]"></div>
                    <div className="bg-slate-900/80 p-3.5 rounded-xl border border-white/10 text-xs space-y-1 hover:border-blue-500/40 transition-colors">
                      <div className="flex items-center justify-between text-slate-400 font-mono text-[10px]">
                        <span>{item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'N/A'}</span>
                        <span className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded font-mono">{item.source}</span>
                      </div>
                      <p className="font-semibold text-slate-200 font-sans">{item.action_summary}</p>
                    </div>
                  </div>
                ))}
              </div>
            </AppleGlassCard>
          )}

          {/* Tab 4: Correlated Evidence */}
          {activeTab === 'evidence' && (
            <AppleGlassCard borderRadius={18} hoverLift={2} className="p-5 space-y-4 border border-white/10 shadow-xl">
              <h3 className="font-display font-bold text-white text-sm flex items-center space-x-2">
                <FileText className="w-4 h-4 text-blue-400" />
                <span>Correlated Security Detections & Telemetry Evidence</span>
              </h3>

              <div className="space-y-3">
                {evidenceData?.detections?.map((det: any, dIdx: number) => (
                  <div key={dIdx} className="bg-slate-900/80 p-3.5 rounded-xl border border-white/10 text-xs space-y-1.5 hover:border-blue-500/40 transition-colors">
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-bold text-blue-400">{det.rule_name}</span>
                      <span className="text-slate-400 text-[10px]">{det.mitre_technique}</span>
                    </div>
                    <pre className="bg-black/60 p-2.5 rounded-lg text-[11px] font-mono text-emerald-400 overflow-x-auto border border-white/5">
                      {JSON.stringify(det.evidence, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </AppleGlassCard>
          )}

          {/* Analyst Ground Truth Feedback Form */}
          <AppleGlassCard borderRadius={18} hoverLift={2} className="p-5 space-y-4 border border-white/10 shadow-xl">
            <h3 className="font-display font-bold text-white text-sm flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span>Analyst Ground Truth Feedback</span>
            </h3>

            {feedbackSuccess && (
              <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs p-3 rounded-lg flex items-center space-x-2">
                <CheckCircle className="w-4 h-4" />
                <span>Feedback successfully recorded into active calibration model.</span>
              </div>
            )}

            <form onSubmit={handleSubmitFeedback} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {[
                  { id: 'CONFIRMED_INCIDENT', label: 'Confirmed Incident' },
                  { id: 'FALSE_POSITIVE', label: 'False Positive' },
                  { id: 'BENIGN', label: 'Benign Activity' },
                  { id: 'NEEDS_INVESTIGATION', label: 'Needs Triage' },
                ].map((opt) => (
                  <button
                    type="button"
                    key={opt.id}
                    onClick={() => setFeedbackDecision(opt.id)}
                    className={`py-2 px-3 rounded-xl border text-center font-display font-semibold transition-all ${
                      feedbackDecision === opt.id
                        ? 'bg-blue-600 border-blue-500 text-white shadow-md'
                        : 'bg-slate-900/80 border-white/10 text-slate-400 hover:text-white hover:border-white/20'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <textarea
                placeholder="Enter investigation notes or justification..."
                value={feedbackNotes}
                onChange={(e) => setFeedbackNotes(e.target.value)}
                className="w-full bg-slate-950/80 border border-white/10 rounded-xl p-3 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 h-20 font-sans"
              />

              <button
                type="submit"
                disabled={feedbackSubmitting}
                className="bg-blue-600 hover:bg-blue-500 text-white font-display font-semibold text-xs px-4 py-2.5 rounded-xl transition-colors disabled:opacity-50 shadow-lg shadow-blue-600/30"
              >
                {feedbackSubmitting ? 'Saving Feedback...' : 'Submit Analyst Feedback'}
              </button>
            </form>
          </AppleGlassCard>
        </div>

        {/* Right Column: 6-Factor Contextual Risk Architecture (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <ScoreBreakdownView breakdown={incident.score_breakdown} />
        </div>
      </div>

      {/* Safe Playbook Modal */}
      {playbookModalOpen && playbookData && (
        <PlaybookModal
          playbook={playbookData}
          onExecuteAction={handleSimulateAction}
          onClose={() => setPlaybookModalOpen(false)}
        />
      )}
    </div>
  );
};
