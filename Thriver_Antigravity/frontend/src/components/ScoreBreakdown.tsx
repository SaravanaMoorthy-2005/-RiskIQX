import React from 'react';
import { ScoreBreakdown as ScoreBreakdownType } from '../types';
import { AppleGlassCard } from './ui/liquid-glass-card';
import { AlertTriangle, Info, ShieldCheck, Gauge, TrendingUp } from 'lucide-react';

interface ScoreBreakdownProps {
  breakdown: ScoreBreakdownType;
}

export const ScoreBreakdownView: React.FC<ScoreBreakdownProps> = ({ breakdown }) => {
  const getBadgeColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40 shadow-[0_0_12px_rgba(239,68,68,0.3)]';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40 shadow-[0_0_12px_rgba(249,115,22,0.3)]';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/40';
    }
  };

  const getScoreGlow = (score: number) => {
    if (score >= 90) return 'text-red-400 drop-shadow-[0_0_15px_rgba(239,68,68,0.5)]';
    if (score >= 75) return 'text-orange-400 drop-shadow-[0_0_15px_rgba(249,115,22,0.5)]';
    if (score >= 50) return 'text-yellow-400 drop-shadow-[0_0_15px_rgba(234,179,8,0.5)]';
    return 'text-blue-400 drop-shadow-[0_0_15px_rgba(59,130,246,0.5)]';
  };

  const level = breakdown?.priority_level || 'MEDIUM';
  const score = breakdown?.final_score ?? 0;
  const attackConf = breakdown?.attack_confidence ?? 0.8;
  const dataConf = breakdown?.data_confidence ?? 1.0;
  const contributions = breakdown?.contributions || {};
  const missingFactors = breakdown?.missing_factors || [];

  return (
    <AppleGlassCard
      enableTilt={false}
      borderRadius={20}
      className="p-5 space-y-5 border border-white/10 shadow-2xl"
    >
      {/* Top Header & Contextual Score Gauge */}
      <div className="border-b border-white/10 pb-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <Gauge className="w-4 h-4 text-blue-400 drop-shadow-[0_0_6px_rgba(59,130,246,0.6)]" />
            <h3 className="font-display font-bold text-white text-sm tracking-tight">Contextual Risk Engine</h3>
          </div>
          <span className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold font-mono border tracking-wider ${getBadgeColor(level)}`}>
            {level}
          </span>
        </div>

        {/* Large Score Card Display */}
        <div className="bg-slate-950/60 p-4 rounded-xl border border-white/10 flex items-center justify-between">
          <div>
            <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono block">Contextual Risk Index</span>
            <div className="flex items-baseline space-x-2 mt-1">
              <span className={`text-4xl font-extrabold font-mono tracking-tight tabular-nums ${getScoreGlow(score)}`}>
                {score.toFixed(1)}
              </span>
              <span className="text-slate-500 text-xs font-mono">/ 100</span>
            </div>
          </div>

          <div className="flex items-center space-x-4 border-l border-white/10 pl-4 text-right">
            <div>
              <div className="flex items-center justify-end space-x-1 text-slate-400 text-[10px] font-sans">
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                <span>Attack Conf.</span>
              </div>
              <span className="font-mono text-base font-bold text-white tabular-nums">
                {Math.round(attackConf * 100)}%
              </span>
            </div>

            <div>
              <div className="flex items-center justify-end space-x-1 text-slate-400 text-[10px] font-sans">
                <Info className="w-3 h-3 text-blue-400" />
                <span>Data Conf.</span>
              </div>
              <span className="font-mono text-base font-bold text-white tabular-nums">
                {Math.round(dataConf * 100)}%
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Uncertainty Warning Callout */}
      {missingFactors.length > 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 flex items-start space-x-2.5 text-xs text-yellow-300">
          <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <p className="font-semibold font-display text-[11px]">Uncertainty Margin — Missing Telemetry Factors:</p>
            <p className="text-slate-400 text-[10px] font-mono">
              {missingFactors.join(' • ')}
            </p>
          </div>
        </div>
      )}

      {/* 6-Factor Contribution Matrix with Laser Alignment */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-[11px] font-display font-semibold text-slate-400 uppercase tracking-wider">
          <span>6-Factor Contribution Model</span>
          <span className="font-mono text-[10px] text-slate-500 font-normal">Normalized Impact</span>
        </div>

        <div className="space-y-2">
          {Object.entries(contributions).map(([key, item]: [string, any]) => {
            const pct = Math.min(100, Math.max(0, item.normalized_value ?? 0));
            return (
              <div
                key={key}
                className="bg-slate-950/60 p-2.5 rounded-xl border border-white/10 hover:border-blue-500/40 transition-colors"
              >
                <div className="flex justify-between items-center text-xs mb-1.5">
                  <div className="flex items-center space-x-2 truncate">
                    <span className="font-medium text-slate-200 font-sans truncate">{item.factor_name}</span>
                    <span className="text-slate-500 font-mono text-[10px] shrink-0">({item.raw_value})</span>
                  </div>
                  <div className="flex items-center space-x-2.5 font-mono text-[11px] shrink-0 ml-2">
                    <span className="text-slate-500 text-[10px]">{((item.weight ?? 0) * 100).toFixed(0)}%</span>
                    <span className="text-blue-400 font-bold tabular-nums">+{(item.contribution ?? 0).toFixed(1)} pts</span>
                  </div>
                </div>

                <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden flex">
                  <div
                    className="bg-gradient-to-r from-blue-600 via-indigo-500 to-cyan-400 h-1.5 rounded-full transition-all duration-500"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </AppleGlassCard>
  );
};
