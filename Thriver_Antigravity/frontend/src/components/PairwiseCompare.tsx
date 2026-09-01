import React from 'react';
import { PairwiseExplanation } from '../types';
import { AppleGlassCard } from './ui/liquid-glass-card';
import { GitCompare, Trophy, ArrowRight, CheckCircle2 } from 'lucide-react';

interface PairwiseCompareProps {
  comparison: PairwiseExplanation;
}

export const PairwiseCompareView: React.FC<PairwiseCompareProps> = ({ comparison }) => {
  if (!comparison || !comparison.factor_deltas || comparison.factor_deltas.length === 0) {
    return (
      <AppleGlassCard borderRadius={18} className="p-5 border border-white/10 shadow-2xl">
        <div className="flex items-center space-x-3 text-slate-300">
          <GitCompare className="w-5 h-5 text-indigo-400 shrink-0" />
          <p className="text-xs font-sans leading-relaxed">
            {comparison?.summary_narrative || 'Pairwise comparison requires at least two active incidents in the triage queue.'}
          </p>
        </div>
      </AppleGlassCard>
    );
  }
  return (
    <AppleGlassCard borderRadius={18} className="p-5 space-y-4 border border-white/10 shadow-2xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/10 pb-3">
        <div className="flex items-center space-x-2.5">
          <div className="bg-indigo-500/20 text-indigo-400 p-2 rounded-xl border border-indigo-500/30">
            <GitCompare className="w-4 h-4 drop-shadow-[0_0_8px_rgba(99,102,241,0.5)]" />
          </div>
          <div>
            <h3 className="font-display font-bold text-white text-sm tracking-tight">Pairwise Battle Matrix — Why #1 over #2?</h3>
            <p className="text-[11px] text-slate-400 font-sans">Comparative factor-by-factor risk delta analysis</p>
          </div>
        </div>

        <div className="bg-indigo-500/15 border border-indigo-500/30 px-3 py-1 rounded-xl text-right">
          <span className="text-[9px] text-slate-400 uppercase tracking-wider block font-display">Ranking Gap</span>
          <span className="text-base font-extrabold text-indigo-400 font-mono tabular-nums">+{comparison.score_gap} pts</span>
        </div>
      </div>

      {/* Decision Summary Callout */}
      <div className="bg-gradient-to-r from-indigo-950/40 via-blue-950/30 to-slate-900/80 border border-indigo-500/30 rounded-xl p-3.5 text-xs text-slate-200 leading-relaxed flex items-start space-x-3 shadow-inner font-sans">
        <Trophy className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-display font-bold text-white block mb-0.5 text-xs">Pairwise Decision Rationale</span>
          {comparison.summary_narrative}
        </div>
      </div>

      {/* Factor Delta Table */}
      <div className="overflow-x-auto rounded-xl border border-white/10">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-white/10 text-slate-400 uppercase tracking-wider text-[10px] bg-slate-950/80 font-display">
              <th className="py-2.5 px-3">Factor</th>
              <th className="py-2.5 px-3">Inc #1 ({comparison.incident_a_score})</th>
              <th className="py-2.5 px-3">Inc #2 ({comparison.incident_b_score})</th>
              <th className="py-2.5 px-3 text-right">Score Delta</th>
              <th className="py-2.5 px-3">Ranking Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 font-sans">
            {comparison.factor_deltas.map((delta, idx) => {
              const isWinning = delta.contribution_diff > 0;
              return (
                <tr key={idx} className={`hover:bg-slate-800/40 transition-colors ${isWinning ? 'bg-indigo-950/15' : ''}`}>
                  <td className="py-2.5 px-3 font-semibold text-slate-200 font-display">{delta.factor_name}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 tabular-nums">
                    {delta.inc_a_value} <span className="text-slate-500 text-[10px]">(+{delta.inc_a_contribution} pts)</span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 tabular-nums">
                    {delta.inc_b_value} <span className="text-slate-500 text-[10px]">(+{delta.inc_b_contribution} pts)</span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-right tabular-nums">
                    <span
                      className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                        isWinning
                          ? 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20'
                          : delta.contribution_diff < 0
                          ? 'text-red-400 bg-red-500/10 border border-red-500/20'
                          : 'text-slate-400'
                      }`}
                    >
                      {delta.contribution_diff > 0 ? `+${delta.contribution_diff}` : delta.contribution_diff} pts
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 text-[11px] leading-normal">
                    {delta.explanation}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </AppleGlassCard>
  );
};
