import React, { useState } from 'react';
import { IncidentSummary } from '../types';
import { AppleGlassCard } from './ui/liquid-glass-card';
import { Search, ShieldAlert, ChevronRight, Server, User, Zap, Shield } from 'lucide-react';

interface InvestigationQueueProps {
  incidents: IncidentSummary[];
  selectedIncidentId?: string;
  onSelectIncident: (id: string) => void;
  isLoading: boolean;
}

export const InvestigationQueue: React.FC<InvestigationQueueProps> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  isLoading,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const filtered = incidents.filter((inc) => {
    const assets = inc.affected_assets || [];
    const matchesSearch =
      (inc.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (inc.incident_id || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      assets.some((a) => (a || '').toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesPriority = priorityFilter === 'ALL' || inc.priority_level === priorityFilter;
    const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter;

    return matchesSearch && matchesPriority && matchesStatus;
  });

  const getPriorityBadgeClass = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-400 border-red-500/30 shadow-[0_0_8px_rgba(239,68,68,0.25)]';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <AppleGlassCard
      enableTilt={false}
      enableShine={false}
      borderRadius={20}
      className="flex flex-col h-full overflow-hidden p-0 border border-white/10 shadow-2xl"
    >
      {/* Header & Filter Inset Bar */}
      <div className="p-4 border-b border-white/10 space-y-3 bg-slate-950/50 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 rounded-lg bg-blue-500/15 border border-blue-500/30 text-blue-400">
              <ShieldAlert className="w-4 h-4 drop-shadow-[0_0_6px_rgba(59,130,246,0.6)]" />
            </div>
            <div>
              <h2 className="font-display font-bold text-white text-sm tracking-tight">Priority Triage Queue</h2>
              <span className="text-[11px] text-slate-400 font-sans">Dynamic Risk Prioritization</span>
            </div>
          </div>
          <span className="bg-blue-500/15 text-blue-300 text-xs px-2.5 py-0.5 rounded-full font-mono border border-blue-500/30 font-semibold">
            {filtered.length} Active
          </span>
        </div>

        {/* Search Bar with Glass Inset */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filter by ID, adversary tactic, or host..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900/90 border border-white/10 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/60 transition-colors font-sans shadow-inner"
          />
        </div>

        {/* Filter Badges */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-slate-900/90 border border-white/10 rounded-xl px-2.5 py-1.5 text-[11px] text-slate-300 focus:outline-none focus:border-blue-500/60 font-sans cursor-pointer"
          >
            <option value="ALL">All Priorities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="LOW">Low Only</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900/90 border border-white/10 rounded-xl px-2.5 py-1.5 text-[11px] text-slate-300 focus:outline-none focus:border-blue-500/60 font-sans cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">Status: NEW</option>
            <option value="TRIAGED">Status: TRIAGED</option>
            <option value="INVESTIGATING">Status: INVESTIGATING</option>
            <option value="AWAITING_APPROVAL">AWAITING APPROVAL</option>
          </select>
        </div>
      </div>

      {/* Incident List with Precision Outcut Cards */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2.5 scrollbar-thin">
        {isLoading ? (
          <div className="p-8 text-center text-slate-400">
            <div className="inline-block w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2"></div>
            <p className="text-xs font-sans">Evaluating 6-factor risk models...</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs font-sans">
            No incidents matched your filter query.
          </div>
        ) : (
          filtered.map((inc) => {
            const isSelected = selectedIncidentId === inc.incident_id;
            return (
              <div
                key={inc.incident_id}
                onClick={() => onSelectIncident(inc.incident_id)}
                className={`group relative rounded-xl p-3.5 cursor-pointer transition-all duration-200 border ${
                  isSelected
                    ? 'bg-blue-600/15 border-blue-500/60 shadow-[0_0_20px_rgba(59,130,246,0.25),inset_0_1px_1px_rgba(255,255,255,0.2)]'
                    : inc.rank === 1
                    ? 'bg-slate-900/80 border-red-500/40 hover:border-red-500/70 shadow-[0_4px_16px_rgba(0,0,0,0.4)]'
                    : 'bg-slate-900/60 border-white/10 hover:border-white/25 hover:bg-slate-900/90 shadow-[0_4px_16px_rgba(0,0,0,0.3)]'
                }`}
              >
                {/* Top Row: Rank Badge, ID, Priority Tag & Score */}
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded-md ${
                        inc.rank === 1
                          ? 'bg-red-500 text-white shadow-[0_0_10px_rgba(239,68,68,0.5)]'
                          : isSelected
                          ? 'bg-blue-500 text-white'
                          : 'bg-slate-800 text-slate-300 border border-white/10'
                      }`}
                    >
                      #{inc.rank}
                    </span>
                    <span className="font-mono text-[11px] text-slate-400 tracking-wide">
                      {inc.incident_id}
                    </span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <span
                      className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border tracking-wider ${getPriorityBadgeClass(
                        inc.priority_level
                      )}`}
                    >
                      {inc.priority_level}
                    </span>
                    <span className="font-mono text-base font-extrabold text-white tracking-tight tabular-nums">
                      {inc.priority_score.toFixed(1)}
                    </span>
                  </div>
                </div>

                {/* Title */}
                <h3 className="font-display font-semibold text-slate-100 text-sm leading-snug tracking-tight group-hover:text-blue-300 transition-colors line-clamp-2">
                  {inc.title}
                </h3>

                {/* Symmetrical Host & User Context Badges */}
                <div className="grid grid-cols-2 gap-2 mt-2.5 pt-2 border-t border-white/5 text-[11px] text-slate-400 font-mono">
                  <div className="flex items-center space-x-1.5 truncate">
                    <Server className="w-3 h-3 text-slate-500 shrink-0" />
                    <span className="truncate text-slate-300">
                      {(inc.affected_assets && inc.affected_assets[0]) || 'Unknown Host'}
                      {inc.affected_assets && inc.affected_assets.length > 1 ? ` (+${inc.affected_assets.length - 1})` : ''}
                    </span>
                  </div>

                  <div className="flex items-center space-x-1.5 truncate justify-end">
                    <User className="w-3 h-3 text-slate-500 shrink-0" />
                    <span className="truncate text-slate-300">
                      {(inc.affected_users && inc.affected_users[0]) || 'System'}
                      {inc.affected_users && inc.affected_users.length > 1 ? ` (+${inc.affected_users.length - 1})` : ''}
                    </span>
                  </div>
                </div>

                {/* Top Drivers Pills */}
                {inc.top_drivers && inc.top_drivers.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2.5">
                    {inc.top_drivers.slice(0, 2).map((driver, dIdx) => (
                      <span
                        key={dIdx}
                        className="bg-slate-950/80 text-slate-300 text-[10px] px-2 py-0.5 rounded-md border border-white/10 font-mono tracking-tight"
                      >
                        {driver}
                      </span>
                    ))}
                    <span className="text-[10px] text-slate-500 font-mono self-center ml-auto">
                      Conf: {Math.round(inc.attack_confidence * 100)}%
                    </span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </AppleGlassCard>
  );
};
