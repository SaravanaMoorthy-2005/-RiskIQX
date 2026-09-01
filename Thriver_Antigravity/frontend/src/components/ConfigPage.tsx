import React, { useState, useEffect } from 'react';
import { fetchScoringConfig, updateScoringConfig, activateSector, resetScoringConfig } from '../api/client';
import { SECTOR_PROFILES, SectorWeights, getSectorProfile } from '../config/sectorProfiles';
import { AppleGlassCard } from './ui/liquid-glass-card';
import { Settings, Save, RotateCcw, AlertTriangle, CheckCircle, Shield, Building2, Layers } from 'lucide-react';

interface ConfigPageProps {
  onConfigUpdated: () => void;
  activeSector?: string;
  onSectorChange?: (sectorId: string) => void;
}

export const ConfigPageView: React.FC<ConfigPageProps> = ({
  onConfigUpdated,
  activeSector: propActiveSector,
  onSectorChange,
}) => {
  const [activeSector, setActiveSector] = useState<string>(propActiveSector || 'healthcare');
  const [weights, setWeights] = useState<SectorWeights>({
    severity: 0.25,
    asset_importance: 0.15,
    affected_users: 0.15,
    data_sensitivity: 0.25,
    attack_confidence: 0.10,
    business_impact: 0.10,
  });

  const [thresholds, setThresholds] = useState({
    critical: 90.0,
    high: 75.0,
    medium: 50.0,
    low: 25.0,
  });

  const [versionName, setVersionName] = useState('weighted-v1-healthcare');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [isModified, setIsModified] = useState(false);

  useEffect(() => {
    loadConfig();
  }, []);

  useEffect(() => {
    if (propActiveSector && propActiveSector !== activeSector) {
      setActiveSector(propActiveSector);
      const profile = getSectorProfile(propActiveSector);
      setWeights({ ...profile.weights });
      setVersionName(profile.defaultVersion);
      setIsModified(false);
    }
  }, [propActiveSector]);

  const loadConfig = async () => {
    try {
      const cfg = await fetchScoringConfig();
      if (cfg.weights) setWeights(cfg.weights);
      if (cfg.thresholds) setThresholds(cfg.thresholds);
      if (cfg.version_name) setVersionName(cfg.version_name);
      if (cfg.active_sector) {
        setActiveSector(cfg.active_sector);
        const profile = getSectorProfile(cfg.active_sector);
        // Check if weights match preset
        const matches = Object.keys(profile.weights).every(
          (k) => Math.abs(profile.weights[k as keyof SectorWeights] - cfg.weights[k]) < 0.001
        );
        setIsModified(!matches);
      }
    } catch (err) {
      console.error('Error fetching scoring config:', err);
    }
  };

  const activeSectorProfile = getSectorProfile(activeSector);

  // Validate sum to 1.0 (with 0.001 floating point tolerance)
  const currentSum = Object.values(weights).reduce((acc, curr) => acc + Number(curr), 0);
  const isValidSum = Math.abs(currentSum - 1.0) < 0.001;

  const handleSelectSector = async (sectorId: string) => {
    const profile = getSectorProfile(sectorId);
    setActiveSector(sectorId);
    setWeights({ ...profile.weights });
    setVersionName(profile.defaultVersion);
    setIsModified(false);
    setMessage(null);

    // Immediately activate the sector so the entire scoring engine recalculates
    setLoading(true);
    try {
      await activateSector(sectorId);
      if (onSectorChange) {
        onSectorChange(sectorId);
      } else {
        onConfigUpdated();
      }
      setMessage({
        type: 'success',
        text: `Active Sector changed to '${profile.name}'. Scoring engine and threat dataset fully recalculated!`,
      });
    } catch (err: any) {
      console.error(err);
      // Even if backend call has network latency, notify parent
      if (onSectorChange) onSectorChange(sectorId);
      else onConfigUpdated();
    } finally {
      setLoading(false);
    }
  };

  const handleWeightChange = (key: keyof SectorWeights, val: number) => {
    const newWeights = { ...weights, [key]: val };
    setWeights(newWeights);

    // Check if new weights deviate from the selected sector's baseline
    const profile = getSectorProfile(activeSector);
    const differs = Object.keys(profile.weights).some(
      (k) => Math.abs(profile.weights[k as keyof SectorWeights] - newWeights[k as keyof SectorWeights]) > 0.001
    );
    setIsModified(differs);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValidSum) {
      setMessage({
        type: 'error',
        text: `Factor weights MUST sum to exactly 1.00 (Current sum: ${currentSum.toFixed(2)})`,
      });
      return;
    }

    setLoading(true);
    try {
      await updateScoringConfig(versionName, weights, thresholds, activeSector);
      setMessage({
        type: 'success',
        text: `Scoring configuration '${versionName}' successfully saved & activated. All threat models updated!`,
      });
      onConfigUpdated();
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleResetDefaults = async () => {
    setLoading(true);
    try {
      await resetScoringConfig();
      const defaultProfile = SECTOR_PROFILES.healthcare;
      setActiveSector('healthcare');
      setWeights({ ...defaultProfile.weights });
      setVersionName(defaultProfile.defaultVersion);
      setIsModified(false);
      setMessage({
        type: 'success',
        text: 'Reset to default Healthcare preset. Scoring engine and threat dataset re-initialized.',
      });
      if (onSectorChange) onSectorChange('healthcare');
      else onConfigUpdated();
    } catch (err: any) {
      console.error(err);
      const defaultProfile = SECTOR_PROFILES.healthcare;
      setActiveSector('healthcare');
      setWeights({ ...defaultProfile.weights });
      setVersionName(defaultProfile.defaultVersion);
      setIsModified(false);
      if (onSectorChange) onSectorChange('healthcare');
      else onConfigUpdated();
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppleGlassCard
      enableTilt={false}
      borderRadius={20}
      className="p-6 md:p-8 max-w-4xl mx-auto space-y-6 border border-white/10 shadow-2xl"
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div className="flex items-center space-x-3">
          <div className="bg-blue-600/15 border border-blue-500/30 p-2.5 rounded-xl text-blue-400 shadow-inner">
            <Settings className="w-6 h-6 drop-shadow-[0_0_6px_rgba(59,130,246,0.5)]" />
          </div>
          <div>
            <h2 className="font-display font-bold text-white text-lg tracking-tight">
              Scoring Model & Weight Configuration
            </h2>
            <p className="text-xs text-slate-400 font-sans">
              Dynamic 6-Factor Contextual Risk Prioritization & Sector Preset Engine
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={handleResetDefaults}
          disabled={loading}
          className="text-xs bg-slate-900/80 hover:bg-slate-800 text-slate-300 px-3.5 py-2 rounded-xl border border-white/10 flex items-center space-x-1.5 transition-colors font-sans self-start sm:self-auto hover:text-white"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Defaults</span>
        </button>
      </div>

      {/* Notifications */}
      {message && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-center space-x-2.5 font-sans ${
            message.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-red-500/10 border-red-500/30 text-red-300'
          }`}
        >
          {message.type === 'success' ? (
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          )}
          <span>{message.text}</span>
        </div>
      )}

      {/* SECTOR PRESET SELECTOR (Core Requirement) */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <span className="text-[11px] text-slate-300 font-display font-semibold uppercase tracking-wider flex items-center space-x-1.5">
            <Building2 className="w-3.5 h-3.5 text-blue-400" />
            <span>Industry Sector Presets</span>
          </span>

          <div className="text-xs font-mono">
            <span className="text-slate-400">Active Sector: </span>
            <span
              className={`font-bold px-2 py-0.5 rounded-md border ${
                isModified
                  ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                  : 'text-blue-400 bg-blue-500/10 border-blue-500/30'
              }`}
            >
              {isModified ? `${activeSectorProfile.name} — Modified` : activeSectorProfile.name}
            </span>
          </div>
        </div>

        {/* 7 Sector Preset Buttons */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {Object.values(SECTOR_PROFILES).map((s) => {
            const isSelected = activeSector === s.id;
            return (
              <button
                type="button"
                key={s.id}
                onClick={() => handleSelectSector(s.id)}
                className={`py-2.5 px-3 rounded-xl border text-center font-display text-xs font-semibold transition-all focus:outline-none focus:ring-2 focus:ring-blue-500/40 ${
                  isSelected
                    ? 'bg-blue-600 border-blue-500 text-white shadow-[0_0_15px_rgba(59,130,246,0.4)] scale-[1.02]'
                    : 'bg-slate-900/80 border-white/10 text-slate-400 hover:text-white hover:border-white/25 hover:bg-slate-800/80'
                }`}
              >
                {s.name}
              </button>
            );
          })}
        </div>

        {/* Selected Sector Context Card */}
        <div className="bg-slate-950/60 p-3.5 rounded-xl border border-white/10 space-y-2 text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
            <span className="font-display font-bold text-white text-xs">
              {activeSectorProfile.name} Context & Threat Posture
            </span>
            <span className="text-slate-400 font-mono text-[11px]">
              {activeSectorProfile.threats.length} Simulated Real-world Threat Scenarios
            </span>
          </div>

          <p className="text-slate-300 text-[11px] font-sans leading-relaxed">
            {activeSectorProfile.description}
          </p>

          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            <span className="text-[10px] text-slate-500 font-mono uppercase mr-1">Sector Priorities:</span>
            {activeSectorProfile.emphasis.map((tag, idx) => (
              <span
                key={idx}
                className="bg-blue-500/10 text-blue-300 text-[10px] font-mono px-2 py-0.5 rounded-md border border-blue-500/20"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Configuration Form */}
      <form onSubmit={handleSave} className="space-y-6 pt-2 border-t border-white/10">
        <div>
          <label className="text-xs text-slate-300 font-semibold block mb-1 font-sans">
            Model Version Identifier
          </label>
          <input
            type="text"
            value={versionName}
            onChange={(e) => {
              setVersionName(e.target.value);
              setIsModified(true);
            }}
            className="w-full bg-slate-950/80 border border-white/10 rounded-xl p-2.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono shadow-inner"
          />
        </div>

        {/* 6-Factor Sliders */}
        <div className="space-y-3">
          <div className="flex justify-between items-center text-xs font-semibold">
            <span className="text-slate-300 uppercase tracking-wider font-display text-[11px]">
              6-Factor Weights (Must Sum to 1.00)
            </span>
            <span
              className={`font-mono text-xs tabular-nums px-2.5 py-0.5 rounded-md border ${
                isValidSum
                  ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 font-bold'
                  : 'text-red-400 bg-red-500/10 border-red-500/30 font-bold animate-pulse'
              }`}
            >
              Sum: {currentSum.toFixed(2)} / 1.00
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {(
              [
                { key: 'severity', label: '1. Severity' },
                { key: 'asset_importance', label: '2. Asset Importance' },
                { key: 'affected_users', label: '3. Affected Users' },
                { key: 'data_sensitivity', label: '4. Data Sensitivity' },
                { key: 'attack_confidence', label: '5. Attack Confidence' },
                { key: 'business_impact', label: '6. Business Impact' },
              ] as const
            ).map(({ key, label }) => {
              const val = weights[key];
              const pct = (Number(val) * 100).toFixed(0);
              return (
                <div
                  key={key}
                  className="bg-slate-950/70 p-3.5 rounded-xl border border-white/10 hover:border-blue-500/40 transition-colors space-y-2"
                >
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-200 font-display font-medium">{label}</span>
                    <span className="font-mono text-blue-400 font-bold text-xs tabular-nums">{pct}%</span>
                  </div>

                  <input
                    type="range"
                    min="0.0"
                    max="0.5"
                    step="0.05"
                    value={val}
                    onChange={(e) => handleWeightChange(key, parseFloat(e.target.value))}
                    className="w-full h-1.5 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-blue-500"
                  />
                </div>
              );
            })}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-3 pt-2">
          <button
            type="submit"
            disabled={loading || !isValidSum}
            className="bg-blue-600 hover:bg-blue-500 text-white font-display font-semibold text-xs px-5 py-2.5 rounded-xl transition-all flex items-center space-x-2 shadow-lg shadow-blue-600/30 disabled:opacity-40 disabled:cursor-not-allowed active:scale-95"
          >
            <Save className="w-4 h-4" />
            <span>{loading ? 'Activating Scoring Engine...' : 'Save & Activate Scoring Model'}</span>
          </button>
        </div>
      </form>
    </AppleGlassCard>
  );
};
