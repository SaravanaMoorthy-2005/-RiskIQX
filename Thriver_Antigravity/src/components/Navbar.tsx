import React from 'react';
import { ShieldAlert, Activity, BarChart3, Settings, Play, RefreshCw, Zap, Building2, ChevronDown } from 'lucide-react';
import { SECTOR_PROFILES, getSectorProfile } from '../config/sectorProfiles';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  activeSector?: string;
  onSectorChange?: (sectorId: string) => void;
  onTriggerScenario: (scenarioKey: string) => void;
  onResetData: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  activeSector = 'healthcare',
  onSectorChange,
  onTriggerScenario,
  onResetData,
}) => {
  const currentProfile = getSectorProfile(activeSector);
  const [sectorMenuOpen, setSectorMenuOpen] = React.useState(false);
  const [simulateMenuOpen, setSimulateMenuOpen] = React.useState(false);

  return (
    <header className="bg-slate-950/70 backdrop-blur-xl border-b border-white/10 px-6 py-3 flex items-center justify-between sticky top-0 z-50 shadow-[0_4px_30px_rgba(0,0,0,0.5)]">
      <div className="flex items-center space-x-3">
        <div className="bg-blue-600/15 border border-blue-500/30 p-2.5 rounded-xl text-blue-400 shadow-inner">
          <ShieldAlert className="w-5 h-5 drop-shadow-[0_0_6px_rgba(59,130,246,0.6)]" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-display font-bold text-lg text-white tracking-tight">RiskIQX</h1>
            <span className="bg-blue-500/15 text-blue-400 text-[10px] px-2 py-0.5 rounded-md border border-blue-500/30 font-mono tracking-wider font-semibold">
              OPERATIONS V1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-sans">
            Contextual Incident Prioritization & Multi-Sector Risk Engine
          </p>
        </div>
      </div>

      {/* Main Navigation Tabs */}
      <nav className="flex items-center space-x-1 bg-slate-950/70 p-1 rounded-xl border border-white/10 shadow-inner">
        <button
          onClick={() => setActiveTab('queue')}
          className={`flex items-center space-x-2 px-3.5 py-1.5 text-xs font-display font-semibold rounded-lg transition-all ${
            activeTab === 'queue'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Investigation Queue</span>
        </button>

        <button
          onClick={() => setActiveTab('dashboard')}
          className={`flex items-center space-x-2 px-3.5 py-1.5 text-xs font-display font-semibold rounded-lg transition-all ${
            activeTab === 'dashboard'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <BarChart3 className="w-3.5 h-3.5" />
          <span>SOC Dashboard</span>
        </button>

        <button
          onClick={() => setActiveTab('config')}
          className={`flex items-center space-x-2 px-3.5 py-1.5 text-xs font-display font-semibold rounded-lg transition-all ${
            activeTab === 'config'
              ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
              : 'text-slate-400 hover:text-white hover:bg-white/5'
          }`}
        >
          <Settings className="w-3.5 h-3.5" />
          <span>Scoring Config</span>
        </button>
      </nav>

      {/* Global Sector Switcher & Simulator Controls */}
      <div className="flex items-center space-x-3">
        {/* Global Active Sector Dropdown */}
        <div className="relative group">
          <button
            type="button"
            onClick={() => {
              setSectorMenuOpen(!sectorMenuOpen);
              setSimulateMenuOpen(false);
            }}
            className="flex items-center space-x-2 bg-slate-900/90 hover:bg-slate-800 text-blue-400 px-3 py-1.5 rounded-xl border border-blue-500/30 text-xs font-display font-semibold shadow-inner transition-colors"
          >
            <Building2 className="w-3.5 h-3.5 text-blue-400" />
            <span className="font-mono text-[11px] text-slate-300 font-normal">Sector:</span>
            <span className="text-white font-bold">{currentProfile.name}</span>
            <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${sectorMenuOpen ? 'rotate-180' : 'group-hover:rotate-180'}`} />
          </button>

          <div className={`absolute right-0 mt-1.5 w-60 bg-slate-950/95 border border-white/10 rounded-xl shadow-2xl p-2 z-50 backdrop-blur-xl ${sectorMenuOpen ? 'block' : 'hidden group-hover:block'}`}>
            <p className="text-[10px] text-slate-400 uppercase tracking-wider font-display font-semibold px-2 py-1">
              Switch Industry Sector Preset
            </p>
            <div className="space-y-0.5 text-xs font-sans">
              {Object.values(SECTOR_PROFILES).map((s) => (
                <button
                  key={s.id}
                  onClick={() => {
                    setSectorMenuOpen(false);
                    if (onSectorChange) onSectorChange(s.id);
                  }}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg flex items-center justify-between transition-colors ${
                    activeSector === s.id
                      ? 'bg-blue-600/30 text-blue-300 font-bold border border-blue-500/40'
                      : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                  }`}
                >
                  <span className="font-display">{s.name}</span>
                  <span className="text-[10px] font-mono text-slate-500">{s.threats.length} threats</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Attack Simulator Dropdown */}
        <div className="relative group">
          <button
            type="button"
            onClick={() => {
              setSimulateMenuOpen(!simulateMenuOpen);
              setSectorMenuOpen(false);
            }}
            className="flex items-center space-x-1.5 bg-slate-900/90 hover:bg-slate-800 text-emerald-400 px-3 py-1.5 rounded-xl border border-emerald-500/30 text-xs font-display font-semibold transition-colors"
          >
            <Zap className="w-3.5 h-3.5 text-emerald-400" />
            <span>Simulate</span>
          </button>

          <div className={`absolute right-0 mt-1.5 w-64 bg-slate-950/95 border border-white/10 rounded-xl shadow-2xl p-2 z-50 backdrop-blur-xl ${simulateMenuOpen ? 'block' : 'hidden group-hover:block'}`}>
            <p className="text-[10px] text-slate-400 uppercase tracking-wider font-display font-semibold px-2 py-1">
              Live Attack Scenarios
            </p>
            <div className="space-y-0.5 text-xs font-sans">
              <button
                onClick={() => {
                  setSimulateMenuOpen(false);
                  onTriggerScenario('ransomware');
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-200"
              >
                1. Ransomware Outbreak
              </button>
              <button
                onClick={() => {
                  setSimulateMenuOpen(false);
                  onTriggerScenario('phishing');
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-200"
              >
                2. Spear Phishing Credential Theft
              </button>
              <button
                onClick={() => {
                  setSimulateMenuOpen(false);
                  onTriggerScenario('brute_force');
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-200"
              >
                3. Distributed Brute Force
              </button>
              <button
                onClick={() => {
                  setSimulateMenuOpen(false);
                  onTriggerScenario('data_exfil');
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-200"
              >
                4. Database Exfiltration
              </button>
              <button
                onClick={() => {
                  setSimulateMenuOpen(false);
                  onTriggerScenario('priv_esc');
                }}
                className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-200"
              >
                5. Admin Privilege Escalation
              </button>
            </div>
          </div>
        </div>

        <button
          onClick={onResetData}
          title="Reload Demo Data"
          className="p-2 bg-slate-900/90 hover:bg-slate-800 text-slate-300 hover:text-white rounded-xl border border-white/10 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>

        <div className="flex items-center space-x-2 pl-2 border-l border-white/10">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
          <span className="text-[11px] font-mono text-slate-300 font-semibold">LIVE SOC</span>
        </div>
      </div>
    </header>
  );
};
