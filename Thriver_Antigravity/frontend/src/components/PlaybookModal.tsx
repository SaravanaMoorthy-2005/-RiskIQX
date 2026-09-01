import React, { useState } from 'react';
import { ShieldCheck, AlertOctagon, CheckCircle2, Play, Lock } from 'lucide-react';

interface PlaybookModalProps {
  playbook: any;
  onExecuteAction: (actionName: string, approved: boolean) => Promise<any>;
  onClose: () => void;
}

export const PlaybookModal: React.FC<PlaybookModalProps> = ({
  playbook,
  onExecuteAction,
  onClose,
}) => {
  const [executingAction, setExecutingAction] = useState<string | null>(null);
  const [approvalRequiredAction, setApprovalRequiredAction] = useState<any | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const handleRunStep = async (step: any, forceApproved: boolean = false) => {
    setExecutingAction(step.action);
    try {
      const res = await onExecuteAction(step.action, forceApproved);
      
      if (res.status === 'APPROVAL_REQUIRED') {
        setApprovalRequiredAction({ step, message: res.message });
      } else if (res.status === 'SUCCESS') {
        setApprovalRequiredAction(null);
        setLogs((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [SIMULATION SUCCESS] ${res.execution_log}`,
        ]);
      }
    } catch (err: any) {
      setLogs((prev) => [...prev, `[ERROR] Execution failed: ${err.message}`]);
    } finally {
      setExecutingAction(null);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-soc-panel border border-soc-border rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-4 border-b border-soc-border flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <h3 className="font-bold text-white text-base">{playbook.name}</h3>
            <span className="bg-emerald-500/20 text-emerald-400 text-[10px] px-2 py-0.5 rounded font-mono border border-emerald-500/30">
              SAFE SIMULATION MODE
            </span>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white font-bold text-lg px-2">
            ×
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-5 flex-1">
          {/* Approval Warning Dialog */}
          {approvalRequiredAction && (
            <div className="bg-red-500/10 border border-red-500/40 rounded-xl p-4 space-y-3">
              <div className="flex items-center space-x-2 text-red-400 font-bold text-sm">
                <AlertOctagon className="w-5 h-5 shrink-0" />
                <span>HUMAN APPROVAL REQUIRED (High-Impact Action)</span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {approvalRequiredAction.message}
              </p>

              <div className="bg-slate-900/80 p-3 rounded border border-red-500/20 text-xs font-mono text-slate-300 space-y-1">
                <div>Action: <span className="text-white font-bold">{approvalRequiredAction.step.action}</span></div>
                <div>Risk Level: <span className="text-red-400 font-bold">{approvalRequiredAction.step.risk}</span></div>
                <div>Safety Status: <span className="text-emerald-400">SAFE SIMULATION ONLY (No real endpoint changes)</span></div>
              </div>

              <div className="flex items-center space-x-3 pt-2">
                <button
                  onClick={() => handleRunStep(approvalRequiredAction.step, true)}
                  className="bg-red-600 hover:bg-red-500 text-white font-semibold text-xs px-4 py-2 rounded-lg transition-colors flex items-center space-x-1.5 shadow-lg shadow-red-600/30"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Approve & Execute Safe Simulation</span>
                </button>

                <button
                  onClick={() => setApprovalRequiredAction(null)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-4 py-2 rounded-lg transition-colors"
                >
                  Cancel Action
                </button>
              </div>
            </div>
          )}

          {/* Steps List */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Playbook Execution Steps
            </h4>
            <div className="space-y-3">
              {playbook.steps.map((step: any, idx: number) => (
                <div key={idx} className="bg-slate-900/70 border border-soc-border p-4 rounded-xl flex items-center justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-slate-300">{idx + 1}. {step.action}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-bold ${
                        step.risk === 'CRITICAL' || step.risk === 'HIGH' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }`}>
                        {step.risk} RISK
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{step.description}</p>
                  </div>

                  <button
                    disabled={executingAction === step.action}
                    onClick={() => handleRunStep(step, false)}
                    className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-3.5 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 font-semibold disabled:opacity-50 shrink-0"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>{executingAction === step.action ? 'Simulating...' : 'Run Step'}</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Simulation Output Log Console */}
          {logs.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Simulation Console Log
              </h4>
              <div className="bg-black/90 font-mono text-[11px] p-3 rounded-lg border border-soc-border space-y-1 max-h-36 overflow-y-auto text-emerald-400">
                {logs.map((log, lIdx) => (
                  <div key={lIdx}>{log}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
