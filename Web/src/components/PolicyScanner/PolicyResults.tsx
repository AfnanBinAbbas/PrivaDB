import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, AlertTriangle, ChevronDown, ChevronUp, FileText, Download, ShieldCheck, X } from 'lucide-react';

interface Finding {
  framework: string;
  clause: string;
  status: string;
  evidence: string;
  reason: string;
  remediation: string;
  severity: string;
}

interface PolicyResultsProps {
  results: {
    findings: Finding[];
    scores: Record<string, number>;
    error?: string;
    fallback?: string;
    policy_url?: string;
  } | null;
  onClose?: () => void;
}

export const PolicyResults: React.FC<PolicyResultsProps> = ({ results, onClose }) => {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  if (!results) return null;

  if (results.error && !results.findings?.length) {
    const errorModal = (
      <AnimatePresence>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-md"
          onClick={onClose}
        >
          <motion.div 
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="relative w-full max-w-lg glass rounded-xl p-6 border border-red-500/20 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <button 
              onClick={onClose}
              className="absolute top-4 right-4 p-2 rounded-full hover:bg-white/10 transition-colors z-10"
            >
              <X className="w-5 h-5 text-muted-foreground hover:text-white" />
            </button>
            <div className="flex items-start gap-4 pr-8">
              <div className="p-3 bg-red-500/10 rounded-full border border-red-500/20 shrink-0">
                <AlertTriangle className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-red-400 mb-1">Policy Scan Failed</h3>
                <p className="text-muted-foreground mb-2">{results.error}</p>
                {results.fallback && (
                  <p className="text-sm font-mono text-cyan-400/80 bg-cyan-900/20 p-2 rounded border border-cyan-500/20 inline-block">
                    {results.fallback}
                  </p>
                )}
              </div>
            </div>
          </motion.div>
        </motion.div>
      </AnimatePresence>
    );
    return createPortal(errorModal, document.body);
  }

  const overallScore = Object.values(results.scores || {}).reduce((a, b) => a + b, 0) / (Object.keys(results.scores || {}).length || 1);
  const isCompliant = overallScore >= 80;
  
  const violations = (results.findings || []).filter(f => f.status !== 'present');

  const exportResults = () => {
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'policy_scan_results.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const modalContent = (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-md"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          className="relative w-full max-w-4xl max-h-[90vh] overflow-hidden glass rounded-xl border border-border/40 shadow-2xl flex flex-col"
          onClick={(e) => e.stopPropagation()}
        >
          <button 
            onClick={onClose}
            className="absolute top-4 right-4 p-2 rounded-full hover:bg-white/10 transition-colors z-10"
          >
            <X className="w-5 h-5 text-muted-foreground hover:text-white" />
          </button>
      <div className="p-6 border-b border-border/30 bg-background/50 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2 mb-1">
            <ShieldCheck className={isCompliant ? "text-green-400" : "text-amber-400"} />
            GRC Policy Compliance
          </h2>
          {results.policy_url && (
            <a href={results.policy_url} target="_blank" rel="noopener noreferrer" className="text-xs text-muted-foreground flex items-center gap-1 hover:text-cyan-400 transition-colors">
              <FileText className="w-3 h-3" />
              {results.policy_url}
            </a>
          )}
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex flex-col items-end">
            <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Overall Score</div>
            <div className={`text-3xl font-mono font-bold ${isCompliant ? 'text-green-400' : 'text-amber-400'}`}>
              {Math.round(overallScore)}/100
            </div>
          </div>
          <button 
            onClick={exportResults}
            className="p-2 glass rounded hover:bg-muted/50 transition-colors"
            title="Download JSON Report"
          >
            <Download className="w-4 h-4 text-cyan-400" />
          </button>
        </div>
      </div>

      <div className="p-6 flex-1 flex flex-col min-h-0">
        {violations.length === 0 ? (
          <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 flex items-center gap-3">
            <CheckCircle className="w-5 h-5 text-green-400 shrink-0" />
            <p className="text-green-400/90 font-medium text-sm">
              No violations found! The website's privacy policy appears compliant with checked frameworks.
            </p>
          </div>
        ) : (
          <div className="mb-4 text-sm font-medium flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-amber-500"></span>
            Violations found ({violations.length})
          </div>
        )}

        <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-3 mt-4">
          {(results.findings || []).map((finding, idx) => {
            const isMissing = finding.status !== 'present';
            const isExpanded = expandedRow === idx;
            
            return (
              <div 
                key={idx} 
                className={`border rounded-lg overflow-hidden transition-all duration-300 ${isMissing ? 'border-amber-500/30 bg-amber-500/5' : 'border-green-500/20 bg-green-500/5 hover:bg-background/40'}`}
              >
                <div 
                  className="p-3 cursor-pointer flex items-center justify-between"
                  onClick={() => setExpandedRow(isExpanded ? null : idx)}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    {isMissing ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : (
                      <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                    )}
                    <div className="truncate">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-background/50 border border-border/50 mr-2">
                        {finding.framework}
                      </span>
                      <span className="font-semibold text-sm">{finding.clause}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {isMissing && (
                      <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded font-bold ${finding.severity === 'high' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'}`}>
                        {finding.severity}
                      </span>
                    )}
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                  </div>
                </div>

                <AnimatePresence>
                  {isExpanded && (
                    <motion.div 
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="border-t border-border/30 bg-background/40"
                    >
                      <div className="p-4 space-y-3 text-sm">
                        {isMissing ? (
                          <>
                            <div>
                              <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Issue</div>
                              <div className="text-amber-400/90">{finding.reason}</div>
                            </div>
                            <div>
                              <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Suggested Fix</div>
                              <div className="text-cyan-400 font-medium">{finding.remediation}</div>
                            </div>
                          </>
                        ) : (
                          <div>
                            <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Evidence Found</div>
                            <div className="font-mono text-xs bg-black/30 p-3 rounded border border-border/50 text-green-300">
                              {finding.evidence || "Satisfied by presence of related keywords."}
                            </div>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );

  return createPortal(modalContent, document.body);
};
