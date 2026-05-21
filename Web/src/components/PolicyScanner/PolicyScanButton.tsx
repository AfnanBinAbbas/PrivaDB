import React, { useState } from 'react';
import { Shield, Loader2, AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface PolicyScanButtonProps {
  baseUrl: string;
  onResults: (results: any) => void;
}

export const PolicyScanButton: React.FC<PolicyScanButtonProps> = ({ baseUrl, onResults }) => {
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!baseUrl) return;
    setIsScanning(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8000/api/v1/policy/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base_url: baseUrl, frameworks: ["GDPR", "CCPA", "ePrivacy"] }),
        signal: AbortSignal.timeout(15000)
      });
      
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      
      const data = await response.json();
      if (data.error) {
        setError(data.error);
      }
      
      // Pass results even if there's an error, so the UI can show the fallback
      onResults(data);
      
    } catch (err: any) {
      let errorMessage = "Failed to scan policy.";
      if (err.name === 'TimeoutError') {
        errorMessage = "Request timed out.";
      } else if (err.message) {
        errorMessage = err.message;
      }
      setError(errorMessage);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="flex flex-col items-start gap-2">
      <motion.button
        onClick={handleScan}
        disabled={isScanning || !baseUrl}
        className="neon-btn flex items-center gap-2 group cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
      >
        {isScanning ? (
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
        ) : (
          <Shield className="w-4 h-4 text-cyan-400 group-hover:text-white transition-colors" />
        )}
        <span className="font-mono text-sm">
          {isScanning ? 'Analyzing Policies...' : 'Run GRC Policy Scan'}
        </span>
      </motion.button>
      
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="text-xs text-red-400 flex items-center gap-1.5"
          >
            <AlertTriangle className="w-3 h-3" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
