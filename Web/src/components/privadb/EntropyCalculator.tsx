import React, { useState, useEffect } from 'react';
import { Calculator, Zap, TrendingUp, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';

interface EntropyCalculatorProps {
  value?: string;
  onEntropyChange?: (entropy: number) => void;
}

const EntropyCalculator: React.FC<EntropyCalculatorProps> = ({
  value = '',
  onEntropyChange
}) => {
  const [inputValue, setInputValue] = useState(value);
  const [entropy, setEntropy] = useState(0);
  const [classification, setClassification] = useState('');

  // Shannon entropy calculation with error handling
  const calculateEntropy = (str: string): number => {
    if (!str) return 0;
    
    if (str.length > 10000) {
      console.warn('Input string is very long, entropy calculation may be slow');
    }

    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    const length = str.length;
    let entropy = 0;

    try {
      for (const count of Object.values(freq)) {
        const p = count / length;
        if (p > 0) {
          entropy -= p * Math.log2(p);
        }
      }
      return isNaN(entropy) ? 0 : entropy;
    } catch (error) {
      console.error('Error calculating entropy:', error);
      return 0;
    }
  };

  // Classify entropy level
  const classifyEntropy = (ent: number): string => {
    if (ent < 2.0) return 'Low (Predictable)';
    if (ent < 3.5) return 'Medium (Semi-random)';
    if (ent < 4.5) return 'High (Random)';
    return 'Very High (Cryptographic)';
  };

  useEffect(() => {
    const ent = calculateEntropy(inputValue);
    setEntropy(ent);
    setClassification(classifyEntropy(ent));
    onEntropyChange?.(ent);
  }, [inputValue, onEntropyChange]);

  const getEntropyColor = (ent: number): string => {
    if (ent < 2.0) return 'text-green-400';
    if (ent < 3.5) return 'text-yellow-400';
    if (ent < 4.5) return 'text-orange-400';
    return 'text-red-400';
  };

  const getProgressWidth = (ent: number): number => {
    return Math.min((ent / 5) * 100, 100);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass rounded-xl p-6 space-y-4"
    >
      <div className="flex items-center gap-3 mb-4">
        <Calculator className="text-primary" size={24} />
        <h3 className="text-lg font-semibold">Live Entropy Calculator</h3>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Zap size={14} />
          <span>Shannon Entropy Analysis</span>
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-2">
            Input Value (IDB Key/Value)
            {inputValue.length > 0 && (
              <span className="float-right text-xs text-muted-foreground">
                {inputValue.length} / 10000 characters
              </span>
            )}
          </label>
          <div className="relative">
            <textarea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value.slice(0, 10000))}
              placeholder="Enter IndexedDB value to analyze..."
              className="w-full h-24 p-3 bg-background/50 border border-border rounded-lg resize-none focus:ring-2 focus:ring-primary/50 focus:border-primary"
              maxLength={10000}
            />
            {inputValue.length > 9000 && (
              <div className="absolute bottom-2 right-2 text-xs text-yellow-500">
                ⚠ Approaching length limit
              </div>
            )}
          </div>
          {inputValue.length === 0 && (
            <p className="text-xs text-muted-foreground mt-1">
              Paste an IndexedDB value here to see its entropy score
            </p>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Entropy Score</span>
              <span className={`text-lg font-mono font-bold ${getEntropyColor(entropy)}`}>
                {entropy.toFixed(3)}
              </span>
            </div>
            <div className="w-full bg-background/30 rounded-full h-2">
              <motion.div
                className="bg-red-400 h-2 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${getProgressWidth(entropy)}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Classification</span>
              <div className="flex items-center gap-2">
                {entropy >= 3.5 ? (
                  <AlertTriangle size={16} className="text-orange-400" />
                ) : (
                  <TrendingUp size={16} className="text-green-400" />
                )}
                <span className="text-sm font-medium">{classification}</span>
              </div>
            </div>
            <div className="text-xs text-muted-foreground">
              {entropy >= 3.5
                ? 'High entropy suggests potential tracking identifier'
                : 'Low entropy indicates predictable or user-provided data'
              }
            </div>
          </div>
        </div>

        <div className="pt-4 border-t border-border">
          <h4 className="text-sm font-medium mb-2">Entropy Scale Reference</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-green-400 rounded"></div>
              <span>&lt; 2.0: Low</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-yellow-400 rounded"></div>
              <span>2.0-3.5: Medium</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-orange-400 rounded"></div>
              <span>3.5-4.5: High</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-red-400 rounded"></div>
              <span>&gt; 4.5: Very High</span>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default EntropyCalculator;