import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useTheme } from './ThemeProvider';

export const CyberBackground: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { theme } = useTheme();
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMousePos({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  if (theme !== 'dark') return <>{children}</>;

  return (
    <div className="relative min-h-screen w-full overflow-hidden">
      {/* Fixed Background Elements */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute inset-0 cyber-grid opacity-20" />
        
        {/* Particle Field */}
        <div className="absolute inset-0 overflow-hidden">
          {[...Array(40)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute w-1 h-1 bg-primary/30 rounded-full"
              initial={{ 
                x: Math.random() * 100 + "%", 
                y: Math.random() * 100 + "%",
                opacity: Math.random() * 0.4 + 0.1
              }}
              animate={{
                y: [null, "-110%"],
                opacity: [0, 1, 0],
                scale: [0, 1.2, 0]
              }}
              transition={{
                duration: Math.random() * 15 + 15,
                repeat: Infinity,
                ease: "linear",
                delay: Math.random() * 15
              }}
            />
          ))}
        </div>

        {/* Interactive Magical Glow */}
        <motion.div 
          className="absolute w-[800px] h-[800px] rounded-full pointer-events-none"
          animate={{ 
            x: mousePos.x - 400,
            y: mousePos.y - 400,
          }}
          style={{
            background: 'rgba(var(--primary-rgb), 0.08)',
            filter: 'blur(60px)',
          }}
          transition={{ type: 'spring', damping: 40, stiffness: 120 }}
        />

        {/* CRT / Scanline Effect */}
        <div className="absolute inset-0 bg-black/10 z-50 opacity-10 pointer-events-none" style={{ backgroundSize: '100% 4px' }} />
        
        {/* Dynamic Scanning Bar */}
        <motion.div
          className="absolute left-0 w-full h-[1px] bg-primary/20 shadow-[0_0_10px_rgba(var(--primary-rgb),0.5)] z-40"
          animate={{ top: ['-5%', '105%'] }}
          transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
        />
        
        {/* Atmospheric Orbs */}
        <div className="absolute top-1/4 -left-20 w-96 h-96 bg-primary/5 rounded-full blur-[120px] animate-pulse" />
        <div className="absolute bottom-1/4 -right-20 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[150px] animate-pulse" style={{ animationDelay: '-4s' }} />
      </div>

      {/* Main Content Content */}
      <div className="relative z-10 w-full">
        {children}
      </div>
    </div>
  );
};
