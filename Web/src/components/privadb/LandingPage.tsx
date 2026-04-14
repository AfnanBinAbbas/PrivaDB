import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface LandingPageProps {
  onReveal: () => void;
}

const CyberParticles = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {[...Array(30)].map((_, i) => (
        <motion.div
          key={i}
          className="absolute w-1 h-1 bg-primary/40 rounded-full"
          initial={{
            x: Math.random() * 100 + "%",
            y: Math.random() * 100 + "%",
            opacity: Math.random() * 0.5 + 0.2
          }}
          animate={{
            y: [null, Math.random() * -100 - 50 + "%"],
            opacity: [0, 1, 0],
            scale: [0, 1.5, 0]
          }}
          transition={{
            duration: Math.random() * 10 + 10,
            repeat: Infinity,
            ease: "linear",
            delay: Math.random() * 10
          }}
        />
      ))}
    </div>
  );
};

const GlitchTitle = ({ text }: { text: string }) => {
  return (
    <div className="relative group">
      <motion.h1
        className="text-7xl md:text-9xl font-bold tracking-tighter mb-4 relative z-10"
        initial={{ letterSpacing: "0.2em", opacity: 0 }}
        animate={{ opacity: 1, letterSpacing: "-0.02em" }}
        transition={{ duration: 2.5, ease: "easeOut", delay: 0.8 }}
      >
        <span className="drop-shadow-[0_0_15px_rgba(var(--primary-rgb),0.5)] bg-clip-text text-transparent bg-gradient-to-r from-[hsl(0,0%,80%)] to-[hsl(0,0%,70%)]">{text}</span>
      </motion.h1>

      {/* Glitch Layers */}
      <motion.div
        className="absolute inset-0 text-7xl md:text-9xl font-bold tracking-tighter mb-4 z-0 text-cyan-500/30 select-none mix-blend-screen"
        animate={{
          x: [-2, 2, -1, 3, -2],
          y: [1, -2, 2, -1, 1],
          opacity: [0, 0.4, 0, 0.2, 0]
        }}
        transition={{ duration: 0.2, repeat: Infinity, repeatDelay: 3 }}
      >
        {text}
      </motion.div>
      <motion.div
        className="absolute inset-0 text-7xl md:text-9xl font-bold tracking-tighter mb-4 z-0 text-fuchsia-500/30 select-none mix-blend-screen"
        animate={{
          x: [2, -3, 1, -2, 2],
          y: [-1, 2, -2, 3, -1],
          opacity: [0, 0.3, 0, 0.5, 0]
        }}
        transition={{ duration: 0.15, repeat: Infinity, repeatDelay: 2.5 }}
      >
        {text}
      </motion.div>
    </div>
  );
};

export const LandingPage: React.FC<LandingPageProps> = ({ onReveal }) => {
  const audioRef = useRef<HTMLAudioElement>(null);
  const [hasInteracted, setHasInteracted] = useState(false);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.volume = 0.6;
      audioRef.current.play().catch(() => { });
    }

    const handleMouseMove = (e: MouseEvent) => {
      setMousePos({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  const handleReveal = () => {
    if (!hasInteracted) {
      setHasInteracted(true);
      audioRef.current?.play().catch(() => { });
    }
    onReveal();
  };

  return (
    <motion.div
      className="fixed inset-0 z-[100] bg-[#050505] flex flex-col items-center justify-center cursor-pointer select-none overflow-hidden"
      initial={{ opacity: 1 }}
      exit={{ opacity: 0, scale: 1.1, filter: 'blur(20px)' }}
      transition={{ duration: 1.2, ease: [0.43, 0.13, 0.23, 0.96] }}
      onClick={handleReveal}
      onPanStart={handleReveal}
    >
      <audio ref={audioRef} src="/logo_reveal_landing_page.mp3" preload="auto" />
      <audio src="/background_music.mp3" loop autoPlay />

      {/* Cyber-Magical Background */}
      <CyberParticles />

      {/* Interactive Magic Glow */}
      <motion.div
        className="absolute w-[350px] h-[350px] rounded-full pointer-events-none z-0"
        animate={{
          x: mousePos.x - 600,
          y: mousePos.y - 300,
        }}
        style={{
          background: 'rgba(var(--primary-rgb), 0.08)',
          filter: 'blur(40px)',
        }}
        transition={{ type: 'spring', damping: 30, stiffness: 150 }}
      />

      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute inset-0 bg-black/10 z-10 opacity-20" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-primary/5 rounded-full blur-[150px] animate-pulse" />
      </div>

      <motion.div
        className="relative z-10 flex flex-col items-center"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 1.8, ease: "easeOut" }}
      >
        {/* Logo Container */}
        <motion.div
          className="relative mb-8"
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{
            opacity: 1,
            scale: 1,
            y: [0, -20, 0],
            rotateY: [0, 10, 0, -10, 0]
          }}
          transition={{
            opacity: { duration: 2 },
            scale: { duration: 1.8 },
            y: { duration: 8, repeat: Infinity, ease: "easeInOut" },
            rotateY: { duration: 8, repeat: Infinity, ease: "easeInOut" }
          }}
        >
          <div className="absolute inset-0 bg-primary/30 blur-3xl rounded-full scale-110 animate-pulse" />
          <img
            src="/logo.png"
            alt="PrivaDB Logo"
            className="w-48 h-48 md:w-64 md:h-64 object-contain relative z-10 drop-shadow-[0_0_50px_rgba(var(--primary-rgb),0.4)]"
          />
        </motion.div>

        <GlitchTitle text="Priva DB" />

        {/* Subtitle / Prompt */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 1, 0.5] }}
          transition={{ duration: 2.5, repeat: Infinity, delay: 2.5 }}
          className="flex flex-col items-center gap-6 mt-12"
        >
          <div className="flex items-center gap-4 text-primary/60 font-mono text-xs uppercase tracking-[0.4em]">
            <span className="w-12 h-[1px] bg-primary/30" />
            Click or Drag to Reveal
            <span className="w-12 h-[1px] bg-primary/30" />
          </div>
          <div className="w-px h-16 bg-primary/60 animate-bounce" />
        </motion.div>
      </motion.div>

      {/* Cyber scanning line */}
      <motion.div
        className="absolute left-0 w-full h-[2px] bg-primary/40 shadow-[0_0_15px_rgba(var(--primary-rgb),0.8)] z-20"
        animate={{ top: ['-10%', '110%'] }}
        transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
      />
    </motion.div>
  );
};
