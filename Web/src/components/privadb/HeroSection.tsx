import React, { useEffect, useRef, useState } from 'react';
import { motion, Variants } from 'framer-motion';

const useCountUp = (target: number, duration = 2000, startOnView = true) => {
  const [count, setCount] = useState(0);
  const [started, setStarted] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!startOnView) {
      setStarted(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) setStarted(true); },
      { threshold: 0.3 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [startOnView]);

  useEffect(() => {
    if (!started) return;
    const start = 0;
    const startTime = performance.now();
    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.floor(eased * target));
      if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }, [started, target, duration]);

  return { count, ref };
};

export const HeroSection: React.FC = () => {
  const sites = useCountUp(677);
  const events = useCountUp(1247);
  const trackers = useCountUp(578);

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15,
        delayChildren: 0.2,
      },
    },
  };

  const itemVariants: Variants = {
    hidden: { opacity: 0, y: 30 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.8, ease: "easeOut" } },
  };

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center px-4 overflow-hidden">
      {/* Animated gradient orbs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl float" />
        <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-primary/5 rounded-full blur-3xl float" style={{ animationDelay: '-3s' }} />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
      </div>

      {/* Data flow animation lines */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="absolute h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent animate-data-flow"
            style={{
              top: `${20 + i * 15}%`,
              width: '200px',
              animationDelay: `${i * 0.8}s`,
              animationDuration: `${3 + i * 0.5}s`,
            }}
          />
        ))}
      </div>

      <motion.div
        className="relative z-10 text-center max-w-4xl mx-auto"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        {/* Badge */}
        <motion.div variants={itemVariants} className="inline-flex items-center gap-2 px-4 py-2 glass rounded-full text-sm text-muted-foreground mb-6">
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          Research Project — Dynamic Taint Analysis
        </motion.div>

        {/* Logo & Title */}
        <motion.div variants={itemVariants} className="flex flex-col items-center justify-center mb-6">
          <motion.img
            src="/logo.png"
            alt="PrivaDB Logo"
            className="w-24 h-24 sm:w-32 sm:h-32 md:w-48 md:h-48 object-contain mb-2 drop-shadow-[0_0_15px_rgba(255,255,255,0.1)]"
            animate={{ y: [-10, 10, -10] }}
            transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
          />
          <h1 className="text-4xl xs:text-5xl sm:text-7xl md:text-8xl lg:text-9xl font-bold tracking-tighter">
            <span className="text-gradient">PRIVADB</span>
          </h1>
        </motion.div>

        {/* Subtitle */}
        <motion.p variants={itemVariants} className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8 leading-relaxed">
          Detecting Persistent Web Tracking via IndexedDB Dynamic Taint Analysis
        </motion.p>

        {/* CTA Buttons */}
        <motion.div variants={itemVariants} className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-10">
          <motion.a
            href="#live-scan"
            className="px-8 py-3.5 bg-primary text-primary-foreground rounded-full font-medium text-sm transition-all glow-sm"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Try Live Scan
          </motion.a>
          <motion.a
            href="#pipeline"
            className="px-8 py-3.5 glass rounded-full font-medium text-sm text-foreground hover:bg-muted/50 transition-all"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Explore Research →
          </motion.a>
        </motion.div>

        {/* Counter Strip */}
        <motion.div variants={itemVariants} className="flex flex-col sm:flex-row items-center justify-center gap-8 sm:gap-16">
          {[
            { ref: sites.ref, count: sites.count, label: 'Sites Analyzed', suffix: '' },
            { ref: events.ref, count: events.count, label: 'Tracking Events', suffix: '' },
            { ref: trackers.ref, count: trackers.count, label: 'Tracker Domains', suffix: '' },
          ].map((stat, i) => (
            <div key={i} ref={stat.ref} className="text-center group">
              <div className="text-4xl md:text-5xl font-bold text-foreground tabular-nums group-hover:text-primary transition-colors">
                {stat.count.toLocaleString()}{stat.suffix}
              </div>
              <div className="text-sm text-muted-foreground mt-1">{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </motion.div>

    </section>
  );
};
