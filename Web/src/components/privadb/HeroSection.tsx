import React, { useEffect, useRef, useState } from 'react';

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

      <div className="relative z-10 text-center max-w-4xl mx-auto">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-2 glass rounded-full text-sm text-muted-foreground mb-8 opacity-0 animate-fade-in" style={{ animationDelay: '0.2s' }}>
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          Research Project — Dynamic Taint Analysis
        </div>

        {/* Title */}
        <h1 className="text-6xl sm:text-7xl md:text-8xl lg:text-9xl font-bold tracking-tighter mb-6 opacity-0 animate-fade-in" style={{ animationDelay: '0.4s' }}>
          <span className="text-gradient">PRIVADB</span>
        </h1>

        {/* Subtitle */}
        <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-12 opacity-0 animate-fade-in leading-relaxed" style={{ animationDelay: '0.6s' }}>
          Detecting Persistent Web Tracking via IndexedDB Dynamic Taint Analysis
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16 opacity-0 animate-fade-in" style={{ animationDelay: '0.8s' }}>
          <a
            href="#live-scan"
            className="px-8 py-3.5 bg-primary text-primary-foreground rounded-full font-medium text-sm hover:opacity-90 transition-all hover:scale-105 glow-sm"
          >
            Try Live Scan
          </a>
          <a
            href="#pipeline"
            className="px-8 py-3.5 glass rounded-full font-medium text-sm text-foreground hover:bg-muted/50 transition-all hover:scale-105"
          >
            Explore Research →
          </a>
        </div>

        {/* Counter Strip */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-8 sm:gap-16 opacity-0 animate-fade-in" style={{ animationDelay: '1s' }}>
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
        </div>
      </div>

      {/* Scroll indicator */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 opacity-0 animate-fade-in" style={{ animationDelay: '1.4s' }}>
        <div className="w-6 h-10 rounded-full border-2 border-muted-foreground/30 flex items-start justify-center p-1.5">
          <div className="w-1.5 h-3 bg-muted-foreground/50 rounded-full animate-bounce" />
        </div>
      </div>
    </section>
  );
};
