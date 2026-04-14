import React, { useState, useEffect, useRef } from 'react';
import { Moon, Sun, Menu, X, Github } from 'lucide-react';
import { useTheme } from './ThemeProvider';
import { motion, AnimatePresence, useScroll, useMotionValueEvent } from 'framer-motion';

const navLinks = [
  { label: 'Live Scan', href: '#live-scan' },
  { label: 'Pipeline', href: '#pipeline' },
  { label: 'Architecture', href: '#architecture' },
  { label: 'Trackers', href: '#trackers' },
  { label: 'Download', href: '#download' },
  { label: 'Collaborate', href: 'https://github.com/AfnanBinAbbas/PrivaDB/tree/main', external: true },
];

export const FloatingNav: React.FC = () => {
  const { theme, toggle } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const { scrollY } = useScroll();

  useMotionValueEvent(scrollY, "change", (latest) => {
    const previous = scrollY.getPrevious() || 0;
    if (latest > previous && latest > 150) {
      setHidden(true);
    } else {
      setHidden(false);
    }
    setScrolled(latest > 50);
  });

  return (
    <motion.nav 
      variants={{
        visible: { y: 0, x: "-50%", opacity: 1 },
        hidden: { y: -100, x: "-50%", opacity: 0 }
      }}
      initial="visible"
      animate={hidden ? "hidden" : "visible"}
      transition={{ duration: 0.35, ease: "easeInOut" }}
      className={`fixed top-4 left-1/2 z-50 transition-all duration-300 ${
        scrolled ? 'glass-strong rounded-full px-5 py-2.5 shadow-lg border-border/40' : 'px-4 py-3'
      }`}
    >
      <div className="flex items-center gap-5">
        <a href="#" className="text-base font-bold text-primary tracking-tighter">PRIVADB</a>
        
        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-0.5">
          {navLinks.map(link => (
            <a
              key={link.href}
              href={link.href}
              target={link.external ? "_blank" : undefined}
              rel={link.external ? "noopener noreferrer" : undefined}
              className={`px-3 py-1 text-xs font-semibold transition-all rounded-full flex items-center gap-1.5 group ${
                link.label === 'Live Scan' 
                ? 'text-primary drop-shadow-[0_0_8px_rgba(59,130,246,0.6)]' 
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
              }`}
            >
              {link.label === 'Collaborate' && <Github size={12} className="group-hover:text-primary transition-colors" />}
              {link.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={toggle}
            className="p-1.5 rounded-full hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>

          {/* Mobile menu button */}
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden p-1.5 rounded-full hover:bg-muted/50 transition-colors"
          >
            {mobileOpen ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>
      </div>

      {/* Mobile dropdown */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.95, y: -10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: -10 }}
            className="md:hidden mt-3 glass-strong rounded-2xl p-4 flex flex-col gap-2 min-w-[200px]"
          >
            {navLinks.map(link => (
              <a
                key={link.href}
                href={link.href}
                target={link.external ? "_blank" : undefined}
                rel={link.external ? "noopener noreferrer" : undefined}
                onClick={() => setMobileOpen(false)}
                className="px-3 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors rounded-lg hover:bg-muted/50 flex items-center gap-2"
              >
                {link.label === 'Collaborate' && <Github size={14} />}
                {link.label}
              </a>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.nav>
  );
};
