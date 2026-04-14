import React, { useState, useEffect } from 'react';
import { Moon, Sun, Menu, X } from 'lucide-react';
import { useTheme } from './ThemeProvider';

const navLinks = [
  { label: 'Live Scan', href: '#live-scan' },
  { label: 'Pipeline', href: '#pipeline' },
  { label: 'Architecture', href: '#architecture' },
  { label: 'Trackers', href: '#trackers' },
  { label: 'Download', href: '#download' },
];

export const FloatingNav: React.FC = () => {
  const { theme, toggle } = useTheme();
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 50);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <nav className={`fixed top-4 left-1/2 -translate-x-1/2 z-50 transition-all duration-500 ${
      scrolled ? 'glass-strong glow-sm rounded-full px-6 py-3' : 'px-6 py-4'
    }`}>
      <div className="flex items-center gap-6">
        <a href="#" className="text-lg font-bold text-primary tracking-tight">PRIVADB</a>
        
        {/* Desktop links */}
        <div className="hidden md:flex items-center gap-1">
          {navLinks.map(link => (
            <a
              key={link.href}
              href={link.href}
              className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors rounded-full hover:bg-muted/50"
            >
              {link.label}
            </a>
          ))}
        </div>

        <button
          onClick={toggle}
          className="ml-2 p-2 rounded-full hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        {/* Mobile menu button */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="md:hidden p-2 rounded-full hover:bg-muted/50 transition-colors"
        >
          {mobileOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div className="md:hidden mt-3 glass-strong rounded-2xl p-4 flex flex-col gap-2">
          {navLinks.map(link => (
            <a
              key={link.href}
              href={link.href}
              onClick={() => setMobileOpen(false)}
              className="px-3 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors rounded-lg hover:bg-muted/50"
            >
              {link.label}
            </a>
          ))}
        </div>
      )}
    </nav>
  );
};
