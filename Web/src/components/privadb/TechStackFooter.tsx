import React from 'react';
import { motion } from 'framer-motion';

const techStack = [
  { name: 'React', url: 'https://cdn.simpleicons.org/react/61DAFB' },
  { name: 'TypeScript', url: 'https://cdn.simpleicons.org/typescript/3178C6' },
  { name: 'Tailwind CSS', url: 'https://cdn.simpleicons.org/tailwindcss/06B6D4' },
  { name: 'Framer Motion', url: 'https://cdn.simpleicons.org/framer/0055FF' },
  { name: 'Python', url: 'https://cdn.simpleicons.org/python/3776AB' },
  { name: 'FastAPI', url: 'https://cdn.simpleicons.org/fastapi/009688' },
  { name: 'Playwright', url: 'https://cdn.simpleicons.org/playwrighttesting/2EAD33' },
  { name: 'SAP', url: 'https://cdn.simpleicons.org/sap/008FD3' },
  { name: 'Chrome', url: 'https://cdn.simpleicons.org/googlechrome/4285F4' },
  { name: 'Firefox', url: 'https://cdn.simpleicons.org/firefoxbrowser/FF7139' },
  { name: 'Foxhound', url: '/graphics/foxhound-logo.png' },
  { name: 'IndexedDB', url: 'https://cdn.simpleicons.org/html5/E34F26' },
];

export const TechStackFooter: React.FC = () => {
  return (
    <footer className="w-full py-12 px-4 border-t border-border/20 bg-background">
      <div className="max-w-6xl mx-auto flex flex-col items-center justify-center">
        <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-widest mb-8 text-center">
          Powered By Modern Technologies
        </h3>

        <div className="flex flex-wrap justify-center items-center gap-x-10 gap-y-8 opacity-80 hover:opacity-100 transition-opacity">
          {techStack.map((tech, i) => (
            <motion.div
              key={tech.name}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
              whileHover={{ scale: 1.12, y: -4 }}
              className="flex flex-col items-center gap-2 cursor-default"
              title={tech.name}
            >
              <div className="w-10 h-10 md:w-12 md:h-12 grayscale hover:grayscale-0 transition-all duration-300 flex items-center justify-center">
                <img
                  src={tech.url}
                  alt={`${tech.name} logo`}
                  className="w-full h-full object-contain"
                  loading="lazy"
                />
              </div>
              <span className="text-[10px] font-mono text-muted-foreground/70 text-center leading-none">
                {tech.name}
              </span>
            </motion.div>
          ))}
        </div>

        <div className="mt-12 text-center text-xs text-muted-foreground/50 font-mono">
          &copy; {new Date().getFullYear()} PrivaDB. All rights reserved. <br />
          Built for advanced privacy analysis and compliance verification.
        </div>
      </div>
    </footer>
  );
};
