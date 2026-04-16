import React from 'react';
import { motion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';

interface Step {
  title: string;
  description: string;
  image: string;
}

const steps: Step[] = [
  {
    title: "The Secret Storage",
    description: "Every website has a secret box called 'IndexedDB' where it keeps your special ID stickers which is commonly called as user identification data.",
    image: "/graphics/chest.jpg",
  },
  {
    title: "Adding the Taint Sticker",
    description: "Our detective team (Chrome & Foxhound) puts a glowing 'Taint Sticker' on your data so we can see it flow from and to the tracker!",
    image: "/graphics/taint_sticker.jpg",
  },
  {
    title: "The Detective Work",
    description: "Chrome acts like a standard postman, while Foxhound is a supersmart detective dog watching every move.",
    image: "/graphics/foxhound_detective.jpg",
  },
  {
    title: "Preventing the Escape",
    description: "If the data tries to fly away in a secret letter to a tracker, we catch it and show you exactly who did it!",
    image: "/graphics/escape.jpeg",
  }
];

export const MethodologyDiagram: React.FC = () => {
  return (
    <section id="methodology" className="py-24 px-4 bg-muted/30 relative overflow-hidden">
      {/* Background Decor */}
      <div className="absolute top-12 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary/20 to-transparent" />

      <div className="max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-5xl font-bold mb-4 tracking-tighter">How it Works</h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Explaining complex web security as simply as possible. Follow the journey of your data.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {steps.map((step, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.15 }}
              viewport={{ once: true }}
              className="relative group"
            >
              <div className="glass rounded-3xl p-6 h-full flex flex-col border-primary/10 hover:border-primary/40 transition-all duration-500 hover:shadow-2xl hover:shadow-primary/10">
                <div className="mb-6 relative h-40 flex items-center justify-center overflow-hidden rounded-2xl bg-black/20">
                  <motion.img
                    src={step.image}
                    alt={step.title}
                    className="w-32 h-32 object-contain"
                    whileHover={{ scale: 1.1, rotate: 2 }}
                  />
                </div>

                {/* Title with Number Badge */}
                <div className="mb-3 flex items-center gap-2">
                  <span className="text-xs font-mono text-primary/70 bg-primary/10 px-2 py-0.5 rounded">
                    {i + 1}
                  </span>
                  <h3 className="font-bold text-lg tracking-tight">{step.title}</h3>
                </div>

                <p className="text-sm text-muted-foreground leading-relaxed">
                  {step.description}
                </p>

                {i < steps.length - 1 && (
                  <div className="hidden lg:block absolute -right-6 top-1/2 -translate-y-1/2 z-20 text-primary opacity-20 group-hover:opacity-100 transition-opacity">
                    <ArrowRight size={24} />
                  </div>
                )}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Cinematic Bottom Banner */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="mt-16 p-8 glass rounded-[2rem] border-primary/20 flex flex-col md:flex-row items-center justify-between gap-8 overflow-hidden relative"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-pink-500/5 pointer-events-none" />
          <div className="relative z-10 space-y-2 text-center md:text-left">
            <h4 className="text-xl font-bold">Ready to see it in action?</h4>
            <p className="text-muted-foreground text-sm">Launch a scan above and watch the detectives work in real-time.</p>
          </div>
          <motion.a
            href="#live-scan"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="relative z-10 px-8 py-3 bg-primary text-primary-foreground rounded-full font-bold shadow-lg hover:shadow-xl hover:bg-primary/90 transition-all"
          >
            Start Scan Now
          </motion.a>
        </motion.div>
      </div>
    </section>
  );
};