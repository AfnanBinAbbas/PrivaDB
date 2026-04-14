import React from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, ShieldCheck, Search, Database, Mail } from 'lucide-react';

const steps = [
  {
    title: "1. The Secret Storage",
    description: "Every website has a secret box called 'IndexedDB' where it keeps your special ID stickers.",
    image: "/graphics/secret_box.png",
    icon: Database,
    color: "text-blue-500"
  },
  {
    title: "2. Adding the Sticker",
    description: "Our detective team (Chrome & Foxhound) puts a glowing 'Taint Sticker' on your data so we can see it!",
    image: "/graphics/taint_sticker.png",
    icon: ShieldCheck,
    color: "text-cyan-500"
  },
  {
    title: "3. The Detective Work",
    description: "Chrome acts like a standard postman, while Foxhound is a supersmart detective dog watching every move.",
    images: ["/graphics/chrome_postman.png", "/graphics/foxhound_detective.png"],
    icon: Search,
    color: "text-orange-500"
  },
  {
    title: "4. Preventing the Escape",
    description: "If the data tries to fly away in a secret letter to a tracker, we catch it and show you exactly who did it!",
    image: "/graphics/flying_letters.png",
    icon: Mail,
    color: "text-pink-500"
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
                  {step.images ? (
                    <div className="flex gap-2">
                       <motion.img 
                        src={step.images[0]} 
                        alt="Chrome" 
                        className="w-16 h-16 object-contain"
                        animate={{ y: [0, -5, 0] }}
                        transition={{ duration: 2, repeat: Infinity }}
                      />
                       <motion.img 
                        src={step.images[1]} 
                        alt="Foxhound" 
                        className="w-16 h-16 object-contain"
                        animate={{ y: [0, -7, 0] }}
                        transition={{ duration: 2.5, repeat: Infinity }}
                      />
                    </div>
                  ) : (
                    <motion.img 
                      src={step.image} 
                      alt={step.title} 
                      className="w-32 h-32 object-contain"
                      whileHover={{ scale: 1.1, rotate: 2 }}
                    />
                  )}
                </div>

                <div className="flex items-center gap-3 mb-3">
                  <div className={`p-2 rounded-lg bg-background shadow-inner ${step.color}`}>
                    <step.icon size={18} />
                  </div>
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
            <p className="text-muted-foreground text-sm">Launch a scan above and watch the detecives work in real-time.</p>
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
