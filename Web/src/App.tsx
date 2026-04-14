import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { ThemeProvider } from "./components/privadb/ThemeProvider";
import { FloatingNav } from "./components/privadb/FloatingNav";
import { HeroSection } from "./components/privadb/HeroSection";
import { ResearchHologram } from "./components/privadb/ResearchHologram";
import { MethodologyDiagram } from "./components/privadb/MethodologyDiagram";
import { ArchitectureSection } from "./components/privadb/ArchitectureSection";
import { LiveScan } from "./components/privadb/LiveScan";
import { PipelineSection } from "./components/privadb/PipelineSection";
import { CodeExplorer } from "./components/privadb/CodeExplorer";
import { TrackerDomains } from "./components/privadb/TrackerDomains";
import { ResearchTables } from "./components/privadb/ResearchTables";
import { FoxhoundResults } from "./components/privadb/FoxhoundResults";
import { LiveExfiltrationMap } from "./components/privadb/LiveExfiltrationMap";
import { DownloadSection } from "./components/privadb/DownloadSection";
import { ConfigSection } from "./components/privadb/ConfigSection";
import { BackToTop } from "./components/privadb/BackToTop";
import { Volume2, VolumeX } from "lucide-react";
import { LandingPage } from "./components/privadb/LandingPage";
import { AnimatePresence } from "framer-motion";
import ScanResults from "./components/privadb/ScanResults";
import AnimatedLinesBackground from "./components/privadb/AnimatedLinesBackground";

const AppLoadingOverlay = ({ show }: { show: boolean }) => (
  show ? (
    <div className="app-loading-overlay">
      <div className="app-loading-spinner" />
      <div className="app-loading-text">Loading PrivaDB...</div>
    </div>
  ) : null
);

const App = () => {
  const audioRef = useRef<HTMLAudioElement>(null);
  const [isMuted, setIsMuted] = useState(false);
  const [volume, setVolume] = useState(0.5);
  const [showLanding, setShowLanding] = useState(true);
  const [appLoading, setAppLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setAppLoading(false), 1200);
    return () => clearTimeout(timer);
  }, []);

  // Sync volume state with audio element
  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.volume = volume;
    }
  }, [volume]);

  // Global click listener to unlock audio on first interaction (landing page)
  useEffect(() => {
    const handleInteraction = () => {
      if (audioRef.current) {
        audioRef.current.play().catch(() => { });
      }
      window.removeEventListener('click', handleInteraction);
      window.removeEventListener('touchstart', handleInteraction);
    };
    window.addEventListener('click', handleInteraction);
    window.addEventListener('touchstart', handleInteraction);
    return () => {
      window.removeEventListener('click', handleInteraction);
      window.removeEventListener('touchstart', handleInteraction);
    };
  }, []);

  const toggleMute = () => {
    const audio = audioRef.current;
    if (!audio) return;

    try {
      const newMuted = !isMuted;
      audio.muted = newMuted;

      if (!newMuted) {
        const playPromise = audio.play();
        if (playPromise !== undefined) {
          playPromise.catch(error => {
            console.error("Playback failed:", error);
          });
        }
      }
      setIsMuted(newMuted);
    } catch (e) {
      console.error("Error in toggleMute:", e);
    }
  };

  return (
    <ThemeProvider>
      <AppLoadingOverlay show={appLoading} />
      <AnimatedLinesBackground />
      <audio ref={audioRef} src="/background_music.mp3" loop />
      <AnimatePresence mode="wait">
        {showLanding && (
          <LandingPage
            key="landing"
            onReveal={() => setShowLanding(false)}
          />
        )}
      </AnimatePresence>

      <motion.div
        className="min-h-screen bg-background text-foreground overflow-x-hidden selection:bg-primary/30 font-sans"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1, delay: 0.5 }}
      >
        {/* Audio Controls */}
        <div className="fixed bottom-24 right-6 z-50 flex flex-col items-center gap-3 group">
          {/* Volume Slider Drawer (Interactive via mouse events) */}
          <div
            className="h-32 w-12 glass rounded-full flex flex-col items-center py-4 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-all duration-300 translate-y-4 group-hover:translate-y-0 shadow-2xl border border-primary/10 cursor-ns-resize select-none"
            onPointerDown={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              const updateVolume = (moveEvent: PointerEvent) => {
                const newValue = Math.max(0, Math.min(1, 1 - (moveEvent.clientY - rect.top) / rect.height));
                const roundedVol = Math.round(newValue * 100) / 100;
                setVolume(roundedVol);

                if (roundedVol > 0 && isMuted) {
                  setIsMuted(false);
                  if (audioRef.current) {
                    audioRef.current.muted = false;
                    audioRef.current.play().catch(() => { });
                  }
                } else if (roundedVol === 0 && !isMuted) {
                  setIsMuted(true);
                  if (audioRef.current) audioRef.current.muted = true;
                }
              };

              updateVolume(e.nativeEvent);
              const onMove = (moveEvent: PointerEvent) => updateVolume(moveEvent);
              const onUp = () => {
                window.removeEventListener('pointermove', onMove);
                window.removeEventListener('pointerup', onUp);
              };
              window.addEventListener('pointermove', onMove);
              window.addEventListener('pointerup', onUp);
            }}
          >
            <div className="relative h-24 w-6 flex justify-center pointer-events-none">
              {/* Visual Bar */}
              <div className="absolute inset-y-0 left-1/2 -translate-x-1/2 w-1.5 bg-primary/20 rounded-full overflow-hidden">
                <div
                  className="absolute bottom-0 left-0 w-full bg-primary"
                  style={{ height: `${volume * 100}%` }}
                />
              </div>
            </div>
            <span className="text-[9px] font-mono mt-2 text-primary font-bold">{Math.round(volume * 100)}</span>
          </div>

          <button
            type="button"
            onClick={toggleMute}
            className="p-3 rounded-full bg-primary/10 border border-primary/20 hover:bg-primary/20 backdrop-blur-md transition-all duration-300 shadow-lg relative"
            title={isMuted ? "Unmute Music" : "Mute Music"}
          >
            {isMuted ? (
              <VolumeX className="w-5 h-5 text-primary" />
            ) : (
              <Volume2 className="w-5 h-5 text-primary" />
            )}

            {/* Tooltip */}
            <span className="absolute right-full mr-4 px-2 py-1 rounded bg-black/80 text-[10px] text-white opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap border border-white/10 uppercase tracking-tighter">
              {isMuted ? "Unmute Cinematic Background" : "Mute Background Music"}
            </span>
          </button>
        </div>

        <FloatingNav />
        <main>
          <HeroSection />
          <MethodologyDiagram />
          <LiveScan />
          <div className="max-w-4xl mx-auto px-4">
            <ScanResults />
          </div>
          <ResearchHologram />
          <ArchitectureSection />
          <PipelineSection />
          <TrackerDomains />
          <DownloadSection />
        </main>
        <BackToTop />
      </motion.div>
    </ThemeProvider>
  );
};

export default App;
