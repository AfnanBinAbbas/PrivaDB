import { useEffect } from "react";
import { ThemeProvider } from "./components/privadb/ThemeProvider";
import { FloatingNav } from "./components/privadb/FloatingNav";
import { HeroSection } from "./components/privadb/HeroSection";
import { MetricsSection } from "./components/privadb/MetricsSection";
import { ArchitectureSection } from "./components/privadb/ArchitectureSection";
import { LiveScan } from "./components/privadb/LiveScan";
import { PipelineSection } from "./components/privadb/PipelineSection";
import { CodeExplorer } from "./components/privadb/CodeExplorer";
import { TrackerDomains } from "./components/privadb/TrackerDomains";
import { ResearchTables } from "./components/privadb/ResearchTables";
import { DownloadSection } from "./components/privadb/DownloadSection";
import { ConfigSection } from "./components/privadb/ConfigSection";
import { BackToTop } from "./components/privadb/BackToTop";

const App = () => {
  // Force dark mode for the premium aesthetic
  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);

  return (
    <ThemeProvider>
      <div className="min-h-screen bg-background text-foreground overflow-x-hidden selection:bg-primary/30 font-sans">
        <FloatingNav />
        <main>
          <HeroSection />
          <MetricsSection />
          <ArchitectureSection />
          <LiveScan />
          <PipelineSection />
          <CodeExplorer />
          <TrackerDomains />
          <ResearchTables />
          <DownloadSection />
          <ConfigSection />
        </main>
        <BackToTop />
      </div>
    </ThemeProvider>
  );
};

export default App;
