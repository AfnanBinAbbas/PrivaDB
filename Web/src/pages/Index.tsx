import React from 'react';
import { ThemeProvider } from '@/components/privadb/ThemeProvider';
import { FloatingNav } from '@/components/privadb/FloatingNav';
import { HeroSection } from '@/components/privadb/HeroSection';
import { PipelineSection } from '@/components/privadb/PipelineSection';
import { MetricsSection } from '@/components/privadb/MetricsSection';
import { ArchitectureSection } from '@/components/privadb/ArchitectureSection';
import { ConfigSection } from '@/components/privadb/ConfigSection';
import { CodeExplorer } from '@/components/privadb/CodeExplorer';
import { TrackerDomains } from '@/components/privadb/TrackerDomains';
import { ResearchTables } from '@/components/privadb/ResearchTables';
import { DownloadSection } from '@/components/privadb/DownloadSection';
import { BackToTop } from '@/components/privadb/BackToTop';
import { LiveScan } from '@/components/privadb/LiveScan';

const Index = () => {
  return (
    <ThemeProvider>
      <div className="min-h-screen bg-background text-foreground animated-gradient-bg">
        <FloatingNav />
        <HeroSection />
        <LiveScan />
        <MetricsSection />
        <ArchitectureSection />
        <ConfigSection />
        <CodeExplorer />
        <TrackerDomains />
        <ResearchTables />
        <DownloadSection />
        <BackToTop />

        {/* Footer */}
        <footer className="py-12 px-4 border-t border-border/50">
          <div className="max-w-6xl mx-auto text-center">
            <p className="text-sm text-muted-foreground">
              PRIVADB — Detecting Persistent Web Tracking via IndexedDB Dynamic Taint Analysis
            </p>
            <p className="text-xs text-muted-foreground/50 mt-2">
              Research Project · 2025
            </p>
          </div>
        </footer>
      </div>
    </ThemeProvider>
  );
};

export default Index;
