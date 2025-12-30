import { useState } from 'react';
import { ChevronRight, ChevronDown, Database, FolderOpen, Key, AlertTriangle, CheckCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { DomainScan, ObjectStore, DatabaseRecord } from '@/types/detector';
import { ScrollArea } from '@/components/ui/scroll-area';

interface DatabaseExplorerProps {
  scans: DomainScan[];
}

export function DatabaseExplorer({ scans }: DatabaseExplorerProps) {
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set([scans[0]?.domain]));
  const [expandedDbs, setExpandedDbs] = useState<Set<string>>(new Set());
  const [expandedStores, setExpandedStores] = useState<Set<string>>(new Set());

  const toggleDomain = (domain: string) => {
    const next = new Set(expandedDomains);
    if (next.has(domain)) next.delete(domain);
    else next.add(domain);
    setExpandedDomains(next);
  };

  const toggleDb = (id: string) => {
    const next = new Set(expandedDbs);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpandedDbs(next);
  };

  const toggleStore = (id: string) => {
    const next = new Set(expandedStores);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpandedStores(next);
  };

  return (
    <div className="glass rounded-xl h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <h3 className="font-semibold flex items-center gap-2">
          <Database className="h-4 w-4 text-primary" />
          Database Schema
        </h3>
        <p className="text-xs text-muted-foreground mt-1">
          {scans.length} domains scanned
        </p>
      </div>
      
      <ScrollArea className="flex-1 p-3">
        <div className="space-y-1">
          {scans.map((scan) => (
            <DomainNode
              key={scan.domain}
              scan={scan}
              isExpanded={expandedDomains.has(scan.domain)}
              onToggle={() => toggleDomain(scan.domain)}
              expandedDbs={expandedDbs}
              toggleDb={toggleDb}
              expandedStores={expandedStores}
              toggleStore={toggleStore}
            />
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

function DomainNode({ 
  scan, 
  isExpanded, 
  onToggle,
  expandedDbs,
  toggleDb,
  expandedStores,
  toggleStore,
}: {
  scan: DomainScan;
  isExpanded: boolean;
  onToggle: () => void;
  expandedDbs: Set<string>;
  toggleDb: (id: string) => void;
  expandedStores: Set<string>;
  toggleStore: (id: string) => void;
}) {
  const statusBadge = scan.status === 'scanning' ? (
    <Badge variant="glow" className="text-[10px] px-1.5 py-0 animate-pulse-glow">
      SCANNING
    </Badge>
  ) : scan.status === 'error' ? (
    <Badge variant="glow-destructive" className="text-[10px] px-1.5 py-0">
      ERROR
    </Badge>
  ) : (
    <Badge variant="glow-success" className="text-[10px] px-1.5 py-0">
      COMPLETE
    </Badge>
  );

  return (
    <div className="animate-fade-in">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-secondary/50 transition-colors text-left"
      >
        {isExpanded ? (
          <ChevronDown className="h-3 w-3 text-muted-foreground flex-shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
        )}
        <span className="text-sm font-mono text-foreground truncate">{scan.domain}</span>
        {statusBadge}
      </button>
      
      {isExpanded && (
        <div className="ml-4 pl-3 border-l border-border/50 mt-1 space-y-1">
          {scan.databases.map((db) => {
            const dbId = `${scan.domain}-${db.name}`;
            const isDbExpanded = expandedDbs.has(dbId);
            
            return (
              <div key={dbId}>
                <button
                  onClick={() => toggleDb(dbId)}
                  className="w-full flex items-center gap-2 px-2 py-1 rounded-md hover:bg-secondary/50 transition-colors text-left"
                >
                  {isDbExpanded ? (
                    <ChevronDown className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                  ) : (
                    <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                  )}
                  <Database className="h-3 w-3 text-primary flex-shrink-0" />
                  <span className="text-sm font-mono truncate">{db.name}</span>
                  <span className="text-[10px] text-muted-foreground">v{db.version}</span>
                </button>
                
                {isDbExpanded && (
                  <div className="ml-4 pl-3 border-l border-border/50 mt-1 space-y-1">
                    {db.stores.map((store) => {
                      const storeId = `${dbId}-${store.name}`;
                      const isStoreExpanded = expandedStores.has(storeId);
                      const hasSuspectedData = store.suspectedUserData.length > 0;
                      
                      return (
                        <StoreNode
                          key={storeId}
                          store={store}
                          isExpanded={isStoreExpanded}
                          onToggle={() => toggleStore(storeId)}
                          hasSuspectedData={hasSuspectedData}
                        />
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function StoreNode({
  store,
  isExpanded,
  onToggle,
  hasSuspectedData,
}: {
  store: ObjectStore;
  isExpanded: boolean;
  onToggle: () => void;
  hasSuspectedData: boolean;
}) {
  return (
    <div>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-2 py-1 rounded-md hover:bg-secondary/50 transition-colors text-left"
      >
        {isExpanded ? (
          <ChevronDown className="h-3 w-3 text-muted-foreground flex-shrink-0" />
        ) : (
          <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
        )}
        <FolderOpen className={cn(
          "h-3 w-3 flex-shrink-0",
          hasSuspectedData ? "text-warning" : "text-muted-foreground"
        )} />
        <span className="text-sm font-mono truncate">{store.name}</span>
        <span className="text-[10px] text-muted-foreground">({store.recordCount})</span>
        {hasSuspectedData && (
          <AlertTriangle className="h-3 w-3 text-warning flex-shrink-0" />
        )}
      </button>
      
      {isExpanded && store.suspectedUserData.length > 0 && (
        <div className="ml-4 pl-3 border-l border-border/50 mt-1 space-y-1">
          {store.suspectedUserData.map((record, idx) => (
            <RecordNode key={idx} record={record} />
          ))}
        </div>
      )}
    </div>
  );
}

function RecordNode({ record }: { record: DatabaseRecord }) {
  return (
    <div className="px-2 py-1.5 rounded-md bg-secondary/30 border border-border/50">
      <div className="flex items-center gap-2">
        <Key className="h-3 w-3 text-warning flex-shrink-0" />
        <span className="text-xs font-mono text-foreground truncate">{record.key}</span>
      </div>
      <div className="mt-1 text-[10px] text-muted-foreground font-mono truncate">
        {record.value.substring(0, 30)}...
      </div>
      <div className="mt-1 flex flex-wrap gap-1">
        {record.detectedPatterns.map((pattern) => (
          <span 
            key={pattern} 
            className="text-[9px] px-1.5 py-0.5 bg-warning/10 text-warning rounded border border-warning/30"
          >
            {pattern}
          </span>
        ))}
      </div>
    </div>
  );
}
