import { useState, useRef } from 'react';
import { Upload, Plus, X, Globe, FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';

interface DomainInputProps {
  onDomainsChange?: (domains: string[]) => void;
}

export function DomainInput({ onDomainsChange }: DomainInputProps) {
  const [domains, setDomains] = useState<string[]>([]);
  const [inputValue, setInputValue] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addDomain = (domain: string) => {
    const cleaned = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (cleaned && !domains.includes(cleaned)) {
      const newDomains = [...domains, cleaned];
      setDomains(newDomains);
      onDomainsChange?.(newDomains);
      return true;
    }
    return false;
  };

  const handleManualAdd = () => {
    if (inputValue.trim()) {
      if (addDomain(inputValue)) {
        toast.success(`Added ${inputValue.trim()}`);
        setInputValue('');
      } else {
        toast.error('Domain already exists or is invalid');
      }
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleManualAdd();
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.txt')) {
      toast.error('Please upload a .txt file');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      const lines = content.split('\n').filter(line => line.trim());
      let addedCount = 0;
      
      lines.forEach(line => {
        if (addDomain(line)) addedCount++;
      });

      toast.success(`Added ${addedCount} domains from file`);
    };
    reader.readAsText(file);
    
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removeDomain = (domain: string) => {
    const newDomains = domains.filter(d => d !== domain);
    setDomains(newDomains);
    onDomainsChange?.(newDomains);
  };

  const clearAll = () => {
    setDomains([]);
    onDomainsChange?.([]);
    toast.info('Cleared all domains');
  };

  return (
    <Card className="glass border-border/50">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Globe className="h-4 w-4 text-primary" />
          Target Domains
          {domains.length > 0 && (
            <Badge variant="secondary" className="ml-auto font-mono text-xs">
              {domains.length} domains
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Manual Input */}
        <div className="flex gap-2">
          <Input
            placeholder="Enter domain (e.g., example.com)"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-background/50 border-border/50 font-mono text-sm"
          />
          <Button 
            size="sm" 
            onClick={handleManualAdd}
            disabled={!inputValue.trim()}
            className="gap-1"
          >
            <Plus className="h-4 w-4" />
            Add
          </Button>
        </div>

        {/* File Upload */}
        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt"
            onChange={handleFileUpload}
            className="hidden"
          />
          <Button
            variant="outline"
            size="sm"
            onClick={() => fileInputRef.current?.click()}
            className="gap-2 flex-1"
          >
            <Upload className="h-4 w-4" />
            Upload domains.txt
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => toast.info('Format: One domain per line\n\nexample.com\ntest.org\nsite.net')}
            className="text-muted-foreground"
          >
            <FileText className="h-4 w-4" />
          </Button>
        </div>

        {/* Domain List */}
        {domains.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Queued for scanning:</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearAll}
                className="h-6 text-xs text-muted-foreground hover:text-destructive"
              >
                Clear all
              </Button>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto p-2 rounded-md bg-background/30 border border-border/30">
              {domains.map((domain) => (
                <Badge
                  key={domain}
                  variant="outline"
                  className="font-mono text-xs gap-1 pr-1 bg-background/50"
                >
                  {domain}
                  <button
                    onClick={() => removeDomain(domain)}
                    className="ml-1 hover:text-destructive transition-colors"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
