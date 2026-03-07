import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, Fingerprint, User, Globe, Activity } from 'lucide-react';

interface TrackingPanelProps {
    trackingAnalysis: any;
}

export function TrackingPanel({ trackingAnalysis }: TrackingPanelProps) {
    if (!trackingAnalysis) return null;

    return (
        <Card className="w-full h-full overflow-hidden">
            <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                    <Activity className="h-5 w-5" />
                    Tracking Analysis
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 overflow-y-auto max-h-[calc(100%-60px)]">

                {/* 🔴 THIS IS THE CODE YOU ASKED ABOUT - IndexedDB Data Being Sent */}
                {trackingAnalysis.domain_specific_report?.transmitted_identifiers_from_indexeddb?.length > 0 && (
                    <div className="space-y-2">
                        <h4 className="text-sm font-semibold flex items-center gap-1 text-destructive">
                            <AlertTriangle className="h-4 w-4" />
                            🔴 IndexedDB Data Being Sent to Servers
                        </h4>
                        <div className="space-y-2">
                            {trackingAnalysis.domain_specific_report.transmitted_identifiers_from_indexeddb.map((item: any, idx: number) => (
                                <div key={idx} className="bg-destructive/10 border border-destructive/20 p-3 rounded-lg">
                                    <div className="font-mono text-xs break-all">{item.identifier}</div>
                                    <div className="flex justify-between mt-2">
                                        <span className="text-xs text-muted-foreground truncate max-w-[200px]">
                                            {item.url}
                                        </span>
                                        <Badge variant="destructive" className="text-[10px]">
                                            Transmitted
                                        </Badge>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Summary Stats */}
                {trackingAnalysis.summary && (
                    <div className="grid grid-cols-2 gap-2">
                        <div className="bg-muted p-3 rounded-lg">
                            <div className="text-xs text-muted-foreground">Persistent IDs</div>
                            <div className="text-2xl font-bold">{trackingAnalysis.summary.total_persistent_identifiers || 0}</div>
                        </div>
                        <div className="bg-muted p-3 rounded-lg">
                            <div className="text-xs text-muted-foreground">Transmitted</div>
                            <div className="text-2xl font-bold">{trackingAnalysis.summary.transmitted_to_network || 0}</div>
                        </div>
                    </div>
                )}

                {/* Network Endpoints */}
                {trackingAnalysis.domain_specific_report?.network_endpoints_sending_data?.length > 0 && (
                    <div className="space-y-2">
                        <h4 className="text-sm font-semibold flex items-center gap-1">
                            <Globe className="h-4 w-4" />
                            Data Sent To These Servers
                        </h4>
                        <div className="space-y-1">
                            {trackingAnalysis.domain_specific_report.network_endpoints_sending_data.slice(0, 5).map((item: any, idx: number) => (
                                <div key={idx} className="bg-muted/50 p-2 rounded text-xs">
                                    <div className="font-medium">{item.domain}</div>
                                    <div className="text-muted-foreground truncate">{item.example_url}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}