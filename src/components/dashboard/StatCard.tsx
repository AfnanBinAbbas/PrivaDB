import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'default' | 'primary' | 'warning' | 'destructive' | 'success';
  trend?: {
    value: number;
    direction: 'up' | 'down';
  };
}

const variantStyles = {
  default: 'border-border',
  primary: 'border-primary/30 glow-primary',
  warning: 'border-warning/30 glow-warning',
  destructive: 'border-destructive/30 glow-destructive',
  success: 'border-success/30 glow-success',
};

const iconStyles = {
  default: 'text-muted-foreground bg-muted',
  primary: 'text-primary bg-primary/20',
  warning: 'text-warning bg-warning/20',
  destructive: 'text-destructive bg-destructive/20',
  success: 'text-success bg-success/20',
};

export function StatCard({ 
  title, 
  value, 
  subtitle, 
  icon: Icon, 
  variant = 'default',
  trend 
}: StatCardProps) {
  return (
    <div className={cn(
      'glass rounded-xl p-5 transition-all duration-300 hover:scale-[1.02] animate-fade-in',
      variantStyles[variant]
    )}>
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-sm text-muted-foreground font-medium">{title}</p>
          <p className="text-3xl font-bold font-mono tracking-tight">{value}</p>
          {subtitle && (
            <p className="text-xs text-muted-foreground">{subtitle}</p>
          )}
          {trend && (
            <div className={cn(
              'flex items-center gap-1 text-xs font-medium',
              trend.direction === 'up' ? 'text-destructive' : 'text-success'
            )}>
              <span>{trend.direction === 'up' ? '↑' : '↓'}</span>
              <span>{trend.value}%</span>
              <span className="text-muted-foreground">vs last hour</span>
            </div>
          )}
        </div>
        <div className={cn(
          'p-3 rounded-lg',
          iconStyles[variant]
        )}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}
