import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary: "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive: "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        warning: "border-transparent bg-warning text-warning-foreground hover:bg-warning/80",
        success: "border-transparent bg-success text-success-foreground hover:bg-success/80",
        outline: "text-foreground",
        glow: "border-transparent bg-primary/20 text-primary border border-primary/50 shadow-[0_0_20px_hsl(var(--primary)/0.4)]",
        "glow-destructive": "border-transparent bg-destructive/20 text-destructive border border-destructive/50 shadow-[0_0_20px_hsl(var(--destructive)/0.4)]",
        "glow-warning": "border-transparent bg-warning/20 text-warning border border-warning/50 shadow-[0_0_20px_hsl(var(--warning)/0.4)]",
        "glow-success": "border-transparent bg-success/20 text-success border border-success/50 shadow-[0_0_20px_hsl(var(--success)/0.4)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
