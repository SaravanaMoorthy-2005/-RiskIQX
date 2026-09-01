import * as React from "react"
import { cn } from "@/lib/utils"

export interface AppleGlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  enableTilt?: boolean;
  enableShine?: boolean;
  hoverLift?: number;
  backgroundBlur?: number;
  glassOpacity?: number;
  backgroundColor?: string;
  strokeColor?: string;
  strokeSize?: number;
  shineColor?: string;
  borderRadius?: number;
}

export const AppleGlassCard = React.forwardRef<HTMLDivElement, AppleGlassCardProps>(
  (
    {
      className,
      children,
      enableTilt = true,
      enableShine = true,
      hoverLift = 6,
      backgroundBlur = 20,
      glassOpacity = 0.75,
      backgroundColor = "rgba(15, 23, 42, 0.72)",
      strokeColor = "rgba(255, 255, 255, 0.12)",
      strokeSize = 1,
      shineColor = "rgba(255, 255, 255, 0.22)",
      borderRadius = 16,
      style,
      onMouseMove,
      onMouseEnter,
      onMouseLeave,
      ...props
    },
    ref
  ) => {
    const [isHovered, setIsHovered] = React.useState(false);
    const [mousePos, setMousePos] = React.useState({ x: 0, y: 0 });
    const cardRef = React.useRef<HTMLDivElement | null>(null);

    const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
      if (enableTilt && cardRef.current) {
        const rect = cardRef.current.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / heightOrSelf(rect.height) - 0.5;
        setMousePos({ x, y });
      }
      onMouseMove?.(e);
    };

    const handleMouseEnter = (e: React.MouseEvent<HTMLDivElement>) => {
      setIsHovered(true);
      onMouseEnter?.(e);
    };

    const handleMouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {
      setIsHovered(false);
      setMousePos({ x: 0, y: 0 });
      onMouseLeave?.(e);
    };

    function heightOrSelf(h: number) {
      return h > 0 ? h : 1;
    }

    const transformStyle = isHovered && enableTilt
      ? `perspective(1000px) rotateX(${-mousePos.y * 7}deg) rotateY(${mousePos.x * 7}deg) translateY(-${hoverLift}px) scale3d(1.008, 1.008, 1.008)`
      : isHovered
      ? `translateY(-${hoverLift}px)`
      : "perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px) scale3d(1, 1, 1)";

    return (
      <div
        ref={(node) => {
          cardRef.current = node;
          if (typeof ref === "function") ref(node);
          else if (ref) ref.current = node;
        }}
        onMouseMove={handleMouseMove}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className={cn(
          "group relative text-slate-100 transition-all duration-300 ease-out",
          className
        )}
        style={{
          borderRadius: `${borderRadius}px`,
          transform: transformStyle,
          transformStyle: "preserve-3d",
          ...style,
        }}
        {...props}
      >
        {/* Layer 1: Frosted Liquid Glass Backdrop */}
        <div
          className="absolute inset-0 pointer-events-none transition-colors duration-300"
          style={{
            backgroundColor: backgroundColor,
            opacity: glassOpacity,
            borderRadius: `${borderRadius}px`,
            backdropFilter: `blur(${backgroundBlur}px) saturate(180%)`,
            WebkitBackdropFilter: `blur(${backgroundBlur}px) saturate(180%)`,
            zIndex: 0,
          }}
        />

        {/* Layer 2: Animated Light Shine Pass-Through Sweep */}
        {enableShine && (
          <div
            className="absolute inset-0 pointer-events-none overflow-hidden"
            style={{
              borderRadius: `${borderRadius}px`,
              zIndex: 1,
            }}
          >
            <div
              className="absolute inset-y-0 w-[120%] pointer-events-none transition-transform duration-700 ease-[cubic-bezier(0.25,0.1,0.25,1)]"
              style={{
                background: `linear-gradient(105deg, transparent 20%, rgba(255, 255, 255, 0.04) 40%, ${shineColor} 50%, rgba(59, 130, 246, 0.25) 54%, transparent 70%)`,
                transform: isHovered ? "translateX(100%)" : "translateX(-120%)",
              }}
            />
          </div>
        )}

        {/* Layer 3: Specular Bevel Border Stroke */}
        <div
          className="absolute inset-0 pointer-events-none transition-all duration-300 group-hover:border-blue-500/40"
          style={{
            border: `${strokeSize}px solid ${strokeColor}`,
            borderRadius: `${borderRadius}px`,
            boxShadow: isHovered
              ? "0 20px 40px -15px rgba(0, 0, 0, 0.6), 0 0 20px -2px rgba(59, 130, 246, 0.15), inset 0 1px 1px 0 rgba(255, 255, 255, 0.22)"
              : "0 10px 30px -10px rgba(0, 0, 0, 0.5), inset 0 1px 1px 0 rgba(255, 255, 255, 0.12)",
            zIndex: 2,
          }}
        />

        {/* Layer 4: Interactive Content */}
        <div className="relative z-10 w-full h-full flex flex-col">
          {children}
        </div>
      </div>
    );
  }
);
AppleGlassCard.displayName = "AppleGlassCard";

/**
 * Direct port of Framer's AppleGlassStack
 */
export interface AppleGlassStackItem {
  title: string;
  body: string;
  icon?: React.ReactNode;
  badge?: string;
  backgroundImage?: { src: string; alt?: string };
}

export interface AppleGlassStackProps {
  items: AppleGlassStackItem[];
  direction?: "vertical" | "horizontal";
  gap?: number;
  containerPadding?: number;
  backgroundColor?: string;
  glassOpacity?: number;
  borderRadius?: number;
  padding?: number;
  titleColor?: string;
  bodyColor?: string;
  hoverLift?: number;
  backgroundBlur?: number;
  strokeSize?: number;
  strokeColor?: string;
  shineColor?: string;
  boxWidth?: number | string;
  boxHeight?: number | string;
  className?: string;
}

export const AppleGlassStack: React.FC<AppleGlassStackProps> = ({
  items,
  direction = "horizontal",
  gap = 16,
  containerPadding = 0,
  backgroundColor = "rgba(15, 23, 42, 0.75)",
  glassOpacity = 0.85,
  borderRadius = 20,
  padding = 24,
  titleColor = "#FFFFFF",
  bodyColor = "rgba(203, 213, 225, 0.85)",
  hoverLift = 8,
  backgroundBlur = 20,
  strokeSize = 1,
  strokeColor = "rgba(255, 255, 255, 0.15)",
  shineColor = "rgba(255, 255, 255, 0.25)",
  boxWidth,
  boxHeight,
  className,
}) => {
  return (
    <div
      className={cn("w-full flex flex-wrap", className)}
      style={{
        flexDirection: direction === "vertical" ? "column" : "row",
        gap: `${gap}px`,
        padding: `${containerPadding}px`,
      }}
    >
      {items.map((item, index) => (
        <AppleGlassCard
          key={index}
          hoverLift={hoverLift}
          backgroundBlur={backgroundBlur}
          glassOpacity={glassOpacity}
          backgroundColor={backgroundColor}
          strokeColor={strokeColor}
          strokeSize={strokeSize}
          shineColor={shineColor}
          borderRadius={borderRadius}
          style={{
            width: boxWidth ? (typeof boxWidth === "number" ? `${boxWidth}px` : boxWidth) : "100%",
            minHeight: boxHeight ? (typeof boxHeight === "number" ? `${boxHeight}px` : boxHeight) : undefined,
          }}
        >
          {item.backgroundImage && (
            <div
              className="absolute inset-0 bg-cover bg-center rounded-[inherit] opacity-20 pointer-events-none"
              style={{ backgroundImage: `url(${item.backgroundImage.src})` }}
              role="img"
              aria-label={item.backgroundImage.alt}
            />
          )}
          <div
            className="flex flex-col justify-center items-start text-left gap-2.5 h-full"
            style={{ padding: `${padding}px` }}
          >
            <div className="flex items-center justify-between w-full">
              {item.icon && <div className="text-blue-400">{item.icon}</div>}
              {item.badge && (
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                  {item.badge}
                </span>
              )}
            </div>
            <h3
              className="font-display font-bold text-lg tracking-tight"
              style={{ color: titleColor }}
            >
              {item.title}
            </h3>
            <p
              className="text-xs leading-relaxed font-sans"
              style={{ color: bodyColor }}
            >
              {item.body}
            </p>
          </div>
        </AppleGlassCard>
      ))}
    </div>
  );
};

/**
 * LiquidCard enhanced with Apple Liquid Glass aesthetic & shine
 */
export function LiquidCard({
  className,
  enableTilt = false,
  enableShine = true,
  borderRadius = 16,
  ...props
}: AppleGlassCardProps) {
  return (
    <AppleGlassCard
      className={cn("p-6", className)}
      enableTilt={enableTilt}
      enableShine={enableShine}
      borderRadius={borderRadius}
      {...props}
    />
  );
}

export function Card({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <AppleGlassCard
      enableTilt={false}
      enableShine={true}
      className={cn("p-6", className)}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        "@container/card-header grid auto-rows-min grid-rows-[auto_auto] items-start gap-1.5 has-data-[slot=card-action]:grid-cols-[1fr_auto] [.border-b]:pb-6",
        className
      )}
      {...props}
    />
  );
}

export function CardTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-title"
      className={cn("font-display leading-none font-bold text-white text-base tracking-tight", className)}
      {...props}
    />
  );
}

export function CardDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-description"
      className={cn("text-slate-400 text-xs font-sans", className)}
      {...props}
    />
  );
}

export function CardAction({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-action"
      className={cn(
        "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
        className
      )}
      {...props}
    />
  );
}

export function CardContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-content"
      className={cn("text-sm font-sans", className)}
      {...props}
    />
  );
}

export function CardFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-footer"
      className={cn("flex items-center [.border-t]:pt-6", className)}
      {...props}
    />
  );
}
