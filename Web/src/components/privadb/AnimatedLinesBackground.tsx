import React from "react";

const AnimatedLinesBackground: React.FC = () => (
  <svg
    className="fixed inset-0 w-full h-full pointer-events-none z-[-1] animated-lines-bg"
    style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', zIndex: 0 }}
    width="100%"
    height="100%"
    viewBox="0 0 1920 1080"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    {[...Array(12)].map((_, i) => (
      <g key={i}>
        <rect
          x={i * 160 + 40}
          y="0"
          width="2"
          height="1080"
          rx="1"
          fill="currentColor"
          className="text-primary/20 dark:text-primary/10"
          opacity="0.15"
        >
          <animate
            attributeName="y"
            values="-200;1080"
            dur={`${6 + i * 0.7}s`}
            repeatCount="indefinite"
            keyTimes="0;1"
          />
        </rect>
      </g>
    ))}
    {[...Array(6)].map((_, i) => (
      <g key={i + 20}>
        <rect
          x="0"
          y={i * 180 + 60}
          width="1920"
          height="2"
          rx="1"
          fill="#f3f4f6"
          opacity="0.06"
        >
          <animate
            attributeName="x"
            values="-1920;1920"
            dur={`${10 + i * 1.2}s`}
            repeatCount="indefinite"
            keyTimes="0;1"
          />
        </rect>
      </g>
    ))}
  </svg>
);

export default AnimatedLinesBackground;
