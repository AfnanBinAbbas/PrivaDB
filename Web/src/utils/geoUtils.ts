
/**
 * Utility for mapping domains to approximate world coordinates (SVG context 800x400)
 */

export const DOMAIN_LOCATIONS: Record<string, { x: number, y: number, region: string }> = {
  // US East
  "google.com": { x: 220, y: 150, region: "US East" },
  "doubleclick.net": { x: 225, y: 145, region: "US East" },
  "facebook.com": { x: 215, y: 160, region: "US East" },
  "amazon-adsystem.com": { x: 230, y: 140, region: "US East" },
  "adnxs.com": { x: 235, y: 135, region: "US East" },
  "rubiconproject.com": { x: 240, y: 130, region: "US East" },
  
  // US West
  "google-analytics.com": { x: 150, y: 160, region: "US West" },
  "googletagmanager.com": { x: 155, y: 155, region: "US West" },
  "cloudflare.com": { x: 145, y: 165, region: "US West" },
  
  // Europe
  "criteo.com": { x: 410, y: 120, region: "Europe" },
  "quantserve.com": { x: 400, y: 110, region: "Europe" },
  "hotjar.com": { x: 420, y: 130, region: "Europe" },
  "spotify.com": { x: 430, y: 100, region: "Europe" },
  
  // Asia
  "baidu.com": { x: 650, y: 160, region: "Asia" },
  "alibaba.com": { x: 670, y: 170, region: "Asia" },
  "tiktok.com": { x: 660, y: 180, region: "Asia" },
  "naver.com": { x: 690, y: 150, region: "Asia" },

  // Others
  "default": { x: 400, y: 200, region: "Global" }
};

export const getDomainCoords = (domain: string) => {
  const base = domain.split('.').slice(-2).join('.');
  return DOMAIN_LOCATIONS[base] || DOMAIN_LOCATIONS[domain] || DOMAIN_LOCATIONS["default"];
};

// Simplified World Map paths (low-res for performance and aesthetic)
export const WORLD_PATH = "M114,142l-2,3l-5,0l-5-4l-7,0l-4-5l-4,1l-1,3l1,4l-4,1l-2,5l2,3l4-2l3,2l4,0l3,3l1,6l3,2l1-4l3,2l4-2l1,4l3,1l1-2l5,1l2-4l4,0l3-5l2,0v-4L114,142z M221,232l-1,4l-5,5l-1,5l-3,3l-4,0l-3,3l-3,0l-1,3l-5-1l-3,4l-3-1l-1,3l-6,0l-2,3l-5,0l-2-2l-4,1l-2-3l-4,0l-1-4l3-4l0-3l4-3l0-4l3,0l1-3l3,0l2-4l3,0l1-5l5,0l5-4l1,3l5,1l1-3l4,1l2,3l5-1l2,4l1,5L221,232z M616,134l-3,2l-4-1l-3,3l-5,0l-3,4l-3,0l-3,3l-4,0l-1,4l-4,0l-3,4l-1,6l-7,3l-6,6l-4,8l-1,4l-4,0l-5,4h-4l-4-2l-3,2l-3-4l0-3l-4-4l0-4l1-3l2-3l1-5l2-3l4-3l2-6l5-3l1-4l5,0l1-5h4l5,3l5-1l1-4l2-2l5,1l4-3l3,1l5-4l4,1l3-2l4,1L616,134z";
