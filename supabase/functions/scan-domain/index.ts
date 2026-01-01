import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ScanResult {
  domain: string;
  timestamp: string;
  databases: DatabaseInfo[];
  endpoints: EndpointInfo[];
  error?: string;
}

interface DatabaseInfo {
  name: string;
  stores: StoreInfo[];
}

interface StoreInfo {
  name: string;
  recordCount: number;
  suspectedUserData: UserDataRecord[];
}

interface UserDataRecord {
  key: string;
  value: string;
  valueLength: number;
  detectedPatterns: string[];
}

interface EndpointInfo {
  url: string;
  method: string;
  parameters: string[];
}

// Detect patterns in data values
function detectPatterns(value: string): string[] {
  const patterns: string[] = [];
  
  if (/^[A-Za-z0-9+/=]+$/.test(value) && value.length % 4 === 0) {
    patterns.push('base64_encoded');
  }
  if (/^[0-9a-fA-F]+$/.test(value)) {
    patterns.push('hex_encoded');
  }
  if (/[a-z]+[A-Z]+[0-9]+/.test(value) || /[A-Z]+[a-z]+[0-9]+/.test(value)) {
    patterns.push('mixed_alphanumeric');
  }
  if (/@/.test(value) && /\./.test(value)) {
    patterns.push('email_pattern');
  }
  if (/^\+?[0-9\-\s]+$/.test(value) && value.length >= 10) {
    patterns.push('phone_pattern');
  }
  if (/_/.test(value)) {
    patterns.push('underscore_separated');
  }
  if (/-/.test(value)) {
    patterns.push('dash_separated');
  }
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value)) {
    patterns.push('uuid');
  }
  if (/^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    patterns.push('jwt_token');
  }
  
  return patterns.length > 0 ? patterns : ['unknown'];
}

// Parse the scraped content to extract potential IndexedDB-like data
function extractDatabaseInfo(markdown: string, html: string): DatabaseInfo[] {
  const databases: DatabaseInfo[] = [];
  
  // Look for JavaScript that references IndexedDB
  const idbPatterns = [
    /indexedDB\.open\(['"]([^'"]+)['"]/gi,
    /createObjectStore\(['"]([^'"]+)['"]/gi,
    /\.objectStore\(['"]([^'"]+)['"]/gi,
    /localStorage\.setItem\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]\)/gi,
    /sessionStorage\.setItem\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]\)/gi,
  ];
  
  const foundDbs = new Map<string, StoreInfo[]>();
  
  // Extract database names from patterns
  for (const pattern of idbPatterns) {
    let match;
    while ((match = pattern.exec(html)) !== null) {
      const dbName = match[1] || 'LocalStorage';
      if (!foundDbs.has(dbName)) {
        foundDbs.set(dbName, []);
      }
    }
  }
  
  // Extract potential user data from the page content
  const dataPatterns = [
    /"user[_-]?id":\s*"([^"]+)"/gi,
    /"email":\s*"([^"]+)"/gi,
    /"token":\s*"([^"]+)"/gi,
    /"session[_-]?id":\s*"([^"]+)"/gi,
    /"auth[_-]?token":\s*"([^"]+)"/gi,
    /data-user-id="([^"]+)"/gi,
    /data-session="([^"]+)"/gi,
  ];
  
  const suspectedData: UserDataRecord[] = [];
  
  for (const pattern of dataPatterns) {
    let match;
    while ((match = pattern.exec(html)) !== null) {
      const value = match[1];
      if (value && value.length > 8) {
        suspectedData.push({
          key: pattern.source.split('"')[1] || 'unknown_key',
          value: value.substring(0, 50) + (value.length > 50 ? '...' : ''),
          valueLength: value.length,
          detectedPatterns: detectPatterns(value),
        });
      }
    }
  }
  
  // If we found data but no explicit DB names, create a default one
  if (suspectedData.length > 0 && foundDbs.size === 0) {
    foundDbs.set('WebStorage', []);
  }
  
  // Add suspected data to the first store
  for (const [dbName, stores] of foundDbs) {
    databases.push({
      name: dbName,
      stores: stores.length > 0 ? stores : [{
        name: 'default_store',
        recordCount: suspectedData.length,
        suspectedUserData: suspectedData,
      }],
    });
  }
  
  return databases;
}

// Extract endpoints from the page
function extractEndpoints(html: string, baseUrl: string): EndpointInfo[] {
  const endpoints: EndpointInfo[] = [];
  const seenUrls = new Set<string>();
  
  // Find API endpoints
  const apiPatterns = [
    /fetch\(['"]([^'"]+)['"]/gi,
    /axios\.[a-z]+\(['"]([^'"]+)['"]/gi,
    /\.ajax\(\{[^}]*url:\s*['"]([^'"]+)['"]/gi,
    /href="([^"]*api[^"]*)"/gi,
    /action="([^"]+)"/gi,
    /src="([^"]+\.js[^"]*)"/gi,
  ];
  
  for (const pattern of apiPatterns) {
    let match;
    while ((match = pattern.exec(html)) !== null) {
      let url = match[1];
      if (url && !seenUrls.has(url) && !url.startsWith('data:')) {
        seenUrls.add(url);
        
        // Extract query parameters
        const params: string[] = [];
        const urlParts = url.split('?');
        if (urlParts.length > 1) {
          const queryString = urlParts[1];
          const paramMatches = queryString.match(/([^&=]+)=/g);
          if (paramMatches) {
            params.push(...paramMatches.map(p => p.replace('=', '')));
          }
        }
        
        endpoints.push({
          url: url,
          method: 'GET',
          parameters: params,
        });
      }
    }
  }
  
  return endpoints.slice(0, 50); // Limit to 50 endpoints
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain } = await req.json();

    if (!domain) {
      return new Response(
        JSON.stringify({ success: false, error: 'Domain is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const apiKey = Deno.env.get('FIRECRAWL_API_KEY');
    if (!apiKey) {
      console.error('FIRECRAWL_API_KEY not configured');
      return new Response(
        JSON.stringify({ success: false, error: 'Firecrawl connector not configured. Please connect Firecrawl in settings.' }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Format URL
    let formattedUrl = domain.trim();
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
      formattedUrl = `https://${formattedUrl}`;
    }

    console.log('Scanning domain:', formattedUrl);

    // First, scrape the main page
    const scrapeResponse = await fetch('https://api.firecrawl.dev/v1/scrape', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: formattedUrl,
        formats: ['markdown', 'html', 'links'],
        onlyMainContent: false,
        waitFor: 3000, // Wait for JS to execute
      }),
    });

    const scrapeData = await scrapeResponse.json();

    if (!scrapeResponse.ok) {
      console.error('Firecrawl scrape error:', scrapeData);
      return new Response(
        JSON.stringify({ 
          success: false, 
          error: scrapeData.error || `Failed to scrape ${domain}` 
        }),
        { status: scrapeResponse.status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const markdown = scrapeData.data?.markdown || scrapeData.markdown || '';
    const html = scrapeData.data?.html || scrapeData.html || '';
    const links = scrapeData.data?.links || scrapeData.links || [];

    // Extract database info and endpoints
    const databases = extractDatabaseInfo(markdown, html);
    const endpoints = extractEndpoints(html, formattedUrl);

    // Also try to map the site for more endpoints
    let additionalLinks: string[] = [];
    try {
      const mapResponse = await fetch('https://api.firecrawl.dev/v1/map', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: formattedUrl,
          limit: 100,
          includeSubdomains: false,
        }),
      });

      if (mapResponse.ok) {
        const mapData = await mapResponse.json();
        additionalLinks = mapData.links || [];
        console.log(`Found ${additionalLinks.length} additional URLs from map`);
      }
    } catch (mapError) {
      console.log('Map request failed, continuing with scrape data only');
    }

    // Add mapped links as endpoints
    for (const link of additionalLinks.slice(0, 30)) {
      if (!endpoints.some(e => e.url === link)) {
        endpoints.push({
          url: link,
          method: 'GET',
          parameters: [],
        });
      }
    }

    const result: ScanResult = {
      domain: domain,
      timestamp: new Date().toISOString(),
      databases,
      endpoints,
    };

    console.log(`Scan complete for ${domain}: ${databases.length} databases, ${endpoints.length} endpoints`);

    return new Response(
      JSON.stringify({ success: true, data: result }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('Error scanning domain:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    return new Response(
      JSON.stringify({ success: false, error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
