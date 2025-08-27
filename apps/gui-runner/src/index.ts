#!/usr/bin/env node

// Browser management imports
import { chromium, Browser, Page } from 'playwright';

// Global variables
let attackStatus = {
  scenario: 'No active scenario',
  step: 'Idle',
  progress: 0,
  findings: 0,
  requests: 0,
  status: 'idle',
  lastUpdate: new Date()
};

let autoRefreshInterval: NodeJS.Timeout | null = null;

// Browser management
let browser: Browser | null = null;
let page: Page | null = null;

// Start the GUI server
console.log('🚀 Starting OWASPAttackSimulator GUI Runner...');

// Initialize browser on startup
async function initializeBrowser() {
  try {
    console.log('🌐 Initializing browser on startup...');
    
    // Try different browser paths
    const possiblePaths = [
      process.env.CHROME_BIN,
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
      '/usr/bin/google-chrome',
      '/usr/bin/chrome',
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', // macOS
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', // Windows
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe' // Windows 32-bit
    ].filter(Boolean);
    
    let browserLaunched = false;
    let lastError = null;
    
    for (const path of possiblePaths) {
      try {
        console.log(`🔍 Trying browser path: ${path}`);
        browser = await chromium.launch({
          headless: true,
          executablePath: path
        });
        console.log(`✅ Browser launched successfully with path: ${path}`);
        browserLaunched = true;
        break;
      } catch (pathError) {
        console.log(`❌ Failed with path ${path}:`, (pathError as Error).message);
        lastError = pathError;
      }
    }
    
    if (!browserLaunched) {
      // Try without specifying executable path (let Playwright find it)
      try {
        console.log('🔍 Trying without executable path (auto-detect)...');
        browser = await chromium.launch({
          headless: true
        });
        console.log('✅ Browser launched successfully with auto-detection');
      } catch (autoError) {
        console.error('❌ All browser launch attempts failed');
        throw lastError || autoError;
      }
    }
    
    // Create initial page
    if (browser) {
      page = await browser.newPage();
      console.log('✅ Initial page created');
      
      // Navigate to a blank page instead of test page
      await page.goto('about:blank');
      console.log('✅ Initial blank page loaded');
    }
    
  } catch (error) {
    console.error('❌ Failed to initialize browser on startup:', error);
    // Don't throw - let the application continue without browser
  }
}

// Initialize browser in background
initializeBrowser();

// Create HTTP server
const http = require('http');
const server = http.createServer((req: any, res: any) => {
  const { method, url } = req;
  const path = new URL(url, `http://${req.headers.host}`).pathname;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (path === '/') {
    // Main dashboard page
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
<!DOCTYPE html>
<html>
<head>
    <title>OWASPAttackSimulator - Attack Dashboard</title>
    <meta charset="utf-8">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@300;400;500;700&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        'ubuntu': ['Ubuntu', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    <style>
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            margin-left: 8px;
        }
        .status-badge.streaming {
            background: #27ae60;
            color: white;
            animation: pulse 1s infinite;
        }
        .status-badge.attack {
            background: #e74c3c;
            color: white;
            animation: pulse 1s infinite;
        }
        .status-badge.ready {
            background: #3498db;
            color: white;
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen font-ubuntu">
    <div class="max-w-7xl mx-auto px-4 py-8">
        <!-- Header -->
        <div class="bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl p-8 mb-8 shadow-lg">
            <div class="flex items-center space-x-4">
                <div class="bg-white/20 p-3 rounded-full">
                    <svg class="w-8 h-8" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"></path>
                    </svg>
        </div>
                <div>
                    <h1 class="text-3xl font-bold">OWASPAttackSimulator</h1>
                    <p class="text-blue-100">Real-time security testing dashboard</p>
            </div>
            </div>
        </div>

        <!-- Attack Status Card -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl font-semibold text-gray-800 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    Attack Status
                </h2>
                <span id="status" class="px-3 py-1 rounded-full text-xs font-medium ${attackStatus.status === 'running' ? 'bg-red-100 text-red-800 animate-pulse' : attackStatus.status === 'completed' ? 'bg-gradient-to-r from-green-400 to-emerald-500 text-white shadow-lg' : attackStatus.status === 'failed' || (attackStatus.step && attackStatus.step.includes('Failed')) ? 'bg-red-500 text-white' : 'bg-gray-100 text-gray-800'}">${attackStatus.status === 'completed' ? '✅ COMPLETED' : attackStatus.status === 'failed' || (attackStatus.step && attackStatus.step.includes('Failed')) ? '❌ FAILED' : attackStatus.status.toUpperCase()}</span>
                </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div class="bg-gray-50 rounded-lg p-4">
                    <div class="text-sm text-gray-600 mb-1">Scenario</div>
                    <div id="scenario-name" class="font-medium text-gray-900">${attackStatus.scenario}</div>
                </div>
                <div class="bg-gray-50 rounded-lg p-4">
                    <div class="text-sm text-gray-600 mb-1">Current Step</div>
                    <div id="current-step" class="font-medium text-gray-900">${attackStatus.step}</div>
                </div>
                <div class="bg-gray-50 rounded-lg p-4">
                    <div class="text-sm text-gray-600 mb-1">Progress</div>
                    <div class="flex items-center">
                        <div class="flex-1 bg-gray-200 rounded-full h-2 mr-2">
                            <div id="progress-bar" class="bg-blue-500 h-2 rounded-full transition-all duration-300" style="width: ${attackStatus.progress}%"></div>
                        </div>
                        <span id="progress-text" class="text-sm font-medium text-gray-900">${attackStatus.progress}%</span>
                    </div>
            </div>
        </div>

            <div class="text-xs text-gray-500">
                Last Update: <span id="last-update">${attackStatus.lastUpdate.toLocaleString()}</span>
            </div>
                </div>

        <!-- Live Browser Card -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl font-semibold text-gray-800 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"></path>
                    </svg>
                    Live Browser
                    <span class="status-badge ready">READY</span>
                </h2>
            </div>
            
            <div id="browser-container" class="bg-gray-50 rounded-lg border-2 border-dashed border-gray-300 min-h-[400px] flex items-center justify-center">
                <div class="text-center text-gray-500">
                    <svg class="w-12 h-12 mx-auto mb-4 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"></path>
                    </svg>
                    <p class="text-sm">Browser stream will appear here</p>
                </div>
            </div>
        </div>

        <!-- Live Logs Card -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl font-semibold text-gray-800 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-purple-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"></path>
                    </svg>
                    Live Logs
                </h2>
                <button onclick="location.reload()" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 flex items-center">
                    <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd"></path>
                    </svg>
                    Refresh
                </button>
            </div>
            
            <div id="logs" class="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm h-64 overflow-y-auto">
[${new Date().toISOString()}] GUI Runner started successfully<br>
[${new Date().toISOString()}] HTTP server listening on port 3000<br>
[${new Date().toISOString()}] gRPC broker ready on port 50051<br>
[${new Date().toISOString()}] Waiting for attack scenarios...<br>
            </div>
        </div>
    </div>

    <script>
        let browserConnected = false;
        let browserProcess = null;
        let autoRefreshInterval = null;

        // Browser streaming functions
        function startScreenshotStreaming() {
            const container = document.getElementById('browser-container');
            container.innerHTML = '<img id="screenshot" src="/api/browser/screenshot" style="width: 100%; height: 100%; object-fit: cover;" onload="updateStreamingStatus()" onerror="handleStreamingError()" />';
            
            // Auto-refresh screenshot every 2 seconds for smooth streaming
            setInterval(() => {
                const img = document.getElementById('screenshot');
                if (img) {
                    img.src = '/api/browser/screenshot?' + Date.now();
                }
            }, 2000);
        }
        
        function startScreenshotStreaming() {
            const container = document.getElementById('browser-container');
            container.innerHTML = '<img id="screenshot" src="/api/browser/screenshot" style="width: 100%; height: 100%; object-fit: cover; border-radius: 8px;" onload="updateStreamingStatus()" onerror="handleStreamingError()" />';
            
            // Auto-refresh screenshot every 2 seconds for smooth streaming
            setInterval(() => {
                const img = document.getElementById('screenshot');
                if (img) {
                    img.src = '/api/browser/screenshot?' + Date.now();
                }
            }, 2000);
        }
        
        function updateStreamingStatus() {
            const badge = document.querySelector('.status-badge');
            if (badge) {
                badge.className = 'status-badge streaming';
                badge.textContent = 'LIVE';
            }
        }
        
        function handleStreamingError() {
            const badge = document.querySelector('.status-badge');
            if (badge) {
                badge.className = 'status-badge';
                badge.textContent = 'ERROR';
                badge.style.background = '#e74c3c';
            }
            
            setTimeout(() => {
                const img = document.getElementById('screenshot');
                if (img) {
                    img.src = '/api/browser/screenshot?' + Date.now();
                }
            }, 3000);
        }

        function removeBrowser() {
            const container = document.getElementById('browser-container');
            container.innerHTML = '<div class="browser-placeholder"></div>';
            
            setTimeout(() => {
                startScreenshotStreaming();
            }, 3000); // Wait 3 seconds for browser to start
        }

        // Auto-refresh status every 2 seconds
        setInterval(async () => {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();
                
                // Update attack status
                document.getElementById('scenario-name').textContent = status.scenario;
                document.getElementById('current-step').textContent = status.step;
                const isFailed = status.status === 'failed' || (status.step && status.step.includes('Failed'));
                document.getElementById('status').textContent = status.status === 'completed' ? '✅ COMPLETED' : isFailed ? '❌ FAILED' : status.status.toUpperCase();
                document.getElementById('status').className = 'px-3 py-1 rounded-full text-xs font-medium ' + (status.status === 'running' ? 'bg-red-100 text-red-800 animate-pulse' : status.status === 'completed' ? 'bg-gradient-to-r from-green-400 to-emerald-500 text-white shadow-lg' : isFailed ? 'bg-red-500 text-white' : 'bg-gray-100 text-gray-800');
                document.getElementById('progress-bar').style.width = status.progress + '%';
                document.getElementById('progress-text').textContent = status.progress;

                document.getElementById('last-update').textContent = new Date(status.lastUpdate).toLocaleString();
                
                // Auto-start screenshot streaming if attack is running and browser is not streaming
                if (status.status === 'running' && !document.querySelector('#screenshot')) {
                    setTimeout(() => {
                        startScreenshotStreaming();
                    }, 1000);
                }
            } catch (error) {
                console.error('Error updating status:', error);
            }
        }, 2000);
    </script>
</body>
</html>
    `);
  } else if (path === '/api/browser/screenshot' && req.method === 'GET') {
    // Take actual screenshot from browser
    console.log('📸 Taking screenshot...');
    
    (async () => {
      try {
        // Check if browser and page are ready
        if (!browser || !page) {
          console.log('⏳ Browser not ready yet, using fallback image');
          // Return fallback image if browser not ready
          const fallbackImage = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
          res.writeHead(200, { 
            'Content-Type': 'image/png',
            'Content-Length': fallbackImage.length.toString(),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
          });
          res.end(fallbackImage);
          return;
        }
        
        // Take screenshot
        console.log('📸 Taking screenshot...');
        const screenshot = await page.screenshot({
          type: 'png',
          fullPage: false
        });
        
        console.log('✅ Screenshot taken successfully, size:', screenshot.length, 'bytes');
    
    res.writeHead(200, { 
      'Content-Type': 'image/png',
          'Content-Length': screenshot.length.toString(),
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
        res.end(screenshot);
      } catch (error) {
        console.error('❌ Error taking screenshot:', error);
        
        // Create a proper error image with text instead of 1x1 pixel
        try {
          // Create a simple HTML page with error message
          const errorHtml = `
            <html>
              <head>
                <style>
                  body { 
                    font-family: Arial, sans-serif; 
                    background: #f0f0f0; 
                    margin: 0; 
                    padding: 40px; 
                    text-align: center; 
                  }
                  .error-box { 
                    background: white; 
                    border: 2px solid #e74c3c; 
                    border-radius: 8px; 
                    padding: 30px; 
                    max-width: 500px; 
                    margin: 0 auto; 
                  }
                  .error-icon { font-size: 48px; margin-bottom: 20px; }
                  .error-title { color: #e74c3c; font-size: 24px; margin-bottom: 15px; }
                  .error-message { color: #666; font-size: 16px; }
                </style>
              </head>
              <body>
                <div class="error-box">
                  <div class="error-icon">📸</div>
                  <div class="error-title">Screenshot Error</div>
                  <div class="error-message">Browser screenshot failed to load.<br>Error: ${(error as Error).message}</div>
                </div>
              </body>
            </html>
          `;
          
          // Launch a temporary browser to create the error image
          const tempBrowser = await chromium.launch({
            headless: true
          });
          
          const tempPage = await tempBrowser.newPage();
          await tempPage.setContent(errorHtml);
          
          const errorScreenshot = await tempPage.screenshot({
            type: 'png',
            fullPage: false
          });
          
          await tempBrowser.close();
          
          res.writeHead(200, { 
            'Content-Type': 'image/png',
            'Content-Length': errorScreenshot.length.toString(),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
          });
          res.end(errorScreenshot);
          
        } catch (fallbackError) {
          console.error('❌ Even fallback failed:', fallbackError);
          
          // Ultimate fallback - 1x1 transparent pixel
          const fallbackImage = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
          
          res.writeHead(200, { 
            'Content-Type': 'image/png',
            'Content-Length': fallbackImage.length.toString(),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
          });
          res.end(fallbackImage);
        }
      }
    })();
  } else if (path === '/api/browser/screenshot' && req.method === 'POST') {
    // Take screenshot via POST request
    console.log('📸 Taking screenshot via POST...');
    
    (async () => {
      try {
        // Initialize browser once if not already done
        if (!browser) {
          console.log('🌐 Initializing browser...');
          try {
            // Try different browser paths
            const possiblePaths = [
              process.env.CHROME_BIN,
              '/usr/bin/chromium-browser',
              '/usr/bin/chromium',
              '/usr/bin/google-chrome',
              '/usr/bin/chrome',
              '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', // macOS
              'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', // Windows
              'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe' // Windows 32-bit
            ].filter(Boolean);
            
            let browserLaunched = false;
            let lastError = null;
            
            for (const path of possiblePaths) {
              try {
                console.log(`🔍 Trying browser path: ${path}`);
                browser = await chromium.launch({
                  headless: true,
                  executablePath: path
                });
                console.log(`✅ Browser launched successfully with path: ${path}`);
                browserLaunched = true;
                break;
              } catch (pathError) {
                console.log(`❌ Failed with path ${path}:`, (pathError as Error).message);
                lastError = pathError;
              }
            }
            
            if (!browserLaunched) {
              // Try without specifying executable path (let Playwright find it)
              try {
                console.log('🔍 Trying without executable path (auto-detect)...');
                browser = await chromium.launch({
                  headless: true
                });
                console.log('✅ Browser launched successfully with auto-detection');
              } catch (autoError) {
                console.error('❌ All browser launch attempts failed');
                throw lastError || autoError;
              }
            }
          } catch (browserError) {
            console.error('❌ Failed to launch browser:', browserError);
            throw browserError;
          }
        }
        
        // Create or reuse page
        if (!page) {
          
          if (!browser) {
            throw new Error('Browser is null after launch attempt');
          }
          
          page = await browser.newPage();
          
          // Navigate to a blank page
          await page.goto('about:blank');
        }
        
        // Take screenshot
        const screenshot = await page.screenshot({
          type: 'png',
          fullPage: false
        });
        
        console.log('✅ Screenshot taken successfully via POST, size:', screenshot.length, 'bytes');
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          success: true, 
          message: 'Screenshot taken successfully',
          size: screenshot.length
        }));
      } catch (error) {
        console.error('❌ Error taking screenshot via POST:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          success: false, 
          error: (error as Error).message 
        }));
      }
    })();
  } else if (path === '/api/status') {
    console.log('🔍 API Request - Path:', path, 'Method:', req.method, 'URL:', req.url);
    // API endpoint for status
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(attackStatus));
  } else if (path === '/api/attack/start' && req.method === 'POST') {
    // Start real attack from CLI
    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      (async () => {
        try {
          const attackData = JSON.parse(body);
          console.log('Real attack started from CLI:', attackData);
          
          attackStatus = {
            scenario: attackData.scenario || 'CLI Attack',
            step: `Initializing ${attackData.method || 'attack'}`,
            progress: 0,
            findings: 0,
            requests: 0,
            status: 'running',
            lastUpdate: new Date()
          };
          
          // Auto-start browser if not running
          if (!browser) {
            console.log('🌐 Auto-starting browser for attack...');
            try {
              browser = await chromium.launch({
                headless: true,
                executablePath: process.env.CHROME_BIN || '/usr/bin/chromium-browser',
                args: [
                  '--no-sandbox',
                  '--disable-setuid-sandbox',
                  '--disable-dev-shm-usage',
                  '--disable-accelerated-2d-canvas',
                  '--no-first-run',
                  '--no-zygote',
                  '--disable-gpu',
                  '--disable-web-security',
                  '--disable-features=VizDisplayCompositor',
                  '--remote-debugging-port=9222',
                  '--remote-debugging-address=0.0.0.0'
                ]
              });
              
              page = await browser.newPage();
              console.log('✅ Browser auto-started successfully');
            } catch (error) {
              console.error('❌ Failed to auto-start browser:', error);
            }
          }
          
          console.log('Updated attack status:', attackStatus);
          
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, attackId: Date.now() }));
        } catch (error) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
      })();
    });
    return;
  } else if (path === '/api/browser/start' && req.method === 'POST') {
    // Start browser with remote debugging
    console.log('Starting browser with remote debugging...');
    
    (async () => {
      try {
        if (browser) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            success: true, 
                    debugUrl: 'http://simulation-gui:9222',
          message: 'Browser already running'
          }));
          return;
        }

        // Launch browser with remote debugging for Docker
        browser = await chromium.launch({
          headless: false, // Cloudflare için headless: false gerekli
          executablePath: process.env.CHROME_BIN || '/usr/bin/chromium-browser',
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu',
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--remote-debugging-port=9222',
            '--remote-debugging-address=0.0.0.0',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--window-size=1920,1080',
            '--start-maximized',
            '--disable-blink-features=AutomationControlled',
            '--disable-extensions-except=/path/to/extension',
            '--load-extension=/path/to/extension'
          ]
        });

        // Create a new page
        page = await browser.newPage();
        
        // Don't navigate initially, just start browser
        console.log('Browser page created successfully');

        console.log('Browser started successfully');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          success: true, 
          debugUrl: 'http://simulation-gui:9222',
          message: 'Browser started with remote debugging'
        }));
      } catch (error) {
        console.error('Error starting browser:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: (error as Error).message }));
      }
    })();
  } else if (path === '/api/browser/stop' && req.method === 'POST') {
    // Stop browser
    console.log('Stopping browser...');
    
    (async () => {
      try {
        if (page) {
          await page.close();
          page = null;
        }
        
        if (browser) {
          await browser.close();
          browser = null;
        }
        
        console.log('Browser stopped successfully');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'Browser stopped' }));
      } catch (error) {
        console.error('Error stopping browser:', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: (error as Error).message }));
      }
    })();
  } else if (path === '/api/browser/navigate' && req.method === 'POST') {
    // Navigate to URL
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', () => {
      (async () => {
        try {
          const data = JSON.parse(body);
          console.log('Navigating to:', data.url);
          
          if (!page) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Browser not running' }));
            return;
          }
          
          await page.goto(data.url);
          
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, message: `Navigated to ${data.url}` }));
        } catch (error) {
          console.error('Error navigating:', error);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: (error as Error).message }));
        }
      })();
    });
    return;

  } else if (path === '/api/browser/action' && req.method === 'POST') {
    // Browser action (navigate, fill, click) with retry mechanism
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', () => {
      (async () => {
        try {
          const data = JSON.parse(body);
          console.log('Browser action:', data);
          
          if (!page) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Browser not running' }));
            return;
          }
          
          // Retry mechanism for browser actions
          const maxRetries = 3;
          let lastError: Error | null = null;
          
          for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
          switch (data.action) {
            case 'navigate':
                  console.log(`🚀 Starting navigation to: ${data.url}`);
                  
                  // Use wait parameter from scenario if provided, otherwise default to domcontentloaded
                  const waitUntil = data.wait || 'domcontentloaded';
                  console.log(`⏳ Wait parameter: ${data.wait}, Using: ${waitUntil}`);
                  
                  await page.goto(data.url, { waitUntil: waitUntil, timeout: 45000 });
                  
                  // Get current URL and title for verification
                  const currentUrl = page.url();
                  const currentTitle = await page.title();
                  console.log(`📍 Current URL: ${currentUrl}`);
                  console.log(`📄 Current Title: ${currentTitle}`);
                  
                  // Quick check for Cloudflare
                  try {
                    const cloudflareCheckbox = await page.$('input[type="checkbox"]');
                    if (cloudflareCheckbox) {
                      console.log(`🔍 Found Cloudflare checkbox, clicking...`);
                      await cloudflareCheckbox.click();
                      await page.waitForTimeout(1000);
                      console.log(`✅ Cloudflare checkbox clicked`);
                    }
                  } catch (e) {
                    // No Cloudflare, continue
                  }
                  
                  // Verify navigation was successful
                  if (currentUrl === data.url || currentUrl.includes(new URL(data.url).hostname)) {
                    console.log(`✅ Navigation successful: ${data.url} (Attempt ${attempt}/${maxRetries})`);
                  } else {
                    console.log(`⚠️ Navigation may have failed. Expected: ${data.url}, Got: ${currentUrl}`);
                  }
              break;
              
            case 'fill':
                  // Try multiple selectors for better element finding
                  const selectorName = data.selector.replace('#', '').replace('.', '');
                  const fillSelectors = [
                    data.selector,
                    `input[name="${selectorName}"]`,
                    `input[name="username"]`,
                    `input[name="user"]`,
                    `input[name="email"]`,
                    `input[type="text"]`,
                    `input[type="email"]`,
                    `input[placeholder*="username"]`,
                    `input[placeholder*="user"]`,
                    `input[placeholder*="email"]`,
                    `input[placeholder*="login"]`,
                    `input[type="password"]`,
                    `input[name="password"]`,
                    `input[name="pass"]`,
                    `input[placeholder*="password"]`,
                    `input[placeholder*="pass"]`
                  ];
                  
                  let fillSuccess = false;
                  for (const selector of fillSelectors) {
                    try {
                      // Wait longer for elements to appear
                      await page.waitForSelector(selector, { timeout: 10000, state: 'visible' });
                      // Additional wait to ensure element is ready
                      await page.waitForTimeout(1000);
                      await page.fill(selector, data.value);
                      console.log(`✅ Filled: ${selector} = ${data.value} (Attempt ${attempt}/${maxRetries})`);
                      fillSuccess = true;
                      break;
                    } catch (selectorError) {
                      console.log(`⚠️ Selector ${selector} failed, trying next...`);
                    }
                  }
                  
                  if (!fillSuccess) {
                    throw new Error(`Could not find any fillable element for selector: ${data.selector}`);
                  }
              break;
              
            case 'click':
                  // Try multiple selectors for better element finding
                  const clickSelectors = [
                    data.selector,
                    `button[type="submit"]`,
                    `input[type="submit"]`,
                    `button:contains("Login")`,
                    `button:contains("Submit")`,
                    `input[value*="Login"]`,
                    `input[value*="Submit"]`
                  ];
                  
                  let clickSuccess = false;
                  for (const selector of clickSelectors) {
                    try {
                      // Wait longer for elements to appear
                      await page.waitForSelector(selector, { timeout: 10000, state: 'visible' });
                      // Additional wait to ensure element is ready
                      await page.waitForTimeout(1000);
                      await page.click(selector);
                      console.log(`✅ Clicked: ${selector} (Attempt ${attempt}/${maxRetries})`);
                      clickSuccess = true;
                      break;
                    } catch (selectorError) {
                      console.log(`⚠️ Selector ${selector} failed, trying next...`);
                    }
                  }
                  
                  if (!clickSuccess) {
                    throw new Error(`Could not find any clickable element for selector: ${data.selector}`);
                  }
              break;
              
            default:
              throw new Error(`Unknown action: ${data.action}`);
          }
          
              // If we reach here, action was successful
          res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ 
                success: true, 
                message: `Action ${data.action} completed (Attempt ${attempt}/${maxRetries})`,
                attempt: attempt
              }));
              return;
              
            } catch (error) {
              lastError = error as Error;
              console.log(`❌ Browser action failed (Attempt ${attempt}/${maxRetries}): ${error}`);
              
              if (attempt < maxRetries) {
                console.log(`🔄 Retrying in 2 seconds...`);
                await new Promise(resolve => setTimeout(resolve, 2000));
              }
            }
          }
          
          // If we reach here, all attempts failed
          console.error(`💥 Browser action failed after ${maxRetries} attempts:`, lastError);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            success: false, 
            error: `Action ${data.action} failed after ${maxRetries} attempts: ${lastError?.message}`,
            attempts: maxRetries
          }));
          
        } catch (error) {
          console.error('Error executing browser action:', error);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: (error as Error).message }));
        }
      })();
    });
    return;
  } else if (path === '/api/attack/update' && req.method === 'POST') {
    // Update attack progress from CLI
    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const updateData = JSON.parse(body);
        console.log('Attack progress update:', updateData);
        
        attackStatus = {
          ...attackStatus,
          ...updateData,
          lastUpdate: new Date()
        };
        
        // Preserve scenario name if it exists
        if (attackStatus.scenario && attackStatus.scenario.startsWith('Scenario:')) {
          // Keep the scenario name
        } else if (updateData.scenario) {
          attackStatus.scenario = updateData.scenario;
        }
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  } else if (path === '/health') {
    // Health check endpoint
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    }));
  } else if (path.startsWith('/api/')) {
    console.log('🚨 UNKNOWN API PATH:', path, 'Method:', req.method, 'URL:', req.url);
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('API Not Found: ' + path);
  } else {
    // 404 handler
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🌐 HTTP server listening on port ${PORT}`);
  console.log(`📊 Dashboard available at: http://localhost:${PORT}`);
});

// Start gRPC broker (placeholder)
console.log('🔌 gRPC broker ready on port 50051');



// Keep the process alive
console.log('💓 GUI Runner heartbeat... (1)');
let heartbeatCount = 1;

setInterval(() => {
  heartbeatCount++;
  console.log(`💓 GUI Runner heartbeat... (${heartbeatCount})`);
}, 60000);

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down GUI Runner...');
  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
  }
  server.close(() => {
    console.log('✅ GUI Runner stopped gracefully');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM, shutting down...');
  process.exit(0);
});
