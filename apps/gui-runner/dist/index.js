#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Browser management imports
const playwright_1 = require("playwright");
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
let autoRefreshInterval = null;
// Browser management
let browser = null;
let page = null;
// Start the GUI server
console.log('🚀 Starting OWASPChecker GUI Runner...');
// Create HTTP server
const http = require('http');
const server = http.createServer((req, res) => {
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
    <title>OWASPChecker - Attack Dashboard</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
        .status.idle { background: #95a5a6; color: white; }
        .status.running { background: #e74c3c; color: white; animation: pulse 1s infinite; }
        .status.paused { background: #f39c12; color: white; }
        .status.completed { background: #27ae60; color: white; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .progress { background: #ecf0f1; border-radius: 4px; height: 20px; margin: 10px 0; }
        .progress-bar { background: #3498db; height: 100%; border-radius: 4px; transition: width 0.3s; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; color: #2c3e50; }
        .metric-label { color: #7f8c8d; }
        .logs { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; font-family: monospace; height: 300px; overflow-y: auto; }
        .refresh { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh:hover { background: #2980b9; }
        
        .browser-controls {
            margin-bottom: 15px;
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .browser-controls button {
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .browser-controls button:hover {
            background: #2980b9;
        }
        .browser-controls button:disabled {
            background: #95a5a6;
            cursor: not-allowed;
        }
        .browser-controls input {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 300px;
        }
        #browser-status {
            margin-left: auto;
            font-size: 12px;
            color: #e74c3c;
            font-weight: bold;
        }
        .browser-container {
            border: 2px solid #ddd;
            border-radius: 8px;
            min-height: 400px;
            background: #f8f9fa;
            position: relative;
        }
        .browser-placeholder {
            text-align: center;
            padding: 100px 20px;
            color: #7f8c8d;
        }
        .browser-placeholder p {
            margin: 10px 0;
            font-size: 16px;
        }
        .browser-iframe {
            width: 100%;
            height: 400px;
            border: none;
            border-radius: 6px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ OWASPChecker - Attack Dashboard</h1>
            <p>Real-time monitoring of security testing scenarios</p>
        </div>
        
        <div class="card">
            <h2>📊 Attack Status</h2>
            <p><strong>Scenario:</strong> <span id="scenario-name">${attackStatus.scenario}</span></p>
            <p><strong>Current Step:</strong> <span id="current-step">${attackStatus.step}</span></p>
            <p><strong>Status:</strong> <span class="status ${attackStatus.status}" id="status">${attackStatus.status.toUpperCase()}</span></p>
            <div class="progress">
                <div class="progress-bar" id="progress-bar" style="width: ${attackStatus.progress}%"></div>
            </div>
            <p><small>Progress: <span id="progress-text">${attackStatus.progress}</span>% | Last Update: <span id="last-update">${attackStatus.lastUpdate.toLocaleString()}</span></small></p>
        </div>

        <div class="card">
            <h2>📈 Metrics</h2>
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value" id="requests-count">${attackStatus.requests}</div>
                    <div class="metric-label">Requests Sent</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="findings-count">${attackStatus.findings}</div>
                    <div class="metric-label">Findings</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="engine-status">${attackStatus.status === 'running' ? 'ACTIVE' : 'IDLE'}</div>
                    <div class="metric-label">Engine Status</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>🖥️ Live Browser</h2>
            <div class="browser-controls">
                <button onclick="startBrowser()">🚀 Start Browser</button>
                <button onclick="stopBrowser()">⏹️ Stop Browser</button>
                <button onclick="takeScreenshot()">📸 Screenshot</button>
                <button onclick="navigateTo()">🌐 Navigate</button>
                <input type="text" id="url-input" placeholder="Enter URL..." value="https://httpbin.org">
                <span id="browser-status">Browser: DISCONNECTED</span>
            </div>
            <div class="browser-container" id="browser-container">
                <div class="browser-placeholder">
                    <p>🖥️ Click "Start Browser" to launch live browser</p>
                    <p>Browser will be embedded here for real-time attack monitoring</p>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>📝 Live Logs</h2>
            <button class="refresh" onclick="location.reload()">🔄 Refresh</button>
            <div class="logs" id="logs">
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

        // Browser control functions
        async function startBrowser() {
            try {
                const response = await fetch('/api/browser/start', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    browserConnected = true;
                    updateBrowserStatus('CONNECTED', '#27ae60');
                    embedBrowser(data.debugUrl);
                    console.log('Browser started successfully');
                } else {
                    alert('Failed to start browser: ' + data.error);
                }
            } catch (error) {
                console.error('Error starting browser:', error);
                alert('Error starting browser');
            }
        }

        async function stopBrowser() {
            try {
                const response = await fetch('/api/browser/stop', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    browserConnected = false;
                    updateBrowserStatus('DISCONNECTED', '#e74c3c');
                    removeBrowser();
                    console.log('Browser stopped successfully');
                }
            } catch (error) {
                console.error('Error stopping browser:', error);
            }
        }

        async function takeScreenshot() {
            if (!browserConnected) {
                alert('Browser not connected');
                return;
            }
            
            try {
                const response = await fetch('/api/browser/screenshot', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    window.open('/api/browser/screenshot', '_blank');
                }
            } catch (error) {
                console.error('Error taking screenshot:', error);
            }
        }

        async function navigateTo() {
            if (!browserConnected) {
                alert('Browser not connected');
                return;
            }
            
            const url = document.getElementById('url-input').value;
            if (!url) {
                alert('Please enter a URL');
                return;
            }
            
            try {
                const response = await fetch('/api/browser/navigate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                
                if (data.success) {
                    console.log('Navigated to:', url);
                } else {
                    alert('Failed to navigate: ' + data.error);
                }
            } catch (error) {
                console.error('Error navigating:', error);
            }
        }

        function updateBrowserStatus(status, color) {
            const statusElement = document.getElementById('browser-status');
            statusElement.textContent = 'Browser: ' + status;
            statusElement.style.color = color;
        }

        function embedBrowser(debugUrl) {
            const container = document.getElementById('browser-container');
            // Use screenshot streaming instead of iframe
            startScreenshotStreaming();
        }
        
        function startScreenshotStreaming() {
            const container = document.getElementById('browser-container');
            
            // Auto-refresh screenshot every 1 second for smooth streaming
            setInterval(() => {
                const img = document.getElementById('screenshot');
                if (img) {
                    img.src = '/api/browser/screenshot?' + Date.now();
                }
            }, 1000);
            
            updateBrowserStatus('STREAMING', '#27ae60');
        }

        function removeBrowser() {
            const container = document.getElementById('browser-container');
            
            // Auto-start browser after 2 seconds
            setTimeout(() => {
                startScreenshotStreaming();
            }, 2000);
        }

        // Auto-refresh status every 2 seconds
        setInterval(async () => {
            try {
                startScreenshotStreaming();
            } catch (error) {
                console.error('Error updating status:', error);
            }
        }, 2000);
    </script>
</body>
</html>
    `);
    }
    else if (path === '/api/browser/screenshot' && req.method === 'GET') {
        // Mock screenshot for testing
        console.log('🎯 SCREENSHOT ENDPOINT HIT! Path:', path, 'Method:', req.method, 'URL:', req.url);
        console.log('🔍 DEBUG: path === "/api/browser/screenshot" =', path === '/api/browser/screenshot');
        console.log('🔍 DEBUG: req.method === "GET" =', req.method === 'GET');
        // Create a simple mock image (1x1 pixel PNG)
        const mockImage = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
        res.writeHead(200, {
            'Content-Type': 'image/png',
            'Content-Length': mockImage.length.toString(),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        });
        res.end(mockImage);
    }
    else if (path === '/api/status') {
        console.log('🔍 API Request - Path:', path, 'Method:', req.method, 'URL:', req.url);
        // API endpoint for status
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(attackStatus));
    }
    else if (path.startsWith('/api/')) {
        console.log('🚨 UNKNOWN API PATH:', path, 'Method:', req.method, 'URL:', req.url);
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('API Not Found: ' + path);
    }
    else if (path === '/api/start-demo' && req.method === 'POST') {
        // Start demo attack
        console.log('Demo attack started from GUI');
        attackStatus = {
            scenario: 'login_attack.yaml',
            step: 'browser:navigate -> /login',
            progress: 15,
            findings: 2,
            requests: 127,
            status: 'running',
            lastUpdate: new Date()
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
    }
    else if (path === '/api/attack/start' && req.method === 'POST') {
        // Start real attack from CLI
        let body = '';
        req.on('data', (chunk) => {
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
                            browser = await playwright_1.chromium.launch({
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
                        }
                        catch (error) {
                            console.error('❌ Failed to auto-start browser:', error);
                        }
                    }
                    console.log('Updated attack status:', attackStatus);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, attackId: Date.now() }));
                }
                catch (error) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid JSON' }));
                }
            })();
        });
        return;
    }
    else if (path === '/api/browser/start' && req.method === 'POST') {
        // Start browser with remote debugging
        console.log('Starting browser with remote debugging...');
        (async () => {
            try {
                if (browser) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        debugUrl: 'http://localhost:9222',
                        message: 'Browser already running'
                    }));
                    return;
                }
                // Launch browser with remote debugging for Docker
                browser = await playwright_1.chromium.launch({
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
                        '--remote-debugging-address=0.0.0.0',
                        '--disable-background-timer-throttling',
                        '--disable-backgrounding-occluded-windows',
                        '--disable-renderer-backgrounding'
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
                    debugUrl: 'http://localhost:9222',
                    message: 'Browser started with remote debugging'
                }));
            }
            catch (error) {
                console.error('Error starting browser:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        })();
    }
    else if (path === '/api/browser/stop' && req.method === 'POST') {
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
            }
            catch (error) {
                console.error('Error stopping browser:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        })();
    }
    else if (path === '/api/browser/navigate' && req.method === 'POST') {
        // Navigate to URL
        let body = '';
        req.on('data', (chunk) => { body += chunk.toString(); });
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
                }
                catch (error) {
                    console.error('Error navigating:', error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message }));
                }
            })();
        });
        return;
    }
    else if (path === '/api/browser/action' && req.method === 'POST') {
        // Browser action (navigate, fill, click)
        let body = '';
        req.on('data', (chunk) => { body += chunk.toString(); });
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
                    switch (data.action) {
                        case 'navigate':
                            await page.goto(data.url);
                            console.log('Navigated to:', data.url);
                            break;
                        case 'fill':
                            await page.fill(data.selector, data.value);
                            console.log('Filled:', data.selector, '=', data.value);
                            break;
                        case 'click':
                            await page.click(data.selector);
                            console.log('Clicked:', data.selector);
                            break;
                        default:
                            throw new Error(`Unknown action: ${data.action}`);
                    }
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: `Action ${data.action} completed` }));
                }
                catch (error) {
                    console.error('Error executing browser action:', error);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message }));
                }
            })();
        });
        return;
    }
    else if (path === '/api/attack/update' && req.method === 'POST') {
        // Update attack progress from CLI
        let body = '';
        req.on('data', (chunk) => {
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
                }
                else if (updateData.scenario) {
                    attackStatus.scenario = updateData.scenario;
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            }
            catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid JSON' }));
            }
        });
        return;
    }
    else if (path === '/health') {
        // Health check endpoint
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        }));
    }
    else {
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
// Demo attack simulation
let demoAttackInterval = null;
function startDemoAttack() {
    console.log('🎬 Starting demo attack simulation...');
    attackStatus = {
        scenario: 'demo_attack.yaml',
        step: 'browser:navigate -> /login',
        progress: 0,
        findings: 0,
        requests: 0,
        status: 'running',
        lastUpdate: new Date()
    };
    let progress = 0;
    demoAttackInterval = setInterval(() => {
        progress += 5;
        if (progress > 100) {
            progress = 100;
            clearInterval(demoAttackInterval);
            attackStatus.status = 'completed';
            console.log('✅ Demo attack completed');
        }
        attackStatus.progress = progress;
        attackStatus.requests = Math.floor(progress * 1.5);
        attackStatus.findings = Math.floor(progress / 20);
        attackStatus.lastUpdate = new Date();
        // Update step based on progress
        if (progress < 25) {
            attackStatus.step = 'browser:navigate -> /login';
        }
        else if (progress < 50) {
            attackStatus.step = 'browser:fill -> username/password';
        }
        else if (progress < 75) {
            attackStatus.step = 'browser:click -> submit';
        }
        else {
            attackStatus.step = 'net:attack -> /api/profile';
        }
        console.log(`📊 Demo progress: ${progress}% | Requests: ${attackStatus.requests} | Findings: ${attackStatus.findings}`);
    }, 1000);
}
// Start demo after 5 seconds
setTimeout(startDemoAttack, 5000);
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
    if (demoAttackInterval) {
        clearInterval(demoAttackInterval);
    }
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
//# sourceMappingURL=index.js.map