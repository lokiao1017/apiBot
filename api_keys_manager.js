// api_keys_manager.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // For generating API keys

const API_KEYS_FILE = path.join(__dirname, 'api_keys.json');
let apiKeysData = {}; // In-memory cache

// Tier definitions
const TIERS = {
    free: {
        limit: 100,
        resetIntervalHours: 48, // 2 days
        durationDays: null // Free keys don't expire by duration
    },
    paid1: { // ₱100
        limit: 50000,
        resetIntervalHours: 24,
        durationDays: 3
    },
    paid2: { // ₱300
        limit: 80000,
        resetIntervalHours: 24,
        durationDays: 3
    }
};

function loadApiKeys() {
    try {
        if (fs.existsSync(API_KEYS_FILE)) {
            const fileContent = fs.readFileSync(API_KEYS_FILE, 'utf-8');
            apiKeysData = JSON.parse(fileContent);
        } else {
            // Initialize with a free key if file doesn't exist
            console.log("API keys file not found. Initializing with default free key.");
            apiKeysData = {
                "sinfree": {
                    userId: "free_user",
                    tierName: "free",
                    checkLimit: TIERS.free.limit,
                    checksMade: 0,
                    validUntil: null, // Free keys don't expire like this
                    lastReset: new Date().toISOString(),
                    resetIntervalHours: TIERS.free.resetIntervalHours,
                    createdAt: new Date().toISOString()
                }
            };
            saveApiKeys();
        }
    } catch (error) {
        console.error("Error loading API keys:", error);
        apiKeysData = {}; // Fallback to empty if error
    }
}

function saveApiKeys() {
    try {
        fs.writeFileSync(API_KEYS_FILE, JSON.stringify(apiKeysData, null, 2), 'utf-8');
    } catch (error) {
        console.error("Error saving API keys:", error);
    }
}

function generateApiKey() {
    return crypto.randomBytes(16).toString('hex');
}

function addApiKey(userId, tierName) {
    if (!TIERS[tierName]) {
        return { error: "Invalid tier name." };
    }

    const apiKey = generateApiKey();
    const tierConfig = TIERS[tierName];
    const now = new Date();
    let validUntil = null;
    if (tierConfig.durationDays) {
        const expiryDate = new Date(now);
        expiryDate.setDate(now.getDate() + tierConfig.durationDays);
        validUntil = expiryDate.toISOString();
    }

    apiKeysData[apiKey] = {
        userId: userId,
        tierName: tierName,
        checkLimit: tierConfig.limit,
        checksMade: 0,
        validUntil: validUntil,
        lastReset: now.toISOString(),
        resetIntervalHours: tierConfig.resetIntervalHours,
        createdAt: now.toISOString(),
        history: [] // To store check timestamps if needed
    };
    saveApiKeys();
    return { apiKey, details: apiKeysData[apiKey] };
}

function removeApiKey(apiKey) {
    if (apiKeysData[apiKey]) {
        delete apiKeysData[apiKey];
        saveApiKeys();
        return { success: true, message: "API key removed." };
    }
    return { error: "API key not found." };
}

function getApiKeyInfo(apiKey) {
    if (apiKeysData[apiKey]) {
        return { details: apiKeysData[apiKey] };
    }
    return { error: "API key not found." };
}

function findApiKeyByUserId(userId) {
    for (const apiKey in apiKeysData) {
        if (apiKeysData[apiKey].userId === userId) {
            return { apiKey, details: apiKeysData[apiKey] };
        }
    }
    return { error: "No API key found for this user ID." };
}


function validateAndConsumeApiKey(apiKey) {
    const keyData = apiKeysData[apiKey];
    if (!keyData) {
        return { valid: false, message: "Invalid API key.", status: 401 };
    }

    const now = new Date();

    // Check expiration for paid keys
    if (keyData.validUntil && new Date(keyData.validUntil) < now) {
        return { valid: false, message: "API key expired.", status: 403 };
    }

    // Check for reset
    const lastResetDate = new Date(keyData.lastReset);
    const resetIntervalMs = keyData.resetIntervalHours * 60 * 60 * 1000;
    if (now.getTime() - lastResetDate.getTime() >= resetIntervalMs) {
        keyData.checksMade = 0;
        keyData.lastReset = now.toISOString();
    }

    // Check limit
    if (keyData.checksMade >= keyData.checkLimit) {
        return { valid: false, message: "API key check limit reached.", status: 429 };
    }

    // Consume one check
    keyData.checksMade++;
    // Add to history (optional, can be simple or more detailed)
    if (!keyData.history) keyData.history = [];
    keyData.history.push({ timestamp: now.toISOString() });
    // Prune history if it gets too long (e.g., keep last 1000 checks)
    if (keyData.history.length > 1000) keyData.history.shift();

    saveApiKeys(); // Save changes (checksMade, lastReset, history)

    return { valid: true, message: "API key valid.", keyData };
}

// Load keys on module start
loadApiKeys();

module.exports = {
    addApiKey,
    removeApiKey,
    getApiKeyInfo,
    findApiKeyByUserId,
    validateAndConsumeApiKey,
    TIERS // export Tiers for admin endpoint
};