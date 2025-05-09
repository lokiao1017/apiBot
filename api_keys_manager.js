// api_keys_manager.js
const fs = require('fs');
const path = require('path');
const { DateTime } = require('luxon');
const crypto = require('crypto');

const KEYS_FILE = path.join(__dirname, '.api_keys.json');

const TIERS = {
    "free": { checkLimit: 10, durationDays: null, resetInterval: 'daily' }, // 10 checks per day
    "basic": { checkLimit: 100, durationDays: 30, resetInterval: 'daily' }, // 100 checks per day for 30 days
    "pro": { checkLimit: 1000, durationDays: 30, resetInterval: 'daily' }, // 1000 checks per day for 30 days
    "unlimited": { checkLimit: Infinity, durationDays: 30, resetInterval: null } // Unlimited checks for 30 days
};

let apiKeys = {};

function loadKeys() {
    try {
        if (fs.existsSync(KEYS_FILE)) {
            const data = fs.readFileSync(KEYS_FILE, 'utf-8');
            apiKeys = JSON.parse(data);
            // Hydrate dates
            for (const key in apiKeys) {
                if (apiKeys[key].createdAt) apiKeys[key].createdAt = DateTime.fromISO(apiKeys[key].createdAt);
                if (apiKeys[key].validUntil) apiKeys[key].validUntil = DateTime.fromISO(apiKeys[key].validUntil);
                if (apiKeys[key].lastReset) apiKeys[key].lastReset = DateTime.fromISO(apiKeys[key].lastReset);
            }
        }
    } catch (e) {
        console.error("Error loading API keys:", e);
        apiKeys = {};
    }
}

function saveKeys() {
    try {
        // Serialize dates before saving
        const serializableKeys = {};
        for (const key in apiKeys) {
            serializableKeys[key] = { ...apiKeys[key] };
            if (apiKeys[key].createdAt instanceof DateTime) serializableKeys[key].createdAt = apiKeys[key].createdAt.toISO();
            if (apiKeys[key].validUntil instanceof DateTime) serializableKeys[key].validUntil = apiKeys[key].validUntil.toISO();
            if (apiKeys[key].lastReset instanceof DateTime) serializableKeys[key].lastReset = apiKeys[key].lastReset.toISO();
        }
        fs.writeFileSync(KEYS_FILE, JSON.stringify(serializableKeys, null, 2));
    } catch (e) {
        console.error("Error saving API keys:", e);
    }
}

loadKeys();

function generateApiKey() {
    return crypto.randomBytes(20).toString('hex');
}

function addApiKey(userId, tierName) {
    if (!TIERS[tierName]) {
        throw new Error(`Invalid tier: ${tierName}`);
    }
    const apiKey = generateApiKey();
    const tier = TIERS[tierName];
    const now = DateTime.now();

    apiKeys[apiKey] = {
        apiKey,
        userId,
        tierName,
        checkLimit: tier.checkLimit,
        checksMade: 0,
        createdAt: now,
        validUntil: tier.durationDays ? now.plus({ days: tier.durationDays }) : null,
        lastReset: tier.resetInterval ? now : null, // Set lastReset to now for daily limits
        resetInterval: tier.resetInterval,
        active: true
    };
    saveKeys();
    // Return a copy with serialized dates for consistency if needed by caller, or live DateTime objects
    const resultKey = {...apiKeys[apiKey]};
    if (resultKey.createdAt) resultKey.createdAt = resultKey.createdAt.toISO();
    if (resultKey.validUntil) resultKey.validUntil = resultKey.validUntil.toISO();
    if (resultKey.lastReset) resultKey.lastReset = resultKey.lastReset.toISO();

    return { apiKey, userId, tierName, details: resultKey };
}

function removeApiKey(apiKey) {
    if (apiKeys[apiKey]) {
        delete apiKeys[apiKey];
        saveKeys();
        return { success: true, message: "API key removed." };
    }
    return { error: true, message: "API key not found." };
}

function getApiKeyInfo(apiKey) {
    if (apiKeys[apiKey]) {
        const keyData = {...apiKeys[apiKey]}; // Return a copy
        // Serialize dates for output
        if (keyData.createdAt instanceof DateTime) keyData.createdAt = keyData.createdAt.toISO();
        if (keyData.validUntil instanceof DateTime) keyData.validUntil = keyData.validUntil.toISO();
        if (keyData.lastReset instanceof DateTime) keyData.lastReset = keyData.lastReset.toISO();
        return { keyData };
    }
    return { error: true, message: "API key not found." };
}

function findApiKeysByUserId(userId) {
    const userKeys = Object.values(apiKeys).filter(k => k.userId === userId).map(k => {
        const keyData = {...k};
        if (keyData.createdAt instanceof DateTime) keyData.createdAt = keyData.createdAt.toISO();
        if (keyData.validUntil instanceof DateTime) keyData.validUntil = keyData.validUntil.toISO();
        if (keyData.lastReset instanceof DateTime) keyData.lastReset = keyData.lastReset.toISO();
        return keyData;
    });
    if (userKeys.length > 0) {
        return { keys: userKeys };
    }
    return { error: true, message: "No API keys found for this user ID." };
}

function getAllKeys() {
    // Return a copy with serialized dates
    const allKeysCopy = {};
    for (const key in apiKeys) {
        allKeysCopy[key] = { ...apiKeys[key] };
        if (apiKeys[key].createdAt instanceof DateTime) allKeysCopy[key].createdAt = apiKeys[key].createdAt.toISO();
        if (apiKeys[key].validUntil instanceof DateTime) allKeysCopy[key].validUntil = apiKeys[key].validUntil.toISO();
        if (apiKeys[key].lastReset instanceof DateTime) allKeysCopy[key].lastReset = apiKeys[key].lastReset.toISO();
    }
    return allKeysCopy;
}

async function validateAndConsumeApiKey(apiKey) {
    const keyData = apiKeys[apiKey];
    if (!keyData || !keyData.active) {
        return { valid: false, message: "API key invalid or inactive.", status: 403 };
    }

    if (keyData.validUntil && DateTime.now() > keyData.validUntil) {
        keyData.active = false; // Deactivate expired key
        saveKeys();
        return { valid: false, message: "API key expired.", status: 403 };
    }

    // Handle usage reset (e.g., daily)
    if (keyData.resetInterval === 'daily' && keyData.lastReset) {
        const now = DateTime.now();
        if (now.startOf('day') > keyData.lastReset.startOf('day')) {
            keyData.checksMade = 0;
            keyData.lastReset = now;
        }
    }
    
    if (keyData.checkLimit !== Infinity && keyData.checksMade >= keyData.checkLimit) {
        return { valid: false, message: "API key usage limit reached.", status: 429, keyData };
    }

    keyData.checksMade += 1;
    saveKeys();
    return { valid: true, keyData };
}

module.exports = {
    addApiKey,
    removeApiKey,
    validateAndConsumeApiKey,
    getApiKeyInfo,
    findApiKeysByUserId,
    getAllKeys,
    TIERS
};