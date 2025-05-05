// --- crypto-helpers.js ---
// Helper functions for Web Crypto API and Base64 Handling

/**
 * Converts a Base64URL encoded string to an ArrayBuffer.
 * Needed for decoding the key stored in Flask session.
 * @param {string} b64url - Base64URL encoded string.
 * @returns {ArrayBuffer}
 */
function base64UrlDecode(b64url) {
    try {
        let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) {
            b64 += '=';
        }
        return base64ToArrayBuffer(b64);
    } catch (e) {
        console.error("Base64URL decoding failed:", e);
        throw new Error("Invalid Base64URL string for key decoding.");
    }
}

/**
 * Converts a standard Base64 string to an ArrayBuffer.
 * @param {string} base64 - Standard Base64 encoded string.
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
    try {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (e) {
        console.error("Base64 decoding failed:", e);
        throw new Error("Invalid Base64 string.");
    }
}

/**
 * Converts an ArrayBuffer to a standard Base64 string.
 * Used for logging raw keys consistently.
 * @param {ArrayBuffer} buffer - The ArrayBuffer to encode.
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

/**
 * Derives a 32-byte AES key from a password and salt using PBKDF2.
 * Logs the standard Base64 representation of the raw key.
 * @param {string} password - The master password.
 * @param {string} saltString - The salt (e.g., user's email).
 * @returns {Promise<ArrayBuffer>} - Promise resolving to the raw key bytes (ArrayBuffer).
 */
async function deriveKeyRawBytes(password, saltString) {
    try {
        const salt = new TextEncoder().encode(saltString.toLowerCase()); // Use consistent casing for salt
        const passwordBuffer = new TextEncoder().encode(password);
        const iterations = 390000; // Match Python backend KDF iterations

        const keyMaterial = await crypto.subtle.importKey(
            'raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
            keyMaterial,
            256 // Derive 256 bits (32 bytes)
        );

        // --- ADDED LOGGING ---
        try {
            console.log(`DEBUG: JS Derived Key (Raw -> Standard Base64): ${arrayBufferToBase64(derivedBits)}`);
        } catch(logErr) { console.error("DEBUG: Error logging JS derived key", logErr); }
        // --- END LOGGING ---

        return derivedBits; // Return raw ArrayBuffer
    } catch (error) {
        console.error("Key derivation failed:", error);
        throw new Error("Could not derive encryption key.");
    }
}

/**
 * Encrypts data (object) using AES-GCM with the provided raw key bytes.
 * @param {ArrayBuffer} keyBuffer - The raw 32-byte AES key.
 * @param {object} data - The JavaScript object to encrypt.
 * @returns {Promise<string>} - Promise resolving to the Base64 encoded encrypted data (IV + Ciphertext).
 */
async function encryptData(keyBuffer, data) {
    try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const dataString = JSON.stringify(data);
        const encodedData = new TextEncoder().encode(dataString);
        const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
        const encryptedContent = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cryptoKey, encodedData);
        const combinedBuffer = new Uint8Array(iv.length + encryptedContent.byteLength);
        combinedBuffer.set(iv, 0);
        combinedBuffer.set(new Uint8Array(encryptedContent), iv.length);
        return arrayBufferToBase64(combinedBuffer); // Return standard Base64
    } catch (error) {
        console.error("Encryption failed:", error);
        throw new Error("Could not encrypt data.");
    }
}

/**
 * Decrypts Base64 encoded data using AES-GCM with the provided raw key bytes.
 * @param {ArrayBuffer} keyBuffer - The raw 32-byte AES key.
 * @param {string} encryptedB64Data - Base64 encoded data (IV + Ciphertext).
 * @returns {Promise<object|null>} - Promise resolving to the decrypted object, or null on failure.
 */
async function decryptData(keyBuffer, encryptedB64Data) {
    try {
        const combinedData = base64ToArrayBuffer(encryptedB64Data);
        if (combinedData.byteLength < 12) throw new Error("Encrypted data too short.");
        const iv = combinedData.slice(0, 12);
        const ciphertext = combinedData.slice(12);
        const cryptoKey = await crypto.subtle.importKey("raw", keyBuffer, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
        const decryptedContent = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cryptoKey, ciphertext);
        const decodedString = new TextDecoder().decode(decryptedContent);
        return JSON.parse(decodedString);
    } catch (error) {
        // Log the specific crypto error, helpful for debugging (e.g., Authentication tag mismatch)
        console.error(`Decryption failed: ${error.name} - ${error.message}`);
        return null; // Indicate failure
    }
}

/**
 * Escapes HTML special characters in a string.
 * @param {string} unsafe - The potentially unsafe string.
 * @returns {string} - The escaped string.
 */
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

/**
 * Computes the SHA-1 hash of a string.
 * @param {string} text - The string to hash.
 * @returns {Promise<string>} - Promise resolving to the SHA-1 hash as an uppercase hex string.
 */
async function sha1Hash(text) {
    // ... (implementation as previously provided)
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex.toUpperCase(); // HIBP API uses uppercase hex
    } catch (error) {
        console.error("SHA-1 Hashing failed:", error);
        throw new Error("Could not compute SHA-1 hash.");
    }
}

/**
 * Checks if a password has been exposed in known data breaches using HIBP Pwned Passwords API (FREE version).
 * Uses k-Anonymity.
 * @param {string} password - The password to check.
 * @returns {Promise<{isPwned: boolean, count: number | null, error: string | null}>}
 */
async function checkHIBPPassword(password) {
    // ... (implementation as previously provided)
    if (!password) {
        return { isPwned: false, count: null, error: null }; // Cannot check empty password
    }
    try {
        const hash = await sha1Hash(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);
        const apiUrl = `https://api.pwnedpasswords.com/range/${prefix}`; // FREE endpoint

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

        const response = await fetch(apiUrl, {
             method: 'GET',
             signal: controller.signal
         });

        clearTimeout(timeoutId);

        if (!response.ok) {
             if (response.status === 404) {
                 // 404 means the prefix wasn't found (good!)
                 return { isPwned: false, count: 0, error: null };
             }
             throw new Error(`HIBP API Error: ${response.status} ${response.statusText}`);
        }

        const text = await response.text();
        const lines = text.split('\r\n');

        for (const line of lines) {
            const [lineSuffix, lineCountStr] = line.split(':');
            if (lineSuffix === suffix) {
                const count = parseInt(lineCountStr, 10);
                console.warn(`Password found in HIBP database ${count} times!`);
                return { isPwned: true, count: count, error: null };
            }
        }
        return { isPwned: false, count: 0, error: null };

    } catch (error) {
        let errorMessage = "Could not check password breach status.";
        if (error.name === 'AbortError') {
            errorMessage = "Breach check timed out.";
        } else if (error instanceof Error) {
             errorMessage = `Breach check failed: ${error.message}`;
        }
        console.error("HIBP Check Error:", error);
        return { isPwned: false, count: null, error: errorMessage };
    }
}
// --- END OF crypto-helpers.js additions ---