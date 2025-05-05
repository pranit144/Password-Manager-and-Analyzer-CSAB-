// --- background.js ---

let inMemoryKeyB64 = null;      // Store Base64 string
let userEmailForSession = null;
let keyExpiryTimer = null;
const KEY_EXPIRY_MINUTES = 30;

// --- Helper Functions ---
// Necessary for converting back when GETTING the key if needed elsewhere,
// but not strictly needed for storing/retrieving the B64 string itself.
// Including for completeness/potential future use.
function base64ToArrayBuffer(base64) {
    try {
        const binary_string = atob(base64); // Use global atob
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
        return bytes.buffer;
    } catch (e) {
        console.error("[Background] Base64 decoding failed:", e);
        throw new Error("Invalid Base64 string.");
    }
}

function clearKeyAndTimer() {
    console.log("[Background] Clearing key and timer...");
    inMemoryKeyB64 = null; // Clear the B64 string
    userEmailForSession = null;
    if (keyExpiryTimer) { clearTimeout(keyExpiryTimer); keyExpiryTimer = null; }
    console.log("[Background] In-memory key cleared.");
    // chrome.action.setIcon({ path: "icons/icon128_locked.png" }).catch(e => console.warn("Error setting icon:", e));
}

function resetKeyExpiryTimer() {
    if (keyExpiryTimer) { clearTimeout(keyExpiryTimer); }
    if (inMemoryKeyB64) { // Check if B64 string exists
        keyExpiryTimer = setTimeout(clearKeyAndTimer, KEY_EXPIRY_MINUTES * 60 * 1000);
        console.log(`[Background] Key expiry timer reset (${KEY_EXPIRY_MINUTES} mins). Timer ID: ${keyExpiryTimer}`);
    } else {
        console.log("[Background] No key exists, expiry timer not set.");
    }
}

// Listener for messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const senderType = sender.tab ? `content script (${sender.tab.url})` : `popup/extension (${sender.id})`;
    console.log(`[Background] Received message: ACTION=${request.action} from ${senderType}`);

    if (!sender.tab) { resetKeyExpiryTimer(); }

    try {
        if (request.action === 'storeKey') {
            console.log("[Background] Handling 'storeKey'");
             // *** THIS IS THE CORRECTED CHECK ***
            if (typeof request.keyB64 === 'string' && request.keyB64.length > 10 && request.email) { // Check for keyB64 string
                inMemoryKeyB64 = request.keyB64; // Store Base64 string
                userEmailForSession = request.email;
                console.log("[Background] Key (Base64) stored successfully for", userEmailForSession);
                resetKeyExpiryTimer();
                sendResponse({ success: true });
            } else {
                // *** THIS LOG MATCHES THE EXPECTATION OF keyB64 ***
                console.error("[Background] StoreKey request missing valid keyB64 (string) or email.");
                sendResponse({ success: false, error: "Missing valid keyB64 or email" });
            }
            return false; // Synchronous response

        } else if (request.action === 'getKey') {
             console.log("[Background] Handling 'getKey'. Key (B64) exists?", !!inMemoryKeyB64);
             if (inMemoryKeyB64 && userEmailForSession) {
                 console.log("[Background] Key (Base64) found for", userEmailForSession);
                 // Send Base64 string back
                 sendResponse({ success: true, keyB64: inMemoryKeyB64, email: userEmailForSession });
             } else {
                 console.log("[Background] Key not found in memory.");
                 sendResponse({ success: false });
             }
             // **MUST return true for potential async response pathway**
             // Although sendResponse is called synchronously here, message listeners
             // should generally return true if they might ever call sendResponse later.
             return true;

        } else if (request.action === 'clearKey') {
            console.log("[Background] Handling 'clearKey'");
            clearKeyAndTimer();
            sendResponse({ success: true });
             return false; // Synchronous response

        } else if (request.action === 'getEmail') {
             console.log("[Background] Handling 'getEmail'. Email stored?", userEmailForSession || "No");
             sendResponse({success: true, email: userEmailForSession });
              return false; // Synchronous response
        }
        else {
            console.log("[Background] Unknown action received:", request.action);
        }

    } catch (error) {
         console.error(`[Background] Error handling action '${request.action}':`, error);
         try { sendResponse({ success: false, error: `Background script error: ${error.message}` }); }
         catch (responseError) { console.error("[Background] Failed to send error response:", responseError); }
         return false;
    }

    // If no specific handler matched and returned, return false by default.
    // However, the 'getKey' handler MUST return true.
    // The structure above handles this correctly now.
});

// Initial setup log
console.log("[Background] Service worker script loaded and listener attached.");