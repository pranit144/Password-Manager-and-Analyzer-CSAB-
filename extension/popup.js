// --- START OF FILE popup.js ---

// --- Global Variables ---
const API_BASE_URL = 'http://127.0.0.1:5000';
let derivedEncryptionKey = null; // ArrayBuffer | null - Key used for crypto ops
let userEmail = null; // string | null
let allCredentials = [];
let currentDomain = 'N/A';

// --- DOM Elements ---
const loginView = document.getElementById('login-view');
const mainView = document.getElementById('main-view');
const emailInput = document.getElementById('email');
const masterPasswordLoginInput = document.getElementById('masterPasswordLogin');
const loginBtn = document.getElementById('login-btn');
const loginError = document.getElementById('login-error');
const statusIndicator = document.getElementById('status-indicator');
const passwordList = document.getElementById('password-list');
const searchInput = document.getElementById('search-input');
const addPasswordBtn = document.getElementById('add-password-btn');
const addPasswordForm = document.getElementById('add-password-form');
const savePasswordBtn = document.getElementById('save-password-btn');
const cancelAddBtn = document.getElementById('cancel-add-btn');
const serviceInput = document.getElementById('service');
const newUsernameInput = document.getElementById('new-username');
const newPasswordInput = document.getElementById('new-password');
const masterPasswordSaveInput = document.getElementById('masterPasswordSave');
const saveError = document.getElementById('save-error');
const logoutBtn = document.getElementById('logout-btn');
const currentDomainSpan = document.getElementById('current-domain');
const generatePopupPasswordBtn = document.getElementById('generate-popup-password-btn');
const popupThemeToggleBtn = document.getElementById('popup-theme-toggle');
const popupGenLengthSlider = document.getElementById('popup-gen-length');
const popupGenLengthValueSpan = document.getElementById('popup-gen-length-value');
const popupGenLowercaseCheckbox = document.getElementById('popup-gen-lowercase');
const popupGenUppercaseCheckbox = document.getElementById('popup-gen-uppercase');
const popupGenDigitsCheckbox = document.getElementById('popup-gen-digits');
const popupGenSymbolsCheckbox = document.getElementById('popup-gen-symbols');
const popupStrengthArea = document.getElementById('popup-strength-area');
const popupStrengthIndicator = document.getElementById('popup-strength-indicator');
const popupStrengthTextLabel = document.getElementById('popup-strength-text-label');
const popupStrengthFeedbackDiv = document.getElementById('popup-strength-feedback');

// --- Event Listeners ---
loginBtn.addEventListener('click', handleLoginAttempt);
logoutBtn.addEventListener('click', handleLogout);
addPasswordBtn.addEventListener('click', showAddForm);
cancelAddBtn.addEventListener('click', hideAddForm);
savePasswordBtn.addEventListener('click', handleSavePassword);
searchInput.addEventListener('input', handleSearchFilter);
generatePopupPasswordBtn.addEventListener('click', handleGeneratePopupPassword);
popupGenLengthSlider.addEventListener('input', () => { popupGenLengthValueSpan.textContent = popupGenLengthSlider.value; });
newPasswordInput.addEventListener('input', handlePopupPasswordInput);
if (popupThemeToggleBtn) popupThemeToggleBtn.addEventListener('click', togglePopupTheme);


// --- Initialization ---
document.addEventListener('DOMContentLoaded', async () => {
    console.log("Popup: DOMContentLoaded");
    applyPopupTheme();
    // Make sure crypto helpers are loaded
    if (typeof arrayBufferToBase64 === 'undefined' || typeof base64ToArrayBuffer === 'undefined' || typeof deriveKeyRawBytes === 'undefined' || typeof decryptData === 'undefined' || typeof encryptData === 'undefined') {
         console.error("Crypto helpers not loaded! Ensure crypto-helpers.js is included correctly.");
         showLoginView("Error: Required crypto functions missing. Reload extension.");
         return;
    }
    await getCurrentTabDomain();
    await checkLoginStatus();
});

// --- Theme Handling ---
function applyPopupTheme() {
    chrome.storage.local.get(['popupTheme'], (result) => {
        const theme = result.popupTheme || 'light'; // Default to light
        document.body.setAttribute('data-theme', theme);
        if (popupThemeToggleBtn) {
            popupThemeToggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
        }
    });
}
function togglePopupTheme() {
    const currentTheme = document.body.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    chrome.storage.local.set({ popupTheme: newTheme }, () => { applyPopupTheme(); });
}

// --- Communication with Background Script ---
async function sendMessageToBackground(message) {
    console.log("[Popup] Sending message to background ->", message.action, message); // Log sent message
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(message, (response) => {
            const lastError = chrome.runtime.lastError;
            if (lastError) {
                console.error(`[Popup] Error sending '${message.action}':`, lastError.message);
                let errorMsg = `Error contacting background: ${lastError.message}. Reload extension?`;
                if (lastError.message.includes("Receiving end does not exist")) {
                    errorMsg = "Background service not running. Try reloading the extension.";
                }
                reject(new Error(errorMsg));
            } else {
                 console.log("[Popup] Received response from background for ->", message.action, response); // Log received response
                resolve(response);
            }
        });
    });
}

// --- Authentication ---
async function checkLoginStatus() {
    console.log("Popup: Checking login status...");
    try {
        const response = await sendMessageToBackground({ action: 'getKey' });

        // Check for key as Base64 string
        if (response && response.success && typeof response.keyB64 === 'string' && response.email) {
            console.log("Popup: Key (Base64) retrieved from background for", response.email);
            try {
                // Convert Base64 back to ArrayBuffer
                derivedEncryptionKey = base64ToArrayBuffer(response.keyB64); // Assumes base64ToArrayBuffer is loaded
                userEmail = response.email;
                console.log("Popup: Key successfully converted back to ArrayBuffer.");
                showMainView(true); // Show main view and load credentials
                updateDomainDisplay();
            } catch (conversionError) {
                console.error("Popup: Failed to convert key from Base64 ->", conversionError);
                throw new Error("Invalid key format received from background."); // Throw to be caught below
            }
        } else {
             console.log("Popup: No valid key found in background. Checking for email.");
             // If no key in background, check if we know the email (for unlock prompt)
             const emailCheckResponse = await sendMessageToBackground({ action: 'getEmail' });
             if (emailCheckResponse && emailCheckResponse.success && emailCheckResponse.email) {
                  userEmail = emailCheckResponse.email; // Store email locally ONLY for unlock prompt
                  console.log("Popup: Background remembers email", userEmail, "-> Prompting for unlock.");
                  showLoginView(`Unlock Manager for ${userEmail}`);
                  if(emailInput) emailInput.value = userEmail; // Pre-fill email
                  if(masterPasswordLoginInput) masterPasswordLoginInput.focus(); // Focus password
             } else {
                  console.log("Popup: Background has no key or email -> Full login required.");
                  userEmail = null; // Ensure email is null
                  derivedEncryptionKey = null;
                  showLoginView(); // Show full login prompt
                  if(emailInput) emailInput.focus();
             }
        }
    } catch (error) {
        // This catch block handles errors from sendMessageToBackground
        console.error("Popup: Failed during checkLoginStatus ->", error.message);
        showLoginView(error.message || 'Error contacting background service.'); // Display the error message from the catch
        userEmail = null;
        derivedEncryptionKey = null;
    }
}


async function handleLoginAttempt() {
    const emailToUse = userEmail || emailInput.value.trim(); // Use stored email if unlocking
    const masterPassword = masterPasswordLoginInput.value;
    if (!emailToUse || !masterPassword) { showLoginError("Email and Master Password are required."); return; }

    loginBtn.disabled = true;
    loginBtn.textContent = userEmail ? 'Unlocking...' : 'Logging in...';
    hideLoginError();
    let keyBuffer = null;

    try {
        console.log(`Popup: Attempting key derivation for ${emailToUse}...`);
        keyBuffer = await deriveKeyRawBytes(masterPassword, emailToUse); // Assumes deriveKeyRawBytes is loaded
        console.log("Popup: Key derived successfully locally (ArrayBuffer).");

        const keyB64 = arrayBufferToBase64(keyBuffer); // Assumes arrayBufferToBase64 is loaded
        console.log("Popup: Key converted to Base64 for transport.");

        // *** ADDED DETAILED LOGGING BEFORE SENDING ***
        const messageToSend = {
            action: 'storeKey',
            keyB64: keyB64,
            email: emailToUse
        };
        console.log("[Popup] Preparing to send 'storeKey' message:", JSON.stringify({
            action: messageToSend.action,
            email: messageToSend.email,
            keyB64_type: typeof messageToSend.keyB64,
            keyB64_length: messageToSend.keyB64?.length,
            keyB64_snippet: messageToSend.keyB64?.substring(0, 10) + "..." // Log a snippet
        }, null, 2)); // Added indentation for readability
        // *** END ADDED LOGGING ***

        console.log("Popup: Sending 'storeKey' message with Base64 key to background...");
        const storeResponse = await sendMessageToBackground(messageToSend); // Send the prepared message

        if (!storeResponse || !storeResponse.success) {
            throw new Error(storeResponse?.error || "Failed to store key in background service.");
        }

        // If storing succeeded:
        derivedEncryptionKey = keyBuffer; // Keep local key as ArrayBuffer
        userEmail = emailToUse;          // Update local email

        console.log("Popup: Key stored in background. Showing main view.");
        showMainView(true); // Show main view & trigger data fetch
        updateDomainDisplay();

    } catch (error) {
        console.error('Popup: Login/Unlock error ->', error.message, error);
        derivedEncryptionKey = null; // Clear local key on any failure

        if (error.message.includes("derive") || error.message.includes("Invalid Base64URL")) {
             showLoginError("Key derivation failed. Incorrect Master Password?");
        } else if (error.message.includes("background")) {
             showLoginError(`Session error: ${error.message}. Please try again.`);
        } else {
             showLoginError(`Error: ${error.message}`); // Show other errors
        }

        // Determine which view to show based on whether it was an unlock attempt
        if(userEmail) { // It was an unlock attempt that failed
             showLoginView(`Unlock Failed for ${userEmail}`); // Keep showing unlock prompt
             if (emailInput) emailInput.value = userEmail;
        } else { // It was a login attempt that failed
             showLoginView(); // Show full login
             if (emailInput) emailInput.value = emailToUse; // Keep entered email
        }
         if (masterPasswordLoginInput) masterPasswordLoginInput.value = ''; // Clear password field

    } finally {
        loginBtn.disabled = false;
        // Determine button text based on whether userEmail was set *before* the attempt
        loginBtn.textContent = userEmail ? 'Unlock' : 'Login';
        if (masterPasswordLoginInput) masterPasswordLoginInput.value = '';
    }
}


async function handleLogout() {
    console.log("Popup: Handling logout.");
    const emailBeforeLogout = userEmail;
    derivedEncryptionKey = null; userEmail = null; allCredentials = [];

    try {
        console.log("Popup: Sending 'clearKey' message to background...");
        await sendMessageToBackground({ action: 'clearKey' });
        console.log("Popup: Background key cleared via message.");
    } catch (error) { console.error("Popup: Error sending 'clearKey' to background ->", error.message); }

    try { await fetch(`${API_BASE_URL}/logout`, { method: 'GET', credentials: 'include' }); console.log("Popup: Backend logout request sent."); }
    catch (error) { console.warn("Popup: Backend logout fetch error:", error); }

    showLoginView(`Logged out from ${emailBeforeLogout || 'session'}.`);
    if(emailInput) emailInput.value = ''; if(masterPasswordLoginInput) masterPasswordLoginInput.value = '';
}


// --- UI View Management ---
function showLoginView(message = null) {
    loginView.classList.remove('hidden'); mainView.classList.add('hidden');
    if (message) { showLoginError(message); } else { hideLoginError(); }
    if (!userEmail && emailInput) { emailInput.focus(); }
    else if (userEmail && masterPasswordLoginInput) { masterPasswordLoginInput.focus(); }
}
function showLoginError(message) { loginError.textContent = message; loginError.classList.remove('hidden'); }
function hideLoginError() { loginError.classList.add('hidden'); loginError.textContent = ''; }
function showMainView(fetchData = false) {
    loginView.classList.add('hidden'); mainView.classList.remove('hidden'); hideAddForm();
    if (fetchData && derivedEncryptionKey) { loadAndDisplayCredentials(); }
    else if (!derivedEncryptionKey) { console.error("showMainView called but derivedEncryptionKey is missing!"); showLoginView("Error: Key is missing. Please unlock."); }
    updateDomainDisplay();
}
function updateDomainDisplay() { if (currentDomainSpan) { currentDomainSpan.textContent = `Domain: ${currentDomain}`; currentDomainSpan.title = `Current Tab Domain: ${currentDomain}`; } }
function showAddForm() {
    addPasswordForm.classList.remove('hidden'); addPasswordBtn.classList.add('hidden'); hideSaveError();
    if (currentDomain !== 'N/A' && !serviceInput.value) { let domainName = currentDomain.replace(/^www\./, ''); serviceInput.value = domainName.charAt(0).toUpperCase() + domainName.slice(1); }
    newPasswordInput.value = ''; handlePopupPasswordInput(); masterPasswordSaveInput.value = ''; if(serviceInput) serviceInput.focus();
}
function hideAddForm() {
    addPasswordForm.classList.add('hidden'); addPasswordBtn.classList.remove('hidden');
    serviceInput.value = ''; newUsernameInput.value = ''; newPasswordInput.value = ''; masterPasswordSaveInput.value = ''; hideSaveError();
    popupGenLengthSlider.value = 16; popupGenLengthValueSpan.textContent = '16'; popupGenLowercaseCheckbox.checked = true; popupGenUppercaseCheckbox.checked = true; popupGenDigitsCheckbox.checked = true; popupGenSymbolsCheckbox.checked = true;
    if (popupStrengthArea) popupStrengthArea.style.display = 'none'; if (popupStrengthIndicator) popupStrengthIndicator.className = 'popup-strength-indicator very-weak'; if (popupStrengthTextLabel) popupStrengthTextLabel.textContent = 'Strength:'; if (popupStrengthFeedbackDiv) popupStrengthFeedbackDiv.innerHTML = ''; if (popupStrengthArea) popupStrengthArea.className = 'popup-strength-area';
}
function showSaveError(message) { saveError.textContent = message; saveError.classList.remove('hidden'); }
function hideSaveError() { saveError.textContent = ''; saveError.classList.add('hidden'); }
function setPopupStatus(message, isError = false, duration = 0) { statusIndicator.textContent = message; statusIndicator.className = `status-message ${isError ? 'status-error' : (message.includes("copied") ? 'status-success' : 'status-info')}`; statusIndicator.classList.remove('hidden'); if (duration > 0) { setTimeout(clearPopupStatus, duration); } }
function clearPopupStatus() { statusIndicator.classList.add('hidden'); statusIndicator.textContent = ''; statusIndicator.className = 'status-message status-info'; }


// --- Credential Handling ---
async function loadAndDisplayCredentials() {
    if (!derivedEncryptionKey) {
        // ... error handling ...
        return;
    }
    setPopupStatus("Loading credentials...", false);
    passwordList.innerHTML = '';

    try {
        // ***** VERIFY THIS LINE *****
        const response = await fetch(`${API_BASE_URL}/api/credentials`, {
            method: 'GET',
            credentials: 'include' // <<< ENSURE THIS IS PRESENT!
        });
        // ***** END VERIFICATION *****

        if (!response.ok) {
            if (response.status === 401) {
                console.log("Credentials fetch failed (401), session likely expired.");
                await handleLogout(); // Perform full logout
                showLoginView("Session expired. Please log in again.");
            } else {
                // Throw error for other non-ok statuses
                throw new Error(`Failed to fetch credentials (${response.status})`);
            }
            return; // Stop execution if fetch failed
        }

        // If response.ok, proceed to parse JSON
        const responseText = await response.text(); // Get text first for debugging
        try {
            const encryptedCredentials = JSON.parse(responseText); // Try parsing
            allCredentials = encryptedCredentials || [];
            clearPopupStatus();

            if (allCredentials.length === 0) {
                passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: #777; list-style: none;">No credentials saved yet.</li>`;
            } else {
                filterAndRenderList();
            }
        } catch (jsonError) {
             // This is where the "Unexpected token '<'" error is caught
             console.error("JSON Parsing Error:", jsonError);
             console.error("Received non-JSON response text:", responseText); // Log the actual HTML received
             throw new Error(`Invalid response received from server (Expected JSON, got HTML?). Status: ${response.status}`);
        }

    } catch (error) {
        setPopupStatus(`Error loading credentials: ${error.message}`, true);
        console.error('Load credentials error:', error);
    }
 }
function filterAndRenderList() {
     passwordList.innerHTML = ''; const searchTerm = searchInput.value.toLowerCase().trim(); let filtered = []; let domainMatches = [];
     if (currentDomain !== 'N/A' && !searchTerm) { const lowerCaseDomain = currentDomain.replace(/^www\./, '').toLowerCase(); domainMatches = allCredentials.filter(cred => cred.service_hint && cred.service_hint.toLowerCase().includes(lowerCaseDomain)); const otherCredentials = allCredentials.filter(cred => !domainMatches.includes(cred)); domainMatches.sort((a, b) => (a.service_hint || '').localeCompare(b.service_hint || '')); otherCredentials.sort((a, b) => (a.service_hint || '').localeCompare(b.service_hint || '')); filtered = [...domainMatches, ...otherCredentials]; }
     else { filtered = allCredentials.filter(cred => { if (searchTerm) { const hintMatch = cred.service_hint && cred.service_hint.toLowerCase().includes(searchTerm); const usernameMatch = cred.decrypted_username_temp && cred.decrypted_username_temp.toLowerCase().includes(searchTerm); return hintMatch || usernameMatch; } else { return true; } }); filtered.sort((a, b) => (a.service_hint || '').localeCompare(b.service_hint || '')); }
     if (filtered.length === 0) { const message = searchTerm ? "No credentials match search." : (allCredentials.length === 0 ? "No credentials saved yet." : "No credentials to display."); passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: #777; list-style: none;">${message}</li>`; return; }
     filtered.forEach(cred => renderCredentialItem(cred, domainMatches.includes(cred)));
}
function renderCredentialItem(credential, isDomainMatch = false) {
    const li = document.createElement('li'); li.className = 'password-item'; li.dataset.encrypted = credential.encrypted_data; li.dataset.serviceHint = credential.service_hint || '(No Hint)';
    if (isDomainMatch) { li.style.backgroundColor = "rgba(0, 123, 255, 0.05)"; }
    const itemContainer = document.createElement('div'); itemContainer.style.flexGrow = '1'; itemContainer.style.overflow = 'hidden';
    const infoDiv = document.createElement('div'); infoDiv.className = 'item-info'; infoDiv.innerHTML = `<strong>${escapeHtml(credential.service_hint || '(No Hint)')}</strong><span class="username-display">(Username Hidden)</span>`;
    const strengthDiv = document.createElement('div'); strengthDiv.className = 'strength-display-popup'; itemContainer.append(infoDiv, strengthDiv);
    const actionsDiv = document.createElement('div'); actionsDiv.className = 'item-actions';
    const showBtn = document.createElement('button'); showBtn.textContent = 'Show'; showBtn.title = 'Decrypt/show details'; showBtn.onclick = (e) => { e.stopPropagation(); handleShowDetails(li); };
    const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy'; copyBtn.title = 'Copy password'; copyBtn.onclick = (e) => { e.stopPropagation(); handleCopyPassword(li); }; copyBtn.style.display = 'none';
    const fillBtn = document.createElement('button'); fillBtn.textContent = 'Fill'; fillBtn.title = 'Fill username & password on current page'; fillBtn.onclick = (e) => { e.stopPropagation(); handleFillPassword(li); }; fillBtn.style.display = 'none';
    if (isDomainMatch) { li.title = `Click to fill ${escapeHtml(credential.service_hint || '')}`; li.style.cursor = 'pointer'; li.addEventListener('click', async (e) => { if (e.target === li || e.target.closest('.item-info')) { if (!derivedEncryptionKey) { alert("Cannot decrypt. Please unlock first."); return; } const decrypted = await decryptData(derivedEncryptionKey, credential.encrypted_data); if (decrypted && decrypted.password) { handleDirectFill(decrypted.username || '', decrypted.password); } else { alert("Decryption failed. Cannot fill."); } } }); }
    actionsDiv.append(showBtn, copyBtn, fillBtn); li.append(itemContainer, actionsDiv); passwordList.appendChild(li);
}
async function handleShowDetails(listItem) {
    if (!derivedEncryptionKey) { alert("Cannot decrypt. Please unlock first."); return; }
    const encryptedDataB64 = listItem.dataset.encrypted; const itemContainer = listItem.querySelector('div[style*="flex-grow"]'); const infoDiv = itemContainer.querySelector('.item-info'); const usernameSpan = infoDiv.querySelector('.username-display'); const strengthDiv = itemContainer.querySelector('.strength-display-popup'); const showBtn = listItem.querySelector('.item-actions button:nth-child(1)'); const copyBtn = listItem.querySelector('.item-actions button:nth-child(2)'); const fillBtn = listItem.querySelector('.item-actions button:nth-child(3)'); const assessmentMap = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];
    if (showBtn.textContent === 'Show') { showBtn.textContent = '...'; showBtn.disabled = true; strengthDiv.style.display = 'none'; const decrypted = await decryptData(derivedEncryptionKey, encryptedDataB64); showBtn.disabled = false; if (decrypted) { const service = decrypted.service || '(No Service)'; const username = decrypted.username || '(No Username)'; const password = decrypted.password || ''; infoDiv.querySelector('strong').textContent = escapeHtml(service); usernameSpan.textContent = escapeHtml(username); listItem.dataset.decryptedPassword = password; listItem.dataset.decryptedUsername = username; listItem.decrypted_username_temp = username.toLowerCase(); showBtn.textContent = 'Hide'; copyBtn.style.display = 'inline-block'; fillBtn.style.display = 'inline-block'; usernameSpan.style.color = ''; if (password && typeof zxcvbn === 'function') { const result = zxcvbn(password); const score = result.score; strengthDiv.textContent = `Strength: ${assessmentMap[score]}`; strengthDiv.className = `strength-display-popup score-${score}`; strengthDiv.style.display = 'block'; } else { strengthDiv.style.display = 'none'; } } else { usernameSpan.textContent = '(Decrypt Failed)'; usernameSpan.style.color = 'red'; showBtn.textContent = 'Error'; strengthDiv.style.display = 'none'; copyBtn.style.display = 'none'; fillBtn.style.display = 'none'; delete listItem.dataset.decryptedPassword; delete listItem.dataset.decryptedUsername; delete listItem.decrypted_username_temp; } }
    else { const originalHint = listItem.dataset.serviceHint; infoDiv.querySelector('strong').textContent = escapeHtml(originalHint); usernameSpan.textContent = '(Username Hidden)'; usernameSpan.style.color = ''; showBtn.textContent = 'Show'; copyBtn.style.display = 'none'; fillBtn.style.display = 'none'; strengthDiv.style.display = 'none'; delete listItem.dataset.decryptedPassword; delete listItem.dataset.decryptedUsername; delete listItem.decrypted_username_temp; }
}
async function handleCopyPassword(listItem) {
    const password = listItem.dataset.decryptedPassword; if (!password) { await handleShowDetails(listItem); const updatedPassword = listItem.dataset.decryptedPassword; if (!updatedPassword) { alert("Decryption failed. Cannot copy."); return; } try { await navigator.clipboard.writeText(updatedPassword); setPopupStatus("Password copied!", false, 1500); } catch (err) { setPopupStatus("Failed to copy.", true); console.error('Copy error:', err); } return; } try { await navigator.clipboard.writeText(password); setPopupStatus("Password copied!", false, 1500); } catch (err) { setPopupStatus("Failed to copy.", true); console.error('Copy error:', err); }
}
async function handleFillPassword(listItem) {
    let password = listItem.dataset.decryptedPassword; let username = listItem.dataset.decryptedUsername; if (!password) { setPopupStatus("Decrypting to fill...", false); await handleShowDetails(listItem); password = listItem.dataset.decryptedPassword; username = listItem.dataset.decryptedUsername; clearPopupStatus(); if (!password) { alert("Decryption failed. Cannot fill."); return; } } handleDirectFill(username || '', password);
}
async function handleDirectFill(username, password) {
    try { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); if (tab?.id) { chrome.tabs.sendMessage(tab.id, { action: 'fillPassword', username: username, password: password }, (response) => { if (chrome.runtime.lastError) { console.error("Fill Error (sending message):", chrome.runtime.lastError.message); setPopupStatus("Error sending fill command.", true, 2000); } else if (response && response.success) { console.log("Fill command sent successfully."); window.close(); } else { console.warn("Content script did not acknowledge fill command or reported failure."); setPopupStatus("Fill command sent.", false, 1500); } }); } else { throw new Error("No active tab found or tab has no ID."); } } catch (error) { setPopupStatus(`Fill Error: ${error.message}`, true); console.error("Fill error:", error); }
}


// --- Password Strength Checking (in Popup Add Form) ---
function handlePopupPasswordInput() {
    const password = newPasswordInput.value; const assessmentMap = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];
    if (password && typeof zxcvbn === 'function') { const result = zxcvbn(password); const score = result.score; const strengthClass = getStrengthClassFromScore(score); popupStrengthArea.style.display = 'block'; popupStrengthIndicator.className = `popup-strength-indicator ${strengthClass}`; popupStrengthTextLabel.textContent = `Strength: ${assessmentMap[score]}`; popupStrengthFeedbackDiv.innerHTML = formatZxcvbnFeedbackPopup(result); popupStrengthArea.className = `popup-strength-area strength-${score}`; }
    else { popupStrengthArea.style.display = 'none'; popupStrengthIndicator.className = 'popup-strength-indicator very-weak'; popupStrengthTextLabel.textContent = 'Strength:'; popupStrengthFeedbackDiv.innerHTML = ''; popupStrengthArea.className = 'popup-strength-area'; }
}
function formatZxcvbnFeedbackPopup(result) {
     let html = '<ul>'; if (result.feedback.warning) { html += `<li class="warning">${escapeHtml(result.feedback.warning)}</li>`; } if (result.feedback.suggestions && result.feedback.suggestions.length > 0) { result.feedback.suggestions.forEach(s => { html += `<li class="suggestion">${escapeHtml(s)}</li>`; }); } else if (!result.feedback.warning) { if (result.score < 3) html += '<li class="suggestion">Consider adding length or variety (caps, numbers, symbols).</li>'; else html += '<li class="suggestion">Looks reasonably strong!</li>'; } html += '</ul>'; return html;
 }
function getStrengthClassFromScore(score) { const classes = ['very-weak', 'weak', 'medium', 'strong', 'very-strong']; return classes[score] || 'very-weak'; }


// --- Password Generation (in Popup Add Form) ---
async function handleGeneratePopupPassword() {
     hideSaveError(); generatePopupPasswordBtn.disabled = true; generatePopupPasswordBtn.textContent = '...'; const options = { length: parseInt(popupGenLengthSlider.value, 10), use_lowercase: popupGenLowercaseCheckbox.checked, use_uppercase: popupGenUppercaseCheckbox.checked, use_digits: popupGenDigitsCheckbox.checked, use_symbols: popupGenSymbolsCheckbox.checked };
     try { const response = await fetch(`${API_BASE_URL}/api/generate_password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify(options) }); const result = await response.json(); if (response.ok && result.password) { newPasswordInput.value = result.password; newPasswordInput.type = 'text'; handlePopupPasswordInput(); setTimeout(() => { if (newPasswordInput.type === 'text') newPasswordInput.type = 'password'; }, 2000); } else { throw new Error(result.error || 'Failed to generate password from API.'); } } catch (error) { showSaveError(`Generate Error: ${error.message}`); console.error('Generate Password Error (Popup):', error); } finally { generatePopupPasswordBtn.disabled = false; generatePopupPasswordBtn.textContent = 'Generate'; }
}


// --- Save New Password ---
async function handleSavePassword() {
    const service = serviceInput.value.trim(); const username = newUsernameInput.value.trim(); const password = newPasswordInput.value; const masterPassword = masterPasswordSaveInput.value;
    if (!service || !username || !password || !masterPassword) { showSaveError("All fields & Master Password required to save."); return; }
    hideSaveError(); savePasswordBtn.disabled = true; savePasswordBtn.textContent = 'Saving...';
    try {
        if (!userEmail) throw new Error("User email missing. Cannot save.");
        const confirmationKeyBuffer = await deriveKeyRawBytes(masterPassword, userEmail);
        if (!confirmationKeyBuffer) throw new Error("Key derivation failed. Incorrect Master Password?");
        if (!derivedEncryptionKey) throw new Error("Encryption key not available. Please unlock first.");
        // Simple byte comparison check
        if (confirmationKeyBuffer.byteLength !== derivedEncryptionKey.byteLength || !new Uint8Array(confirmationKeyBuffer).every((val, i) => val === new Uint8Array(derivedEncryptionKey)[i])) { throw new Error("Master Password does not match the one used for unlock."); }

        const dataToEncrypt = { service, username, password };
        const encryptedB64Data = await encryptData(derivedEncryptionKey, dataToEncrypt); // Assumes encryptData is loaded
        const response = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ encrypted_data: encryptedB64Data, service_hint: service }) });
        const result = await response.json(); if (response.ok && result.success) { setPopupStatus("Credential saved!", false, 2000); hideAddForm(); await loadAndDisplayCredentials(); }
        else { throw new Error(result.message || `Save failed (${response.status})`); }
    } catch (error) { showSaveError(`Save failed: ${error.message}`); console.error('Save error:', error); }
    finally { savePasswordBtn.disabled = false; savePasswordBtn.textContent = 'Encrypt & Save'; masterPasswordSaveInput.value = ''; }
}


// --- Search/Filter ---
function handleSearchFilter() {
    clearTimeout(window.searchDebounceTimer);
    window.searchDebounceTimer = setTimeout(() => { filterAndRenderList(); }, 200);
}

// --- Utility ---
async function getCurrentTabDomain() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) {
            currentDomain = await new Promise((resolve) => {
                let resolved = false;
                 chrome.tabs.sendMessage(tab.id, { action: 'getDomain' }, (response) => {
                     if (resolved) return; resolved = true;
                     if (chrome.runtime.lastError) { console.warn("Get domain message error:", chrome.runtime.lastError.message); resolve((tab.url && tab.url.startsWith('http')) ? new URL(tab.url).hostname : 'N/A'); }
                     else if (response && response.domain) { resolve(response.domain); }
                     else { resolve('N/A'); }
                 });
                 setTimeout(() => { if (!resolved) { resolved = true; console.warn("Timeout getting domain from content script."); resolve((tab.url && tab.url.startsWith('http')) ? new URL(tab.url).hostname : 'N/A'); } }, 350);
            });
        } else { currentDomain = 'N/A'; }
    } catch (error) { console.warn("Could not query active tab:", error); currentDomain = 'Error'; }
    console.log("Current Domain set to:", currentDomain);
}
// --- END OF FILE popup.js ---
function escapeHtml(unsafe) {
     if (typeof unsafe !== 'string') return '';
     return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}