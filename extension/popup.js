// --- Global Variables ---
const API_BASE_URL = 'http://127.0.0.1:5000'; // Ensure this matches your Flask backend
let derivedEncryptionKey = null; // Holds the raw ArrayBuffer key IN MEMORY ONLY
let userEmail = null; // Store logged-in user's email (needed for salt)
let allCredentials = []; // Cache fetched encrypted credentials
let currentDomain = 'N/A'; // Store domain of the active tab

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


// --- Event Listeners ---
loginBtn.addEventListener('click', handleLoginAttempt);
logoutBtn.addEventListener('click', handleLogout);
addPasswordBtn.addEventListener('click', showAddForm);
cancelAddBtn.addEventListener('click', hideAddForm);
savePasswordBtn.addEventListener('click', handleSavePassword);
searchInput.addEventListener('input', handleSearchFilter);

// --- Initialization ---
document.addEventListener('DOMContentLoaded', async () => {
    await checkLoginStatus(); // Check if backend session exists
    await getCurrentTabDomain(); // Get domain info
    // Note: Actual loading of credentials happens AFTER key is derived/confirmed
});

// --- Authentication ---

async function checkLoginStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'GET', credentials: 'include' });
        if (response.ok) {
            const result = await chrome.storage.local.get(['userEmail']);
            if (result.userEmail) {
                userEmail = result.userEmail;
                 // Still need master password to derive key for decryption
                 showLoginView(`Logged in as ${userEmail}. Enter Master Password to unlock.`);
            } else { showLoginView("Session active, but user info missing. Please login again."); }
        } else if (response.status === 401) { showLoginView(); /* Standard login prompt */ }
        else { showLoginView(`Error checking status (${response.status})`); }
    } catch (error) { showLoginView('Could not connect to the server.'); console.error('Status check error:', error); }
}

async function handleLoginAttempt() {
    const email = emailInput.value.trim();
    const masterPassword = masterPasswordLoginInput.value;
    if (!email || !masterPassword) { showLoginError("Email and Master Password are required."); return; }
    loginBtn.disabled = true; loginBtn.textContent = 'Logging in...'; hideLoginError();

    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ email: email, password: masterPassword }), credentials: 'include'
        });
        if (response.ok) {
            console.log("Backend login successful.");
            // Derive key immediately after successful login
            derivedEncryptionKey = await deriveKeyRawBytes(masterPassword, email); // crypto-helpers.js logs here
            userEmail = email;
            await chrome.storage.local.set({ userEmail: userEmail }); // Store email for persistence
            showMainView(true); // true = load credentials now key is derived
        } else {
            const responseText = await response.text();
            const match = responseText.match(/<div class="alert alert-danger">(.*?)<\/div>/);
            const msg = match ? match[1].trim() : `Login failed (${response.status}). Invalid credentials?`;
            showLoginError(msg); derivedEncryptionKey = null; userEmail = null;
            await chrome.storage.local.remove('userEmail');
        }
    } catch (error) {
        showLoginError(`Login error: ${error.message}`); console.error('Login error:', error);
        derivedEncryptionKey = null; userEmail = null; await chrome.storage.local.remove('userEmail');
    } finally {
        loginBtn.disabled = false; loginBtn.textContent = 'Login'; masterPasswordLoginInput.value = '';
    }
}

async function handleLogout() {
    derivedEncryptionKey = null; userEmail = null; allCredentials = [];
    await chrome.storage.local.remove('userEmail');
    try { await fetch(`${API_BASE_URL}/logout`, { method: 'GET', credentials: 'include' }); }
    catch (error) { console.warn("Backend logout error:", error); }
    showLoginView("You have been logged out.");
}

// --- UI View Management --- (Keep functions as before: showLoginView, showLoginError, hideLoginError, showMainView, showAddForm, hideAddForm, showSaveError, hideSaveError, setPopupStatus, clearPopupStatus)
function showLoginView(message = null) { loginView.classList.remove('hidden'); mainView.classList.add('hidden'); if (message) showLoginError(message); else hideLoginError(); if(emailInput) emailInput.focus(); }
function showLoginError(message) { loginError.textContent = message; loginError.classList.remove('hidden'); }
function hideLoginError() { loginError.classList.add('hidden'); loginError.textContent = ''; }
function showMainView(fetchData = false) { loginView.classList.add('hidden'); mainView.classList.remove('hidden'); hideAddForm(); if (fetchData) loadAndDisplayCredentials(); currentDomainSpan.textContent = `Domain: ${currentDomain}`; currentDomainSpan.title = `Current Tab Domain: ${currentDomain}`; }
function showAddForm() { addPasswordForm.classList.remove('hidden'); addPasswordBtn.classList.add('hidden'); hideSaveError(); if (currentDomain !== 'N/A' && !serviceInput.value) { let domainName = currentDomain.replace(/^www\./, ''); serviceInput.value = domainName.charAt(0).toUpperCase() + domainName.slice(1); } if(serviceInput) serviceInput.focus(); }
function hideAddForm() { addPasswordForm.classList.add('hidden'); addPasswordBtn.classList.remove('hidden'); serviceInput.value = ''; newUsernameInput.value = ''; newPasswordInput.value = ''; masterPasswordSaveInput.value = ''; hideSaveError(); }
function showSaveError(message) { saveError.textContent = message; saveError.classList.remove('hidden'); }
function hideSaveError() { saveError.textContent = ''; saveError.classList.add('hidden'); }
function setPopupStatus(message, isError = false) { statusIndicator.textContent = message; statusIndicator.className = `status-message ${isError ? 'status-error' : 'status-info'}`; statusIndicator.classList.remove('hidden'); }
function clearPopupStatus() { statusIndicator.classList.add('hidden'); statusIndicator.textContent = ''; statusIndicator.className = 'status-message status-info'; }


// --- Credential Handling ---

async function loadAndDisplayCredentials() {
    if (!derivedEncryptionKey) { setPopupStatus("Cannot load credentials. Key not available.", true); return; }
    setPopupStatus("Loading credentials...", false); passwordList.innerHTML = '';
    try {
        const response = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'GET', credentials: 'include' });
        if (!response.ok) {
            if (response.status === 401) { showLoginView("Session expired. Login again."); derivedEncryptionKey = null; userEmail = null; await chrome.storage.local.remove('userEmail'); }
            else throw new Error(`Failed to fetch (${response.status})`); return;
        }
        const encryptedCredentials = await response.json(); allCredentials = encryptedCredentials; clearPopupStatus();
        if (!encryptedCredentials || encryptedCredentials.length === 0) { setPopupStatus("No credentials saved yet.", false); }
        else { filterAndRenderList(); }
    } catch (error) { setPopupStatus(`Error loading: ${error.message}`, true); console.error('Load error:', error); }
}

function filterAndRenderList() {
     passwordList.innerHTML = ''; const searchTerm = searchInput.value.toLowerCase().trim();
     const filtered = allCredentials.filter(cred => {
         if (searchTerm) return cred.service_hint && cred.service_hint.toLowerCase().includes(searchTerm);
         else return true; // Show all if no search term
     });
      if (filtered.length === 0) {
         const message = searchTerm ? "No credentials match search." : (allCredentials.length === 0 ? "No credentials saved yet." : "No credentials to display.");
         passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: #777; list-style: none;">${message}</li>`; return;
     }
     filtered.forEach(renderCredentialItem);
}

function renderCredentialItem(credential) {
    const li = document.createElement('li'); li.className = 'password-item'; li.dataset.encrypted = credential.encrypted_data;
    const infoDiv = document.createElement('div'); infoDiv.className = 'item-info';
    infoDiv.innerHTML = `<strong>${escapeHtml(credential.service_hint || '(No Hint)')}</strong><span class="username-display">(Username Hidden)</span>`;
    const actionsDiv = document.createElement('div'); actionsDiv.className = 'item-actions';
    const showBtn = document.createElement('button'); showBtn.textContent = 'Show'; showBtn.title = 'Decrypt/show details'; showBtn.onclick = () => handleShowDetails(li);
    const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy'; copyBtn.title = 'Copy password'; copyBtn.onclick = () => handleCopyPassword(li); copyBtn.style.display = 'none';
    const fillBtn = document.createElement('button'); fillBtn.textContent = 'Fill'; fillBtn.title = 'Fill password'; fillBtn.onclick = () => handleFillPassword(li); fillBtn.style.display = 'none';
    actionsDiv.append(showBtn, copyBtn, fillBtn); li.append(infoDiv, actionsDiv); passwordList.appendChild(li);
}

async function handleShowDetails(listItem) {
    if (!derivedEncryptionKey) { alert("Cannot decrypt. Key missing."); return; }
    const encryptedDataB64 = listItem.dataset.encrypted;
    const infoDiv = listItem.querySelector('.item-info'); const usernameSpan = infoDiv.querySelector('.username-display');
    const showBtn = listItem.querySelector('.item-actions button:nth-child(1)'); const copyBtn = listItem.querySelector('.item-actions button:nth-child(2)'); const fillBtn = listItem.querySelector('.item-actions button:nth-child(3)');

    if (showBtn.textContent === 'Show') {
        showBtn.textContent = '...'; showBtn.disabled = true;
        const decrypted = await decryptData(derivedEncryptionKey, encryptedDataB64); // crypto-helpers.js
        showBtn.disabled = false;
        if (decrypted) {
            infoDiv.querySelector('strong').textContent = escapeHtml(decrypted.service || '(No Service)');
            usernameSpan.textContent = escapeHtml(decrypted.username || '(No Username)');
            listItem.dataset.decryptedPassword = decrypted.password; // Store plain text temporarily
            showBtn.textContent = 'Hide'; copyBtn.style.display = 'inline-block'; fillBtn.style.display = 'inline-block'; usernameSpan.style.color = '';
        } else { usernameSpan.textContent = '(Decrypt Failed)'; usernameSpan.style.color = 'red'; showBtn.textContent = 'Error'; }
    } else {
        const originalHint = allCredentials.find(c => c.encrypted_data === encryptedDataB64)?.service_hint;
        infoDiv.querySelector('strong').textContent = escapeHtml(originalHint || '(No Hint)');
        usernameSpan.textContent = '(Username Hidden)'; usernameSpan.style.color = '';
        showBtn.textContent = 'Show'; copyBtn.style.display = 'none'; fillBtn.style.display = 'none';
        delete listItem.dataset.decryptedPassword; // Clear temp plain text
    }
}

async function handleCopyPassword(listItem) {
     const password = listItem.dataset.decryptedPassword;
     if (!password) { alert("Click 'Show' first to decrypt."); return; }
     try { await navigator.clipboard.writeText(password); setPopupStatus("Password copied!", false); setTimeout(clearPopupStatus, 1500); }
     catch (err) { setPopupStatus("Failed to copy.", true); console.error('Copy error:', err); }
}

async function handleFillPassword(listItem) {
     const password = listItem.dataset.decryptedPassword;
     if (!password) { alert("Click 'Show' first to decrypt."); return; }
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) { await chrome.scripting.executeScript({ target: { tabId: tab.id }, function: fillPasswordOnPage, args: [password] }); window.close(); }
        else throw new Error("No active tab found.");
    } catch (error) { setPopupStatus(`Fill Error: ${error.message}`, true); console.error("Fill error:", error); }
}
function fillPasswordOnPage(password) { /* ... Keep function as provided before ... */
     const passwordInputs = document.querySelectorAll('input[type="password"][autocomplete*="current-password"], input[type="password"]');
     if (passwordInputs.length > 0) { const field = passwordInputs[0]; field.focus(); field.value = password;
         field.dispatchEvent(new Event('input', { bubbles: true, composed: true })); field.dispatchEvent(new Event('change', { bubbles: true }));
         console.log("Password field filled."); }
     else { console.warn("Password field not found for autofill."); }
}

async function handleSavePassword() {
    const service = serviceInput.value.trim(); const username = newUsernameInput.value.trim();
    const password = newPasswordInput.value; const masterPassword = masterPasswordSaveInput.value;
    if (!service || !username || !password || !masterPassword) { showSaveError("All fields & Master PW required."); return; }
     hideSaveError(); savePasswordBtn.disabled = true; savePasswordBtn.textContent = 'Saving...';

    try {
        if (!userEmail) throw new Error("User email missing.");
        // Derive key again using the CONFIRMED master password
        const keyBuffer = await deriveKeyRawBytes(masterPassword, userEmail);
        if (!keyBuffer) throw new Error("Key derivation failed.");

        // --- ADDED LOGGING ---
        try { console.log(`DEBUG: JS Encrypt Key (Raw -> Standard Base64): ${arrayBufferToBase64(keyBuffer)}`); }
        catch(logErr) { console.error("DEBUG: Error logging JS encrypt key", logErr); }
        // --- END LOGGING ---

        const dataToEncrypt = { service, username, password };
        const encryptedB64Data = await encryptData(keyBuffer, dataToEncrypt); // crypto-helpers.js

        const response = await fetch(`${API_BASE_URL}/api/credentials`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
            body: JSON.stringify({ encrypted_data: encryptedB64Data, service_hint: service })
        });
        const result = await response.json();
        if (response.ok && result.success) {
            setPopupStatus("Credential saved!", false); hideAddForm(); setTimeout(clearPopupStatus, 1500);
            await loadAndDisplayCredentials(); // Refresh list
        } else throw new Error(result.message || `Save failed (${response.status})`);
    } catch (error) { showSaveError(`Save failed: ${error.message}`); console.error('Save error:', error);
    } finally { savePasswordBtn.disabled = false; savePasswordBtn.textContent = 'Encrypt & Save'; masterPasswordSaveInput.value = ''; }
}

function handleSearchFilter() { filterAndRenderList(); }

// --- Utility ---
async function getCurrentTabDomain() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url && tab.url.startsWith('http')) { // Only process http/https URLs
             const url = new URL(tab.url); currentDomain = url.hostname;
        } else { currentDomain = 'N/A'; } // Handle chrome://, file:// etc.
    } catch (error) { console.warn("Could not get domain:", error); currentDomain = 'Error'; }
     // Update UI if main view is visible
     if (!mainView.classList.contains('hidden')) {
         currentDomainSpan.textContent = `Domain: ${currentDomain}`;
         currentDomainSpan.title = `Current Tab Domain: ${currentDomain}`;
     }
     // Trigger filtering based on domain if needed (e.g., if list already loaded)
     // if(allCredentials.length > 0) filterAndRenderList(); // Re-filter if needed
}