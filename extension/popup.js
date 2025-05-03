// --- Global Variables ---
const API_BASE_URL = 'http://127.0.0.1:5000';
let derivedEncryptionKey = null;
let userEmail = null;
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

// Popup Generator Option Elements
const popupGenLengthSlider = document.getElementById('popup-gen-length');
const popupGenLengthValueSpan = document.getElementById('popup-gen-length-value');
const popupGenLowercaseCheckbox = document.getElementById('popup-gen-lowercase');
const popupGenUppercaseCheckbox = document.getElementById('popup-gen-uppercase');
const popupGenDigitsCheckbox = document.getElementById('popup-gen-digits');
const popupGenSymbolsCheckbox = document.getElementById('popup-gen-symbols');

// Popup Add Form Strength Elements
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
popupGenLengthSlider.addEventListener('input', () => {
    popupGenLengthValueSpan.textContent = popupGenLengthSlider.value;
});
newPasswordInput.addEventListener('input', handlePopupPasswordInput); // Listener for strength check


// --- Initialization ---
document.addEventListener('DOMContentLoaded', async () => {
    await checkLoginStatus();
    await getCurrentTabDomain();
});

// --- Authentication ---
async function checkLoginStatus() {
    const result = await chrome.storage.local.get(['userEmail']);
    if (result.userEmail) {
        userEmail = result.userEmail;
        showLoginView(`Logged in as ${userEmail}. Enter Master Password to unlock.`);
        if (masterPasswordLoginInput) masterPasswordLoginInput.focus();
    } else {
        try {
            const response = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'GET', credentials: 'include' });
            if (response.ok) {
                showLoginView("Session active, but local user info missing. Please login again to re-sync.");
            } else {
                 showLoginView();
                 if (emailInput) emailInput.focus();
            }
        } catch (error) {
            showLoginView('Could not connect. Ensure the manager is running.');
            console.error('Initial status check error:', error);
        }
    }
}
async function handleLoginAttempt() {
    const email = emailInput.value.trim();
    const masterPassword = masterPasswordLoginInput.value;
    if (!email || !masterPassword) { showLoginError("Email and Master Password are required."); return; }
    loginBtn.disabled = true; loginBtn.textContent = 'Logging in...'; hideLoginError();
    try {
        derivedEncryptionKey = await deriveKeyRawBytes(masterPassword, email);
        const response = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'GET', credentials: 'include' });
        if (response.ok) {
            console.log("Credentials fetch successful (implies login ok).");
            userEmail = email;
            await chrome.storage.local.set({ userEmail: userEmail });
            showMainView(true);
        } else if (response.status === 401) {
             const loginPostResponse = await fetch(`${API_BASE_URL}/login`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ email: email, password: masterPassword }), credentials: 'include' });
             if (loginPostResponse.ok) {
                 console.log("Backend login POST successful.");
                 userEmail = email;
                 await chrome.storage.local.set({ userEmail: userEmail });
                 showMainView(true);
             } else {
                  const responseText = await loginPostResponse.text();
                  const match = responseText.match(/<div class="alert alert-danger">(.*?)<\/div>/);
                  const msg = match ? match[1].trim() : `Login failed (${loginPostResponse.status}). Invalid credentials?`;
                  showLoginError(msg);
                  derivedEncryptionKey = null; userEmail = null;
                  await chrome.storage.local.remove('userEmail');
             }
        } else {
             showLoginError(`Error accessing credentials (${response.status}). Server might be down.`);
             derivedEncryptionKey = null;
        }
    } catch (error) {
        if (error.message.includes("Could not derive") || error.message.includes("Invalid Base64URL")) {
             showLoginError("Key derivation failed. Incorrect Master Password?");
        } else {
             showLoginError(`Login error: ${error.message}. Ensure server is running.`); console.error('Login error:', error);
        }
        derivedEncryptionKey = null; userEmail = null; await chrome.storage.local.remove('userEmail');
    } finally {
        loginBtn.disabled = false; loginBtn.textContent = 'Login';
        if (masterPasswordLoginInput) masterPasswordLoginInput.value = '';
    }
}
async function handleLogout() {
    derivedEncryptionKey = null; userEmail = null; allCredentials = [];
    await chrome.storage.local.remove('userEmail');
    try { await fetch(`${API_BASE_URL}/logout`, { method: 'GET', credentials: 'include' }); }
    catch (error) { console.warn("Backend logout error:", error); }
    showLoginView("You have been logged out.");
}

// --- UI View Management ---
function showLoginView(message = null) { loginView.classList.remove('hidden'); mainView.classList.add('hidden'); if (message) showLoginError(message); else hideLoginError(); if(emailInput) emailInput.focus(); }
function showLoginError(message) { loginError.textContent = message; loginError.classList.remove('hidden'); }
function hideLoginError() { loginError.classList.add('hidden'); loginError.textContent = ''; }
function showMainView(fetchData = false) { loginView.classList.add('hidden'); mainView.classList.remove('hidden'); hideAddForm(); if (fetchData) loadAndDisplayCredentials(); currentDomainSpan.textContent = `Domain: ${currentDomain}`; currentDomainSpan.title = `Current Tab Domain: ${currentDomain}`; }
function showAddForm() { addPasswordForm.classList.remove('hidden'); addPasswordBtn.classList.add('hidden'); hideSaveError(); if (currentDomain !== 'N/A' && !serviceInput.value) { let domainName = currentDomain.replace(/^www\./, ''); serviceInput.value = domainName.charAt(0).toUpperCase() + domainName.slice(1); } if(serviceInput) serviceInput.focus(); }
function hideAddForm() {
    addPasswordForm.classList.add('hidden');
    addPasswordBtn.classList.remove('hidden');
    // Reset form fields
    serviceInput.value = '';
    newUsernameInput.value = '';
    newPasswordInput.value = '';
    masterPasswordSaveInput.value = '';
    hideSaveError();
    // Reset generator options
    popupGenLengthSlider.value = 16;
    popupGenLengthValueSpan.textContent = '16';
    popupGenLowercaseCheckbox.checked = true;
    popupGenUppercaseCheckbox.checked = true;
    popupGenDigitsCheckbox.checked = true;
    popupGenSymbolsCheckbox.checked = true;
    // Clear strength display
    if (popupStrengthArea) popupStrengthArea.style.display = 'none';
    if (popupStrengthIndicator) popupStrengthIndicator.className = 'popup-strength-indicator very-weak'; // Reset class
    if (popupStrengthIndicator) popupStrengthIndicator.style.width = '0%'; // Reset width
    if (popupStrengthTextLabel) popupStrengthTextLabel.textContent = 'Strength:';
    if (popupStrengthFeedbackDiv) popupStrengthFeedbackDiv.innerHTML = '';
    if (popupStrengthArea) popupStrengthArea.className = 'popup-strength-area'; // Reset background
}
function showSaveError(message) { saveError.textContent = message; saveError.classList.remove('hidden'); }
function hideSaveError() { saveError.textContent = ''; saveError.classList.add('hidden'); }
function setPopupStatus(message, isError = false, duration = 0) { statusIndicator.textContent = message; statusIndicator.className = `status-message ${isError ? 'status-error' : 'status-info'}`; statusIndicator.classList.remove('hidden'); if (duration > 0) { setTimeout(clearPopupStatus, duration); } }
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
        if (!encryptedCredentials || encryptedCredentials.length === 0) { passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: #777; list-style: none;">No credentials saved yet.</li>`; }
        else { filterAndRenderList(); }
    } catch (error) { setPopupStatus(`Error loading: ${error.message}`, true); console.error('Load error:', error); }
}

function filterAndRenderList() {
     passwordList.innerHTML = ''; const searchTerm = searchInput.value.toLowerCase().trim();
     const filtered = allCredentials.filter(cred => { if (searchTerm) return cred.service_hint && cred.service_hint.toLowerCase().includes(searchTerm); else return true; });
      if (filtered.length === 0) { const message = searchTerm ? "No credentials match search." : (allCredentials.length === 0 ? "No credentials saved yet." : "No credentials to display."); passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: #777; list-style: none;">${message}</li>`; return; }
     filtered.forEach(renderCredentialItem);
}

function renderCredentialItem(credential) {
    const li = document.createElement('li');
    li.className = 'password-item';
    li.dataset.encrypted = credential.encrypted_data;

    const itemContainer = document.createElement('div'); // Wrap info and strength
    itemContainer.style.flexGrow = '1';
    itemContainer.style.overflow = 'hidden';

    const infoDiv = document.createElement('div');
    infoDiv.className = 'item-info';
    infoDiv.innerHTML = `<strong>${escapeHtml(credential.service_hint || '(No Hint)')}</strong><span class="username-display">(Username Hidden)</span>`;

    const strengthDiv = document.createElement('div');
    strengthDiv.className = 'strength-display-popup'; // Style this class
    // Content set when 'Show' is clicked

    itemContainer.append(infoDiv, strengthDiv);

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'item-actions';
    const showBtn = document.createElement('button'); showBtn.textContent = 'Show'; showBtn.title = 'Decrypt/show details'; showBtn.onclick = () => handleShowDetails(li);
    const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy'; copyBtn.title = 'Copy password'; copyBtn.onclick = () => handleCopyPassword(li); copyBtn.style.display = 'none';
    const fillBtn = document.createElement('button'); fillBtn.textContent = 'Fill'; fillBtn.title = 'Fill password'; fillBtn.onclick = () => handleFillPassword(li); fillBtn.style.display = 'none';

    actionsDiv.append(showBtn, copyBtn, fillBtn);
    li.append(itemContainer, actionsDiv);
    passwordList.appendChild(li);
}


async function handleShowDetails(listItem) {
    if (!derivedEncryptionKey) { alert("Cannot decrypt. Key missing."); return; }
    const encryptedDataB64 = listItem.dataset.encrypted;
    const itemContainer = listItem.querySelector('div[style*="flex-grow"]'); // Find the container
    const infoDiv = itemContainer.querySelector('.item-info');
    const usernameSpan = infoDiv.querySelector('.username-display');
    const strengthDiv = itemContainer.querySelector('.strength-display-popup');
    const showBtn = listItem.querySelector('.item-actions button:nth-child(1)');
    const copyBtn = listItem.querySelector('.item-actions button:nth-child(2)');
    const fillBtn = listItem.querySelector('.item-actions button:nth-child(3)');
    const assessmentMap = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];

    if (showBtn.textContent === 'Show') {
        showBtn.textContent = '...'; showBtn.disabled = true; strengthDiv.style.display = 'none';
        const decrypted = await decryptData(derivedEncryptionKey, encryptedDataB64);
        showBtn.disabled = false;
        if (decrypted) {
            infoDiv.querySelector('strong').textContent = escapeHtml(decrypted.service || '(No Service)');
            usernameSpan.textContent = escapeHtml(decrypted.username || '(No Username)');
            listItem.dataset.decryptedPassword = decrypted.password;
            showBtn.textContent = 'Hide'; copyBtn.style.display = 'inline-block'; fillBtn.style.display = 'inline-block'; usernameSpan.style.color = '';

            // Calculate and show strength
            if (decrypted.password && typeof zxcvbn === 'function') {
                 const result = zxcvbn(decrypted.password);
                 const score = result.score;
                 strengthDiv.textContent = `Strength: ${assessmentMap[score]}`;
                 strengthDiv.className = `strength-display-popup score-${score}`; // Apply color class
                 strengthDiv.style.display = 'block';
            } else {
                 strengthDiv.style.display = 'none';
            }

        } else { usernameSpan.textContent = '(Decrypt Failed)'; usernameSpan.style.color = 'red'; showBtn.textContent = 'Error'; strengthDiv.style.display = 'none';}
    } else {
        // Hide details
        const originalHint = allCredentials.find(c => c.encrypted_data === encryptedDataB64)?.service_hint;
        infoDiv.querySelector('strong').textContent = escapeHtml(originalHint || '(No Hint)');
        usernameSpan.textContent = '(Username Hidden)'; usernameSpan.style.color = '';
        showBtn.textContent = 'Show'; copyBtn.style.display = 'none'; fillBtn.style.display = 'none';
        strengthDiv.style.display = 'none'; // Hide strength
        delete listItem.dataset.decryptedPassword;
    }
}

async function handleCopyPassword(listItem) { const password = listItem.dataset.decryptedPassword; if (!password) { alert("Click 'Show' first to decrypt."); return; } try { await navigator.clipboard.writeText(password); setPopupStatus("Password copied!", false, 1500); } catch (err) { setPopupStatus("Failed to copy.", true); console.error('Copy error:', err); } }
async function handleFillPassword(listItem) { const password = listItem.dataset.decryptedPassword; if (!password) { alert("Click 'Show' first to decrypt."); return; } try { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); if (tab?.id) { await chrome.scripting.executeScript({ target: { tabId: tab.id }, function: fillPasswordOnPage, args: [password] }); window.close(); } else throw new Error("No active tab found."); } catch (error) { setPopupStatus(`Fill Error: ${error.message}`, true); console.error("Fill error:", error); } }
function fillPasswordOnPage(password) { const p = document.querySelectorAll('input[type="password"][autocomplete*="current-password"], input[type="password"]'); if (p.length > 0) { const f = p[0]; f.focus(); f.value = password; f.dispatchEvent(new Event('input', { bubbles: true, composed: true })); f.dispatchEvent(new Event('change', { bubbles: true })); console.log("Password field filled via Secure PWM."); } else { console.warn("Secure PWM: Password field not found."); } }

// Popup Password Input Handler
function handlePopupPasswordInput() {
    const password = newPasswordInput.value;
    const assessmentMap = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];

    if (password && typeof zxcvbn === 'function') {
        const result = zxcvbn(password);
        const score = result.score;
        const strengthClass = getStrengthClassFromScore(score); // Reuse helper

        popupStrengthArea.style.display = 'block';
        popupStrengthIndicator.className = `popup-strength-indicator ${strengthClass}`; // Update bar CSS class
        popupStrengthTextLabel.textContent = `Strength: ${assessmentMap[score]}`;
        popupStrengthFeedbackDiv.innerHTML = formatZxcvbnFeedbackPopup(result); // Use popup formatter

        // Update area background
        popupStrengthArea.className = `popup-strength-area strength-${score}`;

    } else {
        // Clear display
        popupStrengthArea.style.display = 'none';
        popupStrengthIndicator.className = 'popup-strength-indicator very-weak';
        popupStrengthIndicator.style.width = '0%';
        popupStrengthTextLabel.textContent = 'Strength:';
        popupStrengthFeedbackDiv.innerHTML = '';
        popupStrengthArea.className = 'popup-strength-area';
    }
}

// Helper function for popup feedback formatting
function formatZxcvbnFeedbackPopup(result) {
     let html = '<ul>';
     if (result.feedback.warning) {
         html += `<li class="warning">${escapeHtml(result.feedback.warning)}</li>`;
     }
     if (result.feedback.suggestions && result.feedback.suggestions.length > 0) {
         result.feedback.suggestions.forEach(s => { html += `<li class="suggestion">${escapeHtml(s)}</li>`; });
     } else if (!result.feedback.warning) {
         if (result.score < 3) html += '<li class="suggestion">Add length or variety.</li>';
     }
     html += '</ul>';
     return html;
 }
// Reuse strength class helper
function getStrengthClassFromScore(score) {
     const classes = ['very-weak', 'weak', 'medium', 'strong', 'very-strong'];
     return classes[score] || 'very-weak';
}
function escapeHtml(unsafe) {
     if (typeof unsafe !== 'string') return '';
     return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }


// Generate Password Handler (Update to trigger input event)
async function handleGeneratePopupPassword() {
     if (!userEmail || !derivedEncryptionKey) { showSaveError("Please log in fully to generate passwords."); return; }
     hideSaveError();
     generatePopupPasswordBtn.disabled = true; generatePopupPasswordBtn.textContent = '...';

     const options = {
         length: parseInt(popupGenLengthSlider.value, 10),
         use_lowercase: popupGenLowercaseCheckbox.checked,
         use_uppercase: popupGenUppercaseCheckbox.checked,
         use_digits: popupGenDigitsCheckbox.checked,
         use_symbols: popupGenSymbolsCheckbox.checked
     };

     try {
         const response = await fetch(`${API_BASE_URL}/api/generate_password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify(options) });
         const result = await response.json();
         if (response.ok && result.password) {
             newPasswordInput.value = result.password;
             newPasswordInput.type = 'text';
             // !!! TRIGGER INPUT EVENT !!!
             newPasswordInput.dispatchEvent(new Event('input', { bubbles: true }));
             setTimeout(() => { if (newPasswordInput.type === 'text') newPasswordInput.type = 'password'; }, 2000);
         } else { throw new Error(result.error || 'Failed to generate password from API.'); }
     } catch (error) { showSaveError(`Generate Error: ${error.message}`); console.error('Generate Password Error (Popup):', error); }
     finally { generatePopupPasswordBtn.disabled = false; generatePopupPasswordBtn.textContent = 'Generate'; }
}

// Save Password Handler (Updated to reset strength on success in hideAddForm)
async function handleSavePassword() {
    const service = serviceInput.value.trim(); const username = newUsernameInput.value.trim(); const password = newPasswordInput.value; const masterPassword = masterPasswordSaveInput.value;
    if (!service || !username || !password || !masterPassword) { showSaveError("All fields & Master PW required."); return; }
    hideSaveError(); savePasswordBtn.disabled = true; savePasswordBtn.textContent = 'Saving...';
    try {
        if (!userEmail) throw new Error("User email missing.");
        const keyBuffer = await deriveKeyRawBytes(masterPassword, userEmail); if (!keyBuffer) throw new Error("Key derivation failed. Incorrect Master Password?");
        try { console.log(`DEBUG: JS Encrypt Key (Std B64): ${arrayBufferToBase64(keyBuffer)}`); } catch(logErr) {}
        const dataToEncrypt = { service, username, password }; const encryptedB64Data = await encryptData(keyBuffer, dataToEncrypt);
        const response = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ encrypted_data: encryptedB64Data, service_hint: service }) });
        const result = await response.json(); if (response.ok && result.success) { setPopupStatus("Credential saved!", false, 1500); hideAddForm(); await loadAndDisplayCredentials(); }
        else throw new Error(result.message || `Save failed (${response.status})`);
    } catch (error) { showSaveError(`Save failed: ${error.message}`); console.error('Save error:', error); }
    finally { savePasswordBtn.disabled = false; savePasswordBtn.textContent = 'Encrypt & Save'; masterPasswordSaveInput.value = ''; }
}

function handleSearchFilter() { filterAndRenderList(); }

// --- Utility ---
async function getCurrentTabDomain() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.url && tab.url.startsWith('http')) { const url = new URL(tab.url); currentDomain = url.hostname; }
        else { currentDomain = 'N/A'; }
    } catch (error) { console.warn("Could not get domain:", error); currentDomain = 'Error'; }
    if (!mainView.classList.contains('hidden')) { currentDomainSpan.textContent = `Domain: ${currentDomain}`; currentDomainSpan.title = `Current Tab Domain: ${currentDomain}`; }
}