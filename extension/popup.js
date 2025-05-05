// --- START OF FILE popup.js ---

// --- Global Variables ---
const API_BASE_URL = 'http://127.0.0.1:5000'; // Adjust if your backend runs elsewhere
let derivedEncryptionKey = null; // ArrayBuffer | null - Key used for crypto ops after login/unlock
let userEmail = null; // string | null - Email of the logged-in/remembered user
let allCredentials = []; // Array to hold fetched credential objects {id, encrypted_data, service_hint}
let currentDomain = 'N/A'; // Domain of the active browser tab

// --- DOM Elements (Define references early, check existence before use) ---
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
const newPasswordInput = document.getElementById('new-password'); // Reference needed early
const masterPasswordSaveInput = document.getElementById('masterPasswordSave');
const saveError = document.getElementById('save-error');
const logoutBtn = document.getElementById('logout-btn');
const currentDomainSpan = document.getElementById('current-domain');
const generatePopupPasswordBtn = document.getElementById('generate-popup-password-btn');
const popupThemeToggleBtn = document.getElementById('popup-theme-toggle');
// Generator Options Elements
const popupGenLengthSlider = document.getElementById('popup-gen-length');
const popupGenLengthValueSpan = document.getElementById('popup-gen-length-value');
const popupGenLowercaseCheckbox = document.getElementById('popup-gen-lowercase');
const popupGenUppercaseCheckbox = document.getElementById('popup-gen-uppercase');
const popupGenDigitsCheckbox = document.getElementById('popup-gen-digits');
const popupGenSymbolsCheckbox = document.getElementById('popup-gen-symbols');
// Popup Add Form Analysis Elements
const popupStrengthArea = document.getElementById('popup-strength-area');
const popupStrengthIndicator = document.getElementById('popup-strength-indicator');
const popupStrengthTextLabel = document.getElementById('popup-strength-text-label');
const popupStrengthFeedbackDiv = document.getElementById('popup-strength-feedback');
const popupBreachStatusArea = document.getElementById('popup-breach-status');
const popupBreachIndicator = document.getElementById('popup-breach-indicator');


// --- Utility & Helper Functions (Defined Outside DOMContentLoaded) ---

// Debounce function specific to popup analysis
let debounceTimerPopup;
function debouncePopup(func, delay) {
    return function(...args) {
        clearTimeout(debounceTimerPopup);
        debounceTimerPopup = setTimeout(() => {
            func.apply(this, args); // Pass 'this' and arguments
        }, delay);
    };
}

// Helper to format zxcvbn feedback for the popup
function formatZxcvbnFeedbackPopup(result) {
     if (!result || !result.feedback) return '';
     let html = '<ul>';
     if (result.feedback.warning) { html += `<li class="warning">${escapeHtml(result.feedback.warning)}</li>`; }
     if (result.feedback.suggestions && result.feedback.suggestions.length > 0) { result.feedback.suggestions.forEach(s => { html += `<li class="suggestion">${escapeHtml(s)}</li>`; }); }
     else if (!result.feedback.warning) { if (result.score < 3) { html += '<li class="suggestion">Add length or variety (caps, nums, symbols).</li>'; } }
     html += '</ul>';
     return html;
 }

// Helper to map zxcvbn score (0-4) to CSS class
function getStrengthClassFromScore(score) {
     const classes = ['very-weak', 'weak', 'medium', 'strong', 'very-strong'];
     const validScore = Math.max(0, Math.min(score ?? 0, 4));
     return classes[validScore];
 }

// Helper to compare two ArrayBuffers
function compareArrayBuffers(buf1, buf2) {
    if (!buf1 || !buf2 || buf1.byteLength !== buf2.byteLength) return false;
    const view1 = new Uint8Array(buf1);
    const view2 = new Uint8Array(buf2);
    for (let i = 0; i < buf1.byteLength; i++) { if (view1[i] !== view2[i]) return false; }
    return true;
}

// --- Theme Handling ---
function applyPopupTheme() {
    chrome.storage.local.get(['popupTheme'], (result) => {
        const theme = result.popupTheme || 'light';
        document.body.setAttribute('data-theme', theme);
        if (popupThemeToggleBtn) {
            popupThemeToggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
            popupThemeToggleBtn.title = `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`;
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
    console.log("[Popup] Sending message to background ->", message.action, message);
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
                 console.log("[Popup] Received response from background for ->", message.action, response);
                 if (response && response.success === false && response.error) {
                     reject(new Error(response.error));
                 } else {
                    resolve(response);
                 }
            }
        });
    });
}

// --- Authentication Functions ---
async function checkLoginStatus() { /* ... (code as before) ... */
    console.log("Popup: Checking login status...");
    try {
        const response = await sendMessageToBackground({ action: 'getKey' });
        if (response && response.success && typeof response.keyB64 === 'string' && response.email) {
            derivedEncryptionKey = base64ToArrayBuffer(response.keyB64);
            userEmail = response.email;
            showMainView(true); updateDomainDisplay();
        } else {
             const emailCheckResponse = await sendMessageToBackground({ action: 'getEmail' });
             if (emailCheckResponse?.success && emailCheckResponse.email) {
                  userEmail = emailCheckResponse.email;
                  showLoginView(`Unlock Manager for ${userEmail}`);
                  if(emailInput) emailInput.value = userEmail;
                  if(masterPasswordLoginInput) masterPasswordLoginInput.focus();
             } else {
                  userEmail = null; derivedEncryptionKey = null; showLoginView(); if(emailInput) emailInput.focus();
             }
        }
    } catch (error) { console.error("Popup: checkLoginStatus failed:", error); showLoginView(error.message || 'Background error.'); userEmail = null; derivedEncryptionKey = null; }
}
async function handleLoginAttempt() { /* ... (code as before) ... */
    const emailToUse = userEmail || (emailInput ? emailInput.value.trim() : '');
    const masterPassword = masterPasswordLoginInput ? masterPasswordLoginInput.value : '';
    if (!emailToUse || !masterPassword) { showLoginError("Email and Master Password required."); return; }
    if (loginBtn) { loginBtn.disabled = true; loginBtn.textContent = userEmail ? 'Unlocking...' : 'Logging in...'; }
    hideLoginError();
    let keyBuffer = null;
    try {
        keyBuffer = await deriveKeyRawBytes(masterPassword, emailToUse);
        const keyB64 = arrayBufferToBase64(keyBuffer);
        await sendMessageToBackground({ action: 'storeKey', keyB64: keyB64, email: emailToUse });
        derivedEncryptionKey = keyBuffer; userEmail = emailToUse;
        showMainView(true); updateDomainDisplay();
    } catch (error) {
        console.error('Popup: Login/Unlock error:', error); derivedEncryptionKey = null; showLoginError(`Error: ${error.message}`);
        if(userEmail && !derivedEncryptionKey) { showLoginView(`Unlock Failed: ${userEmail}`); if (emailInput) emailInput.value = userEmail; }
        else { showLoginView(); if (emailInput) emailInput.value = emailToUse; }
        if (masterPasswordLoginInput) masterPasswordLoginInput.value = '';
    } finally { if (loginBtn) { loginBtn.disabled = false; loginBtn.textContent = (userEmail && !derivedEncryptionKey) ? 'Unlock' : 'Login'; } if (masterPasswordLoginInput) masterPasswordLoginInput.value = ''; }
}
async function handleLogout() { /* ... (code as before) ... */
    console.log("Popup: Logging out."); const emailBefore = userEmail;
    derivedEncryptionKey = null; userEmail = null; allCredentials = [];
    try { await sendMessageToBackground({ action: 'clearKey' }); } catch (error) { console.error("Popup: Error clearing background key:", error.message); }
    try { await fetch(`${API_BASE_URL}/logout`, { method: 'GET', credentials: 'include' }); } catch (error) { console.warn("Popup: Backend logout failed:", error); }
    showLoginView(`Logged out: ${emailBefore || 'session'}.`); if(emailInput) emailInput.value = ''; if(masterPasswordLoginInput) masterPasswordLoginInput.value = '';
}

// --- UI View Management Functions ---
function showLoginView(message = null) { /* ... (code as before) ... */
    if (loginView) loginView.classList.remove('hidden'); if (mainView) mainView.classList.add('hidden');
    if (message) showLoginError(message); else hideLoginError();
    if (!userEmail && emailInput) emailInput.focus(); else if (userEmail && masterPasswordLoginInput) masterPasswordLoginInput.focus();
}
function showLoginError(message) { if(loginError) { loginError.textContent = message; loginError.classList.remove('hidden'); } }
function hideLoginError() { if(loginError) { loginError.classList.add('hidden'); loginError.textContent = ''; } }
function showMainView(fetchData = false) { /* ... (code as before) ... */
    if (loginView) loginView.classList.add('hidden'); if (mainView) mainView.classList.remove('hidden'); hideAddForm();
    if (fetchData && derivedEncryptionKey) loadAndDisplayCredentials();
    else if (!derivedEncryptionKey) { console.error("showMainView: Key missing!"); showLoginView("Error: Key missing. Unlock."); }
    updateDomainDisplay();
}
function updateDomainDisplay() { /* ... (code as before) ... */
    if (currentDomainSpan) { currentDomainSpan.textContent = `Domain: ${currentDomain}`; currentDomainSpan.title = `Current Tab: ${currentDomain}`; }
}
function showAddForm() { /* ... (code as before - CORRECTED CALL) ... */
    if (addPasswordForm) addPasswordForm.classList.remove('hidden');
    if (addPasswordBtn) addPasswordBtn.classList.add('hidden');
    hideSaveError();
    if (currentDomain !== 'N/A' && serviceInput && !serviceInput.value) { let dN = currentDomain.replace(/^www\./, ''); serviceInput.value = dN.charAt(0).toUpperCase() + dN.slice(1); }
    if (newPasswordInput) newPasswordInput.value = '';
    // ***** CORRECTED: Dispatch event instead of calling function directly *****
    if (newPasswordInput) {
        newPasswordInput.dispatchEvent(new Event('input', { bubbles: true }));
    }
    // ***** END CORRECTION *****
    if (masterPasswordSaveInput) masterPasswordSaveInput.value = '';
    if(serviceInput) serviceInput.focus();
}
function hideAddForm() { /* ... (code as before) ... */
    if (addPasswordForm) addPasswordForm.classList.add('hidden'); if (addPasswordBtn) addPasswordBtn.classList.remove('hidden');
    if (serviceInput) serviceInput.value = ''; if (newUsernameInput) newUsernameInput.value = ''; if (newPasswordInput) newPasswordInput.value = ''; if (masterPasswordSaveInput) masterPasswordSaveInput.value = '';
    hideSaveError();
    if (popupGenLengthSlider) popupGenLengthSlider.value = 16; if (popupGenLengthValueSpan) popupGenLengthValueSpan.textContent = '16';
    if (popupGenLowercaseCheckbox) popupGenLowercaseCheckbox.checked = true; if (popupGenUppercaseCheckbox) popupGenUppercaseCheckbox.checked = true;
    if (popupGenDigitsCheckbox) popupGenDigitsCheckbox.checked = true; if (popupGenSymbolsCheckbox) popupGenSymbolsCheckbox.checked = true;
    if (popupStrengthArea) popupStrengthArea.style.display = 'none'; if (popupBreachStatusArea) popupBreachStatusArea.style.display = 'none';
}
function showSaveError(message) { /* ... (code as before) ... */ if(saveError) { saveError.textContent = message; saveError.classList.remove('hidden'); } }
function hideSaveError() { /* ... (code as before) ... */ if(saveError) { saveError.textContent = ''; saveError.classList.add('hidden'); } }
function setPopupStatus(message, isError = false, duration = 0) { /* ... (code as before) ... */
     if (statusIndicator) { statusIndicator.textContent = message; statusIndicator.className = `status-message ${isError ? 'status-error' : (message.includes("copied") || message.includes("saved") ? 'status-success' : 'status-info')}`; statusIndicator.classList.remove('hidden'); if (duration > 0) { if (window.statusClearTimer) clearTimeout(window.statusClearTimer); window.statusClearTimer = setTimeout(clearPopupStatus, duration); }}
}
function clearPopupStatus() { /* ... (code as before) ... */ if(statusIndicator) { statusIndicator.classList.add('hidden'); statusIndicator.textContent = ''; statusIndicator.className = 'status-message status-info'; }}

// --- Credential Handling Functions ---
async function loadAndDisplayCredentials() { /* ... (code as before) ... */
    if (!derivedEncryptionKey) { console.error("loadDisplay: Key missing."); setPopupStatus("Key missing.", true); return; }
    setPopupStatus("Loading...", false); if (passwordList) passwordList.innerHTML = '';
    try { const resp = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'GET', credentials: 'include' }); if (!resp.ok) { if (resp.status === 401) { await handleLogout(); showLoginView("Session expired."); } else { throw new Error(`Fetch failed (${resp.status})`); } return; } const txt = await resp.text(); try { allCredentials = JSON.parse(txt) || []; clearPopupStatus(); if (allCredentials.length === 0) { if (passwordList) passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: var(--popup-text-secondary); list-style: none;">None saved.</li>`; } else { filterAndRenderList(); } } catch (jsonErr) { console.error("JSON Err:", jsonErr, "Resp:", txt); throw new Error(`Invalid server response (${resp.status})`); } }
    catch (error) { setPopupStatus(`Load Error: ${error.message}`, true); console.error('Load cred error:', error); }
}
function filterAndRenderList() { /* ... (code as before) ... */
     if (!passwordList) return; passwordList.innerHTML = ''; const term = searchInput ? searchInput.value.toLowerCase().trim() : ''; let filtered = []; let domainMatches = [];
     if (currentDomain !== 'N/A' && !term) { const lcDomain = currentDomain.replace(/^www\./, '').toLowerCase(); domainMatches = allCredentials.filter(c => c.service_hint?.toLowerCase().includes(lcDomain)); const others = allCredentials.filter(c => !domainMatches.includes(c)); domainMatches.sort((a, b) => (a.service_hint || '').localeCompare(b.service_hint || '')); others.sort((a, b) => (a.service_hint || '').localeCompare(b.service_hint || '')); filtered = [...domainMatches, ...others]; }
     else { filtered = allCredentials.filter(c => term ? (c.service_hint?.toLowerCase().includes(term)) : true); filtered.sort((a, b) => (a.service_hint || '').localeCompare(b.service_hint || '')); }
     if (filtered.length === 0) { const msg = term ? "No match." : (allCredentials.length === 0 ? "None saved." : "No credentials."); passwordList.innerHTML = `<li style="padding: 10px; text-align: center; color: var(--popup-text-secondary); list-style: none;">${msg}</li>`; return; }
     filtered.forEach(cred => renderCredentialItem(cred, domainMatches.includes(cred)));
}
function renderCredentialItem(credential, isDomainMatch = false) { /* ... (code as before) ... */
     if (!passwordList) return; const li = document.createElement('li'); li.className = 'password-item'; li.dataset.encrypted = credential.encrypted_data; li.dataset.serviceHint = credential.service_hint || '(No Hint)';
     if (isDomainMatch) { li.style.setProperty('--popup-item-hover', 'rgba(0, 123, 255, 0.1)'); li.style.borderLeft = '3px solid var(--popup-primary-color)'; li.style.paddingLeft = '9px'; }
     const itemCont = document.createElement('div'); itemCont.style.flexGrow = '1'; itemCont.style.overflow = 'hidden';
     const infoDiv = document.createElement('div'); infoDiv.className = 'item-info'; infoDiv.innerHTML = `<strong>${escapeHtml(credential.service_hint || '(No Hint)')}</strong><span class="username-display">(Username Hidden)</span>`;
     const strDiv = document.createElement('div'); strDiv.className = 'strength-display-popup'; strDiv.style.display = 'none';
     const brchDiv = document.createElement('div'); brchDiv.className = 'breach-display-popup'; brchDiv.style.display = 'none'; brchDiv.style.fontSize = '0.8em'; brchDiv.style.marginTop = '4px'; brchDiv.style.paddingRight = '5px';
     itemCont.append(infoDiv, strDiv, brchDiv);
     const actsDiv = document.createElement('div'); actsDiv.className = 'item-actions';
     const showBtn = document.createElement('button'); showBtn.textContent = 'Show'; showBtn.title = 'Decrypt/show details'; showBtn.onclick = (e) => { e.stopPropagation(); handleShowDetails(li); };
     const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy'; copyBtn.title = 'Copy password'; copyBtn.style.display = 'none'; copyBtn.onclick = (e) => { e.stopPropagation(); handleCopyPassword(li); };
     const fillBtn = document.createElement('button'); fillBtn.textContent = 'Fill'; fillBtn.title = 'Fill on current page'; fillBtn.style.display = 'none'; fillBtn.onclick = (e) => { e.stopPropagation(); handleFillPassword(li); };
     if (isDomainMatch) { li.title = `Click to fill ${escapeHtml(credential.service_hint || '')}`; li.style.cursor = 'pointer'; li.addEventListener('click', async (e) => { if (e.target === li || infoDiv.contains(e.target)) { if (!derivedEncryptionKey) { alert("Unlock first."); return; } const dec = await decryptData(derivedEncryptionKey, credential.encrypted_data); if (dec?.password) { handleDirectFill(dec.username || '', dec.password); } else { alert("Decrypt failed."); } } }); }
     actsDiv.append(showBtn, copyBtn, fillBtn); li.append(itemCont, actsDiv); passwordList.appendChild(li);
}
async function handleShowDetails(listItem) { /* ... (code as before) ... */
    if (!derivedEncryptionKey) { alert("Unlock first."); return; }
    const encData = listItem.dataset.encrypted; const itemCont = listItem.querySelector('div[style*="flex-grow"]'); if (!itemCont) return;
    const infoD = itemCont.querySelector('.item-info'); const userSpan = infoD?.querySelector('.username-display'); const strDiv = itemCont.querySelector('.strength-display-popup'); const brchDiv = itemCont.querySelector('.breach-display-popup'); const actsDiv = listItem.querySelector('.item-actions');
    const showBtn = actsDiv?.querySelector('button:nth-child(1)'); const copyBtn = actsDiv?.querySelector('button:nth-child(2)'); const fillBtn = actsDiv?.querySelector('button:nth-child(3)');
    if (!infoD || !userSpan || !strDiv || !brchDiv || !actsDiv || !showBtn || !copyBtn || !fillBtn) { console.error("Missing list item elements."); return; }
    const assessmentMap = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];
    if (showBtn.textContent === 'Show') {
        showBtn.textContent = '...'; showBtn.disabled = true; strDiv.style.display = 'none'; brchDiv.style.display = 'none'; brchDiv.textContent = 'Breach: Checking...'; brchDiv.className = 'breach-display-popup loading';
        const dec = await decryptData(derivedEncryptionKey, encData); showBtn.disabled = false;
        if (dec) {
            const svc = dec.service || '(No Service)'; const user = dec.username || '(No Username)'; const pass = dec.password || '';
            listItem.dataset.decryptedPassword = pass; listItem.dataset.decryptedUsername = user;
            infoD.querySelector('strong').textContent = escapeHtml(svc); userSpan.textContent = escapeHtml(user); userSpan.style.color = '';
            showBtn.textContent = 'Hide'; copyBtn.style.display = 'inline-block'; fillBtn.style.display = 'inline-block';
            let strScore = -1;
            if (pass && typeof zxcvbn === 'function') { try { const r = zxcvbn(pass); strScore = r.score; strDiv.textContent = `Strength: ${assessmentMap[strScore]}`; strDiv.className = `strength-display-popup score-${strScore}`; strDiv.style.display = 'block'; } catch(e){ strDiv.textContent = 'Strength: Error'; strDiv.className = 'strength-display-popup score-0'; strDiv.style.display = 'block';} } else { strDiv.style.display = 'none'; }
            if (pass && typeof checkHIBPPassword === 'function') {
                 brchDiv.style.display = 'block'; try { const br = await checkHIBPPassword(pass); if (br.error) { brchDiv.textContent = `Breach: Error`; brchDiv.className = 'breach-display-popup error'; brchDiv.title = escapeHtml(br.error); } else if (br.isPwned) { brchDiv.textContent = `Breach: Compromised! (${br.count})`; brchDiv.className = 'breach-display-popup pwned'; brchDiv.title = `Found in ${br.count} breach(es).`; } else { brchDiv.textContent = 'Breach: Not Found'; brchDiv.className = 'breach-display-popup safe'; brchDiv.title = 'Not found.'; } } catch (be) { brchDiv.textContent = `Breach: Error`; brchDiv.className = 'breach-display-popup error'; brchDiv.title = 'Check failed.'; } }
             else { brchDiv.style.display = 'none'; }
        } else { userSpan.textContent = '(Decrypt Failed)'; userSpan.style.color = 'var(--popup-danger-color)'; showBtn.textContent = 'Error'; strDiv.style.display = 'none'; brchDiv.style.display = 'none'; copyBtn.style.display = 'none'; fillBtn.style.display = 'none'; delete listItem.dataset.decryptedPassword; delete listItem.dataset.decryptedUsername; }
    } else { const origHint = listItem.dataset.serviceHint; infoD.querySelector('strong').textContent = escapeHtml(origHint); userSpan.textContent = '(Username Hidden)'; userSpan.style.color = ''; showBtn.textContent = 'Show'; copyBtn.style.display = 'none'; fillBtn.style.display = 'none'; strDiv.style.display = 'none'; brchDiv.style.display = 'none'; delete listItem.dataset.decryptedPassword; delete listItem.dataset.decryptedUsername; }
}
async function handleCopyPassword(listItem) { /* ... (code as before) ... */
     let pass = listItem.dataset.decryptedPassword; if (!pass) { setPopupStatus("Decrypting...", false); await handleShowDetails(listItem); pass = listItem.dataset.decryptedPassword; clearPopupStatus(); if (!pass) { alert("Decrypt failed."); return; } } try { await navigator.clipboard.writeText(pass); setPopupStatus("Password copied!", false, 1500); } catch (err) { setPopupStatus("Copy failed.", true); console.error('Clipboard err:', err); alert("Copy failed."); }
}
async function handleFillPassword(listItem) { /* ... (code as before) ... */
     let pass = listItem.dataset.decryptedPassword; let user = listItem.dataset.decryptedUsername; if (!pass) { setPopupStatus("Decrypting...", false); await handleShowDetails(listItem); pass = listItem.dataset.decryptedPassword; user = listItem.dataset.decryptedUsername; clearPopupStatus(); if (!pass) { alert("Decrypt failed."); return; } } handleDirectFill(user || '', pass);
}
async function handleDirectFill(username, password) { /* ... (code as before) ... */
     setPopupStatus(`Filling ${currentDomain}...`, false); try { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); if (tab?.id) { chrome.tabs.sendMessage(tab.id, { action: 'fillPassword', username: username, password: password }, (resp) => { if (chrome.runtime.lastError) { console.error("Fill Send Error:", chrome.runtime.lastError.message); setPopupStatus("Error sending fill.", true, 3000); } else if (resp?.success) { window.close(); } else { console.warn("Fill failed/not ack."); setPopupStatus("Fill sent.", false, 2000); } }); } else { throw new Error("No active tab."); } } catch (error) { setPopupStatus(`Fill Error: ${error.message}`, true); console.error("Fill error:", error); }
}

// --- Password Generation ---
async function handleGeneratePopupPassword() { /* ... (code as before - uses dispatchEvent now) ... */
     hideSaveError(); if (generatePopupPasswordBtn) { generatePopupPasswordBtn.disabled = true; generatePopupPasswordBtn.textContent = '...'; }
     const opts = { length: popupGenLengthSlider ? parseInt(popupGenLengthSlider.value, 10) : 16, use_lowercase: popupGenLowercaseCheckbox?.checked ?? true, use_uppercase: popupGenUppercaseCheckbox?.checked ?? true, use_digits: popupGenDigitsCheckbox?.checked ?? true, use_symbols: popupGenSymbolsCheckbox?.checked ?? true };
     if (!opts.use_lowercase && !opts.use_uppercase && !opts.use_digits && !opts.use_symbols) { showSaveError("Select character type."); if (generatePopupPasswordBtn) { generatePopupPasswordBtn.disabled = false; generatePopupPasswordBtn.textContent = 'Generate'; } return; }
     try { const resp = await fetch(`${API_BASE_URL}/api/generate_password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify(opts) }); const res = await resp.json(); if (resp.ok && res.password) { if (newPasswordInput) { newPasswordInput.value = res.password; newPasswordInput.type = 'text'; newPasswordInput.dispatchEvent(new Event('input', { bubbles: true })); setTimeout(() => { if (newPasswordInput?.type === 'text') newPasswordInput.type = 'password'; }, 2000); } } else { throw new Error(res.error || 'API gen failed.'); } } catch (error) { showSaveError(`Generate Error: ${error.message}`); console.error('Generate Err:', error); } finally { if (generatePopupPasswordBtn) { generatePopupPasswordBtn.disabled = false; generatePopupPasswordBtn.textContent = 'Generate'; } }
}

// --- Save New Password ---
async function handleSavePassword() { /* ... (code as before) ... */
    const service = serviceInput ? serviceInput.value.trim() : ''; const username = newUsernameInput ? newUsernameInput.value.trim() : ''; const password = newPasswordInput ? newPasswordInput.value : ''; const masterPassword = masterPasswordSaveInput ? masterPasswordSaveInput.value : '';
    if (!service || !username || !password || !masterPassword) { showSaveError("All fields & Master PW required."); return; }
    hideSaveError(); if (savePasswordBtn) { savePasswordBtn.disabled = true; savePasswordBtn.textContent = 'Saving...'; }
    try { if (!userEmail || !derivedEncryptionKey) throw new Error("Session key missing."); const confirmKey = await deriveKeyRawBytes(masterPassword, userEmail); if (!compareArrayBuffers(confirmKey, derivedEncryptionKey)) throw new Error("Master PW mismatch."); const dataToEnc = { service, username, password }; const encData = await encryptData(derivedEncryptionKey, dataToEnc); const resp = await fetch(`${API_BASE_URL}/api/credentials`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ encrypted_data: encData, service_hint: service }) }); const res = await resp.json(); if (resp.ok && res.success) { setPopupStatus("Saved!", false, 2000); hideAddForm(); await loadAndDisplayCredentials(); } else { throw new Error(res.message || `Save failed (${resp.status})`); } }
    catch (error) { showSaveError(`Save failed: ${error.message}`); console.error('Save error:', error); }
    finally { if (savePasswordBtn) { savePasswordBtn.disabled = false; savePasswordBtn.textContent = 'Encrypt & Save'; } if (masterPasswordSaveInput) masterPasswordSaveInput.value = ''; }
}

// --- Search/Filter ---
function handleSearchFilter() { /* ... (code as before) ... */
    if (window.searchDebounceTimer) clearTimeout(window.searchDebounceTimer);
    window.searchDebounceTimer = setTimeout(filterAndRenderList, 250);
}

// --- Utility: Get Current Tab Domain ---
async function getCurrentTabDomain() { /* ... (code as before) ... */
    try { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); if (tab?.id && tab.url?.startsWith('http')) { currentDomain = await new Promise((resolve) => { let resolved = false; const timer = setTimeout(() => { if (!resolved) { resolved = true; resolve(new URL(tab.url).hostname); } }, 350); chrome.tabs.sendMessage(tab.id, { action: 'getDomain' }, (resp) => { clearTimeout(timer); if (resolved) return; resolved = true; if (chrome.runtime.lastError || !resp?.domain) { resolve(new URL(tab.url).hostname); } else { resolve(resp.domain); } }); }); } else if (tab?.url?.startsWith('http')) { currentDomain = new URL(tab.url).hostname; } else { currentDomain = 'N/A'; } } catch (error) { console.warn("Get domain error:", error); currentDomain = 'Error'; } console.log("Domain:", currentDomain); updateDomainDisplay();
}


// --- DOMContentLoaded Listener (Main Entry Point) ---
document.addEventListener('DOMContentLoaded', async () => {
    console.log("Popup: DOMContentLoaded - Initializing...");
    applyPopupTheme();

    // --- Check Dependencies ---
    let cryptoHelpersLoaded = typeof arrayBufferToBase64 !== 'undefined' && typeof base64ToArrayBuffer !== 'undefined' && typeof base64UrlDecode !== 'undefined' && typeof deriveKeyRawBytes !== 'undefined' && typeof decryptData !== 'undefined' && typeof encryptData !== 'undefined' && typeof sha1Hash !== 'undefined' && typeof checkHIBPPassword !== 'undefined' && typeof escapeHtml !== 'undefined';
    let zxcvbnLoaded = typeof zxcvbn !== 'undefined';

    if (!cryptoHelpersLoaded) { console.error("CRITICAL: Crypto helpers missing!"); showLoginView("Error: Missing functions."); return; }
    if (!zxcvbnLoaded) { console.warn("zxcvbn missing."); if(popupStrengthArea) popupStrengthArea.style.display = 'none'; }

    // --- Define Debounced Analysis Function (INSIDE DOMContentLoaded) ---
    const debouncePopupAnalysis = debouncePopup(async function() {
        const password = this.value; // 'this' is the input
        const assessmentMap = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];

        if (!password) {
            if (popupStrengthArea) popupStrengthArea.style.display = 'none';
            if (popupBreachStatusArea) popupBreachStatusArea.style.display = 'none';
            return;
        }
        if (popupStrengthArea) popupStrengthArea.style.display = 'block';
        if (popupBreachStatusArea) popupBreachStatusArea.style.display = 'flex';
        if (popupStrengthIndicator) popupStrengthIndicator.className = 'popup-strength-indicator';
        if (popupStrengthTextLabel) popupStrengthTextLabel.textContent = 'Strength: Checking...';
        if (popupStrengthFeedbackDiv) popupStrengthFeedbackDiv.innerHTML = '';
        if (popupStrengthArea) popupStrengthArea.className = 'popup-strength-area';
        if (popupBreachIndicator) { popupBreachIndicator.textContent = 'Checking...'; popupBreachIndicator.className = 'breach-indicator loading'; }

        let strengthResult = null; let breachResultPromise = null;
        if (zxcvbnLoaded) { try { strengthResult = zxcvbn(password); } catch(e) { console.error(e);}}
        else { if(popupStrengthArea) popupStrengthArea.style.display = 'none'; }
        if (cryptoHelpersLoaded) { breachResultPromise = checkHIBPPassword(password).catch(e => ({error: "Check failed"})); }
        else { if(popupBreachStatusArea) popupBreachStatusArea.style.display = 'none'; breachResultPromise = Promise.resolve({ error: "Checker N/A" }); }

        // Process Strength
        if (strengthResult && popupStrengthIndicator && popupStrengthTextLabel && popupStrengthFeedbackDiv) {
            const score = strengthResult.score;
            popupStrengthIndicator.className = `popup-strength-indicator ${getStrengthClassFromScore(score)}`;
            popupStrengthTextLabel.textContent = `Strength: ${assessmentMap[score]}`;
            popupStrengthFeedbackDiv.innerHTML = formatZxcvbnFeedbackPopup(strengthResult);
            popupStrengthArea.className = `popup-strength-area strength-${score}`;
        }
        // Process Breach
        if (breachResultPromise && popupBreachIndicator) {
            try { const br = await breachResultPromise; if (br.error) { popupBreachIndicator.textContent = `Error: ${escapeHtml(br.error)}`; popupBreachIndicator.className = 'breach-indicator error'; } else if (br.isPwned) { popupBreachIndicator.textContent = `Compromised! (${br.count})`; popupBreachIndicator.className = 'breach-indicator pwned'; } else { popupBreachIndicator.textContent = 'Not in breaches.'; popupBreachIndicator.className = 'breach-indicator safe'; } }
            catch (error) { popupBreachIndicator.textContent = 'Error checking.'; popupBreachIndicator.className = 'breach-indicator error'; }
        }
    }, 600); // Debounce time

    // --- Attach Event Listeners (INSIDE DOMContentLoaded) ---
    if (loginBtn) loginBtn.addEventListener('click', handleLoginAttempt);
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
    if (addPasswordBtn) addPasswordBtn.addEventListener('click', showAddForm);
    if (cancelAddBtn) cancelAddBtn.addEventListener('click', hideAddForm);
    if (savePasswordBtn) savePasswordBtn.addEventListener('click', handleSavePassword);
    if (searchInput) searchInput.addEventListener('input', handleSearchFilter);
    if (generatePopupPasswordBtn) generatePopupPasswordBtn.addEventListener('click', handleGeneratePopupPassword);
    if (popupGenLengthSlider && popupGenLengthValueSpan) { popupGenLengthSlider.addEventListener('input', () => { popupGenLengthValueSpan.textContent = popupGenLengthSlider.value; }); }
    if (newPasswordInput) { newPasswordInput.addEventListener('input', debouncePopupAnalysis); } // Attach listener here
    if (popupThemeToggleBtn) popupThemeToggleBtn.addEventListener('click', togglePopupTheme);

    // --- Initial Actions ---
    await getCurrentTabDomain();
    await checkLoginStatus();

}); // --- END OF DOMContentLoaded ---

// --- END OF FILE popup.js ---