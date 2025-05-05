// Listen for messages from the popup (for autofill)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fillPassword' && request.password) {
        fillPassword(request.password, request.username); // Pass username too
        sendResponse({ success: true }); // Acknowledge message received
    } else if (request.action === 'getDomain') {
        // Respond with the current page's domain if requested (e.g., by popup)
         sendResponse({ domain: window.location.hostname });
     }
     // Keep the listener alive for asynchronous responses if needed
     // return true; 
});

// Function to fill username and password in the current page
function fillPassword(password, username) {
    // --- Password Field Detection ---
    // Prioritize specific attributes often used for login
    let passwordInput = document.querySelector('input[type="password"][autocomplete*="current-password"]');
    if (!passwordInput) {
        // More robust fallback: Find any visible password field
        const visiblePasswordFields = Array.from(document.querySelectorAll('input[type="password"]'))
                                            .filter(el => el.offsetParent !== null && !el.disabled && !el.readOnly);
        if(visiblePasswordFields.length > 0) {
            passwordInput = visiblePasswordFields[0]; // Use the first visible one
            // If multiple, could try to find one near the username field later
        }
    }

    // --- Username Field Detection (More Heuristic) ---
    let usernameInput = null;
    if (passwordInput) { // Try finding username relative to password field
        const form = passwordInput.closest('form');
        if (form) {
            // Look within the same form first
            usernameInput = form.querySelector('input[type="email"], input[type="text"][autocomplete*="username"], input[type="tel"][autocomplete*="username"]');
            if (!usernameInput) {
                // Fallback: Look for any email/text/tel field before the password field in the form
                const inputs = Array.from(form.querySelectorAll('input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="reset"]):not([type="button"]):not([type="image"])'));
                const passwordIndex = inputs.indexOf(passwordInput);
                if (passwordIndex > 0) {
                    // Look backwards from password field
                    for(let i = passwordIndex - 1; i >= 0; i--) {
                         if(inputs[i].type === 'text' || inputs[i].type === 'email' || inputs[i].type === 'tel'){
                             usernameInput = inputs[i];
                             break;
                         }
                    }
                }
            }
        }
    }
     // Absolute fallback if no form or no input found yet
     if (!usernameInput) {
         usernameInput = document.querySelector('input[type="email"], input[type="text"][autocomplete*="username"], input[type="tel"][autocomplete*="username"]');
     }
     // Final fallback: first visible text/email/tel input if still nothing
     if(!usernameInput){
        const visibleUserFields = Array.from(document.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"]'))
                                         .filter(el => el.offsetParent !== null && !el.disabled && !el.readOnly && el.type !== 'search');
         if(visibleUserFields.length > 0){
             // Maybe check if it's *before* the password field in the DOM as a final heuristic?
              const passwordFieldDomOrder = passwordInput ? Array.from(document.querySelectorAll('input')).indexOf(passwordInput) : Infinity;
              const potentialUserField = visibleUserFields.find(uf => Array.from(document.querySelectorAll('input')).indexOf(uf) < passwordFieldDomOrder);
              usernameInput = potentialUserField || visibleUserFields[0];
         }
     }


    // --- Filling Logic ---
    let filledPassword = false;
    let filledUsername = false;

    if (passwordInput) {
        setInputValue(passwordInput, password);
        filledPassword = true;
        console.log("Secure PWM: Password field found and filled.");
    } else {
        console.warn("Secure PWM: No suitable password input field found on this page.");
    }

    if (username && usernameInput) {
        setInputValue(usernameInput, username);
        filledUsername = true;
        console.log("Secure PWM: Username field found and filled.");
    } else if (username && !usernameInput) {
         console.warn("Secure PWM: Username provided but no suitable input field found.");
    } else if (!username) {
        console.log("Secure PWM: No username provided to fill.");
    }


    // Optional: Attempt to focus the next logical element (e.g., login button)
    // if (filledPassword && filledUsername) {
    //    // Try finding a submit button in the same form
    // }
}

// Helper to set value and dispatch events for better compatibility
function setInputValue(inputElement, value) {
     inputElement.focus();
     inputElement.value = value;
     inputElement.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
     inputElement.dispatchEvent(new Event('change', { bubbles: true }));
     // inputElement.blur(); // Sometimes needed, sometimes breaks things. Test carefully.
}


// --- (Optional but Recommended) Icon Injection ---

// Function to detect login forms and add an icon
function detectAndMarkForms() {
    // Remove existing icons first to avoid duplicates on dynamic updates
     document.querySelectorAll('.secure-pwm-icon').forEach(icon => icon.remove());

    const forms = document.querySelectorAll('form');
    forms.forEach((form) => {
        const hasPasswordField = form.querySelector('input[type="password"]');
        // Simple check for a potential username/email field nearby
        const hasUsernameField = form.querySelector('input[type="email"], input[type="text"], input[type="tel"]');

        if (hasPasswordField && hasUsernameField) {
            // Check if form or password field is likely visible
             if(hasPasswordField.offsetParent === null) return; // Skip hidden fields

            const passwordField = hasPasswordField;

            // Create and style the icon
             const icon = document.createElement('div');
             icon.className = 'secure-pwm-icon'; // Class for identification and removal
             icon.title = 'Fill with Secure Password Manager';
             icon.style.cssText = `
                 position: absolute;
                 width: 18px;
                 height: 18px;
                 background-color: #28a745; /* Green */
                 background-image: url('${chrome.runtime.getURL("icons/icon16.png")}'); /* Use extension icon */
                 background-size: 12px 12px; /* Adjust size */
                 background-repeat: no-repeat;
                 background-position: center;
                 border: 1px solid #1e7e34;
                 border-radius: 50%;
                 cursor: pointer;
                 z-index: 9999;
                 box-shadow: 0 1px 3px rgba(0,0,0,0.2);
                 /* Attempt to position inside/near the right edge of the password field */
                 top: ${passwordField.offsetTop + (passwordField.offsetHeight / 2) - 9}px;
                 left: ${passwordField.offsetLeft + passwordField.offsetWidth - 22}px;
             `;

             // Ensure the *parent* of the input allows absolute positioning relative to it
              const inputWrapper = passwordField.parentElement;
              if (inputWrapper && getComputedStyle(inputWrapper).position === 'static') {
                  inputWrapper.style.position = 'relative'; // Make parent relative if needed
              }
             // Append the icon to the input's parent wrapper if possible, or form
             if (inputWrapper) {
                inputWrapper.appendChild(icon);
             } else if (form && getComputedStyle(form).position !== 'static') {
                 form.appendChild(icon); // Fallback to form if parent is tricky
             } else {
                 // Less ideal: append to body, requires calculating absolute coords
             }


            // Add click handler to the icon (optional - could trigger popup)
            icon.addEventListener('click', (e) => {
                 e.stopPropagation(); // Prevent form submission if icon is inside button area
                // Send message to background/popup to show relevant entries for this domain
                 console.log("Secure PWM icon clicked. Requesting relevant passwords.");
                 chrome.runtime.sendMessage({ action: 'showRelevantPasswords', domain: window.location.hostname });
             });
        }
    });
}

// Run form detection with debouncing
let debounceTimer;
const observer = new MutationObserver(() => {
     clearTimeout(debounceTimer);
     debounceTimer = setTimeout(detectAndMarkForms, 300); // Adjust delay as needed
});

// Initial detection and observation setup
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
        detectAndMarkForms();
        observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'style', 'class', 'hidden', 'disabled'] });
    });
} else {
    detectAndMarkForms(); // Already loaded
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'style', 'class', 'hidden', 'disabled'] });
}