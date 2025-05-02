// Listen for messages from the popup (for autofill)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fillPassword' && request.password) {
        fillPassword(request.password);
        sendResponse({ success: true }); // Acknowledge message received
    } else if (request.action === 'getDomain') {
        // Respond with the current page's domain if requested (e.g., by popup)
         sendResponse({ domain: window.location.hostname });
     }
     // Keep the listener alive for asynchronous responses if needed
     // return true;
});

// Function to fill password in the current page
function fillPassword(password) {
    // Prioritize password fields with specific attributes often used for login
    let passwordInput = document.querySelector('input[type="password"][autocomplete*="current-password"]');
    if (!passwordInput) {
        passwordInput = document.querySelector('input[type="password"]'); // Fallback to any password field
    }

    if (passwordInput) {
        passwordInput.focus();
        // Simulate user input more realistically
        passwordInput.value = password;
        passwordInput.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
        passwordInput.dispatchEvent(new Event('change', { bubbles: true }));
        // Some frameworks need blur to trigger validation/state updates
        // passwordInput.blur();
        console.log("Password field filled.");

        // Optional: Try to find and fill username if available (more complex)
        // This would require passing the username along with the password
        // const usernameInput = document.querySelector('input[type="email"], input[type="text"][autocomplete*="username"]');
        // if(usernameInput && request.username) { /* ... fill username ... */ }

    } else {
        console.warn("No suitable password input field found on this page.");
        // Consider sending a message back to the popup indicating failure?
    }
}

// Function to detect login forms (kept simple for now)
function detectAndMarkForms() {
    // Remove existing icons first to avoid duplicates on dynamic updates
     document.querySelectorAll('.secure-pwm-icon').forEach(icon => icon.remove());

    const forms = document.querySelectorAll('form');
    forms.forEach((form, index) => {
        const hasPasswordField = form.querySelector('input[type="password"]');
        // Check for common username/email field types/names
        const hasUsernameField = form.querySelector('input[type="email"], input[type="text"], input[type="tel"]'); // More permissive check

        if (hasPasswordField && hasUsernameField) {
            // Check if form is likely visible
             if(form.offsetParent === null) return; // Skip hidden forms

            const passwordField = hasPasswordField; // Use the actual password field for positioning reference

            // Add a small icon near the password field
             const icon = document.createElement('div');
             icon.className = 'secure-pwm-icon'; // Add class for easier removal
             icon.title = 'Fill with Secure Password Manager';
             icon.style.cssText = `
                 position: absolute;
                 width: 18px;
                 height: 18px;
                 background-color: #28a745; /* Green */
                 border-radius: 50%;
                 cursor: pointer;
                 z-index: 9999;
                 /* Position near the password field (adjust as needed) */
                 left: ${passwordField.offsetLeft + passwordField.offsetWidth - 22}px;
                 top: ${passwordField.offsetTop + (passwordField.offsetHeight / 2) - 9}px;
                 box-shadow: 0 1px 3px rgba(0,0,0,0.3);
             `;
             // Ensure the form or a parent allows absolute positioning
             if (getComputedStyle(form).position === 'static') {
                  form.style.position = 'relative';
             }
            // Append to the form or directly to the body if form positioning is difficult
             form.appendChild(icon); // Or document.body.appendChild(icon) with adjustments

            // Add click handler to the icon (optional - primary trigger is popup)
            icon.addEventListener('click', (e) => {
                 e.stopPropagation(); // Prevent form submission if icon is inside button area
                // Optionally send message to background/popup to show relevant entries
                 console.log("Secure PWM icon clicked.");
                 // chrome.runtime.sendMessage({ action: 'showRelevantPasswords', domain: window.location.hostname });
             });
        }
    });
}

// Run form detection initially and on changes
let debounceTimer;
const observer = new MutationObserver((mutations) => {
     // Debounce the detection to avoid excessive runs on busy pages
     clearTimeout(debounceTimer);
     debounceTimer = setTimeout(detectAndMarkForms, 250);
});

// Initial detection after DOM loads
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", detectAndMarkForms);
} else {
    detectAndMarkForms(); // Already loaded
}

// Observe changes in the DOM
observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true, // Observe attribute changes (like 'type' or 'style')
    attributeFilter: ['type', 'style', 'class'] // Be specific if possible
});