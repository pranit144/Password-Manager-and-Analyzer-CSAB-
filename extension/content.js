// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fillPassword') {
        fillPassword(request.password);
    }
});

// Function to fill password in the current page
function fillPassword(password) {
    // Find all password input fields
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    
    if (passwordInputs.length > 0) {
        // Focus on the first password field
        passwordInputs[0].focus();
        
        // Create and dispatch input events to simulate user typing
        const inputEvent = new Event('input', { bubbles: true });
        passwordInputs[0].value = password;
        passwordInputs[0].dispatchEvent(inputEvent);
        
        // Create and dispatch change event
        const changeEvent = new Event('change', { bubbles: true });
        passwordInputs[0].dispatchEvent(changeEvent);
    }
}

// Function to detect login forms
function detectLoginForm() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const hasPasswordField = form.querySelector('input[type="password"]');
        const hasUsernameField = form.querySelector('input[type="text"], input[type="email"]');
        
        if (hasPasswordField && hasUsernameField) {
            // Add a small icon to indicate password manager integration
            const icon = document.createElement('div');
            icon.style.cssText = `
                position: absolute;
                right: 10px;
                top: 10px;
                width: 20px;
                height: 20px;
                background-color: #4CAF50;
                border-radius: 50%;
                cursor: pointer;
            `;
            form.style.position = 'relative';
            form.appendChild(icon);
            
            // Add click handler to the icon
            icon.addEventListener('click', () => {
                // Get the current domain
                const domain = window.location.hostname;
                
                // Request passwords for this domain from the popup
                chrome.runtime.sendMessage({
                    action: 'getPasswordsForDomain',
                    domain: domain
                });
            });
        }
    });
}

// Run form detection when the page loads
document.addEventListener('DOMContentLoaded', detectLoginForm);

// Also run when new content is loaded (for dynamic pages)
const observer = new MutationObserver((mutations) => {
    mutations.forEach(() => {
        detectLoginForm();
    });
});

observer.observe(document.body, {
    childList: true,
    subtree: true
}); 