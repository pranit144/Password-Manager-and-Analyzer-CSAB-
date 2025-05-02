// API endpoint
const API_URL = 'http://localhost:5000/api';

// DOM elements
const loginForm = document.getElementById('login-form');
const mainContent = document.getElementById('main-content');
const passwordList = document.getElementById('password-list');
const addPasswordBtn = document.getElementById('add-password-btn');
const addPasswordForm = document.getElementById('add-password-form');
const savePasswordBtn = document.getElementById('save-password-btn');

// Event listeners
document.getElementById('login-btn').addEventListener('click', handleLogin);
addPasswordBtn.addEventListener('click', () => {
    addPasswordForm.classList.toggle('hidden');
});
savePasswordBtn.addEventListener('click', handleSavePassword);

// Handle login
async function handleLogin() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        // In a real implementation, you would verify credentials
        // For now, we'll just show the main content
        loginForm.classList.add('hidden');
        mainContent.classList.remove('hidden');
        await loadPasswords();
    } catch (error) {
        console.error('Login failed:', error);
        alert('Login failed. Please try again.');
    }
}

// Load passwords from the blockchain
async function loadPasswords() {
    try {
        const response = await fetch(`${API_URL}/passwords`);
        const passwords = await response.json();
        
        passwordList.innerHTML = '';
        passwords.forEach(password => {
            const item = document.createElement('div');
            item.className = 'password-item';
            item.innerHTML = `
                <strong>${password.service}</strong><br>
                Username: ${password.username}<br>
                Password: ••••••••
            `;
            item.addEventListener('click', () => {
                // Copy password to clipboard
                navigator.clipboard.writeText(password.password);
                alert('Password copied to clipboard!');
            });
            passwordList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading passwords:', error);
        alert('Error loading passwords. Please try again.');
    }
}

// Save new password
async function handleSavePassword() {
    const service = document.getElementById('service').value;
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;

    try {
        const response = await fetch(`${API_URL}/add_password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ service, username, password })
        });

        if (response.ok) {
            alert('Password saved successfully!');
            document.getElementById('service').value = '';
            document.getElementById('new-username').value = '';
            document.getElementById('new-password').value = '';
            addPasswordForm.classList.add('hidden');
            await loadPasswords();
        } else {
            throw new Error('Failed to save password');
        }
    } catch (error) {
        console.error('Error saving password:', error);
        alert('Error saving password. Please try again.');
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is already logged in
    chrome.storage.local.get(['isLoggedIn'], (result) => {
        if (result.isLoggedIn) {
            loginForm.classList.add('hidden');
            mainContent.classList.remove('hidden');
            loadPasswords();
        }
    });
}); 