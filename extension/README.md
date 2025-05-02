# Blockchain Password Manager Extension

A Chrome extension for the Blockchain Password Manager that allows you to securely store and manage your passwords.

## Features

- Secure password storage using blockchain technology
- Auto-fill passwords on websites
- Easy password management through browser extension
- One-click password copying
- Secure login system

## Installation

1. Make sure the Blockchain Password Manager backend is running on `http://localhost:5000`
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the `extension` folder
5. The extension should now be installed and visible in your Chrome toolbar

## Usage

1. Click the extension icon in your Chrome toolbar
2. Log in with your credentials
3. To add a new password:
   - Click "Add New Password"
   - Fill in the service, username, and password
   - Click "Save"
4. To use a saved password:
   - Click on the password in the list to copy it to clipboard
   - Or visit the website and click the green icon that appears on the login form

## Security Notes

- All passwords are stored securely in the blockchain
- Passwords are never stored in plain text
- The extension only communicates with your local blockchain instance
- Make sure to keep your login credentials secure

## Development

To modify the extension:

1. Make changes to the files in the `extension` folder
2. Go to `chrome://extensions/`
3. Find the extension and click the refresh icon
4. The changes will be applied

## Requirements

- Chrome browser
- Running instance of the Blockchain Password Manager backend
- Internet connection (for blockchain operations) 