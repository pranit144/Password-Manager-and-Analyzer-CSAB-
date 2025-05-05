# Secure E2EE Password Manager & Analyzer

This project combines a Flask web application with a Chrome browser extension to provide a secure password management solution featuring End-to-End Encryption (E2EE), password strength analysis, and breach detection. User credentials are encrypted client-side before being sent to a Supabase backend, ensuring the server never sees plaintext passwords.

**Core Principles:**

*   **End-to-End Encryption:** Passwords and associated data are encrypted/decrypted *only* in the user's browser using a key derived from their Master Password.
*   **Zero Knowledge (Server):** The backend stores only encrypted data and cannot decrypt user passwords.
*   **Client-Side Security Focus:** Critical cryptographic operations happen client-side (Web Crypto API in the browser/extension).

## Features

*   **User Authentication:** Secure registration and login system using Flask-Login and Bcrypt for hashing Master Passwords.
*   **End-to-End Encryption:** AES-GCM encryption using Web Crypto API, with keys derived using PBKDF2HMAC-SHA256.
*   **Supabase Backend:** Utilizes Supabase (PostgreSQL) for user management and encrypted credential storage.
*   **Chrome Extension:**
    *   Popup interface for quick access to credentials.
    *   Login/Unlock directly within the popup.
    *   View, search, copy, and auto-fill credentials.
    *   Add new credentials directly from the popup.
    *   Integrated password generator.
    *   Password strength analysis (ZXCVBN + HIBP breach check) in the "Add New" form.
    *   Theme toggle (light/dark).
    *   Content script for interacting with web pages (auto-fill).
*   **Web Application (Flask):**
    *   User registration and login pages.
    *   Interface to add new credentials.
    *   Page to view/decrypt stored credentials.
    *   Password analysis page:
        *   Analyze strength and breach status of a single password.
        *   Analyze *all* stored passwords (decrypts client-side for analysis).
        *   Optional AI-powered insights via Google Gemini API.
*   **Password Generation:** Secure password generator with customizable options (length, character sets).
*   **Password Strength Analysis:** Uses the robust ZXCVBN library (client-side in popup/web app, server-side via API).
*   **Breach Detection:** Integrates with the **free** Have I Been Pwned (HIBP) Pwned Passwords API (using k-Anonymity for privacy) on the client-side.
*   **"Remember Me" Functionality:** Secure session persistence using Flask-Login.
*   **Theme Toggle:** Light/Dark mode support in the web app and extension popup.

## Tech Stack

*   **Backend:** Python 3, Flask, Supabase (Python Client), Flask-Login, Flask-Bcrypt, python-dotenv, cryptography, zxcvbn-python, google-generativeai (optional)
*   **Frontend (Web App):** HTML, CSS, JavaScript, Jinja2, ZXCVBN.js
*   **Frontend (Extension):** HTML, CSS, JavaScript (Web Crypto API), ZXCVBN.js, Chrome Extension APIs
*   **Database:** Supabase (PostgreSQL backend)
*   **APIs:**
    *   Have I Been Pwned (HIBP) Pwned Passwords API (Range Endpoint - Free)
    *   Google Gemini API (Optional - Requires API Key)

## Prerequisites

*   Python 3.9+
*   `pip` (Python package installer)
*   A Supabase Account (Free tier is sufficient)
*   Google Chrome (or other Chromium-based browser like Edge, Brave)
*   (Optional) Google Gemini API Key for enhanced password analysis features.

## Setup & Installation

1.  **Clone the Repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Set up Supabase:**
    *   Go to [Supabase](https://supabase.com/) and create a new project.
    *   Navigate to **Project Settings** > **API**.
    *   Find your **Project URL** and the **`anon` public API Key**. You'll need these for the `.env` file.
    *   Go to the **SQL Editor** in your Supabase dashboard.
    *   Create the necessary tables by running the following SQL (or use a schema migration tool):

        ```sql
        -- users table
        CREATE TABLE users (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            email character varying UNIQUE NOT NULL,
            password_hash character varying NOT NULL,
            created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
        );

        -- Ensure email is lowercase for consistency
        ALTER TABLE users ADD CONSTRAINT users_email_check CHECK ((email = lower((email)::text)));

        -- credentials table
        CREATE TABLE credentials (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            encrypted_data text NOT NULL,
            service_hint character varying, -- For easier identification without decryption
            created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
        );

        -- Index for faster lookups by user_id
        CREATE INDEX idx_credentials_user_id ON public.credentials USING btree (user_id);

        -- Enable Row Level Security (VERY IMPORTANT)
        ALTER TABLE users ENABLE ROW LEVEL SECURITY;
        ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;

        -- RLS Policy: Users can only see/manage their own credentials
        CREATE POLICY "Users can manage their own credentials"
        ON credentials
        FOR ALL
        USING (auth.uid() = user_id);

        -- RLS Policy: Users can see their own user record (e.g., for profile info if needed)
        CREATE POLICY "Users can view their own user record"
        ON users
        FOR SELECT
        USING (auth.uid() = id);

        -- RLS Policy: Allow users to update their own record (if needed, e.g., change email - requires more logic)
        -- CREATE POLICY "Users can update their own user record"
        -- ON users
        -- FOR UPDATE
        -- USING (auth.uid() = id);

        -- NOTE: Inserting new users requires the service_role key or disabling RLS temporarily
        -- during backend registration if using anon key, OR handle user creation via Supabase Auth.
        -- The current Python code uses the anon key to insert directly, assuming RLS might
        -- need adjustment or you handle auth differently in production.
        -- For simplicity in this setup, we assume direct insert works, but review RLS for inserts.

        ```

3.  **Configure Backend (`.env` file):**
    *   Create a file named `.env` in the root project directory (where `app.py` is).
    *   Add the following environment variables:

        ```dotenv
        SUPABASE_URL=YOUR_SUPABASE_PROJECT_URL
        SUPABASE_KEY=YOUR_SUPABASE_ANON_PUBLIC_KEY
        FLASK_SECRET_KEY=generate_a_very_strong_random_secret_key_here # Use os.urandom(24).hex() in Python to generate one
        GEMINI_API_KEY=YOUR_GOOGLE_GEMINI_API_KEY # Optional: Leave blank or remove if not using Gemini

        # Optional: Set to 'development' for debug mode, 'production' otherwise
        FLASK_ENV=development
        ```
    *   **Important:** Replace placeholders with your actual Supabase URL/Key and generate a strong `FLASK_SECRET_KEY`.

4.  **Install Backend Dependencies:**
    *   Open your terminal in the project root directory.
    *   (Recommended) Create and activate a virtual environment:
        ```bash
        python -m venv venv
        # Windows
        venv\Scripts\activate
        # macOS/Linux
        source venv/bin/activate
        ```
    *   Install the required packages:
        ```bash
        pip install -r requirements.txt
        ```

5.  **Load Chrome Extension:**
    *   Open Google Chrome.
    *   Go to `chrome://extensions/`.
    *   Enable "Developer mode" (usually a toggle in the top-right corner).
    *   Click "Load unpacked".
    *   Navigate to and select the directory containing the extension's `manifest.json` file (e.g., an `extension` subfolder if you have one).
    *   The extension icon should appear in your Chrome toolbar.

## Running the Application

1.  **Start the Flask Backend:**
    *   Make sure your virtual environment is activated (if you created one).
    *   Run the Flask app from the project root directory:
        ```bash
        python app.py
        ```
    *   The backend should start, typically on `http://127.0.0.1:5000`.

2.  **Use the Web Application:**
    *   Open your web browser and navigate to `http://127.0.0.1:5000`.
    *   You can register a new user or log in if you already have an account.

3.  **Use the Chrome Extension:**
    *   Click the extension's icon in your Chrome toolbar.
    *   If you are logged into the web application *in the same browser session*, the extension might automatically detect the session (via background script communication). If not, log in via the popup.
    *   The popup allows adding, viewing, copying, and filling credentials.

## Usage Guide

*   **Registration/Login:** Use the web interface (`http://127.0.0.1:5000/register` or `/login`) or the extension popup to create an account or log in. Your Master Password is crucial and **cannot be recovered**.
*   **Adding Credentials:**
    *   **Web App:** Navigate to `/add` after logging in.
    *   **Extension:** Click the extension icon, then click "+ Add New Credential". Fill in the details and confirm with your Master Password.
*   **Generating Passwords:** Use the "Generate" button in the "Add New Credential" forms (web app or extension popup). Customize options as needed.
*   **Viewing/Decrypting:**
    *   **Web App:** Navigate to `/storage`. Click "Show" on an entry to decrypt and view details client-side.
    *   **Extension:** Click the icon. Click "Show" on an entry. Strength and breach status are checked upon showing.
*   **Copying Passwords:** In the extension popup or `/storage` page, click "Show" first, then a "Copy" button will appear.
*   **Filling Passwords:**
    *   **Extension:** When on a login page, click the extension icon. Entries matching the domain appear first. Click the list item (if it's a domain match) or click "Show" then "Fill".
    *   **Content Script Icon (Optional):** If enabled/working, an icon may appear in password fields. Clicking it can trigger the popup or directly fill credentials (depending on implementation).
*   **Analyzing Passwords:**
    *   Navigate to `/analyse` in the web app.
    *   Enter a single password for immediate analysis.
    *   Click "Load & Analyse All Stored Credentials" to decrypt (client-side) and analyze all your saved passwords for strength and potential breaches.
*   **Logging Out:** Click the "Logout" link available in the header of the web app pages or within the extension popup. This clears the session key.

## Security Considerations

*   **Master Password:** This is the most critical piece of information. Choose a strong, unique Master Password that you don't use anywhere else. **If you forget it, your encrypted data is irrecoverable.**
*   **End-to-End Encryption:** The design ensures the server (Flask backend and Supabase) only ever handles encrypted data blobs. Decryption keys are derived client-side from the Master Password and ideally only held in memory (sessionStorage or background script memory) during an active session.
*   **Backend Security:** While the backend doesn't handle decryption, it's vital to secure it against unauthorized access, ensure dependencies are up-to-date, and use HTTPS for any real-world deployment. Master Password *hashes* (using Bcrypt) are stored for login verification.
*   **Supabase Row Level Security (RLS):** RLS policies **must** be enabled and correctly configured in Supabase to prevent users from accessing each other's encrypted data. The provided SQL includes basic policies, but review and test them thoroughly.
*   **API Keys (`.env`):** Keep your `.env` file secure and **never commit it to version control**. Ensure `FLASK_SECRET_KEY` is strong and random. The `GEMINI_API_KEY` should also be treated as sensitive.
*   **HTTPS:** For any non-local deployment, HTTPS is **mandatory** to protect login credentials and session cookies during transit.
*   **XSS/CSRF:** Standard web security practices should be followed in the Flask application to prevent Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) attacks. Use Flask-WTF or similar libraries if forms are more complex. Ensure Jinja2 autoescaping is enabled (default).
*   **Extension Permissions:** The extension requests permissions like `activeTab`, `scripting`, `storage`, and `cookies`. These are necessary for its core functions (filling passwords, storing session state, communicating with the backend). Be aware of what permissions extensions request.
*   **k-Anonymity (HIBP):** Password breach checking via HIBP uses k-Anonymity, meaning your full password hash is *not* sent to the HIBP server, preserving privacy for that specific check.
*   **Session Management:** The Flask session stores the *derived* encryption key (Base64URL encoded). Session security (cookie flags like HttpOnly, Secure, SameSite) is important. The "Remember Me" feature extends session lifetime but relies on secure cookie handling. The background script also holds the key temporarily.
*   **Disclaimer:** This project is primarily for educational/demonstration purposes. While it implements strong E2EE concepts, deploying it for highly sensitive data requires thorough security audits and hardening beyond this basic setup.

## Development

*   **Backend:** Modify `app.py` and related files. The Flask development server usually auto-reloads on changes (`FLASK_ENV=development`).
*   **Extension:**
    *   Modify HTML, CSS, or JS files within the extension directory.
    *   Go back to `chrome://extensions/`.
    *   Find the extension card and click the refresh icon (circular arrow).
    *   Close and reopen the popup or refresh the web page where the content script runs to see changes.

## Future Improvements

*   Implement Email Breach Checking (requires HIBP paid API or alternative service).
*   Add Secure Notes storage feature.
*   Implement Two-Factor Authentication (2FA) for login.
*   Add Password History (store previous encrypted versions).
*   More robust error handling and user feedback.
*   UI/UX enhancements for both web app and extension.
*   Option for users to host their own backend easily (e.g., Docker setup).
*   Detailed deployment guide (e.g., Heroku, Render, Docker).
*   Formal security audit.
*   Cross-browser compatibility testing (Firefox support would require manifest/API changes).
