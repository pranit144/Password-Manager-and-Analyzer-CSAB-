import os
import json
import hashlib
import time
import re
import base64
import traceback # For detailed error logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from supabase import create_client, Client # Use v2 import style
# Note: cryptography library parts are only needed for derive_key now
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

app = Flask(__name__)
# Make sure FLASK_SECRET_KEY is set strong in your .env!
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key_please_change')
app.config['ENV'] = os.environ.get('FLASK_ENV', 'production')
app.config['DEBUG'] = app.config['ENV'] == 'development'


# --- Supabase Configuration ---
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY") # Anon key

if not supabase_url or not supabase_key:
    raise ValueError("Supabase URL and Key must be set in .env file")

supabase: Client = create_client(supabase_url, supabase_key)
print("Supabase client initialized.")

# --- Authentication Setup ---
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
print("Flask-Login initialized.")

# --- User Model for Flask-Login ---
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    user_data = session.get('user_data')
    if user_data and user_data['id'] == user_id:
        return User(id=user_data['id'], email=user_data['email'])
    # print(f"User {user_id} not found in session.") # Reduced verbosity
    return None


# --- Gemini LLM Configuration ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
genai_available = False
if GEMINI_API_KEY and GEMINI_API_KEY.startswith("AIza"):
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        genai_available = True
        print("Gemini API configured successfully.")
    except Exception as e:
        print(f"Warning: Failed to configure Gemini API: {e}")
else:
     print("Warning: Gemini API key not found or looks invalid. LLM features will use mock/basic analysis.")


# --- E2EE Helper Functions ---
def derive_key(master_password: str, salt_or_email: str) -> bytes:
    """
    Derives a 32-byte key suitable for AES using PBKDF2HMAC.
    Uses email (lowercase) as salt for simplicity - *replace with stored unique salt in production*.
    Returns the key BASE64 URL-SAFE ENCODED (suitable for session/storage).
    """
    salt = salt_or_email.lower().encode('utf-8')
    iterations = 390000 # Match JS side
    kdf = PBKDF2HMAC( algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations )
    key_bytes = kdf.derive(master_password.encode('utf-8')) # Raw 32 bytes

    # --- ADDED LOGGING ---
    # Log the standard Base64 representation for easier comparison with JS console log
    try:
        raw_key_standard_b64 = base64.b64encode(key_bytes).decode('utf-8')
        print(f"DEBUG: PY Derived Key (Raw -> Standard Base64): {raw_key_standard_b64}")
    except Exception as log_e:
        print(f"DEBUG: Error logging derived key: {log_e}")
    # --- END LOGGING ---

    # Return URL-safe Base64 encoded key for session storage
    key_b64url_encoded = base64.urlsafe_b64encode(key_bytes)
    return key_b64url_encoded

# --- Password Analysis Functions ---
# (get_character_composition, get_llm_password_insights, get_basic_password_analysis_from_chars, get_mock_llm_insights_from_chars)
# Keep these functions as they were in the previous correct version.
# ... (Copy the 4 analysis functions from the previous response here) ...
def get_character_composition(password):
    """Generates character composition dict."""
    composition = { 'lowercase': 0, 'uppercase': 0, 'digits': 0, 'special': 0 }
    if not password: return composition # Handle None or empty string
    for char in password:
        if char.islower(): composition['lowercase'] += 1
        elif char.isupper(): composition['uppercase'] += 1
        elif char.isdigit(): composition['digits'] += 1
        elif not char.isalnum() and not char.isspace(): composition['special'] += 1 # More specific special char check
    return composition

def get_llm_password_insights(password_characteristics: dict):
    """ Get password analysis insights from Gemini API based on characteristics."""
    global genai_available
    try:
        use_mock = app.config['DEBUG'] or not genai_available
        if use_mock:
            return get_mock_llm_insights_from_chars(password_characteristics)

        generation_config = { "temperature": 0.2, "top_p": 0.8, "top_k": 40, "max_output_tokens": 512 }
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]
        model = genai.GenerativeModel('gemini-1.5-flash', generation_config=generation_config, safety_settings=safety_settings)

        prompt = f"""
        Analyze a password based *only* on the following characteristics. Provide a security assessment.
        DO NOT attempt to guess the password or ask for it.
        Return ONLY a valid JSON object with the exact structure below, no other text or explanations.
        {{
            "strength_score": 1-5 (integer, 1=very weak, 5=very strong),
            "assessment": "Very Weak/Weak/Medium/Strong/Very Strong",
            "insights": ["Specific observations based on characteristics provided"],
            "suggestions": ["Actionable improvement tips based on characteristics"]
        }}

        Password Characteristics:
        Length: {password_characteristics.get('length', 0)}
        Contains Lowercase: {'Yes' if password_characteristics.get('composition', {}).get('lowercase', 0) > 0 else 'No'}
        Contains Uppercase: {'Yes' if password_characteristics.get('composition', {}).get('uppercase', 0) > 0 else 'No'}
        Contains Digits: {'Yes' if password_characteristics.get('composition', {}).get('digits', 0) > 0 else 'No'}
        Contains Special Chars: {'Yes' if password_characteristics.get('composition', {}).get('special', 0) > 0 else 'No'}
        """
        response = model.generate_content(prompt)

        if not response.candidates or not hasattr(response.candidates[0], 'content') or not response.candidates[0].content.parts:
             print(f"Gemini response blocked or empty. Reason: {response.prompt_feedback}")
             return get_basic_password_analysis_from_chars(password_characteristics)

        response_text = response.text
        json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', response_text, re.DOTALL | re.IGNORECASE)
        if not json_match: json_match = re.search(r'({.*})', response_text, re.DOTALL)

        if json_match:
            try:
                insights_json = json.loads(json_match.group(1))
                if all(k in insights_json for k in ['strength_score', 'assessment', 'insights', 'suggestions']):
                    return { 'strength': insights_json.get('strength_score', 1), 'assessment': insights_json.get('assessment', 'Weak'),
                             'insights': insights_json.get('insights', []), 'suggestions': insights_json.get('suggestions', []) }
                else: raise ValueError("Missing keys in JSON response")
            except (json.JSONDecodeError, ValueError) as json_err:
                 print(f"LLM JSON processing Error: {json_err}. Falling back.")
                 return get_basic_password_analysis_from_chars(password_characteristics)
        else:
            print("LLM JSON pattern not found. Falling back.")
            return get_basic_password_analysis_from_chars(password_characteristics)
    except Exception as e:
        print(f"Error getting Gemini insights: {type(e).__name__} - {e}")
        return get_basic_password_analysis_from_chars(password_characteristics)

def get_basic_password_analysis_from_chars(characteristics: dict):
    """ Basic password analysis based on characteristics. Returns same structure as LLM."""
    strength = 0; insights = []; suggestions = []
    length = characteristics.get('length', 0)
    composition = characteristics.get('composition', {})
    # Score Calculation (simple example)
    if length < 8: insights.append("Short (< 8 chars)"); suggestions.append("Use 12+ chars.")
    elif length < 12: strength += 1; insights.append("Okay length (8-11)") ; suggestions.append("Use 12+ chars.")
    else: strength += 2; insights.append("Good length (12+)")
    if composition.get('uppercase', 0) > 0: strength += 1
    else: insights.append("No uppercase"); suggestions.append("Add A-Z.")
    if composition.get('lowercase', 0) > 0: strength += 1
    else: insights.append("No lowercase"); suggestions.append("Add a-z.")
    if composition.get('digits', 0) > 0: strength += 1
    else: insights.append("No numbers"); suggestions.append("Add 0-9.")
    if composition.get('special', 0) > 0: strength += 1
    else: insights.append("No special chars"); suggestions.append("Add !@#$.")
    # Map score (0-6) to 1-5 rating
    score_map = {0: 1, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 5}
    final_score = score_map.get(strength, 1)
    assessment_map = {1: "Very Weak", 2: "Weak", 3: "Medium", 4: "Strong", 5: "Very Strong"}
    assessment = assessment_map.get(final_score, "Weak")
    if final_score == 5 and not insights: insights.append("Meets basic complexity.")
    return {'strength': final_score, 'assessment': assessment, 'insights': insights, 'suggestions': suggestions}

def get_mock_llm_insights_from_chars(characteristics: dict):
    """ Generates mock LLM insights based on characteristics."""
    basic_analysis = get_basic_password_analysis_from_chars(characteristics)
    if basic_analysis['strength'] < 4: basic_analysis['suggestions'].append("Consider passphrase.")
    if not basic_analysis['insights'] and basic_analysis['strength'] >= 4: basic_analysis['insights'].append("Good length/variety.")
    return basic_analysis


# --- Routes ---

@app.route('/')
def home():
    if current_user.is_authenticated: return redirect(url_for('add_password_page'))
    else: return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('add_password_page'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip(); password = request.form.get('password', '')
        if not email or not password:
            flash('Email and Master Password are required.', 'danger'); return render_template('login.html'), 400
        try:
            response = supabase.table('users').select("id, email, password_hash").eq('email', email).maybe_single().execute()
            if hasattr(response, 'data') and response.data:
                user_data = response.data; stored_hash = user_data['password_hash']
                if bcrypt.check_password_hash(stored_hash, password):
                    user_obj = User(id=user_data['id'], email=user_data['email'])
                    login_user(user_obj)
                    session['user_data'] = {'id': user_data['id'], 'email': user_data['email']}
                    # Derive key and store URL-safe Base64 version in session
                    derived_key_b64url = derive_key(password, user_data['email'])
                    session['encryption_key'] = derived_key_b64url.decode('utf-8')
                    flash('Logged in successfully!', 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('add_password_page'))
                else: flash('Login failed. Invalid email or password.', 'danger')
            else: flash('Login failed. Invalid email or password.', 'danger')
            return render_template('login.html'), 401
        except Exception as e:
            flash(f'An error occurred during login. Please try again.', 'danger')
            print(f"Login Exception for {email}: {type(e).__name__} - {e}"); traceback.print_exc()
            return render_template('login.html'), 500
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('add_password_page'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', ''); confirm_password = request.form.get('confirm_password', '')
        if not email or not password or not confirm_password: flash('All fields are required.', 'danger'); return render_template('register.html'), 400
        if password != confirm_password: flash('Passwords do not match.', 'danger'); return render_template('register.html'), 400
        try:
            check_response = supabase.table('users').select("id", count='exact').eq('email', email).execute()
            if hasattr(check_response, 'count') and check_response.count is not None and check_response.count > 0:
                flash('Email address is already registered. Please login.', 'warning'); return redirect(url_for('login'))
            elif not hasattr(check_response, 'count'): print(f"WARNING: Supabase check for {email} lacked 'count': {check_response}")

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            insert_response = supabase.table('users').insert({'email': email, 'password_hash': hashed_password}).execute()
            if hasattr(insert_response, 'data') and insert_response.data:
                 flash('Registration successful! Please log in.', 'success'); return redirect(url_for('login'))
            else:
                 print(f"ERROR: Registration failed for {email}. Response: {insert_response}")
                 flash("Registration failed due to a server error.", 'danger')
                 return render_template('register.html'), 500
        except Exception as e:
            flash(f'An error occurred during registration. Please try again.', 'danger')
            print(f"Registration Exception for {email}: {type(e).__name__} - {e}"); traceback.print_exc()
            return render_template('register.html'), 500
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('encryption_key', None); session.pop('user_data', None)
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# --- Main Application Pages (Require Login) ---

@app.route('/add')
@login_required
def add_password_page(): return render_template('index.html')

@app.route('/storage')
@login_required
def storage(): return render_template('storage.html')

@app.route('/analyse')
@login_required
def analyse(): return render_template('analyse.html')

# --- API Endpoints (Require Login) ---

@app.route('/api/credentials', methods=['GET'])
@login_required
def get_credentials():
    user_id = current_user.id
    try:
        response = supabase.table('credentials').select("id, encrypted_data, service_hint, created_at").eq('user_id', user_id).order('created_at', desc=True).execute()
        # Check response structure for Supabase v2 (data attribute is primary)
        if hasattr(response, 'data'):
            return jsonify(response.data)
        else: # Fallback or error logging if structure changes
            print(f"Supabase get credentials unexpected response for user {user_id}. Response: {response}")
            return jsonify({'error': 'Failed to retrieve credentials'}), 500
    except Exception as e:
        print(f"Error in get_credentials for user {user_id}: {e}"); traceback.print_exc()
        return jsonify({'error': 'Server error retrieving credentials'}), 500

@app.route('/api/credentials', methods=['POST'])
@login_required
def add_credential():
    data = request.json; user_id = current_user.id
    encrypted_data = data.get('encrypted_data'); service_hint = data.get('service_hint')
    if not encrypted_data: return jsonify({'success': False, 'message': 'Encrypted data payload is required.'}), 400
    try:
        insert_response = supabase.table('credentials').insert({'user_id': user_id, 'encrypted_data': encrypted_data, 'service_hint': service_hint}).execute()
        # Check response structure for Supabase v2
        if hasattr(insert_response, 'data') and insert_response.data:
            return jsonify({'success': True, 'message': 'Credential saved successfully.'})
        else:
            print(f"Supabase insert credentials error for user {user_id}. Response: {insert_response}")
            # Attempt to get more specific error if available (structure might vary)
            error_msg = "Failed to save credential"
            if hasattr(insert_response, 'error') and insert_response.error and hasattr(insert_response.error, 'message'):
                error_msg += f": {insert_response.error.message}"
            return jsonify({'success': False, 'message': error_msg}), 500
    except Exception as e:
        print(f"Error in add_credential for user {user_id}: {e}"); traceback.print_exc()
        return jsonify({'success': False, 'message': 'Server error saving credential'}), 500

@app.route('/api/analyse_password', methods=['POST'])
@login_required
def analyse_password_api():
    data = request.json; characteristics = data.get('characteristics')
    if not characteristics or not isinstance(characteristics, dict):
         return jsonify({'error': 'Password characteristics payload is required.'}), 400
    analysis = get_llm_password_insights(characteristics)
    feedback = []
    if 'insights' in analysis: feedback.extend([f"Issue: {ins}" for ins in analysis['insights'] if ins])
    if 'suggestions' in analysis: feedback.extend([f"Tip: {sug}" for sug in analysis['suggestions'] if sug])
    if not feedback:
        if analysis.get('strength', 0) == 5: feedback.append("Tip: Looks good based on characteristics!")
        else: feedback.append("Issue: Review password based on assessment.")
    return jsonify({ 'strength': analysis.get('strength', 1), 'assessment': analysis.get('assessment', 'Weak'), 'feedback': feedback })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])