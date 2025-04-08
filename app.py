from flask import Flask, render_template, request, jsonify, redirect, url_for
from blockchain import Blockchain
import hashlib
import json
import os
import time
import requests
import re
import google.generativeai as genai  # Import the Gemini library

app = Flask(__name__)

# Initialize blockchain
blockchain = Blockchain()

# Load blockchain from file if it exists
if os.path.exists('blockchain.json'):
    with open('blockchain.json', 'r') as f:
        blockchain_data = json.load(f)
        blockchain.chain = blockchain_data['chain']
        blockchain.pending_transactions = blockchain_data['pending_transactions']

# Configure Gemini API
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBRzLEPudJzVNDQpckpxhbkA3aF9Inr5v0")  # Store actual key in environment variable
genai.configure(api_key=GEMINI_API_KEY)


def get_llm_password_insights(password):
    """
    Get password analysis insights from Gemini API
    """
    try:
        # Check if we're in development/testing mode and return mock data
        if os.environ.get("FLASK_ENV") == "development" or not GEMINI_API_KEY.startswith("AI"):
            return get_mock_llm_insights(password)

        # Setup the Gemini model with specific parameters
        generation_config = {
            "temperature": 0.2,  # Lower temperature for more consistent outputs
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 1024,
        }

        model = genai.GenerativeModel(
            'gemini-2.0-flash',
            generation_config=generation_config
        )

        # Prepare prompt for Gemini
        prompt = f"""
        Analyze the following password for strengths and weaknesses. DO NOT include the actual 
        password in your response. Return ONLY a JSON object with the following structure:
        {{
            "strength_score": 1-5 (integer),
            "assessment": "Very Weak/Weak/Medium/Strong/Very Strong",
            "insights": [list of specific insights about the password's strengths and weaknesses],
            "suggestions": [list of actionable suggestions to improve the password]
        }}

        For reference, the password uses the following characters: {get_character_composition(password)}
        The password is {len(password)} characters long.
        """

        # Make API request to Gemini
        response = model.generate_content(prompt)

        # Extract JSON from response
        # The response might include explanatory text, so we need to extract just the JSON part
        response_text = response.text

        # First attempt to find JSON enclosed in triple backticks (common with Gemini)
        match = re.search(r'```json\s*({.*?})\s*```', response_text, re.DOTALL)
        if not match:
            # If not found, try finding any JSON-like content
            match = re.search(r'({.*})', response_text, re.DOTALL)

        if match:
            try:
                insights_json = json.loads(match.group(1))
                # Standardize the key names in case Gemini uses slightly different ones
                result = {
                    'strength': insights_json.get('strength_score', 1),
                    'assessment': insights_json.get('assessment', 'Weak'),
                    'insights': insights_json.get('insights', []),
                    'suggestions': insights_json.get('suggestions', [])
                }
                return result
            except json.JSONDecodeError:
                # If JSON parsing fails, fallback to basic analysis
                return get_basic_password_analysis(password)
        else:
            # If no JSON pattern is found, fallback to basic analysis
            return get_basic_password_analysis(password)

    except Exception as e:
        print(f"Error getting Gemini insights: {e}")
        # If any error occurs, fall back to basic analysis
        return get_basic_password_analysis(password)


def get_character_composition(password):
    """Create a safe representation of character types in password"""
    composition = {
        'lowercase': 0,
        'uppercase': 0,
        'digits': 0,
        'special': 0
    }

    for char in password:
        if char.islower():
            composition['lowercase'] += 1
        elif char.isupper():
            composition['uppercase'] += 1
        elif char.isdigit():
            composition['digits'] += 1
        else:
            composition['special'] += 1

    return composition


def get_mock_llm_insights(password):
    """
    Generate mock LLM insights for development/testing
    This is more sophisticated than basic analysis but doesn't require actual API calls
    """
    # Perform basic analysis
    basic_analysis = get_basic_password_analysis(password)
    strength = basic_analysis['strength']

    # Check for common patterns
    has_common_pattern = False
    common_patterns = [
        r'123', r'qwerty', r'password', r'admin', r'welcome',
        r'abc', r'111', r'000', r'pass', r'letmein'
    ]

    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            has_common_pattern = True
            break

    # Check for sequential characters
    sequential_chars = False
    for i in range(len(password) - 2):
        chars = password[i:i + 3].lower()
        if chars.isalpha() and ord(chars[0]) + 1 == ord(chars[1]) and ord(chars[1]) + 1 == ord(chars[2]):
            sequential_chars = True
            break

    # Check for repeating characters
    repeating_chars = False
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] and password[i + 1] == password[i + 2]:
            repeating_chars = True
            break

    # Add more sophisticated insights
    insights = []
    suggestions = []

    if has_common_pattern:
        insights.append("Contains a common password pattern")
        suggestions.append("Avoid using common words or patterns like '123', 'password', or 'qwerty'")
        # Reduce strength if it contains common patterns
        strength = max(1, strength - 1)

    if sequential_chars:
        insights.append("Contains sequential characters")
        suggestions.append("Avoid sequential characters like 'abc' or '123'")

    if repeating_chars:
        insights.append("Contains repeating characters")
        suggestions.append("Avoid repeating the same character multiple times in a row")

    # Length-based insights
    if len(password) < 10:
        insights.append("Password length is below recommended minimum of 10 characters")
        suggestions.append("Increase password length to at least 10-12 characters")
    elif len(password) >= 16:
        insights.append("Good password length")

    # Add more sophisticated suggestions
    if strength < 4:
        suggestions.append("Consider using a passphrase: a combination of 4+ random words")
        suggestions.append("Add unexpected special characters in the middle of words")

    # Merge with basic feedback
    insights.extend([fb for fb in basic_analysis['feedback'] if fb not in insights])

    # Update assessment based on all factors
    if has_common_pattern or repeating_chars or sequential_chars:
        strength = min(strength, 3)  # Cap at Medium if it has these issues

    # Determine final assessment
    if strength == 5:
        assessment = "Very Strong"
    elif strength == 4:
        assessment = "Strong"
    elif strength == 3:
        assessment = "Medium"
    elif strength == 2:
        assessment = "Weak"
    else:
        assessment = "Very Weak"

    return {
        'strength': strength,
        'assessment': assessment,
        'insights': insights,
        'suggestions': suggestions
    }


def get_basic_password_analysis(password):
    """
    Basic password analysis as fallback when LLM is unavailable
    """
    strength = 0
    feedback = []

    # Check length
    if len(password) < 8:
        feedback.append("Password is too short, should be at least 8 characters")
    else:
        strength += 1

    # Check for uppercase letters
    if any(c.isupper() for c in password):
        strength += 1
    else:
        feedback.append("Password should contain uppercase letters")

    # Check for lowercase letters
    if any(c.islower() for c in password):
        strength += 1
    else:
        feedback.append("Password should contain lowercase letters")

    # Check for numbers
    if any(c.isdigit() for c in password):
        strength += 1
    else:
        feedback.append("Password should contain numbers")

    # Check for special characters
    special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?/\\'
    if any(c in special_chars for c in password):
        strength += 1
    else:
        feedback.append("Password should contain special characters")

    # Overall strength assessment
    if strength == 5:
        assessment = "Very Strong"
    elif strength == 4:
        assessment = "Strong"
    elif strength == 3:
        assessment = "Medium"
    elif strength == 2:
        assessment = "Weak"
    else:
        assessment = "Very Weak"

    return {
        'strength': strength,
        'assessment': assessment,
        'feedback': feedback
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/storage')
def storage():
    return render_template('storage.html')


@app.route('/analyse')
def analyse():
    return render_template('analyse.html')


@app.route('/api/passwords', methods=['GET'])
def get_passwords():
    passwords = blockchain.get_all_data()
    return jsonify(passwords)


@app.route('/api/add_password', methods=['POST'])
def add_password():
    data = request.json
    service = data.get('service')
    username = data.get('username')
    password = data.get('password')

    # Generate hash for verification
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Store both the original password and the hash
    # In a real app, you would encrypt the original password properly
    transaction = {
        'service': service,
        'username': username,
        'password': password,  # Store original password (should be encrypted in production)
        'password_hash': hashed_password,
        'timestamp': time.time()
    }

    # Add to blockchain
    blockchain.add_transaction(transaction)
    blockchain.mine()

    # Save blockchain to file
    with open('blockchain.json', 'w') as f:
        json.dump({
            'chain': blockchain.chain,
            'pending_transactions': blockchain.pending_transactions
        }, f)

    return jsonify({'success': True})


@app.route('/api/analyse_password', methods=['POST'])
def analyse_password():
    data = request.json
    password = data.get('password')

    # Get insights from Gemini API (or fallback to basic analysis)
    analysis = get_llm_password_insights(password)

    # Transform insights and suggestions to consistent feedback format
    feedback = []
    if 'insights' in analysis:
        feedback.extend([f"Issue: {insight}" for insight in analysis['insights']])
    if 'suggestions' in analysis:
        feedback.extend([f"Tip: {suggestion}" for suggestion in analysis['suggestions']])
    if 'feedback' in analysis:
        feedback.extend(analysis['feedback'])

    return jsonify({
        'strength': analysis['strength'],
        'assessment': analysis['assessment'],
        'feedback': feedback
    })


@app.route('/api/analyse_all_passwords', methods=['GET'])
def analyse_all_passwords():
    passwords = blockchain.get_all_data()
    results = []

    for entry in passwords:
        password = entry.get('password')
        if password:
            # Get insights from Gemini API (or fallback to basic analysis)
            analysis = get_llm_password_insights(password)

            # Transform insights and suggestions to consistent feedback format
            feedback = []
            if 'insights' in analysis:
                feedback.extend([f"Issue: {insight}" for insight in analysis['insights']])
            if 'suggestions' in analysis:
                feedback.extend([f"Tip: {suggestion}" for suggestion in analysis['suggestions']])
            if 'feedback' in analysis:
                feedback.extend(analysis['feedback'])

            results.append({
                'service': entry.get('service'),
                'username': entry.get('username'),
                'strength': analysis['strength'],
                'assessment': analysis['assessment'],
                'feedback': feedback
            })

    return jsonify(results)


if __name__ == '__main__':
    app.run(debug=True)