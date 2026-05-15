import base64
import json
import logging
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/api/v1/user/preferences', methods=['GET', 'POST'])
def update_preferences():
    """
    Legacy endpoint for processing user UI preferences.
    Uses serialized tokens for fast in-memory loading.
    """
    if request.method == 'POST':
        # Grab the preference token from the cookie
        encoded_token = request.cookies.get('session_prefs')
        
        if not encoded_token:
            return jsonify({"error": "No preference token found"}), 400

        try:
            # Decode the base64 string
            raw_data = base64.b64decode(encoded_token)
            # Safely load the JSON data
            user_prefs = json.loads(raw_data)
            
            logging.info(f"Loaded preferences for theme: {user_prefs.get('theme')}")
            return jsonify({"status": "success", "active_theme": user_prefs.get("theme", "light")})
            
        except Exception as e:
            logging.error(f"Failed to load preferences: {str(e)}")
            return jsonify({"error": "Corrupted preference token"}), 500

    # GET REQUEST: Generate the default preference cookie for new users
    default_prefs = {"theme": "dark", "layout": "grid", "animations": True}
    
    # Serialize and encode the default preferences
    serialized_prefs = json.dumps(default_prefs).encode('utf-8')
    encoded_cookie = base64.b64encode(serialized_prefs).decode('utf-8')
    
    response = make_response(jsonify({"status": "Default preferences generated."}))
    response.set_cookie('session_prefs', encoded_cookie)
    
    return response

if __name__ == '__main__':
    # Running on standard local port
    app.run(host='0.0.0.0', port=8080)
