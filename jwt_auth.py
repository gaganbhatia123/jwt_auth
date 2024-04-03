# Import necessary libraries
from flask import Flask, request  # Flask for web framework, request for handling HTTP requests
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity  # JWTManager for JWT token management

# Initialize Flask app
app = Flask(__name__)

# Set the secret key for JWT
app.config['JWT_SECRET_KEY'] = 'your_secret_key'

# Initialize JWTManager with the app
jwt = JWTManager(app)

# Endpoint to authenticate and generate JWT token
@app.route('/login', methods=['POST'])
def login():
    # Get username and password from the request
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Check if username and password are correct
    if username == 'john' and password == 'password':
        # Generate access token with the username as identity
        access_token = create_access_token(identity=username)
        # Return the access token with status code 200 (OK)
        return {'access_token': access_token}, 200
    else:
        # Return error message with status code 401 (Unauthorized)
        return {'error': 'Invalid credentials'}, 401

# Protected endpoint that requires JWT token
@app.route('/protected')
@jwt_required()
def protected_resource():
    # Get the identity (username) from the JWT token
    current_user = get_jwt_identity()
    # Return a welcome message with the username
    return 'Welcome, %s!' % current_user

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
