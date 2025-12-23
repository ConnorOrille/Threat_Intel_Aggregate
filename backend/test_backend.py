from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'test-secret-key-123'
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    # Create token immediately (no database)
    token = create_access_token(identity=email)
    return jsonify({'token': token, 'email': email})

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': 'Success!', 'user': current_user})

if __name__ == '__main__':
    app.run(debug=True, port=5001)