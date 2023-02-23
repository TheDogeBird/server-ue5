from flask import Flask, jsonify, request, send_file, make_response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
import os
import json
import sqlite3
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

# Define a list of authorized users (username, password hash, and roles)
authorized_users = [
    {'username': 'user1', 'password_hash': generate_password_hash('password1'), 'roles': ['user']},
    {'username': 'user2', 'password_hash': generate_password_hash('password2'), 'roles': ['user', 'admin']}
]

# Define a list of registered users (username and password hash)
registered_users = []

# Define a list of roles and their permissions
roles = {
    'user': ['read'],
    'admin': ['read', 'write']
}

auth = HTTPBasicAuth()

# This function checks if a username and password match an authorized user
@auth.verify_password
def verify_password(username, password):
    for user in authorized_users:
        if user['username'] == username and check_password_hash(user['password_hash'], password):
            return username

# This function checks if a user is authorized to perform a certain action
def is_authorized(username, permission):
    for user in authorized_users:
        if user['username'] == username and permission in roles[user['roles'][0]]:
            return True
    return False

# This endpoint allows a user to register for the system
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    for user in authorized_users:
        if user['username'] == username:
            abort(400, description='Username already exists')
    password_hash = generate_password_hash(password)
    registered_users.append({'username': username, 'password_hash': password_hash})
    authorized_users.append({'username': username, 'password_hash': password_hash, 'roles': ['user']})
    return make_response(jsonify({'message': 'User registered successfully'}), 201)

# This endpoint returns a list of all available GLTF files
@app.route('/gltf', methods=['GET'])
@auth.login_required
def get_gltf_list():
    gltf_dir = 'gltf/'
    gltf_files = [f for f in os.listdir(gltf_dir) if os.path.isfile(os.path.join(gltf_dir, f))]
    return jsonify(gltf_files)

# This endpoint returns a specified GLTF file in a JSON response
@app.route('/gltf/<filename>', methods=['GET'])
@auth.login_required
def get_gltf_file(filename):
    if not is_authorized(auth.current_user(), 'read'):
        abort(401, description='Unauthorized')
    gltf_path = f'gltf/{filename}'
    if os.path.isfile(gltf_path):
        with open(gltf_path, 'r') as f:
            gltf_data = f.read()
            return jsonify({'gltf_file': gltf_data})
    else:
        abort(404, description='File not found')

# This endpoint returns a specified GLTF file in a JSON response with meta-data
@app.route('/gltf/<filename>/meta', methods=['GET'])
@auth.login_required
def get_gltf_file_meta(filename):
    if not is_authorized(auth.current_user(), 'read'):
        abort(401, description='Unauthorized')
    gltf_path = f'gltf/{filename}'
    if os.path.isfile(gltf_path):
        with open(gltf_path, 'r') as f:
            gltf_data = json.loads(f.read())
            gltf_metadata = {
                'filename': filename,
                'size': os.path.getsize(gltf_path),
                'type': 'GLTF',
                'author': 'Anonymous',
                'created': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            gltf_data['metadata'] = gltf_metadata
            if 'download' in request.args:
                return send_file(gltf_path, as_attachment=True, attachment_filename=filename)
            else:
                return jsonify(gltf_data)
    else:
        abort(404, description='File not found')

# This endpoint allows a user to upload a GLTF file with meta-data
@app.route('/gltf', methods=['POST'])
@auth.login_required
def upload_gltf_file():
    if not is_authorized(auth.current_user(), 'write'):
        abort(401, description='Unauthorized')
    if 'file' not in request.files:
        abort(400, description='No file provided')
    gltf_file = request.files['file']
    if gltf_file.filename == '':
        abort(400, description='No file selected')
    if not gltf_file.filename.endswith('.gltf'):
        abort(400, description='Invalid file format. Only GLTF files are allowed.')
    metadata = request.form.get('metadata')
    if metadata:
        metadata_dict = json.loads(metadata)
        if 'author' in metadata_dict:
            author = metadata_dict['author']
        else:
            author = 'Anonymous'
    else:
        author = 'Anonymous'
    gltf_file.save(os.path.join('gltf', gltf_file.filename))
    gltf_metadata = {
        'filename': gltf_file.filename,
        'size': os.path.getsize(os.path.join('gltf', gltf_file.filename)),
        'type': 'GLTF',
        'author': author,
        'created': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    with open(os.path.join('gltf', gltf_file.filename), 'r') as f:
        gltf_data = json.loads(f.read())
        gltf_data['metadata'] = gltf_metadata
    with open(os.path.join('gltf', gltf_file.filename), 'w') as f:
        f.write(json.dumps(gltf_data))
    return make_response(jsonify({'message': 'File uploaded successfully'}), 201)

if __name__ == '__main__':
    app.run(debug=True)
