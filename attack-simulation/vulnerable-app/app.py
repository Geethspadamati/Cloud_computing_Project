from flask import Flask, request, jsonify
import mysql.connector

app = Flask(__name__)

DB_CONFIG = {
    'host': 'sqli-project-db.cbkwoocygz03.us-east-2.rds.amazonaws.com',
    'user': 'admin',
    'password': 'SQLi_Project_2024!',
    'database': 'userdata'
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    db = get_db()
    cursor = db.cursor(dictionary=True)
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    db.close()
    return jsonify({'query': query, 'results': result})

@app.route('/search')
def search():
    name = request.args.get('name', '')
    db = get_db()
    cursor = db.cursor(dictionary=True)
    query = "SELECT id, full_name, email FROM users WHERE full_name LIKE '%" + name + "%'"
    cursor.execute(query)
    result = cursor.fetchall()
    db.close()
    return jsonify({'query': query, 'results': result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
