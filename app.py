from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'superpremiumsecret'

def init_db():
    with sqlite3.connect("scadenze.db") as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS utenti (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL)''')
        c.execute("SELECT * FROM utenti WHERE username = 'admin'")
        if not c.fetchone():
            c.execute("INSERT INTO utenti (username, password) VALUES (?, ?)", 
                      ('admin', generate_password_hash('admin')))
        conn.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect("scadenze.db")
        c = conn.cursor()
        username = request.form['username']
        password = request.form['password']
        c.execute("SELECT password FROM utenti WHERE username=?", (username,))
        result = c.fetchone()
        conn.close()
        if result and check_password_hash(result[0], password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return "Credenziali errate", 403
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    init_db()
    app.run(debug=True)