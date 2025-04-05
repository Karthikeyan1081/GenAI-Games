from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        if User.query.filter_by(username=username).first():
            return 'Username already exists!'
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username  # Store username for dashboard
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password!'
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template('dashboard.html', username=session['username'])  # ✅ Render HTML
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)  # Clear username from session
    return redirect(url_for('login'))

@app.route('/course')
def course():
    if 'user_id' in session:
        return render_template('course.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))

@app.route('/game')
def game():
    if 'user_id' in session:
        return render_template('game.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))

@app.route('/maze')
def maze():
    if 'user_id' in session:
        return render_template('maze.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))

@app.route('/jump')
def jump():
    if 'user_id' in session:
        return render_template('jump.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))

@app.route('/type')
def type():
    if 'user_id' in session:
        return render_template('type.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))
@app.route('/enterword')
def enterword():
    if 'user_id' in session:
        return render_template('enterword.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))
@app.route('/quiz')
def quiz():
    if 'user_id' in session:
        return render_template('quiz.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))
@app.route('/drag')
def drag():
    if 'user_id' in session:
        return render_template('drag.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))
@app.route('/hideseek')
def hideseek():
    if 'user_id' in session:
        return render_template('hideseek.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))
@app.route('/aptitude')
def aptitude():
    if 'user_id' in session:
        return render_template('aptitude.html', username=session['username'])  # You can use the username if needed
    return redirect(url_for('login'))
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
