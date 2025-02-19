from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modello Utente
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    image = db.Column(db.String(300))
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    attendees = db.Column(db.Text, default='')  # Lista di ID utente separati da virgole

@app.route('/join_event/<int:event_id>')
@login_required
def join_event(event_id):
    event = Event.query.get_or_404(event_id)
    user_id = str(current_user.id)

    # Controlliamo se l'utente è già nella lista partecipanti
    attendees_list = event.attendees.split(',') if event.attendees else []
    if user_id not in attendees_list:
        attendees_list.append(user_id)
        event.attendees = ','.join(attendees_list)
        db.session.commit()
        flash('Hai partecipato all\'evento!', 'success')
    else:
        flash('Partecipi già a questo evento!', 'info')

    return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username già esistente!', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registrazione completata! Ora puoi accedere.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenziali non valide', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    events = Event.query.all()
    return render_template('index.html', events=events)

@app.route('/add_event', methods=['GET', 'POST'])
@login_required
def add_event():
    if request.method == 'POST':
        title = request.form['title']
        image = request.form['image']
        date = request.form['date']
        time = request.form['time']
        description = request.form['description']
        new_event = Event(title=title, image=image, date=date, time=time, description=description, attendees='')
        db.session.add(new_event)
        db.session.commit()
        flash('Evento aggiunto con successo!', 'success')
        return redirect(url_for('index'))
    return render_template('add_event.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=False)

