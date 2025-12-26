from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime, timezone
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "mestech_final_v13"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Track active users
active_users = 0

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(11), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty = db.Column(db.String(50))
    subject_code = db.Column(db.String(20))
    subject_name = db.Column(db.String(100))
    content = db.Column(db.Text)
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    votes = db.relationship('Vote', backref='thread', cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='thread', cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    author = db.Column(db.String(20))
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    votes = db.relationship('Vote', backref='comment', cascade="all, delete-orphan")

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(11), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=True)
    reason = db.Column(db.String(200))
    reporter = db.Column(db.String(20))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(student_id="ADMIN").first():
        admin = User(student_id="ADMIN", password=generate_password_hash("admin123"), is_admin=True)
        db.session.add(admin)
        db.session.commit()

# --- Global Data ---
@app.context_processor
def inject_globals():
    user_votes = []
    if 'user' in session:
        v_list = Vote.query.filter_by(user_id=session['user']).all()
        user_votes = [f"t{v.thread_id}" if v.thread_id else f"c{v.comment_id}" for v in v_list]
    
    return dict(
        uv=user_votes,
        total_posts=Thread.query.count(),
        total_votes=Vote.query.count(),
        online_users=active_users
    )

# --- Socket Events ---
@socketio.on('connect')
def handle_connect():
    global active_users
    active_users += 1
    socketio.emit('user_count', active_users)

@socketio.on('disconnect')
def handle_disconnect():
    global active_users
    active_users -= 1
    socketio.emit('user_count', active_users)

# --- ROUTES ---

@app.route('/')
def index():
    search_query = request.args.get('search')
    faculty_filter = request.args.get('faculty')
    query = Thread.query

    if faculty_filter:
        query = query.filter_by(faculty=faculty_filter)
        
    if search_query:
        query = query.filter(Thread.subject_code.contains(search_query.upper()))

    threads = query.order_by(Thread.date_posted.desc()).all()
    return render_template('index.html', threads=threads)

@app.route('/login', methods=['POST'])
def login():
    u = User.query.filter_by(student_id=request.form.get('student_id')).first()
    if u and check_password_hash(u.password, request.form.get('password')):
        if u.is_banned: 
            flash("Account banned.")
            return redirect(url_for('index'))
        session['user'] = u.student_id
        session['is_admin'] = u.is_admin
        return redirect(url_for('index'))
    flash("Invalid ID or Password.")
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    sid = request.form.get('student_id')
    pw = request.form.get('password')
    if User.query.filter_by(student_id=sid).first():
        flash("Student ID already exists!")
    else:
        new_user = User(student_id=sid, password=generate_password_hash(pw))
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! Please login.")
    return redirect(url_for('index'))

@app.route('/post', methods=['POST'])
def post():
    if 'user' in session:
        t = Thread(faculty=request.form['faculty'], subject_code=request.form['code'].upper(), 
                   subject_name=request.form['name'], content=request.form['content'], author=session['user'])
        db.session.add(t)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/vote/<string:type>/<int:tid>')
def vote(type, tid):
    if 'user' not in session: return redirect(url_for('index'))
    v = Vote.query.filter_by(user_id=session['user'], 
                             thread_id=tid if type=='thread' else None, 
                             comment_id=tid if type=='comment' else None).first()
    if v: db.session.delete(v)
    else: db.session.add(Vote(user_id=session['user'], 
                               thread_id=tid if type=='thread' else None, 
                               comment_id=tid if type=='comment' else None))
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

@app.route('/report/<int:tid>', methods=['POST'])
def report(tid):
    if 'user' in session:
        db.session.add(Report(thread_id=tid, reason=request.form['reason'], reporter=session['user']))
        db.session.commit()
    return redirect(request.referrer)

@app.route('/admin')
def admin():
    if not session.get('is_admin'): return redirect(url_for('index'))
    return render_template('admin.html', reports=Report.query.all(), users=User.query.all())

@app.route('/admin/action/<string:act>/<int:id>')
def admin_action(act, id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    if act == 'del':
        t = Thread.query.get(id)
        if t:
            Report.query.filter_by(thread_id=id).delete()
            db.session.delete(t)
    elif act == 'ignore':
        r = Report.query.get(id); db.session.delete(r) if r else None
    elif act == 'ban':
        u = User.query.get(id); u.is_banned = not u.is_banned if u else None
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/thread/<int:thread_id>')
def view_thread(thread_id):
    t = Thread.query.get_or_404(thread_id)
    return render_template('thread.html', thread=t)

@app.route('/comment/<int:thread_id>', methods=['POST'])
def add_comment(thread_id):
    if 'user' in session:
        c = Comment(content=request.form['content'], author=session['user'], thread_id=thread_id,
                    parent_id=request.form.get('parent_id'))
        db.session.add(c)
        db.session.commit()
    return redirect(url_for('view_thread', thread_id=thread_id))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    socketio.run(app, debug=True)