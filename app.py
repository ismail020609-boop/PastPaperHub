import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime, timezone
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "mestech_final_v13"

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'uploads/papers'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'zip', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)

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
    file_path = db.Column(db.String(200), nullable=True) 
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
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True) 
    reason = db.Column(db.String(200))
    reporter = db.Column(db.String(20))
    
    thread = db.relationship('Thread', backref='reported_in')
    comment = db.relationship('Comment', backref='reported_in')

with app.app_context():
    db.create_all()
    if not User.query.filter_by(student_id="ADMIN").first():
        admin = User(student_id="ADMIN", password=generate_password_hash("admin123"), is_admin=True)
        db.session.add(admin)
        db.session.commit()

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
        online_users=active_users,
        site_name="Mael's Blueprint"
    )

@socketio.on('connect')
def handle_connect():
    global active_users
    active_users += 1
    socketio.emit('user_count', active_users)

@socketio.on('disconnect')
def handle_disconnect():
    global active_users
    active_users = max(0, active_users - 1)
    socketio.emit('user_count', active_users)

# --- Routes ---

@app.route('/')
def index():
    search_query = request.args.get('search')
    faculty_filter = request.args.get('faculty')
    query = Thread.query
    if faculty_filter: query = query.filter_by(faculty=faculty_filter)
    if search_query:
        query = query.filter((Thread.subject_code.ilike(f'%{search_query}%')) | (Thread.subject_name.ilike(f'%{search_query}%')))
    threads = query.order_by(Thread.date_posted.desc()).all()
    return render_template('index.html', threads=threads)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/create-thread')
def create_thread():
    if 'user' not in session:
        flash("You must be logged in to create a thread.")
        return redirect(url_for('index'))
    return render_template('create_thread.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/post', methods=['POST'])
def post():
    if 'user' not in session: return redirect(url_for('index'))
    file = request.files.get('paper_file')
    filename = None
    if file and allowed_file(file.filename):
        filename = f"{int(datetime.now().timestamp())}_{secure_filename(file.filename)}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    t = Thread(faculty=request.form['faculty'], subject_code=request.form['code'].upper(), 
               subject_name=request.form['name'], content=request.form['content'], 
               author=session['user'], file_path=filename)
    db.session.add(t)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/report/<string:target_type>/<int:tid>', methods=['POST'])
def report(target_type, tid):
    if 'user' in session:
        if target_type == 'thread':
            rep = Report(thread_id=tid, reason=request.form['reason'], reporter=session['user'])
        else:
            rep = Report(comment_id=tid, reason=request.form['reason'], reporter=session['user'])
        db.session.add(rep)
        db.session.commit()
        flash("Report submitted.")
    return redirect(request.referrer or url_for('index'))

@app.route('/delete-thread/<int:tid>')
def delete_thread(tid):
    t = Thread.query.get_or_404(tid)
    if session.get('user') == t.author or session.get('is_admin'):
        if t.file_path:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], t.file_path)
            if os.path.exists(file_path): os.remove(file_path)
        db.session.delete(t)
        db.session.commit()
        flash("Thread deleted.")
    return redirect(url_for('index'))

@app.route('/admin/action/<string:act>/<int:id>')
def admin_action(act, id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    if act == 'del': 
        t = Thread.query.get(id)
        if t:
            if t.file_path:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], t.file_path)
                if os.path.exists(file_path): os.remove(file_path)
            Report.query.filter_by(thread_id=id).delete()
            db.session.delete(t)
    elif act == 'del_comment': 
        c = Comment.query.get(id)
        if c:
            # Change admin deletion to soft delete as well
            Report.query.filter_by(comment_id=id).delete()
            c.content = "[Comment removed by admin]"
            c.author = "system"
    elif act == 'ignore':
        r = Report.query.get(id)
        if r: db.session.delete(r)
    elif act == 'ban':
        u = User.query.get(id)
        if u and u.student_id != "ADMIN": u.is_banned = not u.is_banned

    db.session.commit()
    return redirect(url_for('admin'))

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
    flash("Invalid credentials.")
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    sid = request.form.get('student_id')
    pwd = request.form.get('password')
    
    if not sid or not pwd:
        flash("All fields required.")
        return redirect(url_for('index'))

    if User.query.filter_by(student_id=sid).first():
        flash("Student ID already exists.")
    else:
        hashed_pwd = generate_password_hash(pwd)
        new_user = User(student_id=sid, password=hashed_pwd)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.")
    return redirect(url_for('index'))

@app.route('/vote/<string:type>/<int:tid>')
def vote(type, tid):
    if 'user' not in session: return redirect(url_for('index'))
    v = Vote.query.filter_by(user_id=session['user'], 
                             thread_id=tid if type=='thread' else None, 
                             comment_id=tid if type=='comment' else None).first()
    if v: db.session.delete(v)
    else: db.session.add(Vote(user_id=session['user'], thread_id=tid if type=='thread' else None, comment_id=tid if type=='comment' else None))
    db.session.commit()
    return redirect(request.referrer or url_for('index'))

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

@app.route('/admin')
def admin():
    if not session.get('is_admin'): return redirect(url_for('index'))
    return render_template('admin.html', reports=Report.query.all(), users=User.query.all())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/delete-comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user' not in session:
        return redirect('/')
    
    comment = Comment.query.get_or_404(comment_id)
    thread_id = comment.thread_id 
    
    if comment.author == session['user'] or session.get('is_admin'):
        # Updated to Soft Delete
        comment.content = "[Comment removed by admin]"
        comment.author = "system"
        db.session.commit()
        flash("Comment removed.")
    else:
        flash("You do not have permission to delete this comment.")
        
    return redirect(f'/thread/{thread_id}')

@app.route('/get_subjects')
def get_subjects():
    # Fetch all unique subject codes and names from your database
    # Assuming you are using SQLAlchemy/SQLite:
    subjects = Thread.query.with_entities(Thread.subject_code, Thread.subject_name).distinct().all()
    # Convert to a dictionary: {"CS101": "INTRO TO CS", ...}
    subject_map = {s.subject_code: s.subject_name for s in subjects}
    return jsonify(subject_map)

if __name__ == "__main__":
    socketio.run(app, debug=True)