from flask import Flask, render_template, redirect, url_for, request, session
import os
import subprocess
import bleach
from flask_wtf.csrf import CSRFProtect
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

def create_app():
    # Application setup
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY = os.urandom(32),
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = 'Strict',
        PERMANENT_SESSION_LIFETIME = 600,
        SQLALCHEMY_DATABASE_URI = 'sqlite:///spellchecker.db',
        SQLALCHEMY_TRACK_MODIFICATIONS = True
    )
    csrf = CSRFProtect(app)
    
    # Database setup
    db = SQLAlchemy(app)
    
    class User(db.Model):
        __tablename__ = 'user'
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(100), nullable=False)
        password = db.Column(db.String(100), nullable=False)
        twofa = db.Column(db.String(100), nullable=True)

    class Query(db.Model):
        __tablename__ = 'query'
        id = db.Column(db.Integer, primary_key=True)
        uid = db.Column(db.Integer, db.ForeignKey('user.id'))
        user = db.relationship(User)
        textout = db.Column(db.Text, nullable=False)
        misspelled = db.Column(db.Text, nullable=True)

    class Log(db.Model):
        __tablename__ = 'log'
        id = db.Column(db.Integer, primary_key=True)
        uid = db.Column(db.Integer, db.ForeignKey('user.id'))
        user = db.relationship(User)
        login = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
        logout = db.Column(db.DateTime, nullable=True, default=None)

    db.create_all()
    
    # Database functions
    def register_with_user_info(uname, pword, twofa):
        user = db.session.query(User).filter(User.username == uname).first()
        if not user:
            hashed_pword = bcrypt.hashpw(pword.encode('utf8'), bcrypt.gensalt())
            hashed_twofa = bcrypt.hashpw(twofa.encode('utf8'), bcrypt.gensalt())
            new_user = User(username=uname, password=hashed_pword, twofa=hashed_twofa)
            db.session.add(new_user)
            db.session.commit()
            return 0
        else:
            return 1
        
    def login_with_user_info(uname, pword, twofa):
        user = db.session.query(User).filter(User.username == uname).first()
        if not user:
            return 2
        if bcrypt.checkpw(pword.encode('utf8'), user.password) == False:
            return 2
        if bcrypt.checkpw(twofa.encode('utf8'), user.twofa) == False:
            return 1
        new_log = Log(uid=user.id)
        db.session.add(new_log)
        db.session.commit()
        return 0

    def add_spellcheck(uname, textout, misspelled):
        user = db.session.query(User).filter(User.username == uname).first()
        if user:
            new_query = Query(uid=user.id, textout=textout, misspelled=misspelled)
            db.session.add(new_query)
            db.session.commit()

    def create_admin():
        register_with_user_info("admin", "Administrator@1", "12345678901")
    create_admin()

    # Web application pages
    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/register", methods = ['GET', 'POST'])
    def register():
        success = ""
        if 'username' not in session:
            if request.method == 'POST':
                uname = bleach.clean(request.form['uname'])
                pword = bleach.clean(request.form['pword'])
                twofa = bleach.clean(request.form['2fa'])
                status = register_with_user_info(uname, pword, twofa)
                if status == 0:
                    success = "Registration Success!"
                else:
                    success = "Registration Failure!"
            return render_template("register.html", id = success)
        else:
            success = "Already logged in!"
            return render_template("register.html", id = success)

    @app.route("/login", methods = ['GET', 'POST'])
    def login():
        result = ""
        if 'username' not in session:
            if request.method == 'POST':
                uname = bleach.clean(request.form['uname'])
                pword = bleach.clean(request.form['pword'])
                twofa = bleach.clean(request.form['2fa'])
                status = login_with_user_info(uname, pword, twofa)
                if status == 2:
                    result = "Incorrect username or password!"
                elif status == 1:
                    result = "Two-factor failure!"
                else:
                    result = "Success!"
                    session.permanent = True
                    session['username'] = uname
            return render_template("login.html", id = result)
        else:
            result = "Already logged in!"
            return render_template("login.html", id = result)

    @app.route("/spell_check", methods = ['GET', 'POST'])
    def spell_check():
        if 'username' in session:
            textout = ""
            misspelled = ""
            if request.method == 'POST':
                textout = bleach.clean(request.form['inputtext'])
                with open("test.txt", "w+") as fo:
                    fo.write(textout)
                misspelled = subprocess.check_output(["./a.out", "test.txt", "wordlist.txt"])
                misspelled = misspelled.decode('utf-8').strip().split('\n')
                misspelled = ", ".join(misspelled)
                fo.close()
                os.remove("test.txt")
                name = session['username']
                add_spellcheck(name, textout, misspelled)
            return render_template("spell_check.html", textout = textout, misspelled = misspelled)
        else:
            return redirect(url_for("home"))

    @app.route("/logout")
    def logout():
        if 'username' in session:
            name = session['username']
            userlog = db.session.query(Log).join(User, Log.uid == User.id).filter(User.username == name).order_by(Log.id.desc()).first()
            if userlog:
                userlog.logout = datetime.utcnow()
                db.session.commit()
                session.pop('username', None)
        return redirect(url_for("home"))

    @app.route("/history", methods = ['GET', 'POST'])
    def history():
        if 'username' in session:
            name = session['username']
            if name == 'admin':
                history = ""
                uname = name
                if request.method == 'POST':
                    uname = bleach.clean(request.form['uname'])
                    history = db.session.query(Query).join(User, Query.uid == User.id).filter(User.username == uname).all()
                return render_template("history.html", history=history, searched=uname, name=name)
            else:
                history = db.session.query(Query).join(User, Query.uid == User.id).filter(User.username == name).all()
                return render_template("history.html", history=history, searched=name)
        else:
            return redirect(url_for("home"))

    @app.route("/history/query<int:query_id>")
    def query(query_id):
        if 'username' in session:
            userquery = db.session.query(Query).join(User, Query.uid == User.id).filter(Query.id == query_id).first()
            if userquery:
                name = session['username']
                if userquery.user.username == name or name == 'admin':
                    return render_template("query.html", userquery=userquery)
            return redirect(url_for("history"))
        else:
            return redirect(url_for("home"))

    @app.route("/login_history", methods = ['GET', 'POST'])
    def login_history():
        if 'username' in session and session['username'] == "admin":
            uname = ""
            if request.method == 'POST':
                uname = bleach.clean(request.form['uname'])
                userlog = db.session.query(Log).join(User, Log.uid == User.id).filter(User.username == uname).all()
                if userlog:
                    return render_template("login_history.html", userlog=userlog, uname=uname)
            return render_template("login_history.html", uname=uname)
        else:
            return redirect(url_for("home"))

    @app.after_request
    def add_headers(response):
        response.headers['Strict-Transport-Security'] = "max-age=31536000 ; includeSubDomains"
        response.headers['Content-Security-Policy'] = "default-src 'self' ; style-src 'self' 'unsafe-inline'"
        response.headers['Set-Cookie'] = "HTTPOnly ; Secure"
        response.headers['X-FrameOptions'] = "DENY"
        response.headers['X-XSS-Protection'] = "1 ; mode=block"
        response.headers['X-Content-Type-Options'] = "nosniff"
        return response

    return app

if __name__ == "__main__":
    app.create_app()
