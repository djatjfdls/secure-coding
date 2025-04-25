import sqlite3
import uuid
import re
import bcrypt
import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send, emit, join_room
from functools import wraps
from datetime import datetime, timedelta

# 로그인 시도 제한을 위한 변수
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT_MINUTES = 15

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins='*')
DATABASE = 'market.db'

# DB 연결
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

# DB 테이블 초기화
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블 생성 (login_attempts 및 last_login_attempt 컬럼 포함)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                balance INTEGER DEFAULT 0,
                login_attempts INTEGER DEFAULT 0,  -- 로그인 시도 횟수
                last_login_attempt TEXT  -- 마지막 로그인 시도 시간
            )
        """)

        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)

        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                report_type TEXT NOT NULL
            )
        """)

        db.commit()

#[유저 관련 기능 (회원가입, 로그인, 로그아웃, 프로필)]
# 기본 페이지
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
# 회원가입 처리 (아이디 중복 체크 추가)
# 회원가입 처리 (아이디 중복 체크 추가)
@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # 아이디 형식 검증
        if not (3 <= len(username) <= 20) or not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('아이디는 3~20자의 영문, 숫자, 밑줄만 가능합니다.')
            return redirect(url_for('register'))

        # 비밀번호 길이 검증
        if len(password) < 6:
            flash('비밀번호는 최소 6자 이상이어야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()

        # 아이디 중복 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))  # 중복된 아이디는 등록할 수 없음

        # 사용자 정보 삽입 (비밀번호를 평문으로 저장)
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            # 휴면 계정 체크
            if user['is_active'] == 0:
                flash('휴면 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))

            # 로그인 시도 제한 체크
            if user['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                last_attempt = datetime.strptime(user['last_login_attempt'], "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_attempt < timedelta(minutes=LOGIN_TIMEOUT_MINUTES):
                    flash('로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.')
                    return redirect(url_for('login'))

            # 평문 비밀번호 비교
            if password == user['password']:  # bcrypt 체크 없이 평문 비밀번호 비교
                # 로그인 성공 시 로그인 시도 횟수 초기화
                cursor.execute("UPDATE user SET login_attempts = 0 WHERE id = ?", (user['id'],))
                db.commit()

                session['user_id'] = user['id']
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
            else:
                # 비밀번호 실패 시 로그인 시도 횟수 증가
                cursor.execute("UPDATE user SET login_attempts = login_attempts + 1, last_login_attempt = ? WHERE id = ?", 
                               (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user['id']))
                db.commit()

                flash('아이디 또는 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('login'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 프로필 (bio 업데이트)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

# 비밀번호 변경
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    old_pw = request.form['old_password']
    new_pw = request.form['new_password']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if not bcrypt.checkpw(old_pw.encode('utf-8'), user['password']):
        flash('기존 비밀번호가 일치하지 않습니다.')
        return redirect(url_for('profile'))

    hashed_new_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_new_pw, session['user_id']))
    db.commit()
    flash('비밀번호가 변경되었습니다.')
    return redirect(url_for('profile'))

#[상품+신고 기능]
# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()

        # 상품 등록 (이미지 관련 부분 제거)
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()

        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))  # 대시보드로 리다이렉트

    return render_template('new_product.html')  # GET 요청 시 상품 등록 페이지를 반환

# 상품 목록 (대시보드)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    user_balance = user['balance']

    query = request.args.get('query', '')
    if query:
        cursor.execute("SELECT * FROM product WHERE title LIKE ? OR description LIKE ?",
                       (f"%{query}%", f"%{query}%"))
    else:
        cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    return render_template("dashboard.html", products=products, user=user, query=query, user_balance=user_balance)

# 상품 상세 페이지
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    current_user = None
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()

    return render_template("view_product.html", product=product, seller=seller, user=current_user)

# 상품 수정
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        db.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/my/products/delete/<product_id>', methods=['POST'])
def delete_my_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if product and product['seller_id'] == session['user_id']:
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        flash("상품이 삭제되었습니다.")
    else:
        abort(403)

    return redirect(url_for('dashboard'))

# 상품 신고
@app.route('/report/product/<product_id>', methods=['POST'])
def report_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    reason = request.form['reason'].strip()
    if not reason:
        flash("신고 사유를 입력해주세요.")
        return redirect(url_for('view_product', product_id=product_id))

    report_id = str(uuid.uuid4())
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO report (id, reporter_id, target_id, reason, report_type) VALUES (?, ?, ?, ?, ?)",
        (report_id, session['user_id'], product_id, reason, 'product')
    )
    db.commit()
    flash("신고가 접수되었습니다.")
    return redirect(url_for('view_product', product_id=product_id))

# 사용자 신고 (ID 또는 username 기준)
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target = request.form['target_id'].strip()
        reason = request.form['reason'].strip()
        if not reason:
            flash("신고 사유를 입력해주세요.")
            return render_template("report.html")

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM user WHERE username = ?", (target,))
        user = cursor.fetchone()

        if not user:
            return render_template("report.html", alert="존재하지 않는 사용자입니다.")

        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, report_type) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], user['id'], reason, 'user')
        )
        db.commit()
        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template("report.html")

#[관리자기능+채팅기능]
from functools import wraps
from flask import abort

# 관리자 권한 확인 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or user['is_admin'] != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# 관리자 대시보드
@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html')

# 관리자 유저 관리 페이지 (금액 추가 처리)
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')  # user_id를 받음 (None이면 KeyError 피함)
        amount = request.form.get('amount')  # 금액을 받음

        if user_id and amount:
            try:
                amount = int(amount)  # 금액을 정수로 변환
                cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, user_id))
                db.commit()
                flash(f'{amount} 원이 추가되었습니다.')
            except ValueError:
                flash("금액은 숫자여야 합니다.")
        else:
            flash("잘못된 요청입니다.")
        
        return redirect(url_for('admin_users'))  # 금액 추가 후 유저 목록 페이지로 리다이렉트

    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    return render_template('admin/admin_users.html', users=users)


# 관리자 - 유저 삭제
@app.route('/admin/users/delete/<user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    db.commit()
    flash('유저를 삭제했습니다.')
    return redirect(url_for('admin_users'))

# 관리자 - 휴면 전환
# 관리자 - 휴면 전환
@app.route('/admin/users/deactivate/<user_id>', methods=['POST'])
@admin_required
def deactivate_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash("유저를 휴면 계정으로 전환했습니다.")
    return redirect(url_for('admin_users'))


# 관리자 - 상품 목록
@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    return render_template('admin/admin_products.html', products=products)


# 관리자 - 상품 삭제
@app.route('/admin/products/delete/<product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품을 삭제했습니다.')
    return redirect(url_for('admin_products'))

# 관리자 - 신고 전체 보기
@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT report.*, u1.username AS reporter_name, u2.username AS target_name
        FROM report
        JOIN user u1 ON report.reporter_id = u1.id
        JOIN user u2 ON report.target_id = u2.id
    """)
    reports = cursor.fetchall()
    return render_template('admin/admin_reports.html', reports=reports)

# 관리자 - 신고 삭제
@app.route('/admin/reports/delete/<report_id>', methods=['POST'])
@admin_required
def admin_delete_report(report_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash('신고를 삭제했습니다.')
    return redirect(url_for('admin_reports'))

# 관리자 - 신고된 상품 목록
@app.route('/admin/reports/products')
@admin_required
def admin_reported_products():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT report.*, product.title, product.seller_id
        FROM report
        JOIN product ON report.target_id = product.id
        WHERE report.report_type = 'product'
    """)
    reports = cursor.fetchall()
    return render_template('admin/reported_products.html', reports=reports)

# 관리자 - 신고된 유저 목록
@app.route('/admin/reports/users')
@admin_required
def admin_reported_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT report.*, user.username AS reported_username
        FROM report
        JOIN user ON report.target_id = user.id
        WHERE report.report_type = 'user'
    """)
    reports = cursor.fetchall()
    return render_template('admin/reported_users.html', reports=reports)

# 실시간 전체 채팅 (broadcast)
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())  # 메시지 ID를 새로 생성
    # 메시지를 'message' 이벤트로 broadcast
    emit('message', data, broadcast=True)

    

# 1:1 채팅용 socket.io 이벤트
from flask_socketio import join_room, emit

@socketio.on('join_room')
def handle_join_room_event(data):
    join_room(data['room'])
    emit('receive_message', {
        'username': data['username'],
        'message': f"{data['username']} 님이 입장하셨습니다."
    }, room=data['room'])

@socketio.on('private_message')
def handle_private_message(data):
    print(f"[PRIVATE MESSAGE] {data}")
    message = {
        'room': data['room'],
        'username': data['username'],
        'message': data['message']
    }
    emit('receive_private_message', message, room=data['room'])
    emit('receive_private_message', message, room=f"user_{data['target_id']}")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    print(f"[JOIN USER ROOM] {data['user_id']}")
    join_room(f"user_{data['user_id']}")

#[구매+송금, 유저 목록, 비밀번호 변경, 컨텍스트 처리]
# ✅ 실시간 채팅 기능 (1:1 + 전체)
@socketio.on('private_message')
def handle_private_message(data):
    print(f"[PRIVATE MESSAGE] {data}")
    room = data['room']
    message = {
        'room': room,
        'username': data['username'],
        'message': data['message']
    }
    emit('receive_private_message', message, room=room)
    emit('receive_private_message', message, room=f"user_{data['target_id']}")

@socketio.on('join_user_room')
def handle_join_user_room(data):
    print(f"[JOIN USER ROOM] {data['user_id']}")
    join_room(f"user_{data['user_id']}")

@socketio.on('send_message')
def handle_send_message_event(data):
    if 'username' not in data or 'message' not in data:
        return  # ✅ 메시지 검증
    if len(data['message']) > 500:
        return  # 길이 제한
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# ✅ 관리자 권한 데코레이터
from functools import wraps
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if not user or user['is_admin'] != 1:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ✅ 사용자 목록 페이지
@app.route('/users')
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    query = request.args.get('query', '')
    if current_user['is_admin']:
        cursor.execute("SELECT * FROM user WHERE username LIKE ?", (f"%{query}%",))
    else:
        cursor.execute("SELECT * FROM user WHERE is_admin = 0 AND username LIKE ?", (f"%{query}%",))
    users = cursor.fetchall()

    return render_template('user_list.html', users=users, current_user=current_user, query=query, current_user_name=current_user['username'])

# ✅ 송금 기능
@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender_id = session['user_id']
    receiver_id = request.form['receiver_id']
    amount = int(request.form['amount'])

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT balance FROM user WHERE id = ?", (sender_id,))
    sender_balance = cursor.fetchone()['balance']

    if sender_balance < amount:
        flash("잔액이 부족합니다.")
        return redirect(url_for('dashboard'))

    cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender_id))
    cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
    db.commit()
    flash("송금 완료!")
    return redirect(url_for('dashboard'))

# ✅ 상품 구매
@app.route('/purchase/<product_id>', methods=['POST'])
def purchase_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    buyer_id = session['user_id']
    cursor.execute("SELECT balance FROM user WHERE id = ?", (buyer_id,))
    buyer = cursor.fetchone()

    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("상품이 존재하지 않습니다.")
        return redirect(url_for('dashboard'))

    price = int(product['price'])
    seller_id = product['seller_id']

    if buyer['balance'] < price:
        return """<script>alert('잔액이 부족합니다.'); window.location.href='{}';</script>""".format(
            url_for('view_product', product_id=product_id)
        )

    cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (price, buyer_id))
    cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (price, seller_id))
    db.commit()

    flash("상품을 구매했습니다! 금액이 송금되었습니다.")
    return redirect(url_for('dashboard'))

# ✅ 템플릿에서 실시간 잔액 확인용
@app.context_processor
def inject_user_balance():
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        # user가 None일 경우 user_balance를 0으로 설정
        if user is not None:
            return dict(user_balance=user['balance'])
        else:
            # 사용자 정보가 없을 경우 0 반환
            return dict(user_balance=0)

    # 로그인하지 않은 경우 0 반환
    return dict(user_balance=0)

        

# ✅ 앱 실행
if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
