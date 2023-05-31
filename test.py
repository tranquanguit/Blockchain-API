from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from hashlib import sha256
from datetime import datetime
import pyodbc

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Khởi tạo ứng dụng Flask
app = Flask(__name__)
app.secret_key = '20520722'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://sa:sa@localhost/test-bc-api?driver=ODBC+Driver+17+for+SQL+Server'
db = SQLAlchemy(app)

# Mô hình dữ liệu cho người dùng
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

    def __init__(self, username, password, public_key, private_key):
        self.username = username
        self.password = password
        self.public_key = public_key
        self.private_key = private_key

def generate_rsa_keys():
    # Tạo cặp khóa RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Chuyển đổi khóa thành định dạng PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Chuyển đổi khóa từ định dạng bytes sang chuỗi
    private_key_str = private_pem.decode('utf-8')
    public_key_str = public_pem.decode('utf-8')

    return private_key_str, public_key_str

def rsa_encrypt(password, public_key_str):
    # Chuyển đổi khóa công khai từ chuỗi sang định dạng bytes
    public_pem = public_key_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_pem)
    
    # Mã hóa tin nhắn bằng khóa công khai RSA
    ciphertext = public_key.encrypt(
        password.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Chuyển đổi ciphertext từ định dạng bytes sang chuỗi
    ciphertext_str = ciphertext.hex()
    return ciphertext_str

def rsa_decrypt(ciphertext_str, private_key_str):
    # Chuyển đổi khóa bí mật từ chuỗi sang định dạng bytes
    private_pem = private_key_str.encode('utf-8')
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    # Chuyển đổi ciphertext từ chuỗi sang định dạng bytes
    ciphertext = bytes.fromhex(ciphertext_str)

    # Giải mã ciphertext bằng khóa bí mật RSA
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Chuyển đổi plaintext từ định dạng bytes sang chuỗi
    plaintext_str = plaintext.decode('utf-8')
    return plaintext_str

# Mô hình dữ liệu cho blockchain
class Blockchain(db.Model):
    block_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    previous_hash = db.Column(db.String(256), nullable=False)
    hash = db.Column(db.String(256), nullable=False)
    proof = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    num_coins = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String(50), nullable=False)

    #Constructor
    def __init__(self, user_id, name, num_coins, content):
        self.previous_hash = self.last_block().hash
        self.hash = self.calculateHash()
        self.user_id = user_id
        self.name = name
        self.num_coins = num_coins
        self.content = content
        
    # Hàm lấy ra block cuối cùng trong blockchain
    @classmethod
    def last_block(self):
        last_block = self.query.order_by(self.block_id.desc()).first()
        return last_block
        
    #Hàm tính toán hash trong
    def calculateHash(self):
        #Mining & calculation hash by proof of work
        data = str(self.name) + str(self.num_coins) + str(self.content)
        self.proof = 1
        self.hash = sha256((str(self.timestamp) + str(self.previous_hash) + str(self.user_id) + str(data) + str(self.proof)).encode()).hexdigest()
        while not self.hash.startswith('0000'):
            self.proof += 1
            self.hash = sha256((str(self.timestamp) + str(self.previous_hash) + str(self.user_id) + str(data) + str(self.proof)).encode()).hexdigest()
        
        return self.hash

# Tạo bảng trong cơ sở dữ liệu (chạy một lần)
with app.app_context():
    db.create_all()
    
#Index
@app.route('/', methods=['GET', 'POST'])
def start():
    if request.method == 'POST':
        return render_template('/')
    return render_template('/index.html')

# Route để hiển thị trang xem lịch sử blockchain
@app.route('/view_history')
def view_history():
    # Lấy danh sách các block từ cơ sở dữ liệu
    blocks = Blockchain.query.all()
    if validate_blockchain(blocks):
        return render_template('view_history.html', blocks = blocks)
    else:
        return jsonify({'message': 'Blockchain is invalid!'}), 401


#Trang chủ
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'GET':   
        user_id = session.get('user_id')  # Lấy user_id từ session
        
        if user_id:
            # Tìm người dùng dựa trên user_id
            user = User.query.get(user_id)
            # Lấy username từ người dùng
            username = user.username
            return render_template('home.html', username=username)
        return jsonify({'message': 'Invalid username!'}), 401
    return render_template('home.html')

# Đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Lấy thông tin người dùng từ cơ sở dữ liệu
        user = User.query.filter_by(username=username).first()

        if user is not None:
            # Giải mã mật khẩu bằng khóa bí mật RSA
            decrypted_password = rsa_decrypt(user.password, user.private_key)
        
        if decrypted_password == password:

            # Nếu đăng nhập thành công
            session['user_id'] = user.id  # Lưu user_id vào session
            return redirect(url_for('home'))
        
        return render_template('login.html', error_message = 'block'), 401
            
    return render_template('login.html', error_message = 'none')
    
# Đăng xuất
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Xóa user_id khỏi session
    
    return redirect(url_for('login'))

# Đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if confirm_password == password:
            # Tạo cặp khóa RSA
            private_key, public_key = generate_rsa_keys()

            # Mã hóa mật khẩu bằng khóa công khai RSA
            encrypted_password = rsa_encrypt(password, public_key)
            
            # Lưu thông tin người dùng vào cơ sở dữ liệu
            new_user = User(username=username, password=encrypted_password, public_key=public_key, private_key=private_key)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error_message = 'block')
    return render_template('register.html', error_message = 'none')

#Thêm block mới
@app.route('/add_block', methods=['GET', 'POST'])
def add_block():
    if request.method == 'POST':
        name = request.form.get('name')
        num_coins = request.form.get('num_coins')
        content = request.form.get('content')

        user_id = session.get('user_id')  # Lấy user_id từ session
        
        if user_id:
            # Kiểm tra user_id và lấy thông tin người dùng từ CSDL
            user = User.query.get(user_id)

            if user:
                blockchain = Blockchain(user.id, name, num_coins, content) # Khởi tạo đối tượng Blockchain
                db.session.add(blockchain)
                db.session.commit()
                return redirect(url_for('view_history'))
            
        return jsonify({'message': 'Invalid user or user_id!'}), 401
    return render_template('add_block.html')

# Hàm Kiểm tra tính toàn vẹn của blockchain
def validate_blockchain(blocks):
    for i in range(1, len(blocks)):
        current_block = blocks[i]
        previous_block = blocks[i-1]

        # Kiểm tra hash của block trước đó có khớp với previous_hash của block hiện tại hay không
        if current_block.previous_hash != previous_block.hash:
            return False

        # # Kiểm tra tính toàn vẹn của hash
        # if current_block.hash != calculate_Hash(current_block):
        #     return False

    return True

#Hàm tính toán hash trong
def calculate_Hash(block):
    #Mining & calculation hash by proof of work
    data = str(block.name) + str(block.num_coins) + str(block.content)
    return sha256((str(block.timestamp) + str(block.previous_hash) + str(block.user_id) + str(data) + str(block.proof)).encode()).hexdigest()

if __name__ == '__main__':
    app.run(debug=True)