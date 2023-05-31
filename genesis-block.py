from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from hashlib import sha256
from datetime import datetime
import pyodbc

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Khởi tạo ứng dụng Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://sa:sa@localhost/test-bc-api?driver=ODBC+Driver+17+for+SQL+Server'
db = SQLAlchemy(app)

# Mô hình dữ liệu cho người dùng
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
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

    def __init__(self, previous_hash, user_id, name, num_coins, content):
        self.previous_hash = previous_hash
        self.hash = self.calculateHash()
        self.user_id = user_id
        self.name = name
        self.num_coins = num_coins
        self.content = content
        
    def calculateHash(self):
        # Mining & calculation hash by proof of work
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
        
#Thêm block mới
@app.route('/add_block', methods=['GET', 'POST'])
def add_block():
    if request.method == 'POST':
        # Tạo cặp khóa RSA
        private_key, public_key = generate_rsa_keys()

        # Mã hóa mật khẩu bằng khóa công khai RSA
        encrypted_password = rsa_encrypt("password", public_key)
        
        # Lưu thông tin người dùng vào cơ sở dữ liệu
        new_user = User(username="username", password=encrypted_password, public_key=public_key, private_key=private_key)
        db.session.add(new_user)
        db.session.commit()
        
        blockchain = Blockchain("0000", 1, "Genesis block", 0, "Chuyen coin")  # Khởi tạo đối tượng Blockchain
        db.session.add(blockchain)
        db.session.commit()
        return jsonify({'message': 'Insert block successfully!'})
    return render_template('add_block.html')

if __name__ == '__main__':
    app.run(debug=True)
