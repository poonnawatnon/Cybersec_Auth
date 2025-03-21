from werkzeug.security import generate_password_hash, check_password_hash

# สร้างแฮช
password = "mysecretpassword"
hashed_password = generate_password_hash(password, method='pbkdf2:sha256')# OR method='scrypt', salt_length= {number}
#default hash algorithm  = scrypt
print("Hashed Password:", hashed_password,)

# ตรวจสอบรูปแบบของแฮช
if hashed_password.startswith('pbkdf2:sha256:'):
    print("Using PBKDF2 with SHA256")
elif hashed_password.startswith('pbkdf2:sha512:'):
    print("Using PBKDF2 with SHA512")
elif hashed_password.startswith('bcrypt:'):
    print("Using Bcrypt")
elif hashed_password.startswith('scrypt:'):
    print("Using Scrypt")
elif hashed_password.startswith('argon2:'):
    print("Using Argon2")
else:
    print("Unknown hash algorithm")
