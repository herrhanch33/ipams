# hash_password.py

from werkzeug.security import generate_password_hash

def hash_password(password):
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    return hashed_password

if __name__ == '__main__':
    password = input("Enter the password to hash: ")
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")
