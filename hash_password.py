from streamlit_authenticator.hasher import Hasher

# Replace with your actual password(s)
passwords = ['test123']

# Hash each password
hashed_passwords = Hasher(passwords).generate()

# Print each password and its hashed value
for pw, hash_pw in zip(passwords, hashed_passwords):
    print(f"Password: {pw} --> Hashed: {hash_pw}")
