from itsdangerous import URLSafeTimedSerializer
import itsdangerous

print(f"itsdangerous version in main.py: {itsdangerous.__version__}")

print(f"itsdangerous version: {itsdangerous.__version__}")
SECRET_KEY = "your-secret-key-1234567890"
serializer = URLSafeTimedSerializer(SECRET_KEY)
email = "ops11@example.com"
token = serializer.dumps(email, salt="email-verify")
print(f"Generated token: {token}")
try:
    decoded_email = serializer.loads(token, salt="email-verify", max_age=86400)
    print(f"Decoded email: {decoded_email}")
except Exception as e:
    print(f"Error: {e}")