import base64
import os

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "verys_test")
VERIFY_FROM_ADDR = 'support@mcmlln.dev'
USERNAME_SMTP = os.environ.get('USERNAME_SMTP')
PASSWORD_SMTP = os.environ.get('PASSWORD_SMTP')
SMTP_ENDPOINT = 'smtp.email.us-chicago-1.oci.oraclecloud.com'
SMTP_PORT = 587
VERIFY_BASE_URL = os.environ.get('VERIFY_BASE_URL', 'http://localhost:8080')
VERIFY_DEBUG_ADDR = 'reismcmillan19@gmail.com'
ENCRYPT_COOKIE_NAME = 'token'
ENCRYPT_COOKIE_KEY = 'YWJjZDEyMzRhYmNkMTIzNGFiY2QxMjM0YWJjZDEyMzQ='
ENCRYPT_COOKIE_SEPARATOR = '|'
COOKIE_DOMAIN = None
JWT_EXPIRY = 5 * 60 # 5 minutes
JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY')
ISSUER = os.environ.get('OIDC_ISSUER', 'http://localhost:8080')
VERIFY_TTL = 5 * 60 # 5 minutes
AUTHENTICATION_TTL = 60 * 24 * 60 * 60 # 60 days
AUTHORIZATION_CODE_TTL = 60  # seconds
ID_TOKEN_EXPIRY = 5 * 60  # 5 minutes
FIELD_ENCRYPTION_KEY = 'YWJjZDEyMzRhYmNkMTIzNGFiY2QxMjM0YWJjZDEyMzQ='
VERYS_CLIENT_ID = 'test-verys-client'
VERYS_CLIENT_REDIRECT_URI = 'http://localhost:8080/callback'
VERYS_CLIENT_REGISTRATION_URI = 'http://localhost:8080/register'
LOGGING_ENABLED = False
OPENOBSERVE_ENDPOINT = os.environ.get('OPENOBSERVE_ENDPOINT')
_oo_user = os.environ.get('OPENOBSERVE_USER')
_oo_token = os.environ.get('OPENOBSERVE_TOKEN')
OPENOBSERVE_TOKEN = base64.b64encode(f"{_oo_user}:{_oo_token}".encode()).decode() if _oo_user and _oo_token else None
ALLOWED_ORIGINS=['*']
SEED_PROVIDERS = []  # tests seed providers explicitly
