import base64
import os

MONGO_URI = os.environ.get("MONGO_URI")
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "verys")
VERIFY_FROM_ADDR = 'support@mcmlln.dev'
USERNAME_SMTP = os.environ.get('USERNAME_SMTP')
PASSWORD_SMTP = os.environ.get('PASSWORD_SMTP')
SMTP_ENDPOINT = 'smtp.email.us-chicago-1.oci.oraclecloud.com'
SMTP_PORT = 587
VERIFY_BASE_URL = os.environ.get('VERIFY_BASE_URL')
ENCRYPT_COOKIE_NAME = 'token'
ENCRYPT_COOKIE_KEY = os.environ.get('ENCRYPT_COOKIE_KEY')
ENCRYPT_COOKIE_SEPARATOR = '|'
COOKIE_DOMAIN = os.environ.get('COOKIE_DOMAIN', '.mcmlln.dev')
JWT_EXPIRY = 5 * 60 # 5 minutes
JWT_PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY')
ISSUER = os.environ.get('OIDC_ISSUER', 'https://api.verys.mcmlln.dev')
VERIFY_TTL = 5 * 60 # 5 minutes
AUTHENTICATION_TTL = 60 * 24 * 60 * 60 # 60 days
AUTHORIZATION_CODE_TTL = 60  # seconds
ID_TOKEN_EXPIRY = 5 * 60  # 5 minutes
FIELD_ENCRYPTION_KEY = os.environ.get('FIELD_ENCRYPTION_KEY')
VERYS_CLIENT_ID = os.environ.get('VERYS_CLIENT_ID')
VERYS_CLIENT_REDIRECT_URI = os.environ.get('VERYS_CLIENT_REDIRECT_URI')
VERYS_CLIENT_REGISTRATION_URI = os.environ.get('VERYS_CLIENT_REGISTRATION_URI')
LOGGING_ENABLED = True
OPENOBSERVE_ENDPOINT = os.environ.get('OPENOBSERVE_ENDPOINT')
_oo_user = os.environ.get('OPENOBSERVE_USER')
_oo_token = os.environ.get('OPENOBSERVE_TOKEN')
OPENOBSERVE_TOKEN = base64.b64encode(f"{_oo_user}:{_oo_token}".encode()).decode() if _oo_user and _oo_token else None
ALLOWED_ORIGINS=['https://verys.mcmlln.dev', 'https://moneypenny.mcmlln.dev', 'http://localhost:5173']

# External identity providers seeded at startup (fill-the-gap only; see
# verys/seed.py). Entries without client_id/client_secret are skipped.
MICROSOFT_TENANT = os.environ.get('MICROSOFT_TENANT', 'common')
SEED_PROVIDERS = [
    {
        'provider_id': 'google',
        'display_name': 'Google',
        'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
        'authorization_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint': 'https://oauth2.googleapis.com/token',
        'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs',
        'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
        'scopes': ['openid', 'email', 'profile'],
        'scope': {'name': 'google', 'description': 'Link your Google account'},
    },
    {
        'provider_id': 'microsoft',
        'display_name': 'Microsoft',
        'client_id': os.environ.get('MICROSOFT_CLIENT_ID'),
        'client_secret': os.environ.get('MICROSOFT_CLIENT_SECRET'),
        'authorization_endpoint': f'https://login.microsoftonline.com/{MICROSOFT_TENANT}/oauth2/v2.0/authorize',
        'token_endpoint': f'https://login.microsoftonline.com/{MICROSOFT_TENANT}/oauth2/v2.0/token',
        'jwks_uri': f'https://login.microsoftonline.com/{MICROSOFT_TENANT}/discovery/v2.0/keys',
        'userinfo_endpoint': 'https://graph.microsoft.com/oidc/userinfo',
        # offline_access is required for Microsoft to issue a refresh token.
        'scopes': ['openid', 'email', 'profile', 'offline_access'],
        'scope': {'name': 'microsoft', 'description': 'Link your Microsoft account'},
    },
]
