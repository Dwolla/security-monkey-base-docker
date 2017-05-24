import boto3
import json
import os

from datetime import timedelta


def get_db_url():
    database_s3_bucket = os.environ['DATABASE_S3_BUCKET']
    database_s3_key = os.environ['DATABASE_S3_KEY']
    database_name = os.environ['DATABASE_NAME']
    client = boto3.client('s3')
    s3_object = client.get_object(Bucket=database_s3_bucket,
                                  Key=database_s3_key)
    decoded_s3_body = s3_object['Body'].read().decode('utf-8')
    db_config = json.loads(decoded_s3_body)[database_name]

    return 'postgresql://{user}:{password}@{host}:{port}/{database}'.format(
        user=db_config['user'],
        password=db_config['password'],
        host=db_config['host'],
        port=db_config['port'],
        database=database_name)


def load_dynamic_config():
    config_s3_bucket = os.environ['CONFIG_S3_BUCKET']
    config_s3_key = os.environ['CONFIG_S3_KEY']
    client = boto3.client('s3')
    s3_object = client.get_object(Bucket=config_s3_bucket, Key=config_s3_key)
    return json.loads(s3_object['Body'].read().decode('utf-8'))

config_settings = load_dynamic_config()

LOG_CFG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s %(levelname)s: %(message)s '
            '[in %(pathname)s:%(lineno)d]'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        }
    },
    'loggers': {
        'security_monkey': {
            'handlers': ['console'],
            'level': 'DEBUG'
        },
        'apscheduler': {
            'handlers': ['console'],
            'level': 'INFO'
        }
    }
}

SQLALCHEMY_DATABASE_URI = get_db_url()

SQLALCHEMY_POOL_SIZE = 50
SQLALCHEMY_MAX_OVERFLOW = 15
ENVIRONMENT = 'ec2'
USE_ROUTE53 = False
FQDN = config_settings.get('FQDN')
API_PORT = '5000'
WEB_PORT = '443'
FRONTED_BY_NGINX = True
NGINX_PORT = '443'
WEB_PATH = '/static/ui.html'
BASE_URL = 'https://{}/'.format(FQDN)

SECRET_KEY = config_settings['SECRET_KEY']

MAIL_DEFAULT_SENDER = config_settings.get('MAIL_DEFAULT_SENDER')
SECURITY_REGISTERABLE = True
SECURITY_CONFIRMABLE = config_settings.get('SECURITY_CONFIRMABLE')
SECURITY_RECOVERABLE = config_settings.get('SECURITY_RECOVERABLE')
SECURITY_PASSWORD_HASH = 'bcrypt'
SECURITY_PASSWORD_SALT = config_settings.get('SECURITY_PASSWORD_SALT')
SECURITY_TRACKABLE = True

SECURITY_POST_LOGIN_VIEW = BASE_URL
SECURITY_POST_REGISTER_VIEW = BASE_URL
SECURITY_POST_CONFIRM_VIEW = BASE_URL
SECURITY_POST_RESET_VIEW = BASE_URL
SECURITY_POST_CHANGE_VIEW = BASE_URL

SECURITY_TEAM_EMAIL = config_settings.get('SECURITY_TEAM_EMAIL')

EMAILS_USE_SMTP = config_settings.get('EMAILS_USE_SMTP')
SES_REGION = config_settings.get('SES_REGION')
MAIL_SERVER = config_settings.get('MAIL_SERVER')
MAIL_PORT = config_settings.get('MAIL_PORT')
MAIL_USE_SSL = config_settings.get('MAIL_USE_SSL')
MAIL_USERNAME = config_settings.get('MAIL_USERNAME')
MAIL_PASSWORD = config_settings.get('MAIL_PASSWORD')

WTF_CSRF_ENABLED = True
WTF_CSRF_SSL_STRICT = True # Checks Referer Header. Set to False for API access.
WTF_CSRF_METHODS = ['DELETE', 'POST', 'PUT', 'PATCH']

# "NONE", "SUMMARY", or "FULL"
SECURITYGROUP_INSTANCE_DETAIL = 'FULL'

# Threads used by the scheduler.
# You will likely need at least one core thread for every account being monitored.
CORE_THREADS = 25
MAX_THREADS = 30

# SSO SETTINGS:
ACTIVE_PROVIDERS = []  # "ping", "google" or "onelogin"

PING_NAME = ''  # Use to override the Ping name in the UI.
PING_REDIRECT_URI = "{BASE}api/1/auth/ping".format(BASE=BASE_URL)
PING_CLIENT_ID = ''  # Provided by your administrator
PING_AUTH_ENDPOINT = ''  # Often something ending in authorization.oauth2
PING_ACCESS_TOKEN_URL = ''  # Often something ending in token.oauth2
PING_USER_API_URL = ''  # Often something ending in idp/userinfo.openid
PING_JWKS_URL = ''  # Often something ending in JWKS
PING_SECRET = ''  # Provided by your administrator

GOOGLE_CLIENT_ID = ''
GOOGLE_AUTH_ENDPOINT = ''
GOOGLE_SECRET = ''

ONELOGIN_APP_ID = '<APP_ID>'  # OneLogin App ID provider by your administrator
ONELOGIN_EMAIL_FIELD = 'User.email'  # SAML attribute used to provide email address
ONELOGIN_DEFAULT_ROLE = 'View'  # Default RBAC when user doesn't already exist
ONELOGIN_HTTPS = True  # If using HTTPS strict mode will check the requests are HTTPS
ONELOGIN_SETTINGS = {
    # If strict is True, then the Python Toolkit will reject unsigned
    # or unencrypted messages if it expects them to be signed or encrypted.
    # Also it will reject the messages if the SAML standard is not strictly
    # followed. Destination, NameId, Conditions ... are validated too.
    "strict": True,

    # Enable debug mode (outputs errors).
    "debug": True,

    # Service Provider Data that we are deploying.
    "sp": {
        # Identifier of the SP entity  (must be a URI)
        "entityId": "{BASE}metadata/".format(BASE=BASE_URL),
        # Specifies info about where and how the <AuthnResponse> message MUST be
        # returned to the requester, in this case our SP.
        "assertionConsumerService": {
            # URL Location where the <Response> from the IdP will be returned
            "url": "{BASE}api/1/auth/onelogin?acs".format(BASE=BASE_URL),
            # SAML protocol binding to be used when returning the <Response>
            # message. OneLogin Toolkit supports this endpoint for the
            # HTTP-POST binding only.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        # If you need to specify requested attributes, set a
        # attributeConsumingService. nameFormat, attributeValue and
        # friendlyName can be omitted
        #"attributeConsumingService": {
        #        "ServiceName": "SP test",
        #        "serviceDescription": "Test Service",
        #        "requestedAttributes": [
        #            {
        #                "name": "",
        #                "isRequired": False,
        #                "nameFormat": "",
        #                "friendlyName": "",
        #                "attributeValue": ""
        #            }
        #        ]
        #},
        # Specifies info about where and how the <Logout Response> message MUST be
        # returned to the requester, in this case our SP.
        "singleLogoutService": {
            # URL Location where the <Response> from the IdP will be returned
            "url": "{BASE}api/1/auth/onelogin?sls".format(BASE=BASE_URL),
            # SAML protocol binding to be used when returning the <Response>
            # message. OneLogin Toolkit supports the HTTP-Redirect binding
            # only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        # Specifies the constraints on the name identifier to be used to
        # represent the requested subject.
        # Take a look on src/onelogin/saml2/constants.py to see the NameIdFormat that are supported.
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        # Usually x509cert and privateKey of the SP are provided by files placed at
        # the certs folder. But we can also provide them with the following parameters
        "x509cert": "",
        "privateKey": ""
    },

    # Identity Provider Data that we want connected with our SP.
    "idp": {
        # Identifier of the IdP entity  (must be a URI)
        "entityId": "https://app.onelogin.com/saml/metadata/{APP_ID}".format(APP_ID=ONELOGIN_APP_ID),
        # SSO endpoint info of the IdP. (Authentication Request protocol)
        "singleSignOnService": {
            # URL Target of the IdP where the Authentication Request Message
            # will be sent.
            "url": "https://app.onelogin.com/trust/saml2/http-post/sso/{APP_ID}".format(APP_ID=ONELOGIN_APP_ID),
            # SAML protocol binding to be used when returning the <Response>
            # message. OneLogin Toolkit supports the HTTP-Redirect binding
            # only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        # SLO endpoint info of the IdP.
        "singleLogoutService": {
            # URL Location of the IdP where SLO Request will be sent.
            "url": "https://app.onelogin.com/trust/saml2/http-redirect/slo/{APP_ID}".format(APP_ID=ONELOGIN_APP_ID),
            # SAML protocol binding to be used when returning the <Response>
            # message. OneLogin Toolkit supports the HTTP-Redirect binding
            # only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        # Public x509 certificate of the IdP
        "x509cert": "<ONELOGIN_APP_CERT>"
    }
}

PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)  # Will logout users after period of inactivity.
SESSION_REFRESH_EACH_REQUEST = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
PREFERRED_URL_SCHEME = 'https'

REMEMBER_COOKIE_DURATION = timedelta(minutes=60)  # Can make longer if you want remember_me to be useful
REMEMBER_COOKIE_SECURE = True
REMEMBER_COOKIE_HTTPONLY = True
