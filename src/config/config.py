# Statement for enabling the development environment
DEBUG = True
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TMP_DIR = '/tmp/'

############## mysql config #################
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:password@localhost/zenaratedb'
SQLALCHEMY_TRACK_MODIFICATIONS = False
CSRF_SESSION_KEY = "secret"
SECRET_KEY = "secret"

sender_email = "vivekkaushal1187@gmail.com"
password = "icusradhefpgeeyn"
# receiver_email = "vivekkaushal29797@gmail.com"
