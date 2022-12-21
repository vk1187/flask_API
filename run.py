from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from src.models.All import *
# from werkzeug.security import generate_password_hash, check_password_hash
import jwt, math, random, datetime, smtplib
from argon2 import PasswordHasher
from functools import wraps
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)



def generate_password_hash(password):
    ph = PasswordHasher()
    try:
        result = ph.hash(password)
    except:
        result = password
    return result

def check_password_hash(hash,password):
    ph = PasswordHasher()
    try:
        result=ph.verify(hash, password)
    except:
        result=False
    return result

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(email=data['email']).first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/otp/<email>/', methods=['GET','POST'])
def send_otp(email):
    emailid = email
    digits="0123456789"
    OTP=""
    for i in range(6):
        OTP+=digits[math.floor(random.random()*10)]
    otp = OTP + " is your OTP"
    msg= otp
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    # s.login("vivekkaushal@zenarate.com", "nnhabfzmzvknnzss")
    s.login("vivekkaushal1187@gmail.com", "icusradhefpgeeyn")
    s.sendmail('&&&&&&&&&&&',emailid,msg)
    user = User.query.filter_by(email=email)
    user = user.first()
    if user is not None:
        me = user_verification(user_id=user.id, email=email, otp=int(OTP), verified=0, created_time=datetime.datetime.now())
        db.session.add(me)
        db.session.commit()
        return jsonify({'output': 'otp send sucessfully'})
    else:
        return jsonify({'output': 'user does not exist'})

@app.route('/verify/<email>',methods=['GET','POST'])
def verify(email):
    if request.method =="POST":
        auth = request.form
        output =[]
        otp=auth.get("otp")
        print(otp)
        obj = user_verification.query.filter_by(email=email).first()
        if obj is None:
            return jsonify({'output': 'incorrect email'})
        obj = user_verification.query.filter_by(email=email, otp=otp).first()
        if obj is not None:
            obj = user_verification.query.filter_by(email=email, otp=otp, verified=0).first()
            if obj is None:
                return jsonify({'output': 'otp already verified'})
            obj.verified=1
            db.session.merge(obj)
            db.session.flush()
            db.session.commit()
            print(obj.verified)
            return jsonify({'output':'verified'})
        else:
            return jsonify({'output': 'invalid otp'})
    return jsonify({'output':'otp verified successfully'})

@app.route('/user', methods=['GET','POST'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output_all = []
    for user in users:
        output_all.append({
            'id': user.id,
            'name': user.username,
            'email': user.email
        })
    output_user_details =[{'email':current_user.email, 'name':current_user.username, 'status':"welcome to zenarate"}]
    return jsonify({'user': output_user_details})

@app.route('/login_credentials',methods=['GET','POST'])
def login_required():
    if request.method =="POST":
        auth = request.form
        output =[]
        output.append({
            'output': "invalid password"
        })
        if not auth or not auth.get('username') or not auth.get('password'):
            return make_response(
                'Could not verify',
                401,
                {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
            )
        user = User.query.filter_by(email=auth.get('username')).first()
        if not user:
            output=[{"output":"user doesn't exist"}]
            return jsonify({'output':output})
        if check_password_hash(user.password, auth.get('password')):
            id = user.id
            email =user.email
            token = jwt.encode(
                {'id': id,'email':email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'],
                algorithm="HS256")
            try:
                mfa =user_verification.query.filter_by(user_id=id).first().mfa
            except:
                mfa = 0
            return make_response(jsonify({'token': token, 'mfa':mfa}), 201)
        else:
            output = [{"output": "invalid password"}]
            return jsonify(({'output': output}))

        return "Post Request Success"
    if request.method =="GET":
        return "Get Request Success"

# To verify the rest password otp
@app.route('/verify-otp-to-reset/<email>',methods=['GET','POST'])
def forgot(email):
    if request.method =="POST":
        auth = request.form
        output =[]
        otp=auth.get("otp")
        print(otp)
        obj = user_verification.query.filter_by(email=email).first()
        if obj is None:
            return jsonify({'output': 'incorrect email'})
        obj = user_verification.query.filter_by(email=email, otp=otp).first()
        print(obj,"********")
        if obj is not None:
            obj = user_verification.query.filter_by(email=email, otp=otp, verified=0).first()
            if obj is None:
                return jsonify({'output': 'otp already verified'})
            obj.verified=1
            db.session.merge(obj)
            db.session.flush()
            db.session.commit()
            print(obj.verified)
            return jsonify({'output':'verified'})
        else:
            return jsonify({'output': 'invalid otp'})
    return jsonify({'output':'something went wrong'})

#this function is use to send the otp for the forget password in mail
@app.route('/forgot-password/<email>',methods=['GET','POST'])
def send_otp_forget(email):
    emailid = email
    digits="0123456789"
    OTP=""
    for i in range(6):
        OTP+=digits[math.floor(random.random()*10)]
    otp = OTP + " is your OTP"
    msg= otp
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    # s.login("vivekkaushal@zenarate.com", "nnhabfzmzvknnzss")
    s.login("vivekkaushal1187@gmail.com", "icusradhefpgeeyn")
    s.sendmail('&&&&&&&&&&&',emailid,msg)
    user = User.query.filter_by(email=email)
    user = user.first()
    if user is not None:
        me = user_verification(user_id=user.id, email=email, otp=int(OTP), verified=0, created_time=datetime.datetime.now())
        db.session.add(me)
        db.session.commit()
        return jsonify({'output': 'otp send sucessfully'})
    else:
        return jsonify({'output': 'user does not exist'})

#after verifying otp enter the new password form
# @token_required
# @login_required
@app.route('/new-password/<email>', methods=['GET','POST'])
def new_password(email):
    if request.method =="POST":
        auth = request.form
        if not auth or not auth.get('password') or not auth.get('re_password'):
            return make_response(
                'please enter the password',
                401,
                {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
            )
        elif auth.get('password') != auth.get('re_password'):
            return make_response(
                'password are not same',
                401,
                {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
            )
        elif auth.get('password') == auth.get('re_password'):
            new_password = generate_password_hash(auth.get('password'))
            obj = User.query.filter_by(email=email).first()
            obj.password = new_password
            db.session.merge(obj)
            db.session.commit()
            return jsonify({'output': 'password updated successfully', 'status':200})


#This api is for the support api
@app.route('/upload', methods=['POST'])
def upload_file():
    files = request.files.getlist('files')
    auth = request.form
    email_address = auth.get('email')
    problem =auth.get('problem')
    phone_number=auth.get('phone_number')
    sender_email = "vivekkaushal1187@gmail.com"
    password = "icusradhefpgeeyn"
    receiver_email = 'vivekkaushal29797@gmail.com'

    filename = files[0]
    # filename="sachin1.ipynb"
    problem = problem
    phone_number = phone_number

    # Create MIMEMultipart object
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "User feedback"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # HTML Message Part
    html = f"""\
    <!DOCTYPE html>
    <html>
    <head>

    </head>
    <body>

    <h2>Feedback on some potential new releases:</h2>

    <table>

      <tr>
        <td>Email:-</td>
        <td>{email_address}</td>
      </tr>
       <tr>
        <td>Phone:-</td>
        <td>{phone_number}</td>
      </tr>
      <tr>
        <td>Problem:-</td>
        <td>{problem}</td>
      </tr>

    </table>

    </body>
    </html>
    """

    part = MIMEText(html, "html")
    msg.attach(part)

    # Add Attachment
    try:
        attachment = files[0]
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())

        encoders.encode_base64(part)

        # Set mail headers
        part.add_header(
            "Content-Disposition",
            "attachment", filename = filename.filename
        )
        msg.attach(part)
    except:
        pass
    # Create secure SMTP connection and send email
    # context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, receiver_email, msg.as_string()
        )
    print('Mail Sent')
    success = True
    errors = {"message" : 'something went wrong'}
    if success:
        resp = jsonify({'message': 'Thanks for your contact'})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify(errors)
        resp.status_code = 500
        return resp
if __name__ == '__main__':
    app.run(debug=True, port=8000)