#import imp
from asyncio import proactor_events
from dataclasses import replace
from distutils.command.upload import upload
import mimetypes
#from crypt import methods
from turtle import position
from unicodedata import name
from flask import Flask, render_template, flash, request,redirect,session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, FileField, IntegerField, validators

from wtforms.validators import DataRequired, EqualTo, length
from flask_wtf.file import FileField, FileRequired, FileAllowed
from werkzeug.utils import secure_filename 
import uuid as uuid
import os 

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

from flask_mysqldb import MySQL,MySQLdb 
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from datetime import datetime
from datetime import date

import numpy as np
import tensorflow as tf
from tensorflow import keras
import numpy as np 
import cv2


import base64
from PIL import Image
import io

#load ML model
model = keras.models.load_model('C:/Users/rahma/Desktop/app/model3.h5')

model.make_predict_function()

def predict_label(image_location):
    # pre-process the image
    im = cv2.imread(image_location)
    im = cv2.resize(im, (244, 244))
    im = cv2.cvtColor(im, cv2.COLOR_BGR2RGB)
    im = np.array(im)
    im = np.expand_dims(im, 0)
    a = im.shape
    print(a)
    p = model.predict(im)
    return p.argmax()


UPLOAD_FOLDER = 'C:/Users/rahma/Desktop/app/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}


app = Flask(__name__,static_folder="./uploads")
#app.add_url_rule('uploads',endpoint='myfile', view_func=app.send_static_file )
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
path = os.getcwd()
# file Upload
UPLOAD_FOLDER = os.path.join(path, 'uploads')

if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)

# add db
#old SQLite db
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
#new mysql db
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3307/bibliothequedb'

app.config['SECRET_KEY']= "secretkey"
#initialize the db
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#create a patient model
class patient(db.Model):
    idPatient = db.Column(db.Integer, primary_key= True)
    Full_name = db.Column(db.String(50))
    Age = db.Column(db.String(50))
    Phone = db.Column(db.String(50))
    Nm_Carte = db.Column(db.String(50))
    #patient can have many images scan 
    patient_image = db.relationship('scanIm', backref='patientimage')

# Create a patient form 
class PatientForm(FlaskForm):
    Full_name = StringField("Full name", validators=[DataRequired()])
    Age = StringField("Age", validators=[DataRequired()])
    Phone = StringField("Phone", validators=[DataRequired()])
    Nm_Carte = StringField("number of medical card", validators=[DataRequired()])
    submit = SubmitField("Submit")

    #add patient page
    @app.route('/add_patient', methods=['GET', 'POST'])
    def add_patient():
            form = PatientForm()
            if form.validate_on_submit():
                Patient = patient(Full_name=form.Full_name.data, Age=form.Age.data, Phone=form.Phone.data, Nm_Carte=form.Nm_Carte.data)
                #Clear the form
                form.Full_name.data = ''
                form.Age.data = ''
                form.Phone.data = ''
                form.Nm_Carte.data = ''

                #add patient data to database
                db.session.add(Patient)
                db.session.commit()
                return redirect(url_for('managepatient'))
                #return render_template ("managepatient.html", form=form)

            
            return render_template ("add_patient.html", form=form)
            #
    #update patient page 
    @app.route('/update_patient/<int:idPatient>', methods=['GET','POST'])
    def update_patient(idPatient):
        form = PatientForm()
        patient_update = patient.query.get_or_404(idPatient)
        if request.method == 'POST':
            patient_update.Full_name = request.form['Full_name']
            patient_update.Age = request.form['Age']
            patient_update.Phone = request.form['Phone']
            patient_update.Nm_Carte = request.form['Nm_Carte']
            try:
                db.session.commit()
                flash("patient updated successfully!")
                return render_template ("update_patient.html", 
                    form=form,
                    patient_update = patient_update
                    )
            except:
                db.session.commit()
                flash("Error!")
                return render_template ("update_patient.html", 
                form=form,
                patient_update = patient_update)
        else:
            return render_template ("update_patient.html", 
                form=form,
                patient_update = patient_update)
    #delete patient
    @app.route('/delete/<int:idPatient>')
    def delete_patient(idPatient):
        form = PatientForm()
        patient_to_delete = patient.query.get_or_404(idPatient)
        try:
            db.session.delete(patient_to_delete)
            db.session.commit()
            flash("patient deleted")
            our_patient = patient.query.order_by(patient.idPatient)
            return render_template("managepatient.html" ,form=form,our_patient=our_patient)
        except:
            flash("Try again")
            return render_template("managepatient.html" ,form=form,our_patient=our_patient)
                
#create a scanIm model
class scanIm(db.Model):
    idImage = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String(50))
    file = db.Column(db.LargeBinary) 
    #foreign key refer to primary key of patient 
    patient_scan = db.Column(db.Integer, db.ForeignKey('patient.idPatient')) 


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class CTscanForm(FlaskForm):
    id = IntegerField("id patient", validators=[DataRequired()])
    name = StringField("name", validators=[DataRequired()])
    file = FileField ("image",  validators=[DataRequired()])
    submit = SubmitField("Submit")
    
     
    @app.route('/scan', methods=['GET','POST'])
    
    def upload_file():
        if request.method == 'GET':
            global p_id 
            p_id = request.args.get('id', type=int)
            print(p_id)
            return render_template('scan.html')
        
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No file selected for uploading')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                
                filename = secure_filename(file.filename)
                print(filename)
                image_location = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(image_location)
                flash('File successfully uploaded')
                print(request.files)
                print (file.filename) 

                newFile = scanIm(file=file.read(), name=filename, patient_scan=p_id)
                db.session.add(newFile)
                db.session.commit()

                pr = predict_label(image_location)
                tr = False
                if pr==0:
                    pr="Normal"
                else:
                    pr="Pneumonia"
                if pr is not None:
                    tr =True
                    return render_template('scan.html',p=pr, t=tr, im =filename)

                 
            else:
                flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif')
                return redirect(request.url)

#flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view =  'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#create login form
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")
#create login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            #check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("login succesfully")
                return redirect(url_for('managepatient'))
            else:
                flash("wrong password - Try again")
        else:
            flash("that user doesn't exist")
    return render_template('login.html', form=form)

#create logout page 
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("you have been logged out")
    return render_template('index.html')

#create manage patient page
@app.route('/managepatient', methods=['GET', 'POST'])
@login_required
def managepatient():
    our_patient = patient.query.all()
    return render_template('managepatient.html',our_patient=our_patient)
    


#json 
@app.route('/date')
def get_current_date():
    return {"Date": date.today()}
    
#create user Model
class Users(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False,unique=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False,unique=True)
    address = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100))
    date_added = db.Column(db.DateTime,default=datetime.utcnow)
    #password
    password_hash = db.Column(db.String(100))
    
    @property
    def password(self):
        raise AttributeError('password is not readable attribute')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password) 

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    #create a string
    def __rep__(self):
        return '<Name %r>' % self.name
        
#create a form class
class userForm(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    username = StringField("username", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired()])
    address = StringField("address", validators=[DataRequired()])
    position = StringField("position", validators=[DataRequired()])
    password_hash = PasswordField ("password", validators=[DataRequired(),EqualTo('password_hash2',message='password must match')])
    password_hash2 = PasswordField ("confirm_password", validators=[DataRequired()])
    submit = SubmitField("submit")

    #update database record
    @app.route('/update/<int:id>', methods=['GET', 'POST'])
    def update(id):
        form = userForm()
        name_to_update = Users.query.get_or_404(id)
        if request.method == "POST":
            name_to_update.name = request.form['name']
            name_to_update.email = request.form['email']
            name_to_update.address = request.form['address']
            name_to_update.position = request.form['position']
            try:
                db.session.commit()
                flash("User updated successfully!")
                return render_template ("update.html", 
                form=form,
                name_to_update = name_to_update
                )
            except:
                db.session.commit()
                flash("Error!")
                return render_template ("update.html", 
                form=form,
                name_to_update = name_to_update)
        else:
            return render_template ("update.html", 
                form=form,
                name_to_update = name_to_update)


    #delete database record
    @app.route('/delete/<int:id>')
    def delete(id):
        name = None
        form = userForm()
        user_to_delete = Users.query.get_or_404(id)

        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash("user deleted")
            our_users = Users.query.order_by(Users.date_added)
            return render_template("add_user.html" ,form=form, name=name,our_users=our_users)
        except:
            flash("Try again")
            return render_template("add_user.html" ,form=form, name=name,our_users=our_users)

 #create a form class
class NameForm(FlaskForm):
    name = StringField("what's ur name?", validators=[DataRequired()])
    submit = SubmitField("submit")

    @app.route('/user/add', methods=['GET', 'POST'])

    def add_user():
        name = None
        form = userForm()
        if form.validate_on_submit():
            user = Users.query.filter_by(email=form.email.data).first()
            if user is None:
                #Hashing the psw
                hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
                user = Users(name=form.name.data,username=form.username.data, email=form.email.data,address=form.address.data, position=form.position.data,password_hash=hashed_pw)
                db.session.add(user)
                db.session.commit()
            name = form.name.data
            form.name.data = ''
            form.username.data = ''
            form.email.data = ''
            form.address.data = ''
            form.position.data = ''
            form.password_hash.data = ''
            flash("user added")
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html" ,form=form, name=name,our_users=our_users)

    @app.route('/')

    def index():
        first_name="Rahma"
    
        
        return render_template("index.html", first_name=first_name)

    @app.route('/user/<name>')

    def user(name):
        return render_template("user.html", user_name=name)



if __name__ == '__main__':
    app.run(debug=True)