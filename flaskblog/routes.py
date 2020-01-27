from flask  import  render_template , url_for , flash , redirect , request
from flaskblog import app , db , bcrypt
from flaskblog.forms import RegistrationForm , LoginForm 
from flaskblog.models import User , Post
from flask_login import login_user ,current_user , logout_user , login_required
from flask import Flask, jsonify
from flask import Flask, request, jsonify
import pandas as pd
import re
import numpy as np
import json


@app.route('/')
@app.route('/register' , methods=['GET' , 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('upload_file'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data ,  email = form.email.data , password = hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created , now you can log in', 'success')
        return redirect(url_for('login'))
    return  render_template('register.html' , title='register' , form=form)


@app.route('/login' , methods=['GET' , 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('upload_file'))

    Signform = LoginForm()
    if Signform.is_submitted():
        user = User.query.filter_by(email=Signform.email.data).first()
        if user and bcrypt.check_password_hash(user.password , Signform.password.data):
            login_user(user , remember=Signform.remember.data)
            next_page = request.args.get('next')
            return  redirect(next_page) if next_page else redirect(url_for('upload_file'))
        else:
             flash('Wrong credentials' , 'danger')
    return render_template('login.html' , title='Login' , Signform=Signform)


@app.route("/upload", methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        print(request.files['file'])
        f = request.files['file']
        data_xls = pd.read_csv(f )
        df2 = data_xls.reset_index()
        df2 = pd.DataFrame(df2)
        df2.index = df2.index + 2
        p = df2.dropna(axis=1 , how='all')
        name_filter = df2[df2['Pensioner Name'].astype(str).str.match('(?!(^[a-zA-Z\s\.]*$))')].iloc[:,1].sort_values()
        cnic_filter = df2[df2['CNIC'].astype(str).str.match('(?!(^[\'][0-9+]{5}-[0-9+]{7}-[0-9]{1}[\']$))')].iloc[:,2]
        claim_filter = df2[df2['Claim No'].astype(str).str.match('(?!(^[\'][BDHIKTWXYCEFGJLMNPQSTRA\W][BWACPDZ\W][ATBYZSW102456KJEGUCXR\W][0-9+]{5}[\']$))')].iloc[:,3]
        
        wallet_filter = df2[df2['Wallet Account No'].astype(str).str.contains('^(?!^[0-9+]{8}$)')].iloc[:,4]    
        mobile_filter = df2[df2['Mobile Number'].astype(str).str.contains('^(?!^[3+][0-9+]{9}$)')].iloc[:,5]
        name_filterf= pd.DataFrame(name_filter)
        cnic_filterf = pd.DataFrame(cnic_filter)
        wallet_filterf = pd.DataFrame(wallet_filter)
        mobile_filterf = pd.DataFrame(mobile_filter)
        claim_filterf = pd.DataFrame(claim_filter)

       
        

        return  '{} \t {} \t {} \n {} {}'.format(name_filterf.to_html(), cnic_filterf.to_html(),claim_filterf.to_html(), wallet_filterf.to_html() , mobile_filterf.to_html())
        return name_filterf.to_html()
        
        
    return render_template('home.html' , title='Home')




@app.route('/newabout')
def about():
    return render_template('newabout.html' , title = "About")





@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html' , title = "Account")