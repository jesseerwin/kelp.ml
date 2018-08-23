from flask import Flask, session, redirect, url_for, escape, request, render_template, send_from_directory
from werkzeug.utils import secure_filename
from passlib.hash import sha256_crypt as mpass
from passlib.context import CryptContext
import datetime
import sqlite3
import random
import string
import uuid
import os


#init
domain = "http://127.0.0.1:5000/"
myctx = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"])
app = Flask(__name__)
conn = sqlite3.connect('Main.db', check_same_thread=False)
cur = conn.cursor()

#file setup
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'svg', 'gif','webm', 'pdf', 'md', 'txt', None, 'tar.gz', 'tar.bz2', 'tar.xz', 'tar', 'zip', 'flac', 'mp3', 'mp4'])
app.config['UPLOAD_FOLDER'] = '/uploads/'

# set the secret key.  keep this really secret:
app.secret_key = 'CHANGE_THIS_WHEN_IN_PRODUCTION'



#generate an invite key upon startup
s_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))

#functions and whatnot

def is_empty(any_structure):
	if any_structure:
		return False
	else:
		return True

def change_skey():
	s_key=''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))

def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_acc_level(user):
	cur.execute("SELECT access_level FROM users WHERE username=?", (user,))
	privilege = cur.fetchone()
	return privilege[0]

def get_upload_key(user):
	cur.execute("SELECT upload_key FROM users WHERE username=?", (user,))
	key = cur.fetchone()
	return key[0]

def verify_upload_key(key):
	cur.execute("SELECT upload_key FROM users WHERE upload_key=?", (key,))
	test = cur.fetchone()
	if test == None:
		return False
	return True

def get_uid_from_key(key):
	cur.execute("SELECT uid FROM users WHERE upload_key=?", (key,))
	uid = cur.fetchone()
	return uid[0]

def get_uid_from_username(username):
	cur.execute("SELECT uid FROM users WHERE username=?", (username,))
	uid = cur.fetchone()
	return uid[0]



#pages start here

@app.route('/')
def index():
	return render_template('index.html', session=session)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == "POST":
		username = request.form['username']
		password = request.form['password']
		
		if not is_empty(username) and not is_empty(password):
			session.pop('username', None)
			session.pop('password', None)
			
			#looking for password in database
			cur.execute("SELECT password FROM users WHERE username=?", (username,))
			
			#this gets the password (as a tuple, we'll convert it later)
			enc_psk_tuple = (cur.fetchone())
			
			#if user not found
			if is_empty(enc_psk_tuple):
				msg="user not found"
				return render_template('login.html', session=session, msg=msg)
			
			enc_psk_string ="".join(enc_psk_tuple)
			
			#verification
			if myctx.verify(password, enc_psk_string) == True:
				session['username'] = username
				return redirect(url_for('index'))
			
			#if wrong password
			else:
				msg="wrong password"
				return render_template('login.html', session=session, msg=msg)
		else:
			msg="please fill out all inputs"
			return render_template('login.html', session=session, msg=msg)
	else:
		return render_template('login.html', session=session)



@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == "POST":
		#get all required variables
		username = request.form['username']
		password = request.form['password']
		s_chk = request.form['s_key']
		
		#check if all inputs are filled out
		if not is_empty(username) and not is_empty(password) and not is_empty(s_chk):
			#check if invite key is correct
			if s_key != s_chk:
				msg="invite key not provided"
				return render_template('register.html', session=session, msg=msg)
			
			#check if username already exists
			cur.execute("SELECT username FROM users WHERE username=?", (username,))
			test = cur.fetchone()
			if test != None:
				msg="user already exists"
				return render_template('register.html', session=session, msg=msg)
			
			#everything is good, continue registration
			
			#generate password hash
			hashed_pwd = myctx.hash(password)
			#change the invite key
			change_skey()
			#create a random upload key
			upload_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15))
			cur.execute("INSERT INTO users (uid, date_added, username, password, access_level, upload_key) VALUES(NULL, ?, ?, ?, ?, ?) ;", (datetime.datetime.now().strftime("%Y-%m-%d"),username,hashed_pwd,1,upload_key))
			conn.commit()
			return redirect(url_for('login'))
		
		#if all inputs aren't filled out
		else:
			msg="please fill out all input points"
			return render_template('register.html', session=session, msg=msg)
			
			
		
	#if user has admin level access
	if session.get('username') != None and get_acc_level(session['username']) == 3:
		return render_template('register.html', session=session, s_key=s_key)
	
	return render_template('register.html', session=session)

@app.route('/logout')
def logout():
	session.pop('username', None)
	return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
	if request.method == "POST":
		
		clean = False
		
		if request.form.get('u_clean'):
			clean = True
		
		u_chk = request.form['upload_key']
		u_file  = request.files['u_file']
		
		if not is_empty(u_chk) and u_file:
				
			#check if upload key is correct and check if correct filetype
			if verify_upload_key(u_chk):
				if allowed_file(u_file.filename):
					
					
					
					#actual uploading
					
					#we secure the filename
					filename = secure_filename(u_file.filename)
					filetype = filename.rsplit('.', 1)[1]#we get the filetype
					filename = str(uuid.uuid4())[:8]#i had it longer originally, but that's p unusable
					
					
					path = os.path.dirname(os.path.realpath(__file__))#current directory of program
					path += app.config['UPLOAD_FOLDER'] + filename + '.' + filetype
					u_file.save(path)
					
					#update database
					uid = get_uid_from_key(u_chk)
					cur.execute("INSERT INTO files (fid, corr_uid, filetype, filename) VALUES(NULL, ?, ?, ?) ;", (uid, filetype, filename))
					conn.commit()
					link = domain + filename + '.' + filetype +'\n'
					if clean:
						return link
					else:
						return render_template('upload.html',session=session, u_key=u_chk, link=link)
				else:
					msg="unsupported/unallowed file type\n"
					if clean:
						return msg
					else:	
						return render_template('upload.html',session=session, msg=msg)
					
			else:
				msg="wrong upload key\n"
				if clean:
					return msg
				else:	
					return render_template('upload.html',session=session, msg=msg)
		else:
			msg="file or upload key not found\n"
			if clean:
				return msg
			else:	
				return render_template('upload.html',session=session, msg=msg)
	else:
		if session.get('username') != None:
			#post the upload key to the page if user is logged in
			u_key = get_upload_key(session['username'])
			return render_template('upload.html',session=session, u_key=u_key)
		else:
			return render_template('upload.html',session=session)


@app.route('/<filename>') #finds a filename upon getting it's location
def uploaded_file(filename):
	path = os.path.dirname(os.path.realpath(__file__))#current directory of program
	path += app.config['UPLOAD_FOLDER']
	return send_from_directory(path, filename)


#file deletion will use two routes: one for display, another for deletion
@app.route('/files')
def files():
	#if user has admin level access
	if session.get('username') != None and get_acc_level(session['username']) == 3:
		#display all
		cur.execute("SELECT * FROM files")
		files=cur.fetchall()
		if len(files) != 0:
			return render_template('files.html', session=session, files=files)
		else:
			return render_template('files.html', session=session)
	elif session.get('username') != None:
		#display only the things that correspond to user's uid
		username = session.get('username')
		uid = get_uid_from_username(username)
		cur.execute("SELECT * FROM files WHERE corr_uid=?", (uid,))
		files=cur.fetchall()
		if len(files) != 0:
			return render_template('files.html', session=session, files=files)
		else:
			return render_template('files.html', session=session)
	else:
		return render_template('files.html', session=session)

@app.route('/delete/<filename>')
def delete(filename):
	if session.get('username') != None:
		print ("authorized")
		uid = int(get_uid_from_username(session['username']))
		print (uid)
		file_location = os.path.dirname(os.path.realpath(__file__)) + app.config['UPLOAD_FOLDER']+filename
		real_name = filename.rsplit('.', 1)[0]
		cur.execute("SELECT corr_uid FROM files WHERE filename=?;", (real_name,))
		check = cur.fetchone()
		
		
		print ("file/user check")
		print (uid )
		print (type(uid))
		print(check[0] )
		print  (type(check[0]))
		print (uid == check[0])
		print (file_location)
		print (os.path.exists(file_location))
		
		if os.path.exists(file_location) and uid == check[0]:
			print ("success")
			os.remove(file_location)
			cur.execute ("DELETE FROM files WHERE filename=?", (real_name,))
			conn.commit()	
	return redirect(url_for('files'))
	


if __name__ == '__main__':
	app.run(host='0.0.0.0')
















