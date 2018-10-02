from flask import Flask, session, redirect, url_for, escape, request, render_template, send_from_directory
from werkzeug.utils import secure_filename
from passlib.hash import sha256_crypt as mpass
from passlib.context import CryptContext
import short_url
import datetime
import sqlite3
import base64
import random
import string
import math
import os


# init
domain = "https://kelp.ml/"
myctx = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"])
app = Flask(__name__)
conn = sqlite3.connect('Main.db', check_same_thread=False)
cur = conn.cursor()

# file setup
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'tiff', 'gif', 'webm', 'md', 'txt', 'tar.gz', 'tar.bz2', 'tar.xz', 'tar', 'zip', 'flac', 'mp3', 'mp4'])
app.config['UPLOAD_FOLDER'] = '/uploads/'

# paging setup
app.config['FILES_PER_PAGE'] = 15;


#  set the secret key.  keep this really secret:
app.secret_key = 'please_change_me'



# generate an invite key upon startup
s_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))

# functions and whatnot

def is_empty(any_structure):
	if any_structure:
		return False
	else:
		return True

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

def get_size(path):
	total_size = 0
	for dirpath, dirnames, filenames in os.walk(path):
		for f in filenames:
			fp = os.path.join(dirpath, f)
			total_size += os.path.getsize(fp)
	return total_size

# found this handy dandy function on ill.fi's source
# https://github.com/hvze/ill.fi
def convert_size(size_bytes):
	if size_bytes == 0:
		return '0B'
	size_name = ('b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb')
	i = int(math.floor(math.log(size_bytes, 1024)))
	p = math.pow(1024, i)
	s = round(size_bytes / p, 2)
	return '%s %s' % (s, size_name[i])

# pages start here

@app.route('/')
def index():
	return render_template('index.html', session=session)
	
@app.route('/rice')
def rice():
	return render_template('rice.html', session=session)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == "POST":
		username = request.form['username']
		password = request.form['password']
		
		if not is_empty(username) and not is_empty(password):
			session.pop('username', None)
			session.pop('password', None)
			
			# looking for password in database
			cur.execute("SELECT password FROM users WHERE username=?", (username,))
			
			# this gets the password (as a tuple, we'll convert it later)
			enc_psk_tuple = (cur.fetchone())
			
			# if user not found
			if is_empty(enc_psk_tuple):
				msg="user not found"
				return render_template('login.html', session=session, msg=msg)
			
			enc_psk_string ="".join(enc_psk_tuple)
			
			# verification
			if myctx.verify(password, enc_psk_string) == True:
				session['username'] = username
				return redirect(url_for('index'))
			
			# if wrong password
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
	global s_key
	if request.method == "POST":
		# get all required variables
		username = request.form['username']
		password = request.form['password']
		s_chk = request.form['s_key']
		
		# check if all inputs are filled out
		if not is_empty(username) and not is_empty(password) and not is_empty(s_chk):
			# check if invite key is correct
			if s_key != s_chk:
				msg="invite key not provided"
				return render_template('register.html', session=session, msg=msg)
			
			# check if username already exists
			cur.execute("SELECT username FROM users WHERE username=?", (username,))
			test = cur.fetchone()
			if test != None:
				msg="user already exists"
				return render_template('register.html', session=session, msg=msg)
			
			# everything is good, continue registration
			
			# generate password hash
			hashed_pwd = myctx.hash(password)
			# change the invite key
			s_key=''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))
			# create a random upload key
			upload_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(15))
			cur.execute("INSERT INTO users (uid, date_added, username, password, access_level, upload_key) VALUES(NULL, ?, ?, ?, ?, ?) ;", (datetime.datetime.now().strftime("%Y-%m-%d"),username,hashed_pwd,1,upload_key))
			conn.commit()
			return redirect(url_for('login'))
		
		# if all inputs aren't filled out
		else:
			msg="please fill out all input points"
			return render_template('register.html', session=session, msg=msg)
			
			
		
	# if user has admin level access
	if session.get('username') != None and get_acc_level(session['username']) == 3:
		
		return render_template('register.html', session=session, s_key=s_key)
	
	return render_template('register.html', session=session)

@app.route('/logout')
def logout():
	session.pop('username', None)
	return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
	
	# get upload stats
	disk_usage = get_size(os.path.dirname(os.path.realpath(__file__))+app.config['UPLOAD_FOLDER'])
	disk_usage = convert_size(disk_usage)
	
	cur.execute("SELECT * FROM files")
	count = cur.fetchall()
	file_amount = len(count)
	
	cur.execute("SELECT * FROM users")
	count = cur.fetchall()
	usr_amount = len(count)
	
	stats = (disk_usage, file_amount, usr_amount)
	
	
	
	if request.method == "POST":
		
		
		# clean output check
		clean = False
		if request.form.get('u_clean'):
			clean = True
		
		u_chk = request.form['upload_key']
		u_file  = request.files['u_file']
		
		if not is_empty(u_chk) and u_file:
				
			# check if upload key is correct and check if correct filetype
			if verify_upload_key(u_chk):
				if allowed_file(u_file.filename):
					
					# actual uploading
					
					# securing the filename
					filename = secure_filename(u_file.filename)
					filetype = filename.rsplit('.', 1)[1]# we get the filetype
					filetype = filetype.lower()
					
					realname = filename.rsplit('.', 1)[0]# getting the original filename
					
					# encoded filename generation
					cur.execute("SELECT seq FROM sqlite_sequence WHERE name='files'")
					curr_id = cur.fetchone()
					print (curr_id[0])
					
					filename = short_url.encode_url((curr_id[0]+1))# uses short_url lib
					
					# old method
					# filename = str(uuid.uuid4())[:8]# i had it longer originally, but that's p unusable
					
					
					path = os.path.dirname(os.path.realpath(__file__))# current directory of program
					path += app.config['UPLOAD_FOLDER'] + filename + '.' + filetype
					u_file.save(path)
					
					# update database
					uid = get_uid_from_key(u_chk)
					cur.execute("INSERT INTO files (fid, corr_uid, filetype, filename, org_filename) VALUES(NULL, ?, ?, ?, ?) ;", (uid, filetype, filename, realname))
					conn.commit()
					link = domain + filename + '.' + filetype +'\n'
					if clean:
						return link
					else:
						return render_template('upload.html',session=session, u_key=u_chk, link=link, stats=stats)
				else:
					msg="unsupported/unallowed file type\n"
					if clean:
						return msg
					else:	
						return render_template('upload.html',session=session, msg=msg, stats=stats)
					
			else:
				msg="wrong upload key\n"
				if clean:
					return msg
				else:
					return render_template('upload.html',session=session, msg=msg, stats=stats)
		else:
			msg="file or upload key not found\n"
			if clean:
				return msg
			else:
				return render_template('upload.html',session=session, msg=msg)
	else:
		if session.get('username') != None:
			# post the upload key to the page if user is logged in
			u_key = get_upload_key(session['username'])
			return render_template('upload.html',session=session, u_key=u_key, stats=stats)
		else:
			return render_template('upload.html',session=session, stats=stats)


@app.route('/<filename>') # finds a filename upon getting it's location
def uploaded_file(filename):
	path = os.path.dirname(os.path.realpath(__file__))# current directory of program
	path += app.config['UPLOAD_FOLDER']
	return send_from_directory(path, filename)


# file deletion will use two routes: one for displaying files, another for deletion
@app.route('/files/', defaults={'page': 1})
@app.route('/files/<int:page>')
def files(page):
	
	
	# if user has admin level access
	if session.get('username') != None and get_acc_level(session['username']) == 3:
		# redirect to admin page
		return redirect(url_for('admin'))
		# admin is still wip
	elif session.get('username') != None:

		
		# display only the things that correspond to user's uid
		username = session.get('username')
		uid = get_uid_from_username(username)
		
		cur.execute("SELECT * FROM files WHERE corr_uid=? ORDER BY fid DESC;", (uid,))
		temp=cur.fetchall()
		
		#paging
		
		
		
		# get total amount of posts by user
		file_amount = len(temp)
		page_amount = int((file_amount/app.config['FILES_PER_PAGE']))
		
		
		
		# this basically gets the correct file links from the 'temp'
		# array, which has all of the user's posted pages
		# i honestly didn't think that this would work that well.
		files = temp[(page-1)*app.config['FILES_PER_PAGE']:(page-1)*app.config['FILES_PER_PAGE']+app.config['FILES_PER_PAGE']]
		
		if len(files) != 0:
			return render_template('files.html', session=session, files=files, page_amount=page_amount, curr_page=page)
		
		else:
			return render_template('files.html', session=session)
	
	else:
		return render_template('files.html', session=session)


# admin page, redirect to this from /files/ if user 
@app.route('/admin/', defaults={'page': 1}, methods=['GET', 'POST'])
@app.route('/admin/<int:page>', methods=['GET', 'POST'])
def admin(page):
	if session.get('username') != None and get_acc_level(session['username']) == 3:
		
		# i decided to use GET args because they're much easier to preserve
		# than forms and you don't need to recheck your variables, unlike using a session
		# in hindsight, this is a slightly messy implementation, because i'm passing the same 
		# data twice (pagedata and searchdata, and the args), gonna have to improve on this
		
		args = request.query_string
		# apparantly flask uses utf8 for its strings, so
		# we decode it to raw ascii
		args = args.decode("utf-8")
		
		# these are used for preserving the search form and the current page
		pagedata = [-1] * 2
		searchdata = [-1] * 4
		
		
		# fetch all files
		cur.execute("SELECT * FROM files ORDER BY fid DESC;")
		temp = cur.fetchall()
		file_amount = len(temp)
			
		# search
		searchby = request.args.get('search_by')
		searchquery = request.args.get('search_query')
		
		print (searchby)
		
		if not is_empty(searchby) and not is_empty(searchquery):
			searchdata[0] = searchby
			searchdata[1] = searchquery
			i = 0
			temp2 = []
			for row in temp: # for each row
				s = str(row[int(searchby)])
				sq = str(searchquery)
				
				if s.find(sq) != -1: # if item in search query
					temp2.append(row)# remove the whole row
				
			temp = temp2
			
		# try to get the variables required for sorting
		orderby = request.args.get('order_by')
		descasc = request.args.get('desc_asc')
		
		# check if said variables exist
		if not is_empty(orderby) and not is_empty(descasc):
			
			orderby = int(orderby)
			
			searchdata[2] = orderby
			searchdata[3] = descasc
			if descasc == 'asc':
				temp = sorted(temp, key=lambda row: str(row[orderby]), reverse=False)
			elif descasc == 'desc':
				temp = sorted(temp, key=lambda row: str(row[orderby]), reverse=True)
			
		
		# paging
		
		# get total amount of posts
		file_amount = len(temp)
		page_amount = int((file_amount/app.config['FILES_PER_PAGE']))
		
		pagedata[0] = page_amount
		pagedata[1] = page
		
		
		# see the same line in @app.route(files)
		files = temp[(page-1)*app.config['FILES_PER_PAGE']:(page-1)*app.config['FILES_PER_PAGE']+app.config['FILES_PER_PAGE']]
		
		print (searchdata)
		
		return render_template('admin.html', session=session, files=files, searchdata=searchdata, pagedata=pagedata, args=args)
	else:
		return redirect(url_for('files'))



@app.route('/delete/<filename>')
def delete(filename):
	if session.get('username') != None:
		
		
		uid = int(get_uid_from_username(session['username']))
		
		# get full path of file
		file_location = os.path.dirname(os.path.realpath(__file__)) + app.config['UPLOAD_FOLDER']+filename
		
		# get filename without filetype
		real_name = filename.rsplit('.', 1)[0]
		
		# test if file belongs to correct user, and check if exists
		cur.execute("SELECT corr_uid FROM files WHERE filename=?;", (real_name,))
		check = cur.fetchone()
		
		# if file exists but isnt marked in the database
		if os.path.exists(file_location) and len(check) == 0:
			# delete it since it doesn't belong to anyone
			os.remove(file_location)
			
		# if user owns file or user is admin
		print (uid)
		print (check[0])
		print (get_acc_level(session['username']))
		print (session['username'])
		if uid == check[0] or get_acc_level(session['username']) == 3:
			# delete entry from database, regardless if file exists
			cur.execute ("DELETE FROM files WHERE filename=?", (real_name,))
			conn.commit()
			# delete file if exists
			if os.path.exists(file_location):
				os.remove(file_location)
			
			
			
	return redirect(url_for('files'))

@app.route('/delete/all')
def deleteall():
	if session.get('username') != None:
		uid = int(get_uid_from_username(session['username']))
		cur.execute("SELECT * FROM files WHERE corr_uid=?",(uid,))
		files = cur.fetchall()
		
		path = os.path.dirname(os.path.realpath(__file__)) + app.config['UPLOAD_FOLDER']
		
		
		#first, delete the files, then delete the database entries
		for f in files:
			os.remove(path+f[3]+'.'+f[2])
		
		cur.execute("DELETE FROM files WHERE corr_uid=?", (uid,))
		conn.commit()
		
	return redirect(url_for('files'))

if __name__ == '__main__':
	app.run(host='0.0.0.0')
















