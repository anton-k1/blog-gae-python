import webapp2
import os
import re
import random
import string
import jinja2
import hashlib
import datetime
import time
import math
from google.appengine.ext import db
from google.appengine.ext import ndb
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

##################### Common ######################

class BaseHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_templ(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_templ(template, **kw))

class BlogHandler(BaseHandler):
	def initialize(self, req, res):
		super(BlogHandler, self).initialize(req, res)
		self.user = None
		userid_cookie = req.cookies.get('user_id')
		if userid_cookie:
			if check_userid_cookie(userid_cookie):
				user_id = userid_cookie.split('|')[0]
				user = User.get_by_id(int(user_id))
				if user:
					self.user = user

	def set_userid_cookie(self, user):
		user_id = str(user.key().id())
		userid_cookie = make_userid_cookie(user_id)
		self.response.headers.add_header('Set-Cookie', 'user_id=%s, Path=/' % userid_cookie)

	def get_username(self):
		return self.user.name if self.user else ""

	def check_logged_user(self):
		if not self.user:
			self.redirect('/')
		
################### Common END  ###################

###################### Model ######################

class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	modified = db.DateTimeProperty()
	author_name = db.StringProperty(required = True)
	author_id = db.IntegerProperty()
	num_comments = db.IntegerProperty(default=0)

class Comment(db.Model):
	post_id = db.IntegerProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	text = db.TextProperty(required = True)
	author_name = db.StringProperty(required = True)
	author_id = db.IntegerProperty()
	
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

class Subscriber(db.Model):
	name = db.StringProperty(required=True)
	email = db.StringProperty(required=True)

################     Model END   ##################

################# Authentication ##################

def make_salt():
	return ''.join(random.choice(string.letters) for x in range(5))

def make_pw_hash(login, password, salt=None):
	if not salt:
		salt = make_salt()

	h = hashlib.sha256(login + password + salt).hexdigest()
	return "%s|%s" % (h, salt)

def check_password_correct(login, password, pw_hash):
	salt = pw_hash.split('|')[1]
	return pw_hash == make_pw_hash(login, password, salt)

SECRET = "" #used on production
def make_userid_cookie(user_id):
	userid_hash = hashlib.sha256(SECRET + user_id).hexdigest()
	return "%s|%s" % (user_id, userid_hash)

def check_userid_cookie(cookie):
	user_id = cookie.split('|')[0]
	return cookie == make_userid_cookie(user_id)

USER_RE = re.compile(r"^[0-9a-zA-Z-_]{3,20}$")
def check_login(login):
	return USER_RE.match(login)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def check_password(password):
	return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def check_email(email):
	return EMAIL_RE.match(email)

class Login(BlogHandler):
	def write_login_form(self, error_msg=""):
		self.render('login_form.html', error_msg=error_msg, username=self.get_username())

	def get(self):
		self.write_login_form()

	def post(self):
		login = self.request.get('login')
		pswd = self.request.get('password')

		login_correct = False
		if login:
			user = db.GqlQuery('select * from User where name = :1', login).get()
			if user:
				if check_password_correct(login, pswd, user.pw_hash):
					self.set_userid_cookie(user)
					self.redirect('/')
					return

		self.write_login_form("Incorrect login or password")

class Signup(BlogHandler):
	def write_signup_form(self, error_msg=""):
		self.render('signup_form.html', error_msg=error_msg, username=self.get_username())

	def get(self):
		self.write_signup_form()

	def post(self):
		login = self.request.get('login')
		email = self.request.get('email')
		pswd = self.request.get('password')

		error_msg = ""
		if not check_login(login):
			error_msg = "Incorrect login"
		elif not check_email(email):
			error_msg = "Incorrect email"
		elif not check_password(pswd):
			error_msg = "Incorrect password"

		if error_msg:
			self.write_signup_form(error_msg)
		else:
			# Create user
			user = User(name=login, pw_hash=make_pw_hash(login, pswd), email=email)
			user.put()
			
			self.set_userid_cookie(user)
			self.redirect('/')

class Logout(BlogHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=, Path=/')
		self.redirect('/')

################ Authentication END ###############

################ Blog Handlers ####################
PAGE_SIZE = 5

def get_most_popular():
	#Most Popular
	q = Post.all().order('-num_comments').order('-created')
	most_popular_links = q.fetch(5)
	return most_popular_links

class MainHandler(BlogHandler):
	def get(self):
		page = self.request.get("p")
		if not page:
			page = 0
		else:
			page = int(page)
		print "page=%s" % page
		is_next = None

		q = Post.all().order('-created')
		#TODO fetch with offset in GAE gets all entities from the beginning - bad performance on big data volumes
		posts = q.fetch(PAGE_SIZE + 1, offset=page*PAGE_SIZE)
		if len(posts) == PAGE_SIZE + 1:
			is_next = True
			posts = posts[:PAGE_SIZE]

		count = Post.all(keys_only=True).count()
		pages_num = int(math.ceil(1.0*count/PAGE_SIZE))
		print "pages_num = %s" % pages_num

		self.render('main_page.html', username=self.get_username(), posts=posts, page=page, is_next=is_next, pages_num=pages_num, most_popular_links=get_most_popular())

class ViewPost(BlogHandler):
	def get(self, post_id):
		if post_id:
			post = Post.get_by_id(int(post_id))
			if post:
				comments = Comment.all().filter("post_id =", int(post_id)).order("-created")
				comments = list(comments)
				self.render('post_view_page.html', username=self.get_username(), post=post, comments=comments, most_popular_links=get_most_popular())
			else:
				self.write('404 Not Found')
		

class EditPost(BlogHandler):
	def render_edit_page(self, title="", content=""):
		self.render('post_edit_page.html', username=self.get_username(), title=title, content=content)

	def get(self, post_id):
		if not self.user:
			self.redirect('/')
			return

		if post_id:
			post = Post.get_by_id(int(post_id))
			if post:
				self.render_edit_page(post.title, post.content)
			else:
				self.write('404 Not Found')
		else:
			self.render_edit_page()

	def post(self, post_id):
		if not self.user:
			self.redirect('/')
			return

		post_title = self.request.get('post-title')
		post_content = self.request.get('post-content')

		if post_id:
			#Update existing post
			post = Post.get_by_id(int(post_id))
			if post and (post.title != post_title or post.content != post_content):
				post.title = post_title
				post.content = post_content
				post.modified = datetime.datetime.now()
				post.put()
			else:
				self.write('404 Not Found')
				return
		else:
			#Create new post
			new_post = Post(title=post_title, content=post_content, author_name=self.user.name, author_id=self.user.key().id())
			new_post.put()
			post_id = new_post.key().id()

		self.redirect('/' + str(post_id))

class DeletePost(BlogHandler):
	def get(self, post_id):
		if not self.user:
			self.redirect('/')
			return
		
		if post_id:
			post = Post.get_by_id(int(post_id))
			if post:
				post.delete()

				comments = Comment.all().filter("post_id =", int(post_id)).order("-created")
				comments = list(comments)
				for comment in comments:
					#print "comment " + str(comment.text)
					comment.delete()

				#time.sleep(0.2)
				self.redirect('/')
				return
		
		self.write('404 Not Found')

class AddPostComment(BlogHandler):
	def post(self, post_id):
		user_name = self.request.get('name')
		comment_text = self.request.get('comment')
		
		if post_id:
			post = Post.get_by_id(int(post_id))
			if post:
				comment = Comment(post_id=int(post_id), text=comment_text, author_name=user_name)
				comment.put()
				post.num_comments = post.num_comments + 1
				post.put()
				#time.sleep(0.2)

		self.redirect('/%s/#comments' % str(post_id))
		
class DeleteComment(BlogHandler):
	def get(self, comment_id):
		if not self.user:
			self.redirect('/')
			return

		if comment_id:
			comment = Comment.get_by_id(int(comment_id))
			if comment:
				post_id = comment.post_id
				comment.delete()
				if post_id:
					post = Post.get_by_id(post_id)
					if post:
						post.num_comments = post.num_comments - 1
						post.put()
						#time.sleep(0.2)
						self.redirect('/%s/#comments' % str(post_id))
						return
		
		self.write('404 Not Found')

def check_sub_name(name):
	return len(name) > 0

class Subscribe(BaseHandler):
	def render_sub_page(self, message=""):
		self.render('success_subscription.html', message=message)

	def post(self):
		sub_name = self.request.get("sub_name")
		sub_email = self.request.get("sub_email")

		if not check_sub_name(sub_name) or not check_email(sub_email):
			self.render_sub_page('Invalid user name or email')
		else:
			sub = Subscriber(name=sub_name, email=sub_email)
			sub.put()
			self.render_sub_page('Congratulations! You\'ve subscribed successfully')

####################################################

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/login', Login),
	#('/signup', Signup),
	('/logout', Logout),
	('/_edit(?:/([0-9]+))?/?', EditPost),
	('/([0-9]+)/?', ViewPost),
	('/_delete/([0-9]+)/?', DeletePost),
	('/_comment/([0-9]+)/?', AddPostComment),
	('/_delete_comment/([0-9]+)/?', DeleteComment),
	('/subscribe', Subscribe)
], debug=True)