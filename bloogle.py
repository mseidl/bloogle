#This file is part of bloogle.
#
#Foobar is free software: you can redistribute it and/or modify
#it under the terms of the Affero GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#bloogle is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the Affero GNU General Public License
#along with bloogle.  If not, see <http://www.gnu.org/licenses/>.

import os
import webapp2
import jinja2
import re
import hmac
import logging

from google.appengine.api import memcache
from google.appengine.ext import db
from passlib.hash import pbkdf2_sha512 as pl

pl.default_salt_size = 32
pl.default_rounds = 25000

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                    autoescape = True)




def val_user(user):
    '''Validate the username, checks to see if you have A-Z, a-z, 0-9 and _-'''
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return user and USER_RE.match(user)

def val_pw(pw,verify):
    '''Validate the password, just check if it is between 3 and 20 characters long
       Not strong enough'''
    PW_RE = re.compile(r"^.{3,20}$")
    if pw == verify:
        if PW_RE.match(pw):
            return pw
        else:
            return None
    else:
        return None

def val_email(email):
    '''Validate email, basic but functional check, no need for anything more complex
       blank email is ok'''
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    return not email or EMAIL_RE.match(email)

#IMPORTANT! MUST READ
#ECV value is added to hmac to hash!  Uncomment ecv add a lengthy, somewhat random value.
#Blog will not function without this uncommented
#ecv = ''




class Content(db.Model):
    '''Content for blog posts, StringProperty has 500 character limit
       date is time added, and modified is last time the record was edited'''
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    date = db.DateTimeProperty(auto_now_add = True)
    mod = db.DateTimeProperty(auto_now = True)

class Users(db.Model):
    '''email is not required, date is time added, and mod is last time the
       record was updated'''
    user = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    date = db.DateTimeProperty(auto_now_add = True)
    mod = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, user_id):
        '''decorator to use method without object instance,
           return user by the user id'''
        return Users.get_by_id(user_id)

    @classmethod
    def get_user(cls, user):
        '''decorator to use the method without object instance, return user by user name'''
        u = db.GqlQuery('select * from Users where user = :1', user).get()
        return u

class Helper(webapp2.RequestHandler):
    '''Helper class to add convienence functions to page handlers'''

    def write(self, *a, **kw):
        '''Write some basic html/text to page'''
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        '''render templates'''
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        '''Render page with keywords and templated html'''
        self.write(self.render_str(template, **kw))

    def encrypt_cookie_val(self, val):
        '''Hashes and returns value in the form of value|hash to store in a cookie'''
        return '%s|%s' % (val, hmac.new(ecv, val).hexdigest())

    def verify_userid(self):
        '''Reads user_id from cookie value, and validates against encrypt_cookie_val'''
        uid = self.request.cookies.get('user_id')
        if uid is None:
            return False
        return uid == self.encrypt_cookie_val(uid.split('|')[0])

    def verify_cookie_val(self, val):
        '''Verify  given value against encrypt_cookie_value, val is expecting value|hex format
           straight from cookie'''
        v = self.request.cookies.get(val)
        if v is None:
            return False
        return v == self.encrypt_cookie_val(v.split('|'))

    def encrypt_pw(self, pw):
        '''Use passlib to encrypt password'''
        return pl.encrypt(pw)

    def verify_pw(self, pw, ha):
        '''User passlib to verify password'''
        return pl.verify(pw, ha)

    def valid_login(self):
        '''Validate login form and verify against database data
           for use only with /login page'''
        user = self.request.get('user')
        password = self.request.get('password')
        u = Users.get_user(user)
        if u and self.verify_pw(password, u.password):
            return True
        else:
            return False

class Login(Helper):
    '''Login page'''
    def get(self):
        if self.verify_userid():
            self.redirect('/')
        else:
            self.render('login.html')

    def post(self):
        if self.valid_login():
            u  = Users.get_user(self.request.get('user'))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % self.encrypt_cookie_val(str(u.key().id())))
            self.redirect('/welcome')
        else:
            self.render('login.html', error=True)

class Logout(Helper):
    '''Simply logout by clearing the cookie'''
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')

class Welcome(Helper):
    '''Welcome page'''
    def get(self):
        if self.verify_userid():
                u = self.request.cookies.get('user_id')
                user = Users.by_id(int(u.split('|')[0]))
                self.render('welcome.html', login=True, name=user.name)
        else:
            self.redirect('signup')



class Signup(Helper):
    '''Signup page, registers user to the database if the username is not taken'''
    def get(self):
        self.render('signup.html')

    def post(self):
        '''get all the data from the form, verify it and submit it to the database
           if the user does not exist, then redirect to the welcome page'''
        user = self.request.get('user')
        password = self.request.get('password')
        name = self.request.get('name')
        verify = self.request.get('verify')
        email = self.request.get('email')
        if name and val_user(user) and val_pw(password, verify) and val_email(email):
            users = Users.get_user(user)

            if users is None:
                u = Users(user = user, password = self.encrypt_pw(password),
                            name = name, email = email)
                u.put()
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % self.encrypt_cookie_val(str(u.key().id())))

                self.redirect('/welcome')
            else:
                self.render('signup.html')
        else:
            self.render('signup.html')

class MainPage(Helper):
    '''Front page, returns last 10 blog entries'''
    def get(self):
        key = 'front'
        refresh = False
        con = memcache.get(key)
        if con is None or refresh:
            logging.error('run query')
            con = db.GqlQuery('''
                    select * from Content
                    order by date desc
                    limit 10
                    ''')
            memcache.set(key, con)
        self.render('index.html', con=con, login=self.verify_userid() )

class NewPost(Helper):
    '''add a new blog post to the database, this page is gated'''
    def get(self):
        if self.verify_userid():
            self.render('newpost.html', login=True)
        else:
            self.redirect('/login')


    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.verify_userid() and subject and content:
            c = Content(subject = subject, content = content)
            c.put()
            self.redirect('/post/%s' % str(c.key().id()))
        else:
            self.render('newpost.html', subject=subject, content=content, error='error')

class Post(Helper):
    '''Post page, to view the page for a single blog post'''
    def get(self, post_id=0):
        mkey = 'post' + str(post_id)
        post = memcache.get(mkey)
        refresh = False
        if post is None or refresh:
            logging.error('running db query')
            key = db.Key.from_path('Content', int(post_id))
            post = db.get(key)
            if not post:
                self.error(404)
                return
        memcache.set(mkey, post)
        self.render('post.html', post=post, login=self.verify_userid())



app = webapp2.WSGIApplication([('/', MainPage),
                   ('/post/([0-9]+)', Post),
                   ('/newpost', NewPost),
                   ('/login', Login),
                   ('/logout', Logout),
                   ('/signup', Signup),
                   ('/welcome', Welcome)], debug=True)
