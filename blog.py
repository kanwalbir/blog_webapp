#-----------------------------------------------------------------------------#
#                            PACKAGE AND MODULE IMPORTS                       #
#-----------------------------------------------------------------------------#

"""
Time module imports.
"""
import time
from datetime import datetime, timedelta

"""
Hashing imports.
"""
import hashlib
import hmac
from hmac_key import HMAC_KEY

"""
Google AppEngine imports.
"""
import webapp2
from google.appengine.ext import db
from google.appengine.api import memcache
import logging

"""
Template Engine imports
"""
import jinja2
import os

"""
JSON and XML imports
"""
import json
from xml.dom import minidom

"""
Other Python file imports.
"""
from validations import valid_username, valid_password, valid_email
from hashing import make_salt, make_hash, valid_hash

#-----------------------------------------------------------------------------#
#                            JINJA2 TEMPLATE                                  #
#-----------------------------------------------------------------------------#
"""
All templates are stored in '/templates' folder. Autoescaping is turned on.
"""
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), 
                                       autoescape=True)

#-----------------------------------------------------------------------------#
#                            DATABASE TABLES                                  #
#-----------------------------------------------------------------------------#

"""
Database table for all blog entries. Stores the following information about 
each blog entry:
- Title of the blog
- Content of the blog
- Author of the blog
- Date blog was created
- Date blog was last modified
"""
class DB_BlogEntries(db.Model):
    blog_title = db.StringProperty(required = True)
    blog_content = db.TextProperty(required=True)
    blog_author = db.StringProperty(required = True)
    creation_date = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

#-----------------------------------------------------------------------------#

"""
Database table for blog users. Stores the following information about each 
user:
- Username
- Hash of the password
- User's Email address (optional)
- Date account was created
"""
class DB_Users(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    creation_date = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_username(cls, name):
        u = db.GqlQuery("SELECT * FROM DB_Users WHERE username=:1", str(name))
        return u.get()

#-----------------------------------------------------------------------------#
#                            MEMCACHE FUNCTIONS                               #
#-----------------------------------------------------------------------------#

"""
Manages the cache for the entire blog. If the blog is not cached, then it 
searches the database, adds the blog into the cache and returns the 
results.
"""
BLOG_KEY = 'entire_blog'
def top_entries(update=False):
    key = BLOG_KEY
    entries = memcache.get(key)

    if entries is None or update:
        q = "SELECT * FROM DB_BlogEntries ORDER BY creation_date DESC limit 20"
        entries = db.GqlQuery(q)
        entries = list(entries)
        memcache.set(key, (entries, time.time()))
        return entries
    else:
        return entries[0]

#-----------------------------------------------------------------------------#

"""
Manages the cache for a specific blog entry. If the blog entry is not cached, 
then it searches the database, adds the blog entry into the cache and returns 
the result.
"""
def each_entry(entry_id):
    key = entry_id
    entry = memcache.get(key)
    if entry is None:
        entry = DB_BlogEntries.get_by_id(int(entry_id))
        if entry:
            memcache.set(key, (entry, time.time()))
            return entry
        else:
            return None
    return entry[0]

#-----------------------------------------------------------------------------#
#                            JSON FUNCTIONS                                   #
#-----------------------------------------------------------------------------#
"""
Receives a blog entry and creates a dictionary output of it for JSON 
rendering.
"""
def json_blog(entry):
        t = "%c"
        out = {"title": entry.blog_title, 
               "content": entry.blog_content, 
               "author": entry.blog_author, 
               "created": entry.creation_date.strftime(t), 
               "last_modified": entry.last_modified.strftime(t)}
        return out

#-----------------------------------------------------------------------------#
#                            BASE HANDLER                                     #
#-----------------------------------------------------------------------------#

"""
The base handler inherits the main HTTP request handler. It contains some 
handy functions and is inherited by all other classes in this file.
- Renders the template
- Renders the 404 error
- Renders the JSON page
- Keeps track of the referal page
- Sets the userid in the cookie at login using a hashing function
- Clears the userid cookie
- Reads the userid cookie and verifies that it is valid. If valid, then returns 
  the user information from DB_Users table.
"""
class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **params):
        t = jinja_environment.get_template(template)
        params['user'] = self.check_userid_cookie()
        self.response.out.write(t.render(params))

    def error404(self):
        msg1 = '<h1>404: Not Found</h1>'
        msg2 = 'Oops, something went wrong there. Go back <a href="/blog"> home</a>'
        self.response.out.write(msg1+msg2)

    def render_json(self, args):
        self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
        self.response.out.write(json.dumps(args))

    def find_next_url(self):
        next_url = str(self.request.get('next_url'))
        
        l = next_url.find('/blog/login')
        s = next_url.find('/blog/signup')
        k = next_url.find('/blog')

        if k == -1 or l != -1 or s != -1:
            next_url = '/blog'
        else:
            next_url = next_url[k:]
        return next_url

    def login(self, user):
        x = str(user.key().id())
        hash_x = hmac.new(HMAC_KEY, x).hexdigest()
        self.response.headers.add_header('Set-Cookie', 
                                         'user_id=%s|%s; Path=/' %(x, hash_x))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def check_userid_cookie(self):
        val = self.request.cookies.get('user_id')
        if val:
            uid, hash_uid = val.split('|')
            if hash_uid == hmac.new(HMAC_KEY, uid).hexdigest():
                return DB_Users.get_by_id(int(uid))

#-----------------------------------------------------------------------------#
#                            BLOG ENTRY HANDLERS                              #
#-----------------------------------------------------------------------------#

"""
Renders the home page of the blog from the cache. Loads only 20 most recent 
entries. Creates the JSON output, if the url ends with '.json', otherwise 
defaults to html format.
"""
class Blog(BaseHandler):
    def get(self):
        entries = top_entries()

        if self.request.url.endswith('.json'):
            out = []
            for entry in entries:
                out.append(json_blog(entry))
            self.render_json(out)
        
        else:
            t = int(time.time() - memcache.get(BLOG_KEY)[1])/60
            self.render("blog.html", entries=entries, t=t)

#-----------------------------------------------------------------------------#

"""
Enforces user login before loading the page, otherwise redirects to login 
page. Checks if both blog subject and content are valid. If not valid, then 
prompts the user with an error message. If valid, then creates/updates the blog 
entry in the database, flushes the cache and redirects to the permalink page 
for that entry.
"""
class NewPost(BaseHandler):
    def get(self, entry_id= ""):
        if self.check_userid_cookie():
            if entry_id:
                e = DB_BlogEntries.get_by_id(int(entry_id))
                if e:
                    self.render("newpost.html", page_title="Edit", 
                                subject=e.blog_title, content=e.blog_content)
                else:
                    self.error404()
                    return
            else:
                self.render("newpost.html", page_title="Create New")
        else:
            self.logout()
            self.redirect('/blog/login')

    def post(self, entry_id=""):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            author = self.check_userid_cookie().username
            
            if not entry_id:
                e = DB_BlogEntries(blog_title=subject, blog_content=content, blog_author=author) 
                e.put()
                x = str(e.key().id())
            else:
                e = DB_BlogEntries.get_by_id(int(entry_id))
                e.blog_title = subject
                e.blog_content = content
                e.blog_author = author
                e.put()
                x = str(entry_id)
                memcache.delete(x)

            memcache.delete(BLOG_KEY)
            self.redirect("/blog/%s" %x)

        else:
            error = "We need both subject and some content."
            self.render("newpost.html", subject=subject, content=content, error=error)

#-----------------------------------------------------------------------------#

"""
Renders the individual blog entry page from the cache. Creates the JSON 
output, if the url ends with '.json', otherwise defaults to html format.
"""
class PermaLink(BaseHandler):
    def get(self, entry_id):
        entry = each_entry(entry_id)
        if not entry:
            self.error404()
            return
        
        if self.request.url.endswith('.json'):
            out = json_blog(entry)
            self.render_json(out)
        else:
            t = int(time.time() - memcache.get(entry_id)[1])/60
            self.render("permalink.html", entry=entry, t=t)

#-----------------------------------------------------------------------------#

"""
Clears the cache and redirects to blog home page
"""
class FlushCache(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/blog")

#-----------------------------------------------------------------------------#
#                            LOGIN/LOGOUT/SIGNUP HANDLERS                     #
#-----------------------------------------------------------------------------#

"""
Checks if the username, password, email are valid. If any parameter is, 
invalid then prompts the user with an error message. If all is valid then, 
makes the password hash and stores all the fields in the DB_Users databse. 
Lastly, set a cookie based on the userid and redirects to the referal page.
"""
class Signup(BaseHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/blog')
        self.render("signup.html", next_url=next_url)

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username, email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        elif not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        elif not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        else:
            user_exists = DB_Users.by_username(username)
            if user_exists:
                params['error_username'] = "The user already exists."
                have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            h_password = make_hash(password)
            u = DB_Users(username=username, password_hash=h_password, email=email)
            u.put()
            self.login(u)
            next_url = self.find_next_url()
            self.redirect(next_url)

#-----------------------------------------------------------------------------#

"""
Checks if the username and password are valid and match the entry in the 
databse. If invalid, then prompts the user with an error message. If valid 
then, set a cookie based on the userid and redirects to the referal page.
"""
class Login(BaseHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/blog')
        self.render("login.html", next_url=next_url)

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')

        params = dict(username = username)

        if not username:
            params['error_username'] = "Please enter a valid username."
            have_error = True
        elif not password:
            params['error_password'] = "Please enter a valid password."
            have_error = True
        else:
            user_exists = DB_Users.by_username(username)
            if not user_exists:
                params['error_username'] = "This username does not exist."
                have_error = True
            else:
                if not valid_hash(password, user_exists.password_hash):
                    params['error_password'] = "Thats not a valid password."
                    have_error = True

        if have_error:
            self.render('login.html', **params)
        else:
            self.login(user_exists)
            next_url = self.find_next_url()
            self.redirect(next_url)

#-----------------------------------------------------------------------------#

"""
Clears the cookie and redirects to the referal page.
"""
class Logout(BaseHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/blog')
        self.logout()
        self.redirect(next_url)

#-----------------------------------------------------------------------------#
#                            ROUTING TABLE                                    #
#-----------------------------------------------------------------------------#

"""
Any url not found on the blog, redirects to blog home page.
"""
app = webapp2.WSGIApplication([('/blog/?', Blog), 
                               ('/blog/.json', Blog), 
                               ('/blog/([0-9]+)/?', PermaLink),
                               ('/blog/([0-9]+)/.json', PermaLink),
                               ('/blog/newpost/?', NewPost), 
                               ('/blog/_edit/([0-9]+)/?', NewPost),  
                               ('/blog/flush/?', FlushCache),
                               ('/blog/signup/?', Signup),
                               ('/blog/login/?', Login),
                               ('/blog/logout/?', Logout), 
                               ('/blog/.*', Blog)], 
                               debug=True)

#-----------------------------------------------------------------------------#