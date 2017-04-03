import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# The global function below is for rendering a string.
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# The functions below are for validating password hashing

secret = 'randomosity'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val



class MainHandler(webapp2.RequestHandler):
    """main class that handles rendering, writing and cookies in all the classes
    that inherit from it."""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# The functions below are for hashing and salting to secure passwords.

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """This class designates the database specifics for a user object."""
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """This class designates the database specifics for a post object."""
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty(required = True)
    liked_by = db.ListProperty(str)

    @property
    def likes(self):
        return len(self.liked_by)

    def render(self):
        self.render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

class PostPage(MainHandler):
    """Class that renders the page for a specifc blog post."""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)

        
        comments = Comment.all()

        self.render("permalink.html", post = post, comments = comments) 


class NewPost(MainHandler):
    """Class that renders the form for writing a new blog post."""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content,
                     author = author)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

class EditPost(MainHandler):
    """Class that renders the form to edit an existing blog post."""
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.author == self.user.name:
                self.render("edit.html", subject=post.subject,
                            content=post.content,
                            post_id=post_id)
            else:
                self.redirect('/login')

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

        if post.author == self.user.name:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                error = "subject and content, please!"
                self.render("edit.html", subject=subject, content=content,
                        error=error)

        else:
                self.redirect('/login')

class DeletePost(MainHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post.author == self.user.name:
            post.delete()
            time.sleep(0.1)
            self.redirect('/')

        else:
            self.redirect('/login')

class LikePost(MainHandler):
    """Class that handles adding/removing likes for a post and tracking the
    number of likes it has."""
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user.name != post.author:
            if self.user.name in post.liked_by:
                post.liked_by.remove(self.user.name)
                post.put()
                time.sleep(0.1)
                self.redirect('/')

            else:
                post.liked_by.append(self.user.name)
                post.put()
                time.sleep(0.1)
                self.redirect('/')

        else:
            self.redirect('/?error=You cannot like your own posts!')

class Comment(db.Model):
    """This class designates the database specifics for a comment object."""
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty(required = True)
    post_id = db.IntegerProperty()

    def render(self):
        self.render_text = self.content.replace('\n', '<br>')
        return render_str('comment.html', c = self)

class NewComment(MainHandler):
    """This class renders the form for entering a new post comment."""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        
        if not self.user:
            return self.redirect('/')

        content = self.request.get('content')
        author = self.user.name
        post_id = int(post.key().id())

        if content:
            c = Comment(parent = blog_key(), content = content, author = author,
                        post_id = post_id)
            c.put()
            time.sleep(0.1)
            self.redirect('/%s' % post_id)
        else:
            error = " enter your comment, please!"
            self.render("newcomment.html", content=content, error=error)

class EditComment(MainHandler):
    """Class renders the form for editing an existing post comment."""
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            
            self.render("editcomment.html", c=c, content=c.content)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            c = db.get(key)

        if c.author == self.user.name:
            content = self.request.get('content')
            c.post_id = int(comment_id)
    
            if  content:
                c.content = content
                c.put()
                self.redirect('/%s' % str(c.post_id))
            else:
                error = "enter your comment, please!"
                self.render("editcomment.html", content=content,
                            error=error)
        else:
            self.redirect('/login')

class DeleteComment(MainHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        c = db.get(key)
        if c.author == self.user.name:
            c.delete()
            time.sleep(0.1)
            self.redirect('/%s' % str(c.post_id))

        else:
            self.redirect('/login')

class BlogHome(MainHandler):
    """This class renders the main blog page."""
    def render_blog(self):
        posts = db.GqlQuery('select * from Post order by created desc limit 10')
        comments = db.GqlQuery('select * from Comment order by created desc')
        self.render('home.html', posts = posts, comments=comments)

    def get(self):
        self.render_blog()

#The functions below define and verify valid usernames, passwords and emails.

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return email and EMAIL_RE.match(email)


class Signup(MainHandler):
    """Class handles the creation of a new user."""
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    """Class confirms that a user doe not already exist and welcomes the new
    user."""
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Welcome(MainHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Login(MainHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/')



app = webapp2.WSGIApplication([('/', BlogHome),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/welcome', Welcome),
                               ('/([0-9]+)', PostPage),
                               ('/edit/([0-9]+)', EditPost),
                               ('/deleted/([0-9]+)', DeletePost),
                               ('/liked/([0-9]+)', LikePost),
                               ('/newcomment/([0-9]+)', NewComment),
                               ('/editcomment/([0-9]+)', EditComment),
                               ('/deletedcomment/([0-9]+)', DeleteComment)
                               ], debug=True)
