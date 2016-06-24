# Author: Jonathan D. Peterson 
# Last Modified: 6/20/2016
# 
# Project: Muli-User Database
# 
#imports
import os
import re
import auth

import webapp2
import jinja2

from google.appengine.ext import ndb

# global variables
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Construcor Variables
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


# Helper methods sectopm
def valid_username(username):
    """
    Compare the username to the Regex for a valid username
    """
    return username and USER_RE.match(username)



def valid_password(password):
    """
    Compare the password to the Regex for a valid password    
    """
    return password and PASS_RE.match(password)


def valid_email(email):
    """
    Compare the email to the Regex for a valid email
    """
    return not email or EMAIL_RE.match(email)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)



def render_str(template, **params):
    t = jinja_env.get_template(template)
    self.response.write(template.render(template_values))


# Features to be implemented in future versions
def blog_key(name='default'):
    return ndb.Key.from_path('blogs', name)


def users_key(group='default'):
    return ndb.Key.from_path('users', group)


# Database section
class User(ndb.Model):
    """
    This is the database which store information about the users.
    :name = The username
    :pw_hash = The password hash created by the make_pw_hash method in the
               auth.py module.
    :email = The email of the user (This is optional at this point)
    """
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """
        Used to look up information in the User database by
        looking up the id, and then referencing it to other fields.
        :Returns the id of the user
        """
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """
        Used to look up information in the User database by the user's
        name.
        :Returns the name of the user
        """
        u = User.query().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """
        This will set up an account based on valid infomation that is entered.
        """
        pw_hash = auth.make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        """
        This is the method which is used for testing out if the information
        that is used to attempt to login is correct.
        """
        u = cls.by_name(name)
        if u and auth.valid_pw(name, pw, u.pw_hash):
            return u


class Post(ndb.Model):
    """
    The infromation that will be used in the Post database.
    :author = The user who created the post
    :subject = The title of the post
    :content = The body of the post
    :created = Date/Time stamp when the message is first created.
    :last_modified = The date/time stamp the message was last modified.
    :likes = the number of likes on the post
    :liked_by = The users who liked the post. Also used to help with error
                checking to prevent a user of multiple liking, or liking
                their own post
    """
    author = ndb.StringProperty()
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    likes = ndb.IntegerProperty(default=0)
    liked_by = ndb.StringProperty()

    def render(self):
        """
        Renders any newline and converts it to html break return
        """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @classmethod
    def by_post_name(cls, name):
        """
        Enable searching for the post by the name
        """
        u = cls.query().filter(cls.name == name)
        return u

    @property
    def comments(self):
        """
        Post property used to attach comments, and enable the counting
        of the comments.
        """
        return Comment.query().filter("post = ", str(self.key().id()))


class Comment(ndb.Model):
    """
    This is the database which will hold the individual comments for the posts
    :comment = The comment that was made
    :post = the Post id that is commented.
    """
    comment = ndb.StringProperty(required=True)
    post = ndb.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("comment.html")


# Handler Section
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = auth.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and auth.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.query().order(-Post.created)
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(),
                     author=User.by_name(self.user.name).name,
                     subject=subject,
                     content=content)
            p.put()
            self.redirect('/blog/{}'.format(str(p.key().id())))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        author=User.by_name(self.user.namme),
                        subject=subject, content=content, error=error)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        """
        Will prevent a duplicate name for the user.
        """
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        """
        Will check the inputed information by authentication vs the data
        in the User database
        """
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid username and/or password'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class LikePost(BlogHandler):
    def get(self, post_id):
        """
        Check to see if a user is logging in, if so allow the to like a
        post only once by using error checking. Also will prevent the
        author from liking their own post. Each like will increase the
        value of likes in the Post database.
        """
        if not self.user:
            self.redirect('/login')
        else:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            author = post.author
            current_user = self.user.name

            if author == current_user or current_user in post.liked_by:
                self.redirect('/likeError')
            else:
                post.likes = post.likes + 1
                post.liked_by.append(current_user)
                post.put()
                self.redirect('/blog')


# Modifying Post Handlers
class DeletePost(BlogHandler):
    """
    If the user is not logged in, send to login paged. Only allows the
    user who created the post to delete it.
    :post_id = The id of the post that is being delted.
    """
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = ndb.Key('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = key.get()
            n1 = post.author
            n2 = self.user.name

            if n1 == n2:
                key = ndb.Key('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = key.get()
                post.delete()
                self.render("deletepost.html")
            else:
                self.redirect("/deleteError")


class UpdatePost(BlogHandler):
    def get(self, post_id):
        """
        If the user is not logged in, send to login paged. Only allows the
        user who created the psot to modify it.
        :post_id = The id of the post that is being modified.
        """
        if not self.user:
            self.redirect('/login')
        else:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            # compare the value of the author vs the logged 
            if post.author == self.user.name:
                key = ndb.Key('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = key.get()
                print "post = ", post
                error = ""
                self.render("editpost.html", subject=post.subject,
                            content=post.content, error=error)
            else:
                self.redirect("/editDeleteError")

    def post(self, post_id):
        """
        Updated the infomation on the post that was imputed in the form.
        :post_id = the id of the post the is being modified
        """
        if not self.user:
            self.redirect("/login")
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            p = key.get()
            p.subject = self.request.get('subject')
            p.content = self.request.get('content')
            p.put()
            self.redirect('/blog/')


# Comment Handlers
class NewComment(BlogHandler):
    def get(self, post_id):
        """
        Only will allow logged in users to be able to comment
        """
        if not self.user:
            error = "You must be logged in to comment"
            self.redirect("/login")
            return
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        self.render("newcomment.html",
                    subject=subject,
                    content=content,
                    pkey=post.key())

    def post(self, post_id):
        """
        Will check to see if the proper information was imputed when
        attempting to create a post.
        """
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect('login')
        comment = self.request.get('comment')
        if comment:
            c = Comment(comment=comment,
                        post=post_id,
                        parent=self.user.key())
            c.put()
            self.redirect('/blog/{}'.format(str(post_id)))
        else:
            error = "please provide a comment!"
            self.render("permalink.html",
                        post=post,
                        content=post.content,
                        error=error)


class UpdateComment(BlogHandler):
    def get(self, post_id, comment_id):
        """
        Enable the modification of a comment based on the comment_id and 
        post_id.
        :post_id = The id of the post that the comment is attached to
        :comment_id = The id of the comment
        """
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            self.render("updatecomment.html",
                        subject=post.subject,
                        content=post.content,
                        comment=comment.comment)

    def post(self, post_id, comment_id):
        """
        Checks to see if the user_id who created it is the same as the
        comment_id. If so, allow them to edit the file. If not send them
        to the error page.
        :post_id = The id of the post that the comment is attached to
        :comment_id = The id of the comment
        """
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        else:
            self.redirect('/commenterror')
            
        self.redirect('/blog/{}'.format(str(post_id)))
        


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        """
        Enable the deletion of a comment based on the comment_id and post_id
        :post_id = The id of the post that the comment is attached to
        :comment_id = The id of the comment
        """
        post = Post.get_by_id(int(post_id), parent=blog_key())
        # this ensures the user created the comment
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment:
            comment.delete()
            self.redirect('/blog/{}'.format(str(post_id)))
        else:
            self.redirect('/commenterror')

# Error Handlers (not really needed but in the code written to
# create a fallback.
class CommentError(BlogHandler):
    def get(self):
        self.write('You can only edit or delete comments you have created.')
        
class LikeError(BlogHandler):
    def get(self):
        self.write("You can't like your own post & can only like a post once.")


class EditDeleteError(BlogHandler):
    def get(self):
        self.write('You can only edit or delete posts you have created.')
        

app = webapp2.WSGIApplication(
            [('/', MainPage),
             ('/blog/?', BlogFront),
             ('/blog/([0-9]+)', PostPage),
             ('/blog/newpost', NewPost),
             ('/signup', Register),
             ('/blog/([0-9]+)/like', LikePost),
             ('/likeError', LikeError),
             ('/blog/([0-9]+)/updatepost', UpdatePost),
             ('/blog/([0-9]+)/deletepost', DeletePost),
             ('/editDeleteError', EditDeleteError),
             ('/blog/([0-9]+)/newcomment', NewComment),
             ('/blog/([0-9]+)/updatecomment/([0-9]+)', UpdateComment),
             ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
             ('/commenterror', CommentError),
             ('/login', Login),
             ('/logout', Logout),
             ],
            debug=True)
