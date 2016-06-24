# Author: Jonathan D. Peterson 
# Last Modified: 6/22/2016
# 
# Project: Multi-User Database
# 
#imports
import os
import re
import auth

import webapp2
import jinja2

# Database Modules
import user_db
import post_db
import comment_db

from google.appengine.ext import db

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
    return t.render(params)


# Features to be implemented in future versions
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    return db.Key.from_path('users', group)


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
        self.user = uid and user_db.User.by_id(int(uid))


class MainPage(BlogHandler):
    def get(self):
         self.redirect('/blog')


class BlogFront(BlogHandler):
    def get(self):
        posts = post_db.Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

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
            p = post_db.Post(parent=blog_key(),
                          author=user_db.User.by_name(self.user.name).name,
                          subject=subject,
                          content=content)
            p.put()
            self.redirect('/blog/{}'.format(str(p.key().id())))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        author=user_db.User.by_name(self.user.namme),
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
        u = user_db.User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = user_db.User.register(self.username, self.password, self.email)
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

        u = user_db.User.login(username, password)
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
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
            key = db.Key.from_path('Post',
                                   int(post_id),
                                   parent=blog_key())
            post = db.get(key)
            n1 = post.author
            n2 = self.user.name

            if n1 == n2:
                key = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = db.get(key)
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # compare the value of the author vs the logged 
            if post.author == self.user.name:
                key = db.Key.from_path('Post',
                                       int(post_id),
                                       parent=blog_key())
                post = db.get(key)
                print "post = ", post
                error = ""
                self.render("editPost.html", subject=post.subject,
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
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)
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
        post = post_db.Post.get_by_id(int(post_id), parent=blog_key())
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
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect('login')
        comment = self.request.get('comment')
        if comment:
            c = comment_db.Comment(comment=comment,
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
        post = post_db.Post.get_by_id(int(post_id), parent=blog_key())
        comment = comment_db.Comment.get_by_id(int(comment_id),
                                               parent=self.user.key())
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
        comment = comment_db.Comment.get_by_id(int(comment_id),
                                               parent=self.user.key())
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
        post = post_db.Post.get_by_id(int(post_id), parent=blog_key())
        comment = comment_db.Comment.get_by_id(int(comment_id),
                                               parent=self.user.key())
        if comment:
            comment.delete()
            self.redirect('/blog/{}'.format(str(post_id)))
        else:
            self.redirect('/commenterror')

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
