import comment_db
import blog

from google.appengine.ext import db

class Post(db.Model):
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
    author = db.StringProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)
    liked_by = db.ListProperty(str)

    def render(self):
        """
        Renders any newline and converts it to html break return
        """
        self._render_text = self.content.replace('\n', '<br>')
        return blog.render_str("post.html", p=self)

    @classmethod
    def by_post_name(cls, name):
        """
        Enable searching for the post by the name
        """
        u = cls.all().filter('name =', name).get()
        return u

    @property
    def comments(self):
        """
        Post property used to attach comments, and enable the counting
        of the comments.
        """
        return comment_db.Comment.all().filter("post = ", str(self.key().id()))

