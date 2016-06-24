import blog
from google.appengine.ext import db

class Comment(db.Model):
    """
    This is the database which will hold the individual comments for the posts
    :comment = The comment that was made
    :post = the Post id that is commented.
    """
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)

    @classmethod
    def render(self):
        self.render("comment.html")
