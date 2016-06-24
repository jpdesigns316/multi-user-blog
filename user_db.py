import auth
import blog

from google.appengine.ext import db


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """
    This is the database which store information about the users.
    :name = The username
    :pw_hash = The password hash created by the make_pw_hash method in the
               auth.py module.
    :email = The email of the user (This is optional at this point)
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

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
        u = User.all().filter('name =', name).get()
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