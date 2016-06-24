# Multi-User Project
---
The pupose of this project is to create a framework and understanding of how to create at blog, similar to the ones that are on the internet. This project is an exetension of the material that was taught in the class.
To View this app [Click Here] (http://maze-1335.appspot.com/blog)
## Getting Started
---
1. Install [Python 2.7] (http://www.python.org/)
2. Install the latest [Google App Engine SDK] (https://cloud.google.com/appengine/downloads)  and download the Python version, and the correct one for your OS system.
3. Checkout repository (available after meeting specifications)
```
git clone https://github.com/jpdesigns316/muli-user-blog.git
```

Either run the Google App Engine GUI, which will help you know the port that you can use on your localhost. (default: port 8080) or you can run the commandline:
```
dev_appserver.py --port=#### <app_name> 
```
With --port you can define what port you want to run on.

app_name = The name for the app the you chose

### Explanation of important files
---
**Blog.py**
This is the main blog file which holds the methods that help the blog run.

**auth.py**
This is the module used to help authenticated the user data. It has some infromation that should not be in the main blog file, and has been moved to it's own for added security.

**comment.py**
Holds the information for the Comment database.

**post.py**
Holds the information for the Post database.

**user.py**
Holds the information for the User database.

### Directory Stucture
---
| Directory | Description |
|-----------|-------------|
| / | This is the directory which hold the information to run the blog |
| /templates |  Hold the templates that the blog.py uses to make the web pages. |
| /static | The static files with directories to help design the web pages |
| /static/css | The CSS files helped used to format the web pages |
| /static/js | The javascript files, if any, which are used. |
| /static/img | Any images that are used onsite |
| /static/fonts | Any fonts, if any, that are needed. |

### Features
---
- **Created self-error checking** - This refers to checking to make sure only a user can modify his own posts, and not others.
- **User Authenication** - For a bit added security, the data, and methods referring to authenticating a user is in a separate file.
- **Design Elements** - Created a flowing design and logo to help the blog pop. By using the color of the Udacity logo, and some complentary colors, I was able to create a nice color palatte for the blog.
- **Navigation** - Created a navigation bar based on code I previously had designed. This allows the user to navigate through the blog.

### Customize with Bootstrap
---
The portfolio was built on Twitter's [Bootstrap] (http://www.getbootstrap.com) framework. All custom styles are in /static/css in the portfolio repo.

[Bootstrap's CSS Classes] (http://www.getbootstrap.com/css/)
