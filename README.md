#-----------------------------------------------------------------------------#
#                            A Webapp2 Blog                                   #
#-----------------------------------------------------------------------------#

PROBLEM: Build a web application using webapp2 framework which performs all the basic blog functions.

Blog should have following features: 

1. User account management
   - New user registration with password hashing (SHA-256)
   - Login and logout with hashed cookies (HMAC)

2. Blog management
   - Home page that lists all existing blog entries
   - New blog entry submission page (user login required)
   - View any existing blog entry at its permalink page
   - Edit a blog entry (user login required)

3. Caching enabled via Memcache
   - Main blog page
   - All permalink pages
   - Flush cache

4. Blog output in JSON for every blog entry

5. All data stored on Google AppEngine Datastore
6. Web templates implemented using Jinja2 environment
7. Blog hosted on Google AppEngine


Above features can be navigated via following links:

Home:                  /blog
Create New Entry:      /blog/newpost
Permalink Page:        /blog/(d)        (where d is blog id number)
Edit Blog Entry:       /blog/_edit/(d)  (where d is blog id number)
New User Signup:       /blog/signup
User Login:            /blog/login
User Logout:           /blog/logout
JSON Output Home:      /blog/.json
JSON Output Permalink: /blog/(d)/.json  (where d is blog id number)
Flush Memcache:        /blog/flush


IMPLEMENTATION: blog.py

PRODUCTION: http://kanwalbir.appspot.com/blog
#-----------------------------------------------------------------------------#





