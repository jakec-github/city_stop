from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response, session as login_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, City, Stop, Recommendation

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

import random, string, json, requests, httplib2





app = Flask(__name__)

engine = create_engine('sqlite:///city_stop.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
db_session = DBSession()

GOOGLE_CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']

@app.route("/login")
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(32))
    login_session['state'] = state
    return render_template("login.html", state = state)

@app.route("/gconnect", methods=["POST"])
def gconnect():
    print("Login attempted")
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:

        oauth_flow = flow_from_clientsecrets('google_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
        print(credentials)

    except FlowExchangeError :
        response = make_response(json.dumps('Failed to upgrade authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        print("Fail 1")
        return response

    access_token = credentials.access_token
    print(access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads((h.request(url, 'GET')[1]).decode())
    if result.get('error') is not None:
        print("fails 500")
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    gplus_id = credentials.id_token['sub']
    print("gplus_id %s" % gplus_id)
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's client ID doesn't match given app's client ID."), 401)
        print("Token's client ID doesn't match given app's client ID.")
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != GOOGLE_CLIENT_ID:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_gplus_id = login_session.get('gplus_id')

    if stored_gplus_id is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['gplus_id'] = gplus_id
    login_session["access_token"] = access_token

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = json.loads(answer.text)

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

@app.route('/gdisconnect')
def gdisconnect():
    gplus_id = login_session.get('gplus_id')
    print(login_session)
    if gplus_id is None:

        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = login_session["access_token"]
    print("access_token is " + access_token)
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print(result)

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        print("Status not OK")
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        print("Response created")
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route("/fbconnect", methods=["POST"])
def fbconnect():
    print("Connecting with fb")
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Inavalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        print("State is " + request.args.get('state'))
        return response

    access_token = request.data
    access_token = access_token.decode()
    print("Access token is %s" % access_token)


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    print("app_id is " + app_id)
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    print("app_secret is " + app_secret)
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("result is %s" % result)
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.decode().split('"')[3]
    print("Token is " + token)

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    result = result.decode()
    print("result now is " + result)
    data = json.loads(result)
    print('-------')
    print("data is " + str(data))
    print(data['name'])
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result.decode())

    login_session['picture'] = data['data']['url']

    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

@app.route("/fbdisconnect")
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    print(result.decode())
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['facebook_id']
    del login_session['user_id']
    return "you have been logged out"

@app.route("/")
def home_page():

    return render_template("home.html")

def getUserID(email):
    try:
        user = db_session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None

def createUser(login_session):
    print("Creating new user")
    newUser = User(name = login_session['username'],
                   email = login_session['email'],
                   picture = login_session['picture'])
    db_session.add(newUser)
    db_session.commit()
    user = db_session.query(User).filter_by(email = login_session['email']).one()
    return user.id

if __name__ == "__main__":
    app.secret_key = "super_secret_key"
    app.debug = True;
    app.run(host = "0.0.0.0", port = 5000)
