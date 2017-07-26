#!/usr/bin/env python3

from flask import Flask
from flask import render_template
from flask import redirect
from flask import jsonify
from flask import request
from flask import url_for
from flask import flash
from flask import make_response
from flask import session as login_session

from sqlalchemy import create_engine
from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker
from models import Base
from models import User
from models import City
from models import Stop
from models import Recommendation

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

import random
import string
import json
import requests
import httplib2
import bleach

app = Flask(__name__)

engine = create_engine('sqlite:///city_stop.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

GOOGLE_CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']


@app.route("/login")
def login():
    """ Returns a choice of login options """

    # The state is used to verify the user
    state = ''.join(random.choice(string.ascii_uppercase +
                                  string.digits) for i in range(32))
    login_session['state'] = state
    return render_template("login.html", state=state)


@app.route("/logout", methods=["POST"])
def log_out():
    """ Checks authentication provider and runs appropriate function """

    if 'username' not in login_session:
        return redirect('/login')
    if login_session["provider"] == "google":
        return gdisconnect()
    else:
        return fbdisconnect()

    return "Done"


@app.route("/gconnect", methods=["POST"])
def gconnect():
    """ Connects users through google """

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data

    try:

        oauth_flow = flow_from_clientsecrets('google_client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
                    json.dumps('Failed to upgrade authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads((h.request(url, 'GET')[1]).decode())
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
                    json.dumps(
                     "Token's client ID doesn't match given app's client ID."),
                    401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != GOOGLE_CLIENT_ID:
        response = make_response(
                    json.dumps(
                     "Token's user ID doesn't match given user ID."),
                    401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_gplus_id = login_session.get('gplus_id')

    if stored_gplus_id is not None and gplus_id == stored_gplus_id:
        response = make_response(
                    json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        login_session['gplus_id'] = gplus_id
        login_session["access_token"] = access_token
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += ' -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """ Disconnects google users """

    gplus_id = login_session.get('gplus_id')
    if gplus_id is None:

        response = make_response(
                    json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = login_session.get("access_token")
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("Successfully logged out")
        return redirect(url_for("home_page"))
    else:
        response = make_response(
                    json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route("/fbconnect", methods=["POST"])
def fbconnect():
    """ Connects users through facebook """

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Inavalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data
    access_token = access_token.decode()

    fb_client_secrets = json.loads(open("fb_client_secrets.json", "r").read())
    app_id = fb_client_secrets['web']['app_id']
    app_secret = fb_client_secrets['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s'  # noqa
           % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.decode().split('"')[3]

    url = (
     'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email'
     % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    result = result.decode()
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    url = ('https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200'  # noqa
        % token)
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += ' -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route("/fbdisconnect")
def fbdisconnect():
    """ Disconnects facebook users """

    provider = login_session["provider"]
    if provider != "facebook" or provider is None:
        output = ""
        output += "<script>function myFunction(){alert("
        output += "'You are not logged in with facebook.'"
        output += ");}</script><body onload='myFunction()'>"
        return output

    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['facebook_id']
    del login_session['user_id']
    flash("Successfully logged out")
    return redirect(url_for("home_page"))


@app.route("/")
def home_page():
    """ Renders the home page """

    cities = db_session.query(City).all()
    return render_template("home.html", cities=cities)


@app.route("/new_city", methods=["GET", "POST"])
def new_city():
    """ Let's authenticated users add a new city """

    # Screens for user who are not logged in
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_new_city"] = csrf_token
        return render_template("new_city.html", csrf_token=csrf_token)

    if request.method == "POST":
        if login_session["csrf_new_city"] != request.form["csrf-token"]:
            return "csrf error"
        newCity = City(name=bleach.clean(request.form["name"]),
                       user_id=login_session["user_id"])
        db_session.add(newCity)
        db_session.commit()
        flash("New city %s created" % newCity.name)
        return redirect(url_for('home_page'))


@app.route("/city/<city>", methods=["GET", "POST"])
def city(city):
    """ Renders the city page and responds to recommendations """

    city = db_session.query(City).filter_by(name=city).first()

    # Sorts the stops by recommendations
    stops = db_session.query(Stop).filter_by(
        city_id=city.id).order_by(desc(Stop.recommendations)).all()

    # Checks to see which stops have been recommended by the user already
    recommended_stops = []
    if "username" in login_session:
        recommendations = db_session.query(Recommendation).filter_by(
            user_id=login_session["user_id"]).all()
        for recommendation in recommendations:
            recommended_stops.append(recommendation.stop_id)

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_city"] = csrf_token
        return render_template("city.html",
                               city=city,
                               stops=stops,
                               r_stops=recommended_stops,
                               csrf_token=csrf_token)

    if request.method == "POST":

        # Screens for user who are not logged in
        if 'username' not in login_session:
            return redirect('/login')

        if login_session["csrf_city"] != request.form["csrf-token"]:
            return "csrf error"
        if "+1" in request.form.keys():
            stop = db_session.query(Stop).filter_by(
                id=request.form["stop"]).one()
            if db_session.query(Recommendation).filter_by(
                user_id=login_session["user_id"]).filter_by(
                    stop_id=stop.id).first() is not None:
                output = ""
                output += "<script>function myFunction(){alert("
                output += "'You have already recommended this stop.'"
                output += ");}</script><body onload='myFunction()'>"
                return output
            stop.recommendations += 1
            newRecommendation = Recommendation(
                user_id=login_session["user_id"],
                stop_id=stop.id)
            recommended_stops.append(stop.id)
            db_session.add(newRecommendation)
            db_session.commit()
        elif "-1" in request.form.keys():
            stop = db_session.query(Stop).filter_by(
                id=request.form["stop"]).one()
            priorRecommendation = db_session.query(Recommendation).filter_by(
                user_id=login_session["user_id"]).filter_by(
                    stop_id=stop.id).first()
            if priorRecommendation is None:
                output = ""
                output += "<script>function myFunction(){alert("
                output += "'You have not yet recommended this stop.'"
                output += ");}</script><body onload='myFunction()'>"
                return output
            stop.recommendations -= 1
            recommended_stops.remove(stop.id)
            db_session.delete(priorRecommendation)
            db_session.commit()
        csrf_token = csrf_token_generator()
        login_session["csrf_city"] = csrf_token
        return render_template("city.html",
                               city=city,
                               stops=stops,
                               r_stops=recommended_stops,
                               csrf_token=csrf_token)


@app.route("/<city>/new_stop", methods=["GET", "POST"])
def new_stop(city):
    """ Lets authenticated users create a new 'stop' """

    # Screens for user who are not logged in
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_new_stop"] = csrf_token
        return render_template("new_stop.html", csrf_token=csrf_token)

    if request.method == "POST":
        if login_session["csrf_new_stop"] != request.form["csrf-token"]:
            return "csrf error"
        city = db_session.query(City).filter_by(name=city).first()
        newStop = Stop(name=bleach.clean(request.form["name"]),
                       description=bleach.clean(request.form["description"]),
                       recommendations=0,
                       user_id=login_session["user_id"],
                       city_id=city.id)
        db_session.add(newStop)
        db_session.commit()
        flash("New stop %s created" % newStop.name)
        return redirect(url_for('city', city=city.name))


@app.route("/<city>/delete", methods=["GET", "POST"])
def delete_city(city):
    """ Lets authorised users delete a city """

    # Screens for user who are not logged in
    if "username" not in login_session:
        return redirect("/login")

    city = db_session.query(City).filter_by(name=city).one()

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_delete_city"] = csrf_token
        return render_template("delete.html",
                               to_delete=city.name,
                               data="city",
                               csrf_token=csrf_token)

    if request.method == "POST":
        if login_session["csrf_delete_city"] != request.form["csrf-token"]:
            return "csrf error"
        if login_session["user_id"] == city.user_id:
            stops = db_session.query(Stop).filter_by(
                city_id=city.id).all()

            # Deletes all associated stops
            for stop in stops:

                # Deletes all associated recommendations for each stop
                recommendations = db_session.query(Recommendation).filter_by(
                    stop_id=stop.id).all()
                for recommendation in recommendations:
                    db_session.delete(recommendation)

                db_session.delete(stop)
            db_session.delete(city)
            db_session.commit()
            flash("Successfully deleted %s" % city.name)
            return redirect(url_for('home_page'))
        else:
            output = ""
            output += "<script>function myFunction(){alert("
            output += "'You are not authorised to delete this city.'"
            output += ");}</script><body onload='myFunction()'>"
            return output


@app.route("/<city>/<stop>", methods=["GET", "POST"])
def stop(city, stop):
    """ Renders the stop page and responds to recommendations """

    city = db_session.query(City).filter_by(name=city).first()
    recommended_stops = []
    if "username" in login_session:
        recommendations = db_session.query(Recommendation).filter_by(
            user_id=login_session["user_id"]).all()
        for recommendation in recommendations:
            recommended_stops.append(recommendation.stop_id)
    stop = db_session.query(Stop).filter_by(
        name=stop).filter_by(city_id=city.id).first()

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_stop"] = csrf_token
        return render_template("stop.html",
                               city=city,
                               stop=stop,
                               r_stops=recommended_stops,
                               csrf_token=csrf_token)

    if request.method == "POST":
        if login_session["csrf_stop"] != request.form["csrf-token"]:
            return "csrf error"
        if 'username' not in login_session:
            return redirect('/login')
        if "+1" in request.form.keys():
            if db_session.query(Recommendation).filter_by(
                user_id=login_session["user_id"]).filter_by(
                    stop_id=stop.id).first() is not None:
                output = ""
                output += "<script>function myFunction(){alert("
                output += "'You have already recommended this stop.'"
                output += ");}</script><body onload='myFunction()'>"
                return output
            stop.recommendations += 1
            newRecommendation = Recommendation(
                user_id=login_session["user_id"], stop_id=stop.id)
            recommended_stops.append(stop.id)
            db_session.add(newRecommendation)
            db_session.commit()
        elif "-1" in request.form.keys():
            priorRecommendation = db_session.query(Recommendation).filter_by(
                user_id=login_session["user_id"]).filter_by(
                    stop_id=stop.id).first()
            if priorRecommendation is None:
                output = ""
                output += "<script>function myFunction(){alert("
                output += "'You have not yet recommended this stop.'"
                output += ");}</script><body onload='myFunction()'>"
                return output
            stop.recommendations -= 1
            recommended_stops.remove(stop.id)
            db_session.delete(priorRecommendation)
            db_session.commit()
        csrf_token = csrf_token_generator()
        login_session["csrf_stop"] = csrf_token
        return render_template("stop.html",
                               city=city,
                               stop=stop,
                               r_stops=recommended_stops,
                               csrf_token=csrf_token)


@app.route("/<city>/<stop>/edit", methods=["GET", "POST"])
def edit_stop(city, stop):
    """ Lets authorised users edit a stop """

    # Screens for user who are not logged in
    if "username" not in login_session:
        return redirect("/login")
    city = db_session.query(City).filter_by(name=city).first()
    stop = db_session.query(Stop).filter_by(
        name=stop).filter_by(city_id=city.id).first()

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_edit_stop"] = csrf_token
        return render_template("edit.html",
                               city=city,
                               stop=stop,
                               csrf_token=csrf_token)

    if request.method == "POST":
        if login_session["csrf_edit_stop"] != request.form["csrf-token"]:
            return "csrf error"
        if login_session["user_id"] == stop.user_id:
            if "name" in request.form.keys():
                stop.name = bleach.clean(request.form["name"])
            if "description" in request.form.keys():
                stop.description = bleach.clean(request.form["description"])
            db_session.commit()
            flash("Successfully edited %s" % stop.name)
            return redirect(url_for("stop", city=city.name, stop=stop.name))
        else:
            output = ""
            output += "<script>function myFunction(){alert("
            output += "'You are not authorised to edit this stop.'"
            output += ");}</script><body onload='myFunction()'>"
            return output


@app.route("/<city>/<stop>/delete", methods=["GET", "POST"])
def delete_stop(city, stop):
    """ Lets authorised users delete a stop """

    # Screens for user who are not logged in
    if "username" not in login_session:
        return redirect("/login")

    city = db_session.query(City).filter_by(name=city).first()
    stop = db_session.query(Stop).filter_by(
        name=stop).filter_by(city_id=city.id).first()

    if request.method == "GET":
        csrf_token = csrf_token_generator()
        login_session["csrf_delete_stop"] = csrf_token
        return render_template("delete.html",
                               to_delete=stop.name,
                               data="stop",
                               csrf_token=csrf_token)

    if request.method == "POST":
        if login_session["csrf_delete_stop"] != request.form["csrf-token"]:
            return "csrf error"
        if login_session["user_id"] == stop.user_id:

            # Deletes all associated recommendations
            recommendations = db_session.query(Recommendation).filter_by(
                stop_id=stop.id).all()
            for recommendation in recommendations:
                db_session.delete(recommendation)

            db_session.delete(stop)
            db_session.commit()
            flash("Successfully deleted %s" % stop.name)
            return redirect(url_for("city", city=city.name))
        else:
            output = ""
            output += "<script>function myFunction(){alert("
            output += "'You are not authorised to delete this stop.'"
            output += ");}</script><body onload='myFunction()'>"
            return output


@app.route("/api/v1/")
def api_home():
    """ Returns json containing version of the home page """

    cities = db_session.query(City).all()
    return jsonify(Cities=[i.serialize for i in cities]), 200


@app.route("/api/v1/city/<string:city>")
def api_city(city):
    """ Returns json containing version of the city page """

    city = db_session.query(City).filter_by(name=city).first()
    stops = db_session.query(Stop).filter_by(
        city_id=city.id).order_by(desc(Stop.recommendations)).all()

    return jsonify(Stops=[i.serialize for i in stops]), 200


@app.route("/api/v1/<string:city>/<string:stop>")
def api_stop(city, stop):
    """ Returns json containing version of the stop page """

    stop = db_session.query(Stop).filter_by(name=stop).first()

    return jsonify(Stop=[stop.serialize]), 200


def getUserID(email):
    """ Uses email to find a user's id """

    try:
        user = db_session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def createUser(login_session):
    """ Creates a new user including picture """

    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    db_session.add(newUser)
    db_session.commit()
    user = db_session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def csrf_token_generator():
    """ Generates a token used to prevent cross site request forgery """

    return ''.join(random.choice(string.ascii_uppercase +
                                 string.digits) for i in range(32))


if __name__ == "__main__":
    app.secret_key = "super_secret_key"  # Temporary key
    app.debug = True
    app.run(host="0.0.0.0", port=5000)
