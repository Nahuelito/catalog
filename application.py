import random
import string
import httplib2
import json
import requests

from flask import Flask
from flask import render_template, flash
from flask import request, redirect, url_for
from flask import jsonify
from flask import session as login_session
from flask import make_response

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from database_setup import Base
from database_setup import Category, Item, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Item Catalog Application'

app = Flask(__name__)

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/catalog.json')
def catalogJSON():
    items = session.query(Item).all()
    return jsonify(Item=[i.serialize for i in items])


@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(Category.name).all()
    latestItems = session.query(Item).order_by(Item.id).limit(9)

    # This page shows the categories and latest items
    if 'email' in login_session and isAdmin(login_session['email']):
        return render_template(
            'admincatalog.html', categories=categories,
            latestItems=latestItems,
            user_image=login_session['picture'],
            email=login_session['email'],
            username=login_session['username'])
    else:
        loggedIn = 'gplus_id' in login_session
        return render_template(
            'catalog.html', categories=categories,
            latestItems=latestItems, loggedIn=loggedIn,
            login_session=login_session)


@app.route('/login')
def login():
    # Create a state token to prevent request from a thirth party
    # Store in a session for later validation
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html',
                           CLIENT_ID=CLIENT_ID, STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Debug state
    print " Args State:"
    print request.args.get('state')
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(
            json.dumps('Invalid session parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        print "Invalid State Parameter"
        return response

    # Check taht the access token is valid
    access_token = credentials.access_token
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json_dumps(result.get('error')), 500)
        response.headers['Content Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's ID does not match app's"), 401)
        print "Token's ID does not match app's"
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    flash("You are now logged in as %s" % login_session['username'])
    print "Done!"
    return redirect(url_for('showCatalog'))


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['credentials'].access_token
    print 'User name is: %s' % login_session['username']
    print 'Access Token is: %s' % access_token
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'))
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is'
    print result
    if result['status'] == '200':
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash("Successfully Disconnected")
        return redirect(url_for('showCatalog'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Create route for newItem function here
@app.route('/catalog/newItem/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        flash("You must be logged in to create new items")
        return redirect(url_for('showCatalog'))
    if request.method == "POST" and request.form['name'] != '':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=request.form['category_id'],
                       user_id=login_session['user_id'])

        session.add(newItem)
        session.commit()
        flash("A new item has been created!")
        return redirect(url_for('showCatalog'))
    else:
        flash("Item Name cannot be empty!")
        categories = session.query(Category).order_by(Category.name).all()
        return render_template('newitem.html', categories=categories,
                               user_image=login_session['picture'],
                               email=login_session['email'],
                               username=login_session['username'])


# Create route for newCategory function here
@app.route('/catalog/newCategory/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        flash("You must be logged in to create new categories")
        return redirect(url_for('showCatalog'))
    if request.method == "POST":
        if request.form['name'] == "":
            flash("Category Name cannot be empty!")
            categories = session.query(Category).order_by(Category.name).all()
            return render_template('newcategory.html', categories=categories)
        newCategory = Category(name=request.form['name'])

        session.add(newCategory)
        session.commit()
        flash("A new category has been created!")
        return redirect(url_for('showCatalog'))

    else:
        categories = session.query(
            Category).order_by(Category.name).all()
        return render_template('newcategory.html', categories=categories,
                               user_image=login_session['picture'],
                               email=login_session['email'],
                               username=login_session['username'])


@app.route('/catalog/<item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(item_name):
    if 'username' not in login_session:
        flash("You must be logged in to delete items")
        return redirect(url_for('showCatalog'))
    deletedItem = session.query(Item).filter_by(name=item_name).one()
    if deletedItem.user_id != login_session['user_id']:
        flash("""You are not authorized to delete this item.
        Please create your own in order to delete""")
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        session.delete(deletedItem)
        session.commit()
        flash("An item has been deleted.")
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).order_by(Category.name).all()
        return render_template('deleteitem.html', item=deletedItem,
                               categories=categories,
                               user_image=login_session['picture'],
                               email=login_session['email'],
                               username=login_session['username'])


@app.route('/catalog/<category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        flash("You must be logged in to delete categories")
        return redirect(url_for('showAdminCatalog'))
    deletedCategory = session.query(Category).filter_by(
        name=category_name).one()
    if request.method == 'POST':
        # Get default category. If it isn't exists, create it.
        defaultCategory = session.query(Category).filter_by(name='Default')
        if not defaultCategory:
            defaultCategory = Category(name='Default')

        session.add(defaultCategory)
        related_items = session.query(Item).filter_by(
            category_id=deletedCategory.id).all()

        for i in related_items:
            i.category_id = defaultCategory.id
            session.add(i)

        session.delete(deletedCategory)
        session.commit()
        flash("A Category has been deleted.")
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).order_by(Category.name).all()
        return render_template(
            'deletecategory.html', category=deletedCategory,
            categories=categories,
            user_image=login_session['picture'],
            email=login_session['email'],
            username=login_session['username'])


@app.route('/catalog/<item_name>/edit/', methods=['GET', 'POST'])
def editItem(item_name):
    if 'username' not in login_session:
        flash("You must be logged in to edit items")
        return redirect(url_for('showCatalog'))
    editedItem = session.query(Item).filter_by(name=item_name).one()
    if editedItem.user_id != login_session['user_id']:
        flash("""You are not authorized to edit this item.
         Please create your own in order to edit""")
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category_id']:
            editedItem.category_id = request.form['category_id']
        session.add(editedItem)
        session.commit()
        flash("An item has been edited.")
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).order_by(Category.name).all()
        return render_template('edititem.html', item=editedItem,
                               categories=categories,
                               user_image=login_session['picture'],
                               email=login_session['email'],
                               username=login_session['username'])


@app.route('/catalog/<category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        flash("You must be logged in to edit categories")
        return redirect(url_for('showAdminCatalog'))
    deletedCategory = session.query(Category).filter_by(
        name=category_name).one()
    if 'email' in login_session and isAdmin(login_session['email']):
        flash('You are not authorized to edit this Category')
        return redirect(url_for('showCategory'))
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash("A category has been edited.")
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(
            Category).order_by(Category.name).all()
        return render_template('editcategory.html',
                               category=editedCategory,
                               categories=categories)


@app.route('/catalog/<category_name>/<item_name>/')
def showItem(category_name, item_name):
    item = session.query(Item).filter_by(name=item_name).one()
    categories = session.query(Category).order_by(Category.name).all()
    print "Login Session: " + str(login_session['user_id'])
    print "User ID from Item: " + str(item.user_id)

    loggedIn = 'gplus_id' in login_session
    return render_template('item.html', item=item,
                           categories=categories,
                           loggedIn=loggedIn,
                           login_session=login_session)


@app.route('/catalog/<category_name>/items/')
def showCategory(category_name):
    category = session.query(Category).filter_by(
        name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    categories = session.query(Category).order_by(Category.name).all()
    if 'email' in login_session and isAdmin(login_session['email']):
        return render_template(
            'admincategory.html', categories=categories,
            items=items, category_name=category_name,
            user_image=login_session['picture'],
            email=login_session['email'],
            username=login_session['username'])
    else:
        loggedIn = 'gplus_id' in login_session
        return render_template('category.html',
                               items=items, num_items=len(items),
                               categories=categories,
                               category_name=category_name,
                               loggedIn=loggedIn,
                               login_session=login_session)


def createUser(login_session):
    newUser = User(username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def isAdmin(email):
    return login_session['email'] == "nahuel.albino@gmail.com"


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
