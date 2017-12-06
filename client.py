import ssl

from flask import Flask, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth

CLIENT_ID = 'confidential'
CLIENT_SECRET = 'confidential'

app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
oauth = OAuth(app)

remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={'scope': ['email', 'address']},
    base_url='https://localhost:8080/login',
    request_token_url=None,
    access_token_url='https://localhost:8080/oauth/token',
    authorize_url='https://localhost:8080/oauth/authorize'
)


@app.route('/')
def index():
    if 'remote_oauth' in session:
        resp_email = remote.get('api/email')
        if resp_email.status != 200:
            return "Error, couldn't get email from server"
        resp_address = remote.get('/api/address')
        if resp_address.status != 200:
            return "Error, couldn't get address from server"
        email_and_address = {
            'email': resp_email.data['email'],
            'address': resp_address.data['address'],
        }

        return jsonify(email_and_address)
    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )


@app.route('/authorized')
def authorized():
    resp = remote.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['remote_oauth'] = (resp['access_token'], '')
    return jsonify(oauth_token=resp['access_token'])


@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os

    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # context.load_cert_chain('server.crt', 'server.key')
    ssl._create_default_https_context = ssl._create_unverified_context
    app.run(host='localhost', ssl_context='adhoc', port=8000)
