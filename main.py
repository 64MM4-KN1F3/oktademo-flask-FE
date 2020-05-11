import base64
import requests

from flask import Flask, render_template, url_for, redirect, session, json
from flask_oidc import OpenIDConnect

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'OIDC_CLIENT_SECRETS': './client_secrets.json',
    'OIDC_DEBUG': True,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_SCOPES': ["openid", "profile", "groups"],
    'OVERWRITE_REDIRECT_URI': 'http://ec2-18-212-58-209.compute-1.amazonaws.com/authorization-code/callback',
    'OIDC_CALLBACK_ROUTE': '/authorization-code/callback'
})

oidc = OpenIDConnect(app)
user_type = "standard"

#Loading API key separately mainly to keep it out of git repo (it's gitignored)
with open("./api_secrets.json", "r") as f:
    keys = json.load(f)

@app.route("/")
def home():
    return render_template("home.html", oidc=oidc)


@app.route("/login")
def login():
    bu = oidc.client_secrets['issuer'].split('/oauth2')[0]
    cid = oidc.client_secrets['client_id']

    destination = 'http://ec2-18-212-58-209.compute-1.amazonaws.com/profile'
    state = {
        'csrf_token': session['oidc_csrf_token'],
        'destination': oidc.extra_data_serializer.dumps(destination).decode('utf-8')
    }

    return render_template("login.html", oidc=oidc, baseUri=bu, clientId=cid, state=base64_to_str(state))


@app.route("/profile")
def profile():
    user_type="standard"
    info = oidc.user_getinfo(["uid", "sub", "name", "email", "locale", "scp"])
    url = "https://dev-499185.oktapreview.com/api/v1/groups/00grgs5guopWZpRw70h7/users"
    payload = {}
    headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': keys['oktademo_api'] 
    }
    sub = info['sub']
    response = requests.request("GET", url, headers=headers, data = payload)
    if response.status_code in range(200, 299):
        #print(response.text.encode('utf8'))
        data = response.json()
        for item in data:
            if item['id'] == sub:
                user_type = "admin"
                print("Authenticated user is an admin!")
            else:
                print("Authenticated user is a standard user.")
    return render_template("profile.html", profile=info, oidc=oidc, value=user_type)


@app.route("/logout", methods=["POST"])
def logout():
    oidc.logout()

    return redirect(url_for("home"))


def base64_to_str(data):
    return str(base64.b64encode(json.dumps(data).encode('utf-8')))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)
