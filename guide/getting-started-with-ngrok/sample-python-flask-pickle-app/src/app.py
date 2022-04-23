import pickle
import base64
import flask

app = flask.Flask(__name__)

@app.route("/", methods = ["GET"])
def home ():
  template = '''\
<html>
  <head><title>ngrok tutorial</title></head>
  
  <body>
    Can you get a reverse shell? Enter serialized Python Pickle data in base64 encoded form below. <br /><br />
    <form action="/ngrokme" method="post">
      <label for="payload">Enter base64 data:</label>
      <input type="text" name="payload" placeholder="base64-data" />
      <input type="submit" value="Submit" />
    </form>
  </body>
</html>
'''
  return flask.render_template_string(template), 200

@app.route("/ngrokme", methods = ["POST"])
def ngrokme ():
  try:
    payload = base64.urlsafe_b64decode(flask.request.form.get('payload').encode())
    pickle.loads(payload)
  except:
    return 'error unpickling your payload', 200
  return 'hmm, did your reverse shell payload work?', 200

app.run(host = '0.0.0.0', port = 31337, debug = True)