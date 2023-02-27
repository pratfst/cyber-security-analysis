
from flask import Flask, request, render_template
import pickle
import pandas as pd


app = Flask(__name__)


model = pickle.load(open('cyber.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict',methods=['POST'])
def predict():
    '''
    For rendering results on HTML GUI
    '''
    Time = request.form.get("Time")
    protocol=request.form.get("protocol")
    srcbyte=request.form.get("srcbyte")
    dstbyte=request.form.get("dstbyte")
    loginfailed=request.form.get("loginfailed")
    Loggedin=request.form.get("Loggedin")
    Hostlogin=request.form.get("Hostlogin")
    Guestloggedin=request.form.get("Guestloggedin")
    Guestloggedstatus=request.form.get("Guestloggedstatus")

    X = pd.DataFrame([[Time, protocol, srcbyte, dstbyte, loginfailed, Loggedin, Hostlogin, Guestloggedin, Guestloggedstatus]],
     columns = ['durations', 'protocol_type', 'src_bytes', 'dst_bytes',
       'num_failed_logins', 'logged_in', 'is_host_login', 'is_guest_login',
       'dst_host_count'])

    prediction=model.predict(X)[0]
    print(prediction)
    
    if prediction==0:
        
      return render_template('index.html', prediction_text='Based on above Network Behaviour  found :{} '.format("Normal Behaviour"))

    else:

     return render_template('index.html', prediction_text='Based on above Network Behaviour  found :{} '.format("Abnormal Behaviour chances of attack in Network"))
 

app.run()
