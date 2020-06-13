# -*- coding:utf-8 -*-
from flask import Flask,request
from flask import render_template,session,make_response
import jwt
JWT_SECRET= ####REDACTED####
JWT_ALGORITHM="HS256"
app = Flask(__name__)
app.secret_key= ####REDACTED####
def get_flag():
    flag=open("flag.txt","r").read()
    return flag
@app.route('/')
def accueil():
    session['admin']=False
    try:
        if 'token' in request.cookies:
            token = request.cookies.get('token')
            try:
                data=jwt.decode(token,JWT_SECRET,JWT_ALGORITHM)
                if data['admin'] == 'true':
                    session['admin'] = True
            except:
                render_template("error.html",msg="Naaanii! You want to hack me ?")
        else:
            token=jwt.encode({'admin': 'false'}, JWT_SECRET, algorithm=JWT_ALGORITHM)
            response=make_response(render_template("index.html",msg="Welcome Newbie"))
            response.set_cookie("token",token)
            return response
        if session['admin'] == True:
            flag=get_flag()
            return render_template("index.html",msg=flag)
        else:
            return render_template("index.html",msg="Only admins are allowed to see flags")
    except:
        render_template("error.html", msg="Naaanii! You want to hack me ?")

if __name__ == '__main__':
    app.run(host="0.0.0.0",port=1234,debug=False)

