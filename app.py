import re
from tokenize import cookie_re
from unittest import result
from flask import Flask, render_template, request, redirect, url_for, session,jsonify
import pymysql, requests, time
from datetime import datetime
import pandas as pd
from urllib3 import Retry
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, verify_jwt_in_request
from datetime import datetime, timedelta

app = Flask(__name__)    
app.secret_key = 'your secret key'

# Mysql Server ==============================
connection = pymysql.connect(host='localhost', user='root',password='root', db='flask',autocommit=True)
# ===========================================

# JWT: ============= Token for API ================
jwt = JWTManager(app)
# Jwt Config
app.config['JWT_SECRET_KEY'] = "this-is-secret-key" #Required for HS256 alogrithm
ACCESS_EXPIRES = timedelta(minutes=3)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
# JWT_ACCESS_TOKEN_EXPIRES >> Default: datetime.timedelta(minutes=15)

# JWT Algorith >> Default: "HS256"
#=================================================

iter = 0 # Global Variable to check api calls
app.config['JSON_SORT_KEYS'] = False

def login_required(fun):
    def secure_login():
        if session:
            return fun()
        elif verify_jwt_in_request():
            return fun()
    return secure_login
        
@app.route('/',methods =['GET', 'POST'])
@app.route('/login', methods =['GET', 'POST']) #Login by UI or JSON
def login():
    if session:
        return redirect(url_for('getData1'))
    try:
        # IF a Variable pass in header through API CALL:
        if request.headers.get('foo') == 'bar':
            return jsonify(header="In header getting variable 'foo'")
        #=================================================
        
        msg = ''    
        if request.method == 'POST':
            
            if request.is_json:
                email = request.json['email']
                password = request.json['password']    
            else:
                email = request.form['email']
                password = request.form['password']
            
            cursor = connection.cursor()
            cursor.execute('SELECT * FROM user WHERE Email = %s AND Password = %s AND Active = True', (email, password))
            account = cursor.fetchone()
            connection.commit()
            
            if account:
                cursor = connection.cursor()
                cursor.execute('SELECT role.Role FROM flask.user left join flask.role_user on user.UserID = role_user.UserID Inner join flask.role on role_user.RoleID = role.RoleID where user.Active = True and user.email = %s;', (email))
                role = cursor.fetchall() #interceptor
                # JWT : ====For API===================================================
                postman = request.args.get('type')
                #if role[-1][0] == 'Admin':
                if postman == 'postman' and role[-1][0] == 'Admin':
                    token = create_access_token(identity=email)
                    data = {'msg':'Login Succesfully',
                            'token':token,
                            'userid':account[0],
                            'email':email,
                            'token_expires(sec)':int(ACCESS_EXPIRES.total_seconds()) 
                    }
                    return jsonify(data), 201
                #======================================================================
                
                session['role'] = role[-1][0]
                #print(session['role'])
                session['loggedin'] = True
                session['id'] = account[0]
                session['username'] = f"{account[1]} {account[2]}"
                return redirect(url_for('getData1'))
            else:
                msg = 'Incorrect Email / Password !'
        return render_template('login.html', msg = msg)
    except:
        msg = "Something Went Wrong!"
        return render_template('login.html', msg = msg)

@app.route('/logout') #Logout only for Session {UI} not for token {API}
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/User', methods =['GET', 'POST'])# User Edit their Details any user access
def edit():
    if 'id' in session:
        msg = ''
        cursor = connection.cursor()
        if request.method == 'POST':
            username = request.form['first_name']
            lastname = request.form['last_name']
            dob = datetime.strptime(request.form['dob'],"%Y-%m-%d") 
            password = request.form['password']
            email = request.form['email']
            state = request.form['state']
            district = request.form['district']
            id = request.form['update']
            cursor.execute('UPDATE User SET `First_Name` = %s , `Last_Name` = %s, `BirthDate` = %s, `Email` = %s, `Password` = %s, State = %s, District = %s WHERE (`UserID` = %s)', (username,lastname,dob, email, password,state,district,id ))    
            session['username'] = f"{username} {lastname}"
            #cursor.execute('INSERT INTO User VALUES (% s, % s, % s,% s, % s, % s)', (username,lastname,dob, email, password, ))
            msg = f'User ID: {email}, Updated Succesfully'
        
        cursor.execute('SELECT * FROM user where UserID = %s',(session['id']))
        user = cursor.fetchone()
        cursor.execute("select state, district from flask.state,flask.district where state.stateID = district.stateId")
        state = cursor.fetchall()
        dis = {}
        for i,j in state:
            if i not in dis:
                dis[i] = [j]
            else:
                dis[i].append(j)
        connection.commit()
        return render_template('edit.html',user = user, msg=msg,dis=dis,name = session['username'],role = session['role'])
    
    return render_template('login.html', msg="Please Login!")

@app.route('/dashboard', methods =['GET', 'POST']) #Only Admin Able to Access
def admin():
    if 'id' in session:
        msg=''
        cursor = connection.cursor()
        if 'Admin' in session['role']:
            cursor.execute("select UserID from flask.role inner join flask.role_user on role.RoleID = role_user.RoleID where role.Role = 'Admin'")
            admins = [i[0] for i in cursor.fetchall()]    
            cursor.execute('SELECT UserID, First_Name,Last_Name,Email, TIMESTAMPDIFF(YEAR, BirthDate, CURDATE()) AS age, State, District FROM flask.user WHERE Active = True;')
            account = cursor.fetchall()
        else:
            cursor.execute('SELECT UserID, First_Name,Last_Name,Email, TIMESTAMPDIFF(YEAR, BirthDate, CURDATE()) AS age, State, District FROM user where UserID = %s',(session['id']))
            account = cursor.fetchall()
            return redirect(url_for('edit'))
        connection.commit()

        if request.method == 'POST':
            role = request.form.getlist('role')
            userid = int(request.form['user'])
            #print(role)
            #print(userid)
            #print(admins)
            cursor = connection.cursor()
            if (role != []) and (userid not in admins):
                for i in role: # role = ['2']
                    cursor.execute('INSERT INTO flask.role_user VALUES (Null,% s, % s)', (userid,int(i), ))
                    if int(i) == 2:
                        admins.append(userid) 
                #cursor.execute('UPDATE User SET `First_Name` = %s , `Last_Name` = %s, `BirthDate` = %s, `Email` = %s, `Password` = %s, State = %s, District = %s WHERE (`UserID` = %s)', (username,lastname,dob, email, password,state,district,id ))    
                #cursor.execute('INSERT INTO User VALUES (% s, % s, % s,% s, % s, % s)', (username,lastname,dob, email, password, ))
                #msg = f'User ID: {email}, Updated Succesfully'
            elif role == [] and userid in admins:
                cursor.execute('Delete from flask.role_user where UserID = %s and RoleID = 2', (userid, ))
                admins.remove(userid)
            #print(admins)
            connection.commit()

        #Postman call
        postman = request.args.get('type')
        if postman == 'postman':
            row_headers=[x[0] for x in cursor.description]
            json_data=[]
            for result in account:
                json_data.append(dict(zip(row_headers,result)))
            return jsonify(json_data)
        
        '''cursor.execute("select state, district from flask.state,flask.district where state.stateID = district.stateId")
        state = cursor.fetchall()
        dis = {}
        for i,j in state:
            if i not in dis:
                dis[i] = [j]
            else:
                dis[i].append(j)'''
        return render_template('dashboard.html',account = account, msg=msg,name = session['username'],admins = admins)
        #return render_template('dashboard.html',user = user, account = account, msg=msg,dis=dis,name = session['username'])
    
    return render_template('login.html', msg="Please Login!")

# =============================== For API : Token ==================================================

@app.route('/api/test') #Only for API Test to Check after Login working or not
@login_required # Check both session and token 
#@jwt_required
def test():
    try:
        return jsonify(msg = 'Welcome to Test Clear Succesfully!')
    except Exception as e:  
        return jsonify(Exception=e)

def register_user(dic): #function to insert users into DB
    cursor = connection.cursor()
    json_data=[]
    for i in dic:
        cursor.execute('SELECT * FROM User WHERE Email = %s', (i['email']))
        account = cursor.fetchone()
        if account:
            result = {'id':account[0],'msg':'User Already Exist','status':'Active' if account[-1] else 'Not Active'}
            json_data.append(result)
        else:
            print(i['email'])
            cursor.execute('INSERT INTO User VALUES (NULL, % s, % s,% s, % s, % s, % s, % s,True);', (i['first_name'],i['last_name'],i['dob'],i['email'],i['password'],i['state'],i['district'], ))
            cursor.execute('SELECT UserID FROM User WHERE Email = %s AND Active = True', (i['email']))
            account = cursor.fetchone()
            print(account)
            print(i['role'])
            for j in i['role']: #role = ['User','Admin']
                cursor.execute('SELECT RoleID FROM flask.Role WHERE Role = %s', (j))
                roleid = cursor.fetchone()
                print(roleid)
                if roleid:
                    cursor.execute('INSERT INTO role_user VALUES (NULL, % s, % s)', (account[0],roleid))
                else:
                    return f'Not Insert in DB {roleid}{j}'
            
            result = {'id':account[0],'msg':'New user Succesfully Created'}
            json_data.append(result)
    connection.commit()    
    return json_data

@app.route('/api/users', methods=['GET', 'POST']) #Access all Users details
@jwt_required() #No Session Required Token Required
def user():
    #if session: #Login Required
    if request.method == 'POST': #and session['role']=='Admin': #Only Admin has Access
            
        #By Uploading CSV file
        if request.files:
            dic = pd.read_csv(request.files['']).to_dict(orient='records')
            #print(dic[1]['role'].split())
            json_data = register_user(dic)    
            return jsonify(json_data)
            #return 'hello'

        #By Passing Raw JSON in BODY
        elif request.is_json:
            dic = request.get_json()
            json_data = register_user(dic)
            return jsonify(json_data)  
    else:
        cursor = connection.cursor()
        json_data = [{"msg":"Hi Admin Welcome! Below is all Users list"}]
        #if 'Admin' in session['role']:
        cursor.execute('SELECT UserID,First_Name,Last_Name,Email, TIMESTAMPDIFF(YEAR, BirthDate, CURDATE()) AS age, State, District FROM flask.user WHERE Active = True;')
        account = cursor.fetchall()
        #else:
        #    cursor.execute('SELECT First_Name,Last_Name,Email, TIMESTAMPDIFF(YEAR, BirthDate, CURDATE()) AS age, State, District FROM flask.user WHERE Active = True and UserID = %s;',(session['id']))
        #    account = cursor.fetchall()
        #    json_data.append({'msg':'Only Admins are allowed! You are not Admin'})
        connection.commit()
        row_headers=[x[0].lower() for x in cursor.description]
        for result in account:
            json_data.append(dict(zip(row_headers,result)))
        return jsonify(json_data)

            
@app.route('/api/user/<userid>',methods = ['GET','DELETE']) #Access User on UsedID
@jwt_required() #No Session Required Token Required
def userid(userid):
    #if session:
    #    if session['role'] == 'Admin':
    if request.method == 'DELETE':
        cursor = connection.cursor()
        cursor.execute('UPDATE User SET Active = %s WHERE (`UserID` = %s) AND Active = True', (False, userid))
        cursor.execute('SELECT UserId,Email from User WHERE UserID = %s AND Active = False',(userid))
        account = cursor.fetchone()
        connection.commit()
        result = {'id':account[0],'Email':account[1],'msg':'User Succesfully Deleted! No Longer Exist'}
        return jsonify(result)
    else:
        cursor = connection.cursor()
        cursor.execute('SELECT UserID,First_Name,Last_Name,Email, TIMESTAMPDIFF(YEAR, BirthDate, CURDATE()) AS age, State, District FROM flask.user WHERE UserId = %s AND Active = True',(userid))
        account = cursor.fetchone()
        connection.commit()
        row_headers=[x[0].lower() for x in cursor.description]
        return jsonify(dict(zip(row_headers,account)))

# =============================== END API ===========================================================


@app.route('/register', methods =['GET', 'POST']) #Register new user through UI
def register():
    msg = ''
    try:
        if request.method == 'POST':
            username = request.form['first_name']
            lastname = request.form['last_name']
            dob = datetime.strptime(request.form['dob'],"%Y-%m-%d") 
            password = request.form['password']
            email = request.form['email']
            state = request.form['state']
            district = request.form['district']
            cursor = connection.cursor()
            cursor.execute('SELECT * FROM User WHERE Email = %s', (email))
            account = cursor.fetchone()
            connection.commit()
            if account:
                if account[-1] == 0:
                    msg = f'Hi {email} Welcome Back! You Account is now Active, Please Login'
                    cursor = connection.cursor()
                    cursor.execute('UPDATE User SET `First_Name` = %s , `Last_Name` = %s, `BirthDate` = %s, `Email` = %s, `Password` = %s, State = %s, District = %s, Active = True WHERE (`Email` = %s)', (username,lastname,dob, email, password,state,district,email ))                    
                    connection.commit()
                else:
                    msg = f'Hi {email} Account already exists !'
            else:
                cursor.execute('INSERT INTO User VALUES (NULL, % s, % s,% s, % s, % s, % s, % s,True)', (username,lastname,dob, email, password,state,district, ))
                cursor.execute('SELECT UserID FROM User WHERE Email = %s AND Active = True', (email))
                id = cursor.fetchone()
                cursor.execute('INSERT INTO flask.role_user VALUES (NULL, % s, % s)', (id,1, ))
                connection.commit()
                session['loggedin'] = True
                session['username'] = f"{username} {lastname}"
                session['id'] = id
                session['role'] = 'User'
                return redirect(url_for('login'))
                #msg = f'Hi {username}, You Successfully registered with us! Please Login'
        cursor = connection.cursor()
        cursor.execute("select state, district from flask.state,flask.district where state.stateID = district.stateId")
        state = cursor.fetchall()
        dis = {}
        for i,j in state:
            if i not in dis:
                dis[i] = [j]
            else:
                dis[i].append(j)
        return render_template('register.html', msg = msg, dis=dis)
    except:
        msg = "Something Went Wrong!"
        return render_template('register.html', msg = msg)

@app.route("/data1")
def getData1(): #camelcase Ex: getDataById, get_data_by_id
    if session:
        try:
            d = requests.get("https://jsonplaceholder.typicode.com/todos/")
            data1 = d.json()
            d = requests.get("https://datausa.io/api/data?drilldowns=Nation&measures=Population")
            d2 = d.json()
            
            # For Postman 
            postman = request.args.get('type')
            if postman == 'postman':
                return data1
            
            data2 = d2['data']
            source = d2["source"][0]["annotations"]
            name = session['username']
            role = session['role']
            return render_template("index.html", **locals()) #**locals() pass all local variable as dictionary
        except:                      
            if iter < 4: 
                time.sleep(2)
                iter = iter+1
                getData1()
            else:
                return render_template("login.html",msg = 'API Fail no Response')
    else:
        return render_template("login.html",msg = 'Try with Login')

# Only For API call to access data2 if type = 'postman'
@app.route("/data2")
def getData2():
    if session:
        postman = request.args.get('type')
        if postman == 'postman':
            d = requests.get("https://datausa.io/api/data?drilldowns=Nation&measures=Population")
            d2 = d.json()
            return d2
        else:
            return redirect(url_for('getData1'))
    else:
        return render_template("login.html",msg = 'Try with Login')

'''@app.route("/data2")
def getData2():
    if session:
        try:
            d2 = requests.get("https://datausa.io/api/data?drilldowns=Nation&measures=Population")
            data2 = d2.json()
            data = data2['data']
            source = data2["source"][0]["annotations"]
            name = session['username']
            return render_template("index.html",**locals())
        except:
            if iter < 4:
                time.sleep(2)
                iter = iter+1
                getData2()
            else:
                return render_template("login.html",msg = 'API Fail no Response')
    else:
        return render_template("login.html",msg = 'Try with Login')
'''
if __name__ == "__main__":
    app.run(debug=True)