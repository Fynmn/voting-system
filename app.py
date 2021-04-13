from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt

app = Flask(__name__)
app.secret_key = "testing"

#client = MongoClient()
client = pymongo.MongoClient('localhost', 27017)
db = client.get_database('election-system-test')
user_records = db.users
admin_records = db.admin


@app.route("/", methods=['post', 'get'])
def index():
    message = ''
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        section = request.form.get("section")
        
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        
        user_found = user_records.find_one({"name": user})
        email_found = user_records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        if len(password1) < 6:
            message = 'The length of password should be at least 6 characters long'
            return render_template('index.html', message=message)
        if not any([char.isupper() for char in password1]):
            message = 'The password should have atleast one uppercase letter'
            return render_template('index.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed, 'section': section}
            user_records.insert_one(user_input)
            
            user_data = user_records.find_one({"email": email})
            new_email = user_data['email']
   
            return render_template('logged_in.html', email=new_email, section=section)
    return render_template('index.html')


@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        section = session["section"]
        #return render_template('logged_in.html', email=email, section=section)
        return render_template('logged_in.html', email=email, section=section)
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = user_records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            section_val = email_found['section']
            print(email_val)
            print(section_val)
            passwordcheck = email_found['password']
            
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                session["section"] = section_val
                
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')


@app.route("/admin_login", methods=["POST", "GET"])
def admin_login():
    message = 'Please login to your account'
    if "admin_username" in session:
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        username = request.form.get("admin_username")
        password = request.form.get("admin_password")

        username_found = admin_records.find_one({"username": username})
        if username_found:
            username_val = username_found['username']

            passwordcheck = username_found['password']
            
            #if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
            if passwordcheck:
                session["admin_username"] = username_val
                
                return redirect(url_for('admin_panel'))
            else:
                if "admin_username" in session:
                    return redirect(url_for("admin_panel"))
                message = 'Wrong password'
                return render_template('admin_login.html', message=message)
        else:
            message = 'Username not found'
            return render_template('admin_login.html', message=message)
    return render_template('admin_login.html', message=message)


@app.route("/admin", methods=["POST", "GET"])
def admin_panel():
    if "admin_username" in session:
        admin_username = session["admin_username"]

        return render_template('admin_panel.html', admin_username=admin_username)
    else:
        return redirect(url_for("admin_login"))


@app.route("/admin_logout", methods=["POST", "GET"])
def admin_logout():
    if "admin_username" in session:
        session.pop("admin_username", None)
        return render_template("admin_loggedout.html")
    else:
        return render_template('admin_login.html')


#end of code to run it
if __name__ == "__main__":
  app.run(debug=True)