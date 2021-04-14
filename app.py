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


@app.route("/vote", methods=["POST", "GET"])
def vote():
    if "email" in session:
        candidates_records = db.candidates

        #query all positions
        chairperson = candidates_records.distinct("chairperson") #query all documents with chairperson key
        secretary = candidates_records.distinct("secretary")
        treasurer = candidates_records.distinct("treasurer")
        auditor = candidates_records.distinct("auditor")
        business_manager = candidates_records.distinct("business_manager")
        representative = candidates_records.distinct("representative")


        if request.method=="POST":
            if "chairperson_submit_btn" in request.form:
                chairperson_vote = request.form.get("chairperson")
                print(chairperson_vote)
            if "secretary_submit_btn" in request.form:
                secretary_vote = request.form.get("secretary")
                print(secretary_vote)
            if "treasurer_submit_btn" in request.form:    
                treasurer_vote = request.form.get("treasurer")
                print(treasurer_vote)
            if "auditor_submit_btn" in request.form:
                auditor_vote = request.form.get("auditor")
                print(auditor_vote)
            if "business_manager_submit_btn" in request.form:
                business_manager_vote = request.form.get("business_manager")
                print(business_manager_vote)
            if "representative_submit_btn" in request.form:
                representative_vote = request.form.get("representative")
                print(representative_vote)

        return render_template('vote.html', chairperson1=chairperson[0], chairperson2=chairperson[1], chairperson3=chairperson[2], 
        secretary1=secretary[0], secretary2=secretary[1], secretary3=secretary[2], 
        treasurer1=treasurer[0], treasurer2=treasurer[1], treasurer3=treasurer[2],
        auditor1=auditor[0], auditor2=auditor[1], auditor3=auditor[2],
        business_manager1=business_manager[0], business_manager2=business_manager[1], business_manager3=business_manager[2],
        representative1=representative[0], representative2=representative[1], representative3=representative[2])
    else:
        return redirect(url_for("login"))

#end of code to run it
if __name__ == "__main__":
  app.run(debug=True)