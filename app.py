from flask import Flask, render_template, request, redirect, url_for
from flask_mongoengine import MongoEngine, Document
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
import datetime
import requests
import random
import string
import os

app = Flask(__name__)

app.config['MONGODB_SETTINGS'] = {
    'db': 'findmyphonedb',
    'host': os.environ["MONGOLAB_URI"]
}

f = requests.request('GET', 'http://myip.dnsomatic.com')
ip = f.text

db = MongoEngine(app)
app.config['SECRET_KEY'] = os.environ["PROJECTKEY"]
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Document):
    meta = {'collection': 'Users'}
    Name = db.StringField()
    Email = db.StringField()
    Phone = db.StringField()
    Password = db.StringField()

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

@app.route('/',methods=["GET"])
def index():
    return render_template("index.html")

@app.route('/signin',methods=["GET"])
def signin():
    return render_template("signin.html")


@app.route('/signup',methods=["GET"])
def signup():
    return render_template("signup.html")

@app.route('/login',methods=["POST"])
def login():
    data = request.form
    check_user = User.objects(Name=data["your_name"]).first()
    if check_user:
        if check_password_hash(check_user['Password'], data["your_pass"]):
            login_user(check_user)
            return redirect(url_for('loggedin'))
    return render_template("error.html",caption="Oops!",error="Login/Sign Up Error",details="The details you entered are invalid or are already existing. Please go back and try again",link="javascript:history.back()",linkd="Go Back")


@app.route('/register',methods=["POST"])
def register():
    data = request.form
    existing_email = User.objects(Email=data["email"]).first()
    existing_name = User.objects(Name=data["name"]).first()
    existing_phone = User.objects(Name=data["phone"]).first()
    if existing_email is None and existing_name is None and existing_phone is None:
        otp = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        url = "https://www.fast2sms.com/dev/bulk"
        payload = "sender_id=FSTSMS&message=Hello, " +data["name"] +" Welcome to FindMyPhoneDB. Please enter your OTP: " +otp +" to complete Registration.&language=english&route=p&numbers=" +data["phone"]
        headers = {
            'authorization': os.environ["API_KEY"],
            'Content-Type': "application/x-www-form-urlencoded",
            'Cache-Control': "no-cache",
        }
        response = requests.request("POST", url, data=payload, headers=headers)
        myclient = MongoClient("ds039231.mlab.com",39231)
        dbpy = myclient["findmyphonedb"]
        dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
        UserTemp = dbpy.UserTemp
        record = {"Username" : data["name"], "Email" : data["email"], "Phone Number" : data["phone"],"Password" : data["passw"],"OTP" : otp}
        UserTemp.insert_one(record)
        return render_template("otp.html")

    return render_template("error.html",caption="Oops!",error="Login/Sign Up Error",details="The details you entered are invalid or are already existing. Please go back and try again",link="javascript:history.back()",linkd="Go Back")


@app.route('/otpverify',methods=["POST"])
def otpverify():
    rec = request.form
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    UserTemp = dbpy.UserTemp
    data = UserTemp.find_one({"Email" : rec["email"],"Phone Number" : rec["phone"]})
    if data != None:
        if data["OTP"] == rec["otp"]:
            hashpass = generate_password_hash(data["Password"], method='sha256')
            rec = User(data["Username"], data["Email"], data["Phone Number"], hashpass).save()
            login_user(rec)
            UserTemp.delete_one({"Username" : data["Username"]})
            return redirect(url_for('loggedin'))
    return render_template("error.html",caption="Oops!",error="Login/Sign Up Error",details="The details you entered are invalid or are already existing. Please go back and try again",link="javascript:history.back()",linkd="Go Back")


@app.route('/loggedin')
@login_required
def loggedin():
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    UsersDevices = dbpy.UsersDevices
    rec = UsersDevices.find_one({"Username": current_user.Name})
    if rec != None:
        return render_template('home.html',rec = rec["Devices"])
    else:
        return render_template("error.html", caption="Oops!", error="No Devices Registered",
                               details="Seems like this is your first time logging in! Devices that you register will be shown here.",
                               link="/newdevice", linkd="Register Device")


@app.route('/logout', methods = ['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('signin'))

@app.route('/newdevice',methods=["GET","POST"])
@login_required
def device():
    return render_template("newdevice.html")


@app.route('/registerdev',methods=["POST"])
@login_required
def newdevice():
    data = request.form
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    UsersDevices = dbpy.UsersDevices
    rec = UsersDevices.find_one({"Username" : current_user.Name})
    if rec == None:
        new_rec = {"Username": current_user.Name, "Email": current_user.Email, "Phone Number" : current_user.Phone,"Devices": [{"OEM": data["devoem"],
                                                                                            "Name/Model": data[
                                                                                                "devname"],
                                                                                            "Codename": data["devcode"],
                                                                                            "Phone Number": data[
                                                                                                "devph"],
                                                                                            "Serial Number": data[
                                                                                                "devser"],
                                                                                            "IMEI 1": data["devimei1"],
                                                                                            "IMEI 2": data["devimei2"],
                                                                                            "Build Number": data[
                                                                                                "devbuildno"],
                                                                                            "Colour": data["devcolor"],
                                                                                            "Description": data[
                                                                                                "devdesc"],
                                                                                            "Date": datetime.datetime.now().strftime(
                                                                                                "%d:%m:%Y"),
                                                                                            "Time": datetime.datetime.now().strftime(
                                                                                                ),"%H:%M:%S"
                                                                                            "IP Address" : ip,
                                                                                            "Status": "Secure"}]}
        UsersDevices.insert_one(new_rec)
        myclient = MongoClient("ds039231.mlab.com", 39231)
        dbpy = myclient["findmyphonedb"]
        dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
        DeviceLogs = dbpy.DeviceLogs
        log_rec = {"Username": current_user.Name, "Device Phone": data["devph"], "Device Serial": data["devser"],
                   "Date": datetime.datetime.now().strftime("%d:%m:%Y"),
                   "Time": datetime.datetime.now().strftime("%H:%M:%S"),"IP Address" : ip, "Status": "Device Registered"}
        DeviceLogs.insert_one(log_rec)
        return render_template("error.html", caption="Yippe!", error="Device Successfully Registered",
                               details="Your Device is now registered, this will show up in your Dashboard Home",
                               link="/loggedin", linkd="My Devices")
    else:
        myclient = MongoClient("ds039231.mlab.com", 39231)
        dbpy = myclient["findmyphonedb"]
        dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
        UsersDevices = dbpy.UsersDevices
        rec = UsersDevices.find_one({"Username": current_user.Name})
        rec_ser = UsersDevices.find_one({"Devices" : {"$elemMatch" : {"Serial Number" : data["devser"]}}})
        rec_imei1 = UsersDevices.find_one({"Devices" : {"$elemMatch" : {"IMEI 1" : data["devimei1"]}}})
        rec_imei2 = UsersDevices.find_one({"Devices" : {"$elemMatch" : {"IMEI 2" : data["devimei2"]}}})
        if rec_ser == None and rec_imei1 == None and rec_imei2 == None:
            new_rec = {"OEM": data["devoem"],
                        "Name/Model": data["devname"],
                        "Codename": data["devcode"],
                        "Phone Number": data["devph"],
                        "Serial Number": data["devser"],
                        "IMEI 1": data["devimei1"],
                        "IMEI 2": data["devimei2"],
                        "Build Number": data[
                            "devbuildno"],
                        "Colour": data["devcolor"],
                        "Description": data["devdesc"],
                        "Date": datetime.datetime.now().strftime(
                            "%d:%m:%Y"),
                        "Time": datetime.datetime.now().strftime(
                            "%H:%M:%S"),
                       "IP Address": ip,
                        "Status": "Secure"}
            rec["Devices"].append(new_rec)
            UsersDevices.update_one(
                {'_id': rec['_id']},
                {
                    "$set": {
                        "Devices" : rec["Devices"]
                    }
                }
            )
            myclient = MongoClient("ds039231.mlab.com", 39231)
            dbpy = myclient["findmyphonedb"]
            dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
            DeviceLogs = dbpy.DeviceLogs
            log_rec = {"Username": current_user.Name, "Device Phone": data["devph"], "Device Serial": data["devser"],
                       "Date": datetime.datetime.now().strftime("%d:%m:%Y"),
                       "Time": datetime.datetime.now().strftime("%H:%M:%S"), "IP Address" : ip,"Status": "Device Registered"}
            DeviceLogs.insert_one(log_rec)
            return render_template("error.html", caption="Yippe!", error="Device Successfully Registered",
                                   details="Your Device is now registered, this will show up in your Dashboard Home",
                                   link="/loggedin", linkd="My Devices")
        else:
            return render_template("error.html", caption="Oops!", error="Device Already Registered",
                                   details="It seems that this Device already belongs to someone. Please check the Details you have entered",
                                   link="javascript:history.back()", linkd="Go Back")


@app.route('/devicelog',methods=["GET","POST"])
@login_required
def devicelog():
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    DeviceLogs = dbpy.DeviceLogs
    DeviceSearches = dbpy.DeviceSearches
    rec = DeviceLogs.find({"Username": current_user.Name})
    search_recs = DeviceSearches.find({"Username" : current_user.Name})
    return render_template("log.html",recs=rec,srecs = search_recs)

@app.route('/changestatus',methods=["GET","POST"])
@login_required
def changestatus():
    return render_template("change.html")

@app.route('/changereg',methods=["POST"])
@login_required
def changereg():
    data = request.form
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    UsersDevices = dbpy.UsersDevices
    rec = UsersDevices.find_one({"Username": current_user.Name})
    for item in rec["Devices"]:
        if data["devph"] == item["Phone Number"] and data["devser"] == item["Serial Number"]:
            UsersDevices.update_one(
                {'_id': rec['_id'],"Devices" : {"$elemMatch" : {"Phone Number" : data["devph"],"Serial Number" : data["devser"]}}},
                {
                    "$set": {
                        "Devices.$.Status" : "Stolen"
                    }
                }
            )
            myclient = MongoClient("ds039231.mlab.com", 39231)
            dbpy = myclient["findmyphonedb"]
            dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
            DeviceLogs = dbpy.DeviceLogs
            log_rec = {"Username" : current_user.Name,"Device Phone" : data["devph"],"Device Serial" : data["devser"], "Date": datetime.datetime.now().strftime("%d:%m:%Y"),
                                                                                                                        "Time": datetime.datetime.now().strftime("%H:%M:%S"),
                                                                                                                        "IP Address": ip,
                                                                                                                        "Status" : "Marked as Stolen"}
            DeviceLogs.insert_one(log_rec)
            return render_template("error.html", caption="Done!!", error="Device Status changed to Stolen",
                                   details="Your Device is now marked as Stolen any searches made will show up in your Device Log",
                                   link="/devicelog", linkd="Device Logs")
    return render_template("error.html", caption="Oops!!", error="Invalid Details entered!",
                           details="Sorry, the Device you are looking for is not in our Database. Please check the info you have entered",
                           link="javascript:history.back()", linkd="Go Back")

@app.route('/changereg2',methods=["POST"])
@login_required
def changereg2():
    data = request.form
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    UsersDevices = dbpy.UsersDevices
    rec = UsersDevices.find_one({"Username": current_user.Name})
    for item in rec["Devices"]:
        if data["devph"] == item["Phone Number"] and data["devser"] == item["Serial Number"]:
            UsersDevices.update_one(
                {'_id': rec['_id'],"Devices" : {"$elemMatch" : {"Phone Number" : data["devph"],"Serial Number" : data["devser"]}}},
                {
                    "$set": {
                        "Devices.$.Status" : "Secure"
                    }
                }
            )
            myclient = MongoClient("ds039231.mlab.com", 39231)
            dbpy = myclient["findmyphonedb"]
            dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
            DeviceLogs = dbpy.DeviceLogs
            log_rec = {"Username" : current_user.Name,"Device Phone" : data["devph"],"Device Serial" : data["devser"], "Date": datetime.datetime.now().strftime("%d:%m:%Y"),
                                                                                                                        "Time": datetime.datetime.now().strftime("%H:%M:%S"),"IP Address": ip,"Status" : "Marked as Secure"}
            DeviceLogs.insert_one(log_rec)
            return render_template("error.html", caption="Done!!", error="Device Status changed to Secure",
                                   details="Your Device is now marked as Secure.You can go to your Dashboard to see the change!",
                                   link="/loggedin", linkd="My Devices")
    return render_template("error.html", caption="Oops!!", error="Invalid Details entered!",
                           details="Sorry, the Device you are looking for is not in our Database. Please check the info you have entered",
                           link="javascript:history.back()", linkd="Go Back")


@app.route('/checkstatus',methods=["GET","POST"])
@login_required
def checkstatus():
    return render_template("status.html")

@app.route('/statuscheck',methods=["POST"])
@login_required
def statuscheck():
    data = request.form
    myclient = MongoClient("ds039231.mlab.com", 39231)
    dbpy = myclient["findmyphonedb"]
    dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
    UsersDevices = dbpy.UsersDevices
    serim = "Serial Number"
    if len(data) == 7:
        serim = "IMEI 1"
    rec = UsersDevices.find_one({"Devices" : {"$elemMatch" : {"OEM" : data["devoem"], "Name/Model" : data["devname"],serim : data["devser"], "Colour" : data["devcolor"]}}})
    if rec != None:
        myclient = MongoClient("ds039231.mlab.com", 39231)
        dbpy = myclient["findmyphonedb"]
        dbpy.authenticate(os.environ["MUSERNAME"],os.environ["MPASSWORD"])
        DeviceSearches = dbpy.DeviceSearches
        search_rec = {"Username" : rec["Username"],
                      "SearchUser" : current_user.Name,
                      "SearchEmail" : current_user.Email,
                      "SearchPhone" : current_user.Phone,
                      "OEM" : data["devoem"],
                      "Name/Model" : data["devname"],
                      "Serial Number/IMEI" : data["devser"],
                      "Colour" : data["devcolor"],
                      "Description" : data["devdesc"],
                      "Date": datetime.datetime.now().strftime("%d:%m:%Y"),
                       "Time": datetime.datetime.now().strftime("%H:%M:%S"),
                      "IP Address": ip
                      }
        DeviceSearches.insert_one(search_rec)
        for item in rec["Devices"]:
            if item["OEM"] == data["devoem"] and item["Name/Model"] == data["devname"] and item[serim] == data["devser"] and item["Colour"] == data["devcolor"]:
                status,time,date,ip2 = item["Status"],item["Time"],item["Date"],item["IP Address"]
        return render_template("statusresult.html",oem=data["devoem"],name=data["devname"],ser=data["devser"],des=data["devdesc"],stat=status,time=time,date=date,ip4=ip2,color=data["devcolor"])
    return render_template("error.html", caption="Oops!!", error="Invalid Details entered!",
                           details="Sorry, the Device you are looking for is not in our Database. Please check the info you have entered",
                           link="javascript:history.back()", linkd="Go Back")


if __name__ == '__main__':
    app.run()

