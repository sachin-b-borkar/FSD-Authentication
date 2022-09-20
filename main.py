import os
from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api,Resource
import jwt
import uuid
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token,JWTManager,jwt_required,get_jwt_identity ,create_refresh_token

#start the flask app
app = Flask(__name__)
# to connect to mysql db
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:welcome$1234@localhost/user"
db = SQLAlchemy(app)
api = Api(app)
app.config['SECRET_KEY'] = 'your secret key'
jwt = JWTManager()
jwt.init_app(app)

block_list = set()

@jwt.token_in_blocklist_loader()
def check_if_token_in_block_list(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in block_list

# class to create a table and querry using static methods
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

#method to add users
    @staticmethod
    def add_user(username, password):
        data = User.query.filter_by(username=username).first()
        print("user entered data is {}".format(data))
        if data == None:
            hashed = pbkdf2_sha256.hash(password)
            print("hashed password is {}".format(hashed))
            public_id = str(uuid.uuid4())
            print("public id  is {}".format(public_id))
            new_user = User(username=username, password=hashed, public_id=public_id)
            print("new user is {}".format(new_user))
            db.session.add(new_user)
            db.session.commit()
            return {"message":"user created"}
        else:
            return {"message": "user already exists"}

#method to check password and users exists
    @staticmethod
    def check_password(username, password):
         data = User.query.all()
         print("all user entered data from db is {}".format(data))
         for p in data:
            print(p)
            if username == p.username:
                print("user name is {}".format(username))
                print("password is {}".format(password))
                print("password from user data is {}".format(p.password))
                if pbkdf2_sha256.verify(password,p.password):
                    # we can check the encoded token in jwt.io page
                    token=jwt.encode({"public_id":p.public_id,
                                      "exp":datetime.utcnow()+timedelta(minutes=1)},
                                       app.config["SECRET_KEY"])
                    print("encoded token generated is {}".format(token))
                    print("public is {}".format(p.public_id))
                    return {"message": "Login success","token": token}
                else:
                    return {"message": "password incorect"}
         else:
            return {"message": "password incorect"}

# function to check if token presnet then only give access to view users
# def token_required(f):
#     def decorated(*args,**kwargs):
#         token = None
#         if "x-access-token" in request.headers:
#             token=request.headers["x-access-token"]
#         if not token:
#             return {"message": "token missing"}
#         else:
#             try:
#                 data = jwt.decode(token,app.config["SECRET_KEY"],algorithms=["HS256"])
#                 print(" decoded token is {}".format(data))
#                 current_user= User.query.filter_by(public_id=data["public_id"]).first()
#                 if current_user:
#                     return f()
#                 else:
#                     return {"message": "token invalid"}
#             except:
#                 return {"message": "token invalid"}
#     return decorated

# class for signup page using class method without route decorator
class signup(Resource):
    def post(self):
        data = request.get_json()
        print("user data added{}".format(data))
        data= User.add_user(username=data["username"], password=data["password"])
        print(data)
        return jsonify(data)

# class for login page using class method without route decorator
class loginpage(Resource):
    def post(self):
        data = request.get_json()
        print("user data added{}".format(data))
        data =User.check_password(username=data["username"],password=data["password"])
        print(data)
        return jsonify(data)

#decorater for checking if token present then return user list
@app.route("/users", methods =["GET","POST"])
# @token_required
def show_user():
    data = User.query.all()
    print(data)
    name_dict= {}
    for names in data:
        print(names)
        name_dict[names.id] = names.username
    return jsonify(name_dict)

@app.route("/token",methods =["POST"])
def my_token():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    check_user= User.query.filter_by(username=data["username"]).first()
    if check_user:
        access_token = create_access_token(identity=username , fresh=True)
        refresh_token = create_refresh_token(identity=username)
        return jsonify({"access_token": access_token , "refresh_token": refresh_token })

@app.route("/test", methods = ["GET","POST"])
@jwt_required(optional= True)
def mytest():
    current_user = get_jwt_identity()
    print(current_user)
    if current_user:
        return jsonify({"test": "Thanks for wearing your badge"})
    else:
        return jsonify({"test": "Please ensure to wear badge"})

@app.route("/refresh", methods = ["GET","POST"])
@jwt_required(refresh= True)
def reresh_token():
    current_user = get_jwt_identity()
    print(current_user)
    new_access_token = create_access_token(identity=current_user,fresh=False)
    return jsonify({"new_access_token": new_access_token})

@app.route("/revoke", methods = ["GET","POST"])
@jwt_required()
def revoke_token():
    jti = get_jwt()["jti"]
    block_list.add(jti)
    return jsonify({"message": "Loggedout"})

api.add_resource(signup,"/register")
api.add_resource(loginpage,"/login")

if __name__ == "__main__":
    app.run()