from django.db import models
from datetime import datetime, timedelta
import re

class UserManager(models.Manager):

    def basic_validator(self, post_data):
        errors = {}

        name_regex = re.compile(r"^[a-zA-Z]+$")
        email_regex = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")
        year = datetime.now() - timedelta(weeks = 676)

        if not name_regex.match(post_data["fname"]):
            errors["fname"] = "First name should consist of alphabetical characters only"
        if not name_regex.match(post_data["lname"]):
            errors["lname"] = "Last name should consist of alphabetical characters only"
        if not email_regex.match(post_data["email"]):
            errors["email"] = "Email is invalid"

        if post_data["fname"] == "" or len(post_data["fname"]) < 2 or len(post_data["fname"]) > 50:
            errors["fname"] = "First name should have 2 characters to 50 characters long"
        if post_data["lname"] == "" or len(post_data["lname"]) < 2 or len(post_data["lname"]) > 50:
            errors["lname"] = "Last name should have 2 characters to 50 characters long"
        if post_data["email"] == "" or len(post_data["email"]) < 2 or len(post_data["email"]) > 50:
            errors["email"] = "Email should have 2 characters to 50 characters long"
        if post_data["pw"] == "" or len(post_data["pw"]) < 8 or len(post_data["pw"]) > 50:
            errors["pw"] = "Password should be at least 8 characters"
        if post_data["pw"] != post_data["confirm_pw"]:
            errors["confirm_pw"] = "Password and confirm password should match."

        if post_data["date"] == '' or datetime.strptime(post_data["date"], '%Y-%m-%d') > year:
            errors["date"] = "Must be at least 13 years old to register"

        



        # email_check = self.filter(email = post_data["email"])
        # if email_check:
        #     errors["email"] = "Email already exists."

        # if User.objects.filter(email=post_data["email"]):
        #     errors["email"] = "Email already exists."

        try:
            self.get(email=post_data["email"])
            errors["email"] = "Email already in use."
        except:
            pass
        return errors

class User(models.Model):
    first_name = models.CharField(max_length = 50)
    last_name = models.CharField(max_length = 50)
    email = models.CharField(max_length = 384, unique = True)
    password = models.CharField(max_length = 60)
    birthday = models.DateField()
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    objects = UserManager()



