from django import forms
from django.db import models
from .validations import validate_password_strength,validate_object_id,validate_roles

class RoleForm(forms.Form):
    name = forms.CharField(max_length=100)
    permissions = forms.JSONField(required=False)


class UpdateRoleForm(forms.Form):
    role_id = forms.CharField(validators=[validate_object_id], required=True)
    name = forms.CharField(max_length=100, required=True)
    permissions = forms.JSONField(required=False)

class UserForm(forms.Form):
    firstname = forms.CharField(max_length=100)
    lastname = forms.CharField(max_length=100)
    email = forms.EmailField()
    password = forms.CharField(
        widget=forms.PasswordInput(),
        validators=[validate_password_strength],
        help_text="Your password must be at least 8 characters long, include at least one uppercase letter, one lowercase letter, one digit, and one special character."
    )
    roles = forms.CharField(
        widget=forms.TextInput(),
        validators=[validate_roles],
        help_text="Enter roles as a comma-separated list, e.g., 'role1,role2,role3'.",
        required=False
    )

class UserRoleForm(forms.Form):
    user_id = forms.CharField(
        validators=[validate_object_id],
        help_text="Invalid id for user"
    )
    role_id = forms.CharField(
        validators=[validate_object_id],
        help_text="Invalid id for role"
    )
class CustomerFrom(forms.Form):
    customer_name  = forms.CharField()
    postal_address = forms.CharField()
    email = forms.EmailField()
    phone_number = forms.CharField()
    website = forms.URLField()

class IncidentCommentForm(forms.Form):
     remarks =  forms.CharField()

class UserLoginForm(forms.Form):
    email = forms.EmailField(required=True,max_length=320)  
    password = forms.CharField(required=True,min_length=8)

class IncidentForm(forms.Form):
    customer_code = forms.IntegerField(min_value=1000,max_value=9999)
    incident_disposition = forms.CharField(max_length=500)
    executive_involved = forms.CharField(max_length=100)
    name = forms.CharField(max_length=100)

    # Date and location
    date_occured = forms.DateTimeField()
    date_discovered = forms.DateTimeField()
    html_block = forms.CharField()

    # Implications
    criminal_status_view = forms.CharField()
    employee_involvement_view = forms.CharField()
    department = forms.CharField()
    negative_pr = forms.CharField()
    reporting_individual = forms.CharField()
    severity = forms.CharField()

    #privacy
    pii_fields_view = forms.CharField()

    #team formation
    owner = forms.CharField()
    membership_chooser = forms.CharField()