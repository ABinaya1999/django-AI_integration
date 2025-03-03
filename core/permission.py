from django.utils.crypto import get_random_string
from django.urls import resolve
from rest_framework import permissions
from rest_framework.authtoken.models import Token
from university_attendance_management.users.models import User
from university_attendance_management.core.utils import MicrosoftAuth
import os

class DjangoUser:
    def __init__(self, username):
        self.username = username

    def is_django_user(self):
        try:
            user = User.objects.get(username=self.username)
            if user.is_active and user.is_staff:
                return user
            else:
                return False
        except User.DoesNotExist:
            return False

    def create_django_user(self,role):
        try:
            random_password = get_random_string(length=12)
            user_roles = [key for key, value in role.items() if value]
            user, created = User.objects.get_or_create(username=self.username, is_active=True, is_staff=True,
                                               user_role=user_roles)
            if created:
                user.set_password(random_password)
                user.save()
            return user
        except Exception as e:
            pass


class UserPermission:
    def __init__(self, user_role):
        self.user_role = user_role
        
    def has_permission(self, request, view):
        try:
            role_permissions = {
                "admin": {  
                    "ALL_METHODS": "ALL_VIEWS"
                },
                "teacher": {  
                    "GET": "ALL_VIEWS",
                    "POST": {"AttendanceViewSet"},
                    "PATCH": {"AttendanceViewSet"},
                    "DELETE": {"AttendanceViewSet"},
                },
                }
            action = request.method
            view_name = view.__class__.__name__
            
            for role in self.user_role:
                if role in role_permissions:
                    permissions = role_permissions[role]
                    
                    if permissions.get("ALL_METHODS") == "ALL_VIEWS":
                        return True
                    
                    if action in permissions:
                        allowed_views = permissions[action]
                        
                        if allowed_views == "ALL_VIEWS" or view_name in allowed_views:
                            return True
                    
            return False
        except Exception as e:
            return False
    

class MicrosoftPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            auth_header = request.headers.get('Authorization', '').split('Bearer ')[-1]
            microsoft_auth = MicrosoftAuth()
            user_email = microsoft_auth.get_microsoft_email(auth_header)
            django_user = DjangoUser(user_email)
            user = django_user.is_django_user()
            if not user: 
                group_ids = microsoft_auth.get_user_group_ids(auth_header)
                teacher = microsoft_auth.is_in_teacher_group(group_ids) 
                admin = microsoft_auth.is_in_admin_group(group_ids)
                role = {
                    "admin": admin,
                    "teacher": teacher  
                }
                user = django_user.create_django_user(role)
            os.environ["user"] = user.username
            user_role = user.user_role
            return UserPermission(user_role).has_permission(request, view)

        except Exception as e:
            print(e)
            return False


class MicrosoftOrAuthenticatedPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        is_authenticated = permissions.IsAuthenticated().has_permission(request, view)
        if is_authenticated:
            return True
        microsoft_permission = MicrosoftPermission().has_permission(request, view)
        if microsoft_permission:
            return microsoft_permission 


