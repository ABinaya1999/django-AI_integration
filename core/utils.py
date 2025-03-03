import datetime
import os
import random
import string
import uuid
from io import BytesIO
from datetime import date
import environ
import jwt
import requests
from PIL import Image
from django.core.files import File
from django.core.files.storage import default_storage
from django.db.models import FileField
from django.utils.translation import gettext_lazy as _
from jwt import InvalidTokenError
from rest_framework.exceptions import ValidationError
from rest_framework.serializers import raise_errors_on_nested_writes
from rest_framework.utils import model_meta
from django.conf import settings

env = environ.Env()


def generate_filename(filename, keyword):
    """
    Generates filename with uuid and a keyword
    :param filename: original filename
    :param keyword: keyword to be added after uuid
    :return: new filename in string
    """
    ext = filename.split('.')[-1]
    new_filename = "%s.%s" % (keyword, ext)
    return new_filename


def upload_to_folder(instance, filename, folder, keyword):
    """
    Generates the path where it should to uploaded

    :param instance: model instance
    :param filename: original filename
    :param folder: folder name where it should be stored
    :param keyword: keyword to be attached with uuid
    :return: string of new path
    """
    return os.path.join(folder, generate_filename(
        filename=filename,
        keyword=keyword
    ))


def update(instance, serializer_class, data):
    raise_errors_on_nested_writes('update', serializer_class, data)
    info = model_meta.get_field_info(instance)

    for attr, value in data.items():
        if attr in info.relations and info.relations[attr].to_many:
            field = getattr(instance, attr)
            field.set(value)
        else:
            setattr(instance, attr, value)
    instance.updated_at = datetime.datetime.now()
    instance.save()


def reduce_image_size(image, quality=70):
    image_extension = image.name.split('.')[-1]
    image_type = 'jpeg'
    if image_extension == 'png':
        image_type = 'png'
    try:
        img = Image.open(image)
    except FileNotFoundError:
        return image
    thumb_io = BytesIO()
    img.save(thumb_io, image_type, quality=quality)
    new_image = File(thumb_io, name=image.name)
    return new_image


def file_cleanup(sender, **kwargs):
    """
    File cleanup callback used to emulate the old delete
    behavior using signals. Initially django deleted linked
    files when an object containing a File/ImageField was deleted.
    """
    field_names = [f.name for f in sender._meta.get_fields()]
    for fieldname in field_names:
        try:
            field = sender._meta.get_field(fieldname)
        except:
            field = None

        if field and isinstance(field, FileField):
            inst = kwargs["instance"]
            f = getattr(inst, fieldname)
            m = inst.__class__._default_manager
            try:
                if (
                    hasattr(f, "path")
                    and os.path.exists(f.path)
                    and not m.filter(
                    **{"%s__exact" % fieldname: getattr(inst, fieldname)}
                ).exclude(pk=inst._get_pk_val())
                ):
                    default_storage.delete(f.path)
            except:
                pass


def validate_uuid(uuid_string):
    try:
        uuid.UUID(uuid_string)
    except ValueError:
        raise ValidationError({
            'non_field_errors': _('Not a valid UUID')
        })


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_email_disposable(email):
    response = requests.get(
        url=f'https://disposable.debounce.io/?email={email}'
    )
    print(response.json())
    if response.status_code == 200 and response.json().get('disposable') == 'true':
        return True
    return False


def generate_random_string(length=3):
    """Generate a random string of fixed length in lowercase for appending to slug."""
    letters = string.ascii_lowercase + string.digits  # Use lowercase letters
    return ''.join(random.choice(letters) for _ in range(length))


class MicrosoftAuth:
    def __init__(self):

        # Fetch configuration from environment variables
        self.microsoft_public_key_url = env('MICROSOFT_PUBLIC_KEY_URL')
        self.microsoft_client_id = env('MICROSOFT_CLIENT_ID')
        self.microsoft_client_secret = env('MICROSOFT_CLIENT_SECRET')
        self.microsoft_tenant_id = env('MICROSOFT_TENANT_ID')
        self.token_url = f'https://login.microsoftonline.com/{self.microsoft_tenant_id}/oauth2/v2.0/token'
        self.graph_api_url = 'https://graph.microsoft.com/v1.0'

        self.attendance_group_id = env('ATTENDANCE_GROUP_ID', None)

        self.teacher_group_id = env('TEACHER_GROUP_ID', None)
        self.admin_group_id = env('ADMIN_GROUP_ID',None)
        if not all([self.microsoft_public_key_url, self.microsoft_client_id, self.microsoft_client_secret,
                    self.microsoft_tenant_id]):
            raise ValueError("One or more environment variables are not set.")

        self.public_keys = self.get_microsoft_public_keys()

    def send_email(self, recipient_emails, subject, body):
        sender_email = "no-reply@clickconsulting.com.au"
        """
        Sends an email using Microsoft Graph API to multiple recipients.

        :param sender_email: The sender's email address.
        :param recipient_emails: A list of recipient email addresses.
        :param subject: The subject of the email.
        :param body: The body content of the email.
        """
        try:
            # Get an access token
            access_token = self.get_access_token()

            # Ensure recipient_emails is a list
            if isinstance(recipient_emails, str):
                recipient_emails = [recipient_emails]  # Convert to list if it's a single email

            # Format recipients
            recipients = [{"emailAddress": {"address": email}} for email in recipient_emails]

            # Define the email payload
            email_payload = {
                "message": {
                    "subject": subject,
                    "body": {
                        "contentType": "HTML",
                        "content": body
                    },
                    "toRecipients": recipients
                }
            }

            # Use user email instead of "/me" for Application Permissions
            url = f"{self.graph_api_url}/users/{sender_email}/sendMail"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            response = requests.post(url, json=email_payload, headers=headers)

            if response.status_code == 202:
                print("✅ Email sent successfully!")
            else:
                raise Exception(f"Error sending email: {response.status_code}, {response.text}")

        except Exception as e:
            print(f"❌ Failed to send email: {e}")
    def get_microsoft_public_keys(self):

        response = requests.get(self.microsoft_public_key_url)
        jwks = response.json()
        return jwks['keys']

    def verify_token(self, token):
        # Try all available keys to decode the token
        for key in self.public_keys:
            try:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                decoded_token = jwt.decode(token, public_key, algorithms=['RS256'], audience=self.microsoft_client_id)
                return decoded_token
            except InvalidTokenError:
                continue
        raise InvalidTokenError("Invalid token.")

    def decode_access_token(self, token):
        decoded = jwt.decode(token, algorithms=["RS256"], options={"verify_signature": False})
        return decoded

    def get_microsoft_email(self, token):
        decoded_token = self.decode_access_token(token)
        return decoded_token.get('unique_name')

    def get_access_token(self):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        data = {
            'grant_type': 'client_credentials',
            'client_id': self.microsoft_client_id,
            'client_secret': self.microsoft_client_secret,
            'scope': 'https://graph.microsoft.com/.default',
        }

        response = requests.post(self.token_url, headers=headers, data=data)
        response_data = response.json()

        if 'access_token' in response_data:
            return response_data['access_token']
        else:
            raise Exception('Failed to retrieve access token')

    def get_user_license_details(self, user_id, access_token):
        url = f'{self.graph_api_url}/users/{user_id}/licenseDetails'
        headers = {
            'Authorization': f'Bearer {access_token}',
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()  # License details of the user
        else:
            raise Exception(f'Error fetching license details: {response.status_code}, {response.text}')

    def get_user_group_ids(self, auth_token):
        """
        Fetch the group IDs for the user based on the provided authentication token.

        :param auth_token: The user's auth token (access token or ID token).
        :return: A list of group IDs the user is a member of.
        """
        try:
            # Decode the token to get the user's object ID (oid)
            decoded_token = self.decode_access_token(auth_token)
            user_id = decoded_token.get('oid')
            # Get an access token to query Microsoft Graph API
            access_token = self.get_access_token()
            # Query the user's group memberships via Microsoft Graph API
            url = f'{self.graph_api_url}/users/{user_id}/memberOf'
            headers = {
                'Authorization': f'Bearer {access_token}',
            }

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                group_memberships = response.json().get('value', [])
                group_ids = [group['id'] for group in group_memberships]

                return group_ids  # Return the list of group IDs
            else:
                raise Exception(f'Error fetching group memberships: {response.status_code}, {response.text}')

        except Exception as e:
            # Log the error if needed
            print(f'Error in get_user_group_ids: {e}')
            return []

    def is_in_teacher_group(self,group_ids):
        try:
            return self.teacher_group_id in group_ids
        except Exception as e:
            return False

    def is_in_admin_group(self,group_ids):
        try:
            return self.admin_group_id in group_ids
        except Exception as e:
            return False

    def is_faculty(self, auth_token):
        try:
            decoded_token = self.decode_access_token(auth_token)
            user_id = decoded_token.get('oid')
            access_token = self.get_access_token()
            user_license_details = self.get_user_license_details(user_id, access_token)
            sku_part_number = user_license_details['value'][0]['skuPartNumber']
            if sku_part_number == "STANDARDWOFFPACK_FACULTY":
                return True
            else:
                return False
        except Exception as e:
            return False


import datetime
import requests

class MoodleAPI:
    def __init__(self):
        self.base_url = settings.MOODLE_URL
        self.token = settings.MOODLE_TOKEN
        """
        Initialize the Moodle API class.

        :param moodle_url: The base URL of the Moodle instance (e.g., https://yourmoodleurl.com).
        :param token: The API token with sufficient permissions.
        """
        self.moodle_url = self.base_url.rstrip("/") + "/webservice/rest/server.php"


    def get_course_id_by_shortname(self, shortname):
        """
        Fetch the course ID based on its shortname.
        :param shortname: The shortname of the course.
        :return: Course ID if found, else None.
        """
        params = {
            "wstoken": self.token,
            "wsfunction": "core_course_get_courses_by_field",
            "moodlewsrestformat": "json",
            "field": "shortname",
            "value": shortname
        }

        response = requests.get(self.moodle_url, params=params)
        if response.status_code == 200:
            courses = response.json().get("courses", [])
            if courses:
                return courses[0].get("id")  # Return the first matching course's ID
            else:
                print("No course found with the given shortname.")
                return None
        else:
            print(f"Failed to fetch course by shortname. HTTP Status: {response.status_code}")
            print(response.json())
            return None

    def enroll_user_in_course(self, user_email, course_shortname, role_id=5):
        """
        Enroll a user into a course with a specified role.
        :param user_email: The email of the user to enroll.
        :param course_shortname: The shortname of the course.
        :param role_id: The role ID to assign (default is 5, typically the student role).
        :return: Response from the Moodle API.
        """
        user_id = self.get_user_id_by_email(user_email)
        if not user_id:
            return {"success": False, "message": "User not found."}

        course_id = self.get_course_id_by_shortname(course_shortname)

        if not course_id:
            return {"success": False, "message": "Course not found."}

        params = {
            "wstoken": self.token,
            "wsfunction": "enrol_manual_enrol_users",
            "moodlewsrestformat": "json",
            "enrolments[0][roleid]": role_id,
            "enrolments[0][userid]": user_id,
            "enrolments[0][courseid]": course_id
        }
        print(self.token)
        response = requests.post(self.moodle_url, params=params)
        print(response.status_code)
        if response.status_code == 200:

            try:
                print(response.text)
                response_data = response.json()
                print(response_data)
                print("API Response:", response_data)  # Debugging line
                if "warnings" in response_data and not response_data["warnings"]:
                    return {"success": True, "message": "User enrolled successfully."}
                else:
                    return {
                        "success": False,
                        "message": "Warnings or issues occurred.",
                        "details": response_data.get("warnings", "No warnings provided."),
                    }
            except ValueError:
                return {"success": False, "message": "Failed to parse response as JSON."}
        else:
            return {
                "success": False,
                "message": f"Failed to enroll user. HTTP Status: {response.status_code}",
                "details": response.text,
            }
    def get_user_id_by_email(self, user_email):
        """
        Fetch the user ID based on their email.
        :param user_email: The email address of the user.
        :return: User ID if found, else None.
        """
        params = {
            "wstoken": self.token,
            "wsfunction": "core_user_get_users",
            "moodlewsrestformat": "json",
            "criteria[0][key]": "email",
            "criteria[0][value]": user_email
        }

        response = requests.get(self.moodle_url, params=params)
        if response.status_code == 200:
            users = response.json().get("users", [])
            if users:
                return users[0].get("id")  # Return the first matching user's ID
            else:
                print("No user found with the given email.")
                return None
        else:
            print(f"Failed to fetch user by email. HTTP Status: {response.status_code}")
            print(response.json())
            return None

    def get_user_username_by_id(self, user_id):
        """
        Fetch the username (or email) of a user based on their ID.
        :param user_id: The ID of the user.
        :return: Username or email if found, else None.
        """
        params = {
            "wstoken": self.token,
            "wsfunction": "core_user_get_users",
            "moodlewsrestformat": "json",
            "criteria[0][key]": "id",
            "criteria[0][value]": user_id
        }

        response = requests.get(self.moodle_url, params=params)
        if response.status_code == 200:
            users = response.json().get("users", [])
            if users:
                return users[0].get("username")  # Return the user's username
            else:
                print(f"No user found with ID: {user_id}")
                return None
        else:
            print(f"Failed to fetch user by ID. HTTP Status: {response.status_code}")
            print(response.json())
            return None
    def send_password_reset_link(self, user_email):
        """
        Send a password reset link to the user's email.
        :param user_email: The email of the user to send the password reset link to.
        :return: Response from the Moodle API.
        """
        # Define the parameters for the password reset request
        user_id = self.get_user_id_by_email(user_email)
        username = self.get_user_username_by_id(user_id)
        print(username)
        params = {
            "wstoken": self.token,
            "wsfunction": "core_auth_request_password_reset",
            "moodlewsrestformat": "json",
            "username": username  # Moodle uses "username" to identify the user, which can be an email
        }

        response = requests.post(self.moodle_url, params=params)

        # Handle the API response
        if response.status_code == 200:
            try:
                response_data = response.json()
                if "warnings" in response_data and not response_data["warnings"]:
                    return {"success": True, "message": "Password reset link sent successfully!"}
                else:
                    return {"success": False, "message": "Warnings occurred during the process.",
                            "warnings": response_data["warnings"]}
            except ValueError:
                return {"success": False, "message": "Failed to parse response as JSON."}
        else:
            return {"success": False, "message": f"Failed to send reset link. HTTP Status Code: {response.status_code}"}

    def reset_user_password(self, user_email, new_password):
        """
        Reset the user's password and send an email notification.

        :param user_email: The email of the user whose password will be reset.
        :param new_password: The new password for the user.
        :return: Response from the Moodle API.
        """
        get_user_id_by_email = self.get_user_id_by_email(user_email)

        params = {
            "wstoken": self.token,
            "wsfunction": "core_user_update_users",
            "moodlewsrestformat": "json",
            "users[0][id]": get_user_id_by_email,
            "users[0][password]": new_password
        }

        response = requests.post(self.moodle_url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    def format_date(self, timestamp):
        if(timestamp):
            return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")
        else:
            print("No timestamp provided.")
            return None

    def get_category_name_by_id(self, category_id):
        """
        Fetch the category name based on its category ID.
        :param category_id: The ID of the category.
        :return: Category name if found, else None.
        """
        params = {
            "wstoken": self.token,
            "wsfunction": "core_course_get_categories",
            "moodlewsrestformat": "json",
            "criteria[0][key]": "id",
            "criteria[0][value]": category_id
        }

        response = requests.get(self.moodle_url, params=params)

        if response.status_code == 200:
            try:
                categories = response.json()
                if categories and isinstance(categories, list):
                    # Return the name of the first matching category
                    return categories[0].get("name", "Unknown")
                else:
                    print(f"No category found with ID: {category_id}")
                    return None
            except ValueError:
                print("Failed to parse response as JSON.")
                return None
        else:
            print(f"Failed to fetch category by ID. HTTP Status: {response.status_code}")
            print(response.text)
            return None

    def get_all_courses(self):
        """
        Get all course details, including start date, end date, name, and teachers.

        :return: A list of dictionaries containing formatted course details.
        """
        # Define the parameters for fetching courses
        params = {
            "wstoken": self.token,
            "wsfunction": "core_course_get_courses",
            "moodlewsrestformat": "json"
        }

        response = requests.get(self.moodle_url, params=params)

        if response.status_code == 200:
            try:
                courses = response.json()

                # Handle API error messages
                if isinstance(courses, dict) and "exception" in courses:
                    print(f"API Error: {courses['message']}")
                    return []

            except ValueError:
                print("Failed to parse response as JSON.")
                return []

            if not isinstance(courses, list):  # Validate that courses is a list
                print("Unexpected API response structure.")
                return []

            # Extract and format course details
            course_details = []
            for course in courses:
                if not isinstance(course, dict):  # Skip invalid entries
                    continue

                category_id = course.get("categoryid")
                category_name = self.get_category_name_by_id(category_id)

                course_data = {
                    "id": course.get("id"),
                    "fullname": course.get("fullname", "Unknown"),
                    "shortname": course.get("shortname", "Unknown"),
                    "startdate": self.format_date(course.get("startdate", 0)),
                    "enddate": self.format_date(course.get("enddate", 0)),
                    "categoryname": category_name,
                }
                course_details.append(course_data)

            return course_details
        else:
            print(f"Failed to fetch courses. HTTP Status Code: {response.status_code}")
            return []

    def create_user_account(self, username, password, firstname, lastname, email):
        """
        Create a new user account in Moodle.

        :param username: The username for the new account.
        :param password: The password for the new account.
        :param firstname: The first name of the user.
        :param lastname: The last name of the user.
        :param email: The email address of the user.
        :return: Response from the Moodle API.
        """
        params = {
            "wstoken": self.token,
            "wsfunction": "core_user_create_users",
            "moodlewsrestformat": "json",
            "users[0][username]": username,
            "users[0][password]": password,
            "users[0][firstname]": firstname,
            "users[0][lastname]": lastname,
            "users[0][email]": email,
            "users[0][auth]": "manual",  # Manual authentication
        }

        response = requests.post(self.moodle_url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

# Example Usage
# if __name__ == "__main__":
#     # Replace with your Moodle site URL and API token
#     MOODLE_URL = "https://elearning.clickconsulting.com.au"
#     API_TOKEN = "f052d749d880f0c5bfdbfa85787ae7ce"

#     # Initialize the MoodleAPI class
#     moodle_api = MoodleAPI(MOODLE_URL, API_TOKEN)

    # Example 1: Reset a user's password
    # try:
    #     reset_response = moodle_api.reset_user_password("pradeep.dahal222222@gmail.com", "@Churchill321")
    #     print("Password reset response:", reset_response)
    # except Exception as e:
    #     print("Failed to reset password:", e)

    # try:
    #     reset_response = moodle_api.send_password_reset_link("pradeep.dahal222222@gmail.com")
    #     print("Password reset link:", reset_response)
    # except Exception as e:
    #     print("Failed to send password reset link:", e)

    # Example 2: Get all courses
    # try:
    #     courses = moodle_api.get_all_courses()
    #     print("Courses:", courses)
    # except Exception as e:
    #     print("Failed to get courses:", e)
    # try:
    #     resp = moodle_api.enroll_user_in_course("pradeep.dahal222222@gmail.com","Acc Dec")
    #     print("Course ID:", resp)
    # except:
        # pass
    # Example 3: Create a new user account
    # try:
    #     user_response = moodle_api.create_user_account(
    #         username="pradeep222",
    #         password="@Churchill321",
    #         firstname="Pradeep",
    #         lastname="Dahal",
    #         email="pradeep.dahal222222@gmail.com"
    #     )
    #     print("User creation response:", user_response)
    # except Exception as e:
    #     print("Failed to create user:", e)


def generate_strong_password(length=12):
    """
    Generate a strong password with uppercase, lowercase, digits, and special characters.

    :param length: Length of the password (default is 12).
    :return: A randomly generated strong password.
    """
    if length < 8:
        raise ValueError("Password length should be at least 8 characters for security.")

    # Character pools
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_characters = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    # Ensure the password contains at least one of each character type
    all_characters = uppercase + lowercase + digits + special_characters

    # Generate one character from each group to ensure a strong password
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special_characters)
    ]

    # Fill the rest of the password length with random choices from all characters
    password += random.choices(all_characters, k=length - len(password))

    # Shuffle the characters to ensure randomness
    random.shuffle(password)

    return ''.join(password)



def calculate_week_number(start_date, end_date):
    # Convert to datetime if strings are provided
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, "%Y-%m-%d")
    if not start_date:
        return None
    if end_date:
        if end_date < date.today():
            return "Course is over"
    # Calculate the difference in days
    days_difference = (date.today() - start_date).days
    # Calculate the week number (starting from week 1)
    week_number = (days_difference // 7) + 1
    return week_number
