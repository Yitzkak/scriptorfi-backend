# tokens.py
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.models import User

def generate_confirmation_token(user):
    """
    Generates a confirmation token for the user.
    """
    # Encode user ID (primary key) for inclusion in a URL-safe base64 string
    uid = urlsafe_base64_encode(str(user.pk).encode())
    # Generate a token for the user (e.g., email verification)
    token = default_token_generator.make_token(user)
    return uid, token
