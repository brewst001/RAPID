from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class CaseInsensitiveModelBackend(ModelBackend):

    def authenticate(email=None, password=None, **kwargs):
        """
        Created by LNguyen(
        Date: 14Dec2017
        Description: Method to handle backend authentication for case insensitive usernames
        If the given credentials are valid, return a User object.
        """
        UserModel = get_user_model()

        if email is None:
            email=kwargs.get(UserModel.email)

        try:
            user=UserModel.objects.get(email__iexact=email)
            user.backend = 'profiles.backends.CaseInsensitiveModelBackend'
            if user.check_password(password):
                return user

        except UserModel.DoesNotExist:
            # This backend doesn't accept these credentials as arguments. Try the next one.
            UserModel().set_password(password)

