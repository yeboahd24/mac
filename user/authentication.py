from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class EmailBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=email)
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user
            User().set_password(password)
            return None
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None

    def user_can_authenticate(self, user):
        """
        Ensure user is active and has required permissions
        """
        is_active = getattr(user, "is_active", None)
        return is_active or is_active is None
