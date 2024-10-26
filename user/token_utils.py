from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from datetime import datetime, timedelta
import jwt
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class TokenService:
    @staticmethod
    def generate_access_token(user):
        """Generate JWT access token for user"""
        try:
            payload = {
                "user_id": user.id,
                "email": user.email,
                "exp": datetime.utcnow()
                + timedelta(minutes=settings.ACCESS_TOKEN_LIFETIME),
                "iat": datetime.utcnow(),
            }

            token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")

            return token
        except Exception as e:
            logger.error(f"Token generation error: {str(e)}")
            return None

    @staticmethod
    def generate_refresh_token(user):
        """Generate JWT refresh token for user"""
        try:
            payload = {
                "user_id": user.id,
                "exp": datetime.utcnow()
                + timedelta(days=settings.REFRESH_TOKEN_LIFETIME),
                "iat": datetime.utcnow(),
            }

            token = jwt.encode(
                payload, settings.JWT_REFRESH_SECRET_KEY, algorithm="HS256"
            )

            return token
        except Exception as e:
            logger.error(f"Refresh token generation error: {str(e)}")
            return None

    @staticmethod
    def decode_token(token):
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            raise PermissionDenied("Token has expired")
        except jwt.InvalidTokenError:
            raise PermissionDenied("Invalid token")
        except Exception as e:
            logger.error(f"Token decode error: {str(e)}")
            raise PermissionDenied("Token validation failed")
