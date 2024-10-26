from django.http import JsonResponse
from django.core.exceptions import PermissionDenied
from .models import AuditLog, Action, Resource, RolePermission
from .token_utils import TokenService
from django.contrib.auth import get_user_model

from django.utils import timezone
from django.db import models
import logging
from django.conf import settings

User = get_user_model()

logger = logging.getLogger(__name__)


class AuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return self.get_response(request)

        try:
            token = auth_header.split(" ")[1]
            payload = TokenService.decode_token(token)
            request.user = User.objects.get(id=payload["user_id"])
        except (IndexError, User.DoesNotExist):
            return JsonResponse({"error": "Invalid token"}, status=401)
        except PermissionDenied as e:
            return JsonResponse({"error": str(e)}, status=401)

        return self.get_response(request)


class ResourcePermissionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        try:
            # Extract resource and action from request
            resource_path = request.path.strip("/")
            action_name = request.method.lower()

            # Skip permission check for non-protected paths
            if resource_path in settings.UNPROTECTED_PATHS:
                return self.get_response(request)

            # Check user permissions
            if not self.check_permission(request.user, resource_path, action_name):
                self.log_access_denied(request, resource_path, action_name)
                raise PermissionDenied("Insufficient permissions")

            self.log_access_granted(request, resource_path, action_name)
            return self.get_response(request)

        except PermissionDenied as e:
            return JsonResponse(
                {
                    "error": str(e),
                    "detail": "You do not have permission to perform this action",
                },
                status=403,
            )
        except Exception as e:
            logger.error(f"Permission middleware error: {str(e)}")
            return JsonResponse({"error": "Internal server error"}, status=500)

    def check_permission(self, user, resource_path, action_name):
        """Check if user has permission to access resource"""
        try:
            # Get resource and action
            resource = Resource.objects.get(name=resource_path)
            action = Action.objects.get(name=action_name)

            # Get user's roles and their permissions
            user_roles = user.roles.all()
            role_permissions = RolePermission.objects.filter(
                role__in=user_roles, resource=resource, action=action
            )

            if not role_permissions.exists():
                return False

            # Check clearance level
            required_clearance = role_permissions.aggregate(
                models.Max("required_clearance_level")
            )["required_clearance_level__max"]

            user_clearances = user.clearances.filter(
                expires_at__gt=timezone.now()
            ).aggregate(models.Max("clearance_level__level"))[
                "clearance_level__level__max"
            ]

            return user_clearances >= required_clearance

        except (Resource.DoesNotExist, Action.DoesNotExist):
            # If resource or action doesn't exist, deny access
            return False
        except Exception as e:
            logger.error(f"Permission check error: {str(e)}")
            return False

    def log_access_denied(self, request, resource_path, action_name):
        """Log denied access attempts"""
        try:
            AuditLog.objects.create(
                user=request.user,
                action=Action.objects.get(name=action_name),
                resource=Resource.objects.get(name=resource_path),
                result="failure",
                reason="Insufficient permissions",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )
        except Exception as e:
            logger.error(f"Access denied logging error: {str(e)}")

    def log_access_granted(self, request, resource_path, action_name):
        """Log successful access"""
        try:
            AuditLog.objects.create(
                user=request.user,
                action=Action.objects.get(name=action_name),
                resource=Resource.objects.get(name=resource_path),
                result="success",
                reason="Access granted",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
            )
        except Exception as e:
            logger.error(f"Access granted logging error: {str(e)}")

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
