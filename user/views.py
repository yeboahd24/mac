from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
import json
import logging
from .models import AuditLog, Action
from .token_utils import TokenService

logger = logging.getLogger(__name__)


# @method_decorator(csrf_exempt, name="dispatch")
# class LoginView(View):
#     def post(self, request, *args, **kwargs):
#         """
#         Handle user login and return authentication tokens.
#         Args:
#             request: HTTP request object
#         Returns:
#             JsonResponse with tokens and user data or error message
#         """
#         try:
#             # Parse JSON data from request body
#             try:
#                 data = json.loads(request.body)
#                 email = data.get("email")
#                 password = data.get("password")
#             except json.JSONDecodeError:
#                 return JsonResponse(
#                     {"error": "Invalid JSON format in request body"}, status=400
#                 )
#
#             # Validate required fields
#             # if not email or not password:
#             #     self._log_audit(
#             #         None,
#             #         "login_attempt",
#             #         AuditLog.ResultChoices.FAILURE,
#             #         "Missing email or password",
#             #     )
#             #     return JsonResponse(
#             #         {"error": "Both email and password are required"}, status=400
#             #     )
#             #
#             # Authenticate user
#             user = authenticate(request, email=email, password=password)
#             print(user.roles.all())
#             # print(user.clearances.all())
#             # get user department from the clearances
#             if user.clearances.all():
#                 user_department = user.clearances.all()[0].department
#                 user_clearance = user.clearances.all()[0].clearance_level
#                 print(user_clearance)
#                 print(user_department)
#             # if not user:
#             #     self._log_audit(
#             #         None,
#             #         "login_attempt",
#             #         AuditLog.ResultChoices.FAILURE,
#             #         "Invalid credentials",
#             #         extra_data={"email": email},
#             #     )
#             #     return JsonResponse({"error": "Invalid credentials"}, status=401)
#             #
#             # Check if user is active
#             # if not user.is_active:
#             #     self._log_audit(
#             #         user,
#             #         "login_attempt",
#             #         AuditLog.ResultChoices.FAILURE,
#             #         "Account is not active",
#             #     )
#             #     return JsonResponse({"error": "Account is not active"}, status=401)
#             #
#             # Generate tokens
#             access_token = TokenService.generate_access_token(user)
#             refresh_token = TokenService.generate_refresh_token(user)
#
#             # Log successful login
#             # self._log_audit(
#             #     user,
#             #     "login_attempt",
#             #     AuditLog.ResultChoices.SUCCESS,
#             #     "User logged in successfully",
#             # )
#
#             # Return success response
#             return JsonResponse(
#                 {
#                     "access_token": access_token,
#                     "refresh_token": refresh_token,
#                     "user": {
#                         "id": user.id,
#                         "email": user.email,
#                         "username": user.username,
#                     },
#                 }
#             )
#         except Exception as e:
#             logger.error(f"Login error: {str(e)}")
#             # self._log_audit(
#             #     None,
#             #     "login_attempt",
#             #     AuditLog.ResultChoices.FAILURE,
#             #     f"System error: {str(e)}",
#             # )
#             return JsonResponse({"error": "An error occurred during login"}, status=500)
#
#     # def _log_audit(self, user, action_name, result, reason, extra_data=None):
#     #     """
#     #     Helper method to create audit log entries.
#     #     """
#     #     try:
#     #         action, _ = Action.objects.get_or_create(
#     #             name=action_name, defaults={"description": "User login attempt"}
#     #         )
#     #
#     #         audit_data = {
#     #             "user": user,
#     #             "action": action,
#     #             "result": result,
#     #             "reason": reason,
#     #         }
#     #
#     #         if extra_data:
#     #             audit_data["extra_data"] = extra_data
#     #
#     #         AuditLog.objects.create(**audit_data)
#     #     except Exception as e:
#     #         logger.error(f"Error creating audit log: {str(e)}")
#     #
#     #
#
#
@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    def post(self, request, *args, **kwargs):
        """
        Handle user login and return authentication tokens.
        """
        # Initialize variables at the beginning
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        login_action, _ = Action.objects.get_or_create(
            name="login_attempt", defaults={"description": "User login attempt"}
        )
        try:
            # Get or create required resources for audit logging
            # login_action, _ = Action.objects.get_or_create(
            #     name="login_attempt", defaults={"description": "User login attempt"}
            # )
            # login_resource, _ = Resource.objects.get_or_create(
            #     name="authentication", defaults={"description": "Authentication system"}
            # )
            # default_clearance, _ = SecurityClearanceLevel.objects.get_or_create(
            #     name="default", defaults={"description": "Default clearance level"}
            # )
            # default_department, _ = Department.objects.get_or_create(
            #     name="default", defaults={"description": "Default department"}
            # )

            try:
                data = json.loads(request.body)
                email = data.get("email")
                password = data.get("password")

                user = authenticate(request, email=email, password=password)
                # get user department from the clearances
                if user.clearances.all():
                    user_department = user.clearances.all()[0].department
                    user_clearance = user.clearances.all()[0].clearance_level
                    print(user_clearance)
                    print(user_department)

            except json.JSONDecodeError:
                self._create_audit_log(
                    user=user,
                    action=login_action,
                    resource=None,
                    clearance_level=user_clearance,
                    department=user_department,
                    result=AuditLog.ResultChoices.ERROR,
                    reason="Invalid JSON format in request body",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                return JsonResponse(
                    {"error": "Invalid JSON format in request body"}, status=400
                )

            if not email or not password:
                self._create_audit_log(
                    user=user,
                    action=login_action,
                    resource=None,
                    clearance_level=user_clearance,
                    department=user_department,
                    result=AuditLog.ResultChoices.FAILURE,
                    reason="Missing email or password",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                return JsonResponse(
                    {"error": "Both email and password are required"}, status=400
                )

            user = authenticate(request, email=email, password=password)
            if not user:
                self._create_audit_log(
                    user=user,
                    action=login_action,
                    resource=None,
                    clearance_level=user_clearance,
                    department=user_department,
                    result=AuditLog.ResultChoices.FAILURE,
                    reason="Invalid credentials",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                return JsonResponse({"error": "Invalid credentials"}, status=401)

            if not user.is_active:
                self._create_audit_log(
                    user=user,
                    action=login_action,
                    resource=None,
                    clearance_level=user_clearance,
                    department=user_department,
                    result=AuditLog.ResultChoices.FAILURE,
                    reason="Account is not active",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                return JsonResponse({"error": "Account is not active"}, status=401)

            # Generate tokens
            access_token = TokenService.generate_access_token(user)
            refresh_token = TokenService.generate_refresh_token(user)

            # Log successful login
            self._create_audit_log(
                user=user,
                action=login_action,
                resource=None,
                clearance_level=user_clearance,
                department=user_department,
                result=AuditLog.ResultChoices.SUCCESS,
                reason="User logged in successfully",
                ip_address=ip_address,
                user_agent=user_agent,
            )

            return JsonResponse(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "username": user.username,
                    },
                }
            )

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            try:
                self._create_audit_log(
                    user=user,
                    action=login_action,
                    resource=None,
                    clearance_level=user_clearance,
                    department=user_department,
                    result=AuditLog.ResultChoices.ERROR,
                    reason=f"System error: {str(e)}",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
            except Exception as inner_e:
                logger.error(f"Failed to create audit log for error: {str(inner_e)}")

            return JsonResponse({"error": "An error occurred during login"}, status=500)

    def _create_audit_log(self, **kwargs):
        """
        Helper method to create audit log entries using the model's log method.
        """
        try:
            AuditLog.log(**kwargs)
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")

    def get_client_ip(self, request):
        """
        Get client IP address from request
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
