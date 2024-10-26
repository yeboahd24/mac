from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
)

from django.core.validators import MinValueValidator
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .manager import CustomUserManager
from django.db.models import Q
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
import logging

logger = logging.getLogger(__name__)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        _("email address"),
        unique=True,
        db_index=True,
        error_messages={
            "unique": _("A user with that email already exists."),
        },
    )
    username = models.CharField(
        _("username"),
        max_length=255,
        unique=True,
        db_index=True,
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    is_active = models.BooleanField(default=True)
    roles = models.ManyToManyField("Role", through="UserRole")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email", "username"]),
        ]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.username

    def get_short_name(self):
        return self.username


class Role(models.Model):
    name = models.CharField(_("name"), max_length=255, unique=True, db_index=True)
    description = models.TextField(_("description"), blank=True)
    hierarchy_level = models.IntegerField(_("hierarchy level"))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("role")
        verbose_name_plural = _("roles")
        ordering = ["hierarchy_level", "name"]
        indexes = [
            models.Index(fields=["hierarchy_level"]),
        ]

    def __str__(self):
        return f"{self.name} (Level {self.hierarchy_level})"


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("user role")
        verbose_name_plural = _("user roles")
        unique_together = ("user", "role")
        indexes = [
            models.Index(fields=["user", "role"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.role.name}"


class SecurityClearanceLevel(models.Model):
    name = models.CharField(_("name"), max_length=255, unique=True, db_index=True)
    level = models.IntegerField(_("level"), unique=True, db_index=True)
    description = models.TextField(_("description"), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("security clearance level")
        verbose_name_plural = _("security clearance levels")
        ordering = ["level"]
        indexes = [
            models.Index(fields=["level"]),
        ]

    def __str__(self):
        return f"{self.name} (Level {self.level})"


class UserClearance(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="clearances")
    clearance_level = models.ForeignKey(
        SecurityClearanceLevel, on_delete=models.CASCADE
    )
    department = models.ForeignKey("Department", on_delete=models.CASCADE)
    granted_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    granted_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="clearances_granted"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("user clearance")
        verbose_name_plural = _("user clearances")
        ordering = ["-granted_at"]
        indexes = [
            models.Index(fields=["user", "clearance_level", "department"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return (
            f"{self.user.email} - {self.clearance_level.name} ({self.department.name})"
        )

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class Resource(models.Model):
    name = models.CharField(_("name"), max_length=255, db_index=True)
    description = models.TextField(_("description"), blank=True)
    classification_level = models.IntegerField(_("classification level"), db_index=True)
    department = models.ForeignKey("Department", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("resource")
        verbose_name_plural = _("resources")
        ordering = ["name"]
        indexes = [
            models.Index(fields=["classification_level", "department"]),
        ]

    def __str__(self):
        return f"{self.name} (Level {self.classification_level})"


class Action(models.Model):
    name = models.CharField(_("name"), max_length=255, unique=True, db_index=True)
    description = models.TextField(_("description"), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("action")
        verbose_name_plural = _("actions")
        ordering = ["name"]
        indexes = [
            models.Index(fields=["name"]),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        self.name = self.name.lower()  # Normalize action names to lowercase
        super().save(*args, **kwargs)


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="permissions")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    action = models.ForeignKey(Action, on_delete=models.CASCADE)
    required_clearance_level = models.IntegerField(
        _("required clearance level"), validators=[MinValueValidator(0)]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("role permission")
        verbose_name_plural = _("role permissions")
        unique_together = ("role", "resource", "action")
        indexes = [
            models.Index(fields=["role", "resource", "action"]),
            models.Index(fields=["required_clearance_level"]),
        ]

    def __str__(self):
        return f"{self.role.name} - {self.action.name} on {self.resource.name}"

    def clean(self):
        if self.required_clearance_level > self.role.hierarchy_level:
            raise ValidationError(
                {
                    "required_clearance_level": _(
                        "Required clearance level cannot be higher than role hierarchy level"
                    )
                }
            )


class Department(models.Model):
    name = models.CharField(_("name"), max_length=255, unique=True, db_index=True)
    description = models.TextField(_("description"), blank=True)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="subdepartments",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("department")
        verbose_name_plural = _("departments")
        ordering = ["name"]
        indexes = [
            models.Index(fields=["name"]),
        ]

    def __str__(self):
        return self.name

    def get_hierarchy(self):
        hierarchy = [self]
        parent = self.parent
        while parent:
            hierarchy.append(parent)
            parent = parent.parent
        return hierarchy[::-1]

    def clean(self):
        if self.parent == self:
            raise ValidationError({"parent": _("Department cannot be its own parent")})


class AuditLog(models.Model):
    class ResultChoices(models.TextChoices):
        SUCCESS = "success", _("Success")
        FAILURE = "failure", _("Failure")
        ERROR = "error", _("Error")

    user = models.ForeignKey(User, on_delete=models.PROTECT)
    action = models.ForeignKey(Action, on_delete=models.PROTECT)
    resource = models.ForeignKey(
        Resource, on_delete=models.PROTECT, null=True, blank=True
    )
    clearance_level = models.ForeignKey(
        SecurityClearanceLevel, on_delete=models.PROTECT
    )
    department = models.ForeignKey(Department, on_delete=models.PROTECT)
    result = models.CharField(
        max_length=10, choices=ResultChoices.choices, default=ResultChoices.SUCCESS
    )
    reason = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("audit log")
        verbose_name_plural = _("audit logs")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "action", "resource"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["result"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.action.name} - {self.result}"

    @classmethod
    def log(cls, **kwargs):
        try:
            return cls.objects.create(**kwargs)
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
            return None


class Patient(models.Model):
    class GenderChoices(models.TextChoices):
        MALE = "M", _("Male")
        FEMALE = "F", _("Female")
        OTHER = "O", _("Other")
        PREFER_NOT_TO_SAY = "N", _("Prefer not to say")

    first_name = models.CharField(_("first name"), max_length=255)
    last_name = models.CharField(_("last name"), max_length=255)
    date_of_birth = models.DateField(_("date of birth"))
    gender = models.CharField(
        max_length=1,
        choices=GenderChoices.choices,
        default=GenderChoices.PREFER_NOT_TO_SAY,
    )
    department = models.ForeignKey(
        Department, on_delete=models.PROTECT, related_name="patients"
    )
    classification = models.IntegerField(
        _("classification"),
        validators=[MinValueValidator(0)],
        help_text=_("Patient data classification level"),
    )
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="patients_created"
    )
    last_updated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="patients_updated"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("patient")
        verbose_name_plural = _("patients")
        ordering = ["last_name", "first_name"]
        indexes = [
            models.Index(fields=["last_name", "first_name"]),
            models.Index(fields=["date_of_birth"]),
            models.Index(fields=["classification"]),
        ]
        permissions = [
            ("view_sensitive_data", "Can view sensitive patient data"),
            ("export_patient_data", "Can export patient data"),
        ]

    def __str__(self):
        return f"{self.last_name}, {self.first_name}"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @property
    def age(self):
        today = timezone.now().date()
        return (today - self.date_of_birth).days // 365

    def get_medical_history(self):
        return self.medicalrecord_set.all().order_by("-created_at")

    def get_active_prescriptions(self):
        return self.prescription_set.filter(
            Q(end_date__gt=timezone.now()) | Q(end_date__isnull=True)
        )


class MedicalRecord(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.PROTECT)
    doctor = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="medical_records_doctor"
    )
    diagnosis = models.TextField(_("diagnosis"))
    prescription = models.TextField(_("prescription"))
    notes = models.TextField(_("notes"), blank=True)
    attachments = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="medical_records_created"
    )
    last_updated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="medical_records_updated"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("medical record")
        verbose_name_plural = _("medical records")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["patient", "doctor"]),
            models.Index(fields=["created_at"]),
        ]
        permissions = [
            ("modify_diagnosis", "Can modify diagnosis"),
            ("delete_record", "Can delete medical record"),
        ]

    def __str__(self):
        return f"{self.patient.full_name} - {self.created_at.date()}"

    def clean(self):
        if self.created_by.roles.filter(name="doctor").exists():
            raise ValidationError(
                {"created_by": _("Only doctors can create medical records")}
            )


class Prescription(models.Model):
    patient = models.ForeignKey(Patient, on_delete=models.PROTECT)
    doctor = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="prescriptions_doctor"
    )
    medication = models.CharField(_("medication"), max_length=255)
    dosage = models.CharField(_("dosage"), max_length=255)
    instructions = models.TextField(_("instructions"))
    start_date = models.DateField(_("start date"), default=timezone.now)
    end_date = models.DateField(_("end date"), null=True, blank=True)
    refills_remaining = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="prescriptions_created"
    )
    last_updated_by = models.ForeignKey(
        User, on_delete=models.PROTECT, related_name="prescriptions_updated"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("prescription")
        verbose_name_plural = _("prescriptions")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["patient", "doctor"]),
            models.Index(fields=["medication"]),
            models.Index(fields=["start_date", "end_date"]),
        ]

    def __str__(self):
        return f"{self.patient.full_name} - {self.medication}"

    @property
    def is_active(self):
        today = timezone.now().date()
        return (
            self.start_date <= today
            and (self.end_date is None or self.end_date >= today)
            and self.refills_remaining >= 0
        )

    def clean(self):
        if self.end_date and self.end_date < self.start_date:
            raise ValidationError(
                {"end_date": _("End date cannot be before start date")}
            )


# Signal handlers
# NB: Comment out the following lines if you don't want to log user creation (except for superusers)
@receiver(post_save, sender=User)
def create_user_audit_log(sender, instance, created, **kwargs):
    if created:
        AuditLog.objects.create(
            user=instance,
            action=Action.objects.get_or_create(name="user_created")[0],
            result=AuditLog.ResultChoices.SUCCESS,
            reason="User account created",
        )


@receiver(pre_save, sender=MedicalRecord)
def validate_medical_record_changes(sender, instance, **kwargs):
    if instance.pk:
        old_instance = MedicalRecord.objects.get(pk=instance.pk)
        if old_instance.diagnosis != instance.diagnosis:
            if not instance.last_updated_by.roles.filter(name="doctor").exists():
                raise ValidationError(_("Only doctors can modify diagnosis"))


@receiver(post_save, sender=Prescription)
def notify_pharmacy_system(sender, instance, created, **kwargs):
    if created:
        try:
            # Integrate with pharmacy system
            # This is a placeholder for actual integration
            logger.info(f"New prescription created: {instance}")
        except Exception as e:
            logger.error(f"Failed to notify pharmacy system: {str(e)}")


# Managers
class ActivePrescriptionManager(models.Manager):
    def get_queryset(self):
        today = timezone.now().date()
        return (
            super()
            .get_queryset()
            .filter(
                Q(end_date__gte=today) | Q(end_date__isnull=True),
                start_date__lte=today,
                refills_remaining__gte=0,
            )
        )


# Add the manager to Prescription model
Prescription.objects.active = ActivePrescriptionManager()
