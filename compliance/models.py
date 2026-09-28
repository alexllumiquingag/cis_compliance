"""
Modelos del sistema de Compliance CIS
"""
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
import os
from decimal import Decimal


# ============================================================
# GESTIÓN DE BENCHMARKS
# ============================================================

class Benchmark(models.Model):
    """Versión de un benchmark CIS subido desde XLSX"""
    name = models.CharField(max_length=255, help_text="Ej: CIS Red Hat Enterprise Linux 8")
    version = models.CharField(max_length=50, help_text="Ej: 1.0.0, 2.0.0")
    file_original = models.FileField(upload_to='benchmarks/', help_text="XLSX original")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.CharField(max_length=255, blank=True)
    
    class Meta:
        ordering = ['-uploaded_at']
        unique_together = ['name', 'version']
    
    def __str__(self):
        return f"{self.name} v{self.version}"


class BenchmarkPolicy(models.Model):
    """Política individual del benchmark (fila del XLSX)"""
    
    PROFILE_CHOICES = [
        ('L1_SERVER', 'Level 1 - Server'),
        ('L2_SERVER', 'Level 2 - Server'),
    ]
    
    benchmark = models.ForeignKey(Benchmark, on_delete=models.CASCADE, related_name='policies')
    
    # Columnas principales del XLSX
    section = models.CharField(max_length=50, help_text="Ej: 1.1.1")
    recommendation = models.CharField(max_length=50, blank=True, help_text="Ej: 1.1.1.1")
    profile = models.CharField(max_length=20, choices=PROFILE_CHOICES)
    title = models.TextField(help_text="Ej: Ensure cramfs kernel module is not available")
    
    # Detalles de la política
    assessment_status = models.CharField(max_length=100, blank=True)
    description = models.TextField(blank=True)
    rationale_statement = models.TextField(blank=True)
    impact_statement = models.TextField(blank=True)
    remediation_procedure = models.TextField(blank=True)
    audit_procedure = models.TextField(blank=True)
    additional_information = models.TextField(blank=True)
    
    # Controles CIS
    cis_controls = models.TextField(blank=True)
    
    # CIS Safeguards v8
    cis_safeguards_1_v8 = models.TextField(blank=True)
    cis_safeguards_2_v8 = models.TextField(blank=True)
    cis_safeguards_3_v8 = models.TextField(blank=True)
    v8_ig1 = models.BooleanField(default=False)
    v8_ig2 = models.BooleanField(default=False)
    v8_ig3 = models.BooleanField(default=False)
    
    # CIS Safeguards v7
    cis_safeguards_1_v7 = models.TextField(blank=True)
    cis_safeguards_2_v7 = models.TextField(blank=True)
    cis_safeguards_3_v7 = models.TextField(blank=True)
    v7_ig1 = models.BooleanField(default=False)
    v7_ig2 = models.BooleanField(default=False)
    v7_ig3 = models.BooleanField(default=False)
    
    # Metadata adicional
    references = models.TextField(blank=True)
    default_value = models.TextField(blank=True)
    
    class Meta:
        ordering = ['section', 'recommendation']
        indexes = [
            models.Index(fields=['section', 'recommendation', 'title']),
        ]
    
    def __str__(self):
        return f"{self.section} {self.recommendation} - {self.title[:50]}"


# ============================================================
# GESTIÓN DE ASSETS
# ============================================================

class Asset(models.Model):
    """Servidor/Host evaluado"""
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Activo'),
        ('INACTIVE', 'Inactivo'),
    ]
    
    # Opciones para Administrador (14 opciones)
    ADMINISTRATOR_CHOICES = [
        ('ADMIN_1', 'Diners'),
        ('ADMIN_2', 'Kyndryl'),
        ('ADMIN_3', 'Pentasec'),
        ('ADMIN_4', 'Cit'),
        ('ADMIN_5', 'Teradata'),
        ('ADMIN_6', 'Xkale'),
        ('ADMIN_7', 'Telalca'),
        ('ADMIN_8', 'Fesa'),
        ('ADMIN_9', 'Century Link'),
        ('ADMIN_10', 'Visa'),
        ('ADMIN_11', 'Mastercard'),
        ('ADMIN_12', 'Vidortec'),
        ('ADMIN_13', 'Eqtek'),
        ('ADMIN_14', 'SecureSoft'),
        ('ADMIN_15', 'DinersClub-Interdin'),
    ]
    
    # Opciones para Responsable (9 opciones)
    RESPONSIBLE_CHOICES = [
        ('RESP_1', 'Grupo BDD'),
        ('RESP_2', 'Grupo Web'),
        ('RESP_3', 'Grupo Admin Servers'),
        ('RESP_4', 'Seguridad'),
        ('RESP_5', 'Comunicaciones'),
        ('RESP_6', 'Pentasec/Infraestructura Diners'),
        ('RESP_7', 'Pentasec'),
        ('RESP_8', 'SegTI - Operaciones y CSIRT'),
        ('RESP_9', 'SEGTI - Operaciones'),
    ]
    
    # Opciones para Ambiente/Entorno
    ENVIRONMENT_CHOICES = [
        ('PRODUCTION', 'Producción'),
        ('DEVELOPMENT', 'Desarrollo'),
        ('CONTINGENCY', 'Contingencia'),
        ('NOPRODUCTION', 'No producción'),
    ]
    
    # Campos básicos
    hostname = models.CharField(max_length=255, unique=True)
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    
    # Nuevos campos
    pci_standard = models.BooleanField(
        default=False, 
        verbose_name='Estándar PCI',
        help_text='¿El asset está sujeto al estándar PCI DSS?'
    )
    
    administrator = models.CharField(
        max_length=50,
        choices=ADMINISTRATOR_CHOICES,
        blank=True,
        verbose_name='Administrador',
        help_text='Administrador del asset'
    )
    
    responsible = models.CharField(
        max_length=50,
        choices=RESPONSIBLE_CHOICES,
        blank=True,
        verbose_name='Responsable',
        help_text='Responsable del asset'
    )
    
    environment = models.CharField(
        max_length=50,
        choices=ENVIRONMENT_CHOICES,
        blank=True,
        verbose_name='Ambiente/Entorno',
        help_text='Ambiente donde opera el asset'
    )
    
    # Inactivación
    deactivated_at = models.DateTimeField(null=True, blank=True)
    deactivation_reason = models.TextField(blank=True, help_text="Razón de inactivación")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['hostname']
        verbose_name = 'Asset'
        verbose_name_plural = 'Assets'
    
    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"
    
    def deactivate(self, reason):
        """Inactiva el asset con razón"""
        self.status = 'INACTIVE'
        self.deactivated_at = timezone.now()
        self.deactivation_reason = reason
        self.save()


class AssetLayer(models.Model):
    """Capa de hardening para un asset (OS, Web, DB)"""
    
    LAYER_TYPES = [
        ('OS', 'Sistema Operativo'),
        ('WEB', 'Servidor Web'),
        ('DB', 'Base de Datos'),
        ('OTHER', 'Otro'),
    ]
    
    # Tipos de Sistema Operativo
    OS_TYPES = [
        ('WINDOWS', 'Windows Server'),
        ('RHEL', 'Red Hat Enterprise Linux'),
        ('AIX', 'IBM AIX'),
        ('VMWARE_ESXI', 'VMware ESXi'),
        ('UBUNTU', 'Ubuntu Server'),
        ('CENTOS', 'CentOS'),
        ('DEBIAN', 'Debian'),
        ('SLES', 'SUSE Linux Enterprise Server'),
        ('OTHER_OS', 'Otro Sistema Operativo'),
    ]
    
    # Tipos de Servidor Web
    WEB_TYPES = [
        ('APACHE', 'Apache HTTP Server'),
        ('TOMCAT', 'Apache Tomcat'),
        ('IIS', 'Microsoft IIS'),
        ('NGINX', 'Nginx'),
        ('JBOSS', 'Red Hat JBoss'),
        ('WEBLOGIC', 'Oracle WebLogic'),
        ('WEBSPHERE', 'IBM WebSphere'),
        ('OTHER_WEB', 'Otro Servidor Web'),
    ]
    
    # Tipos de Base de Datos
    DB_TYPES = [
        ('ORACLE', 'Oracle Database'),
        ('MSSQL', 'Microsoft SQL Server'),
        ('MYSQL', 'MySQL'),
        ('POSTGRESQL', 'PostgreSQL'),
        ('MONGODB', 'MongoDB'),
        ('DB2', 'IBM DB2'),
        ('MARIADB', 'MariaDB'),
        ('OTHER_DB', 'Otra Base de Datos'),
    ]
    
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='layers')
    layer_type = models.CharField(max_length=20, choices=LAYER_TYPES)
    benchmark = models.ForeignKey(Benchmark, on_delete=models.PROTECT)
    
    # Tipo específico de software según la capa
    software_type = models.CharField(
        max_length=50, 
        blank=True,
        help_text="Tipo específico de software (ej: RHEL, Apache, Oracle)"
    )
    
    # Información adicional (versión, detalles)
    description = models.CharField(
        max_length=255, 
        blank=True, 
        help_text="Ej: Apache 2.4.52, MySQL 8.0.28, Windows Server 2019"
    )
    
    class Meta:
        unique_together = ['asset', 'layer_type', 'benchmark']
        ordering = ['asset', 'layer_type']
    
    def __str__(self):
        software_display = self.get_software_type_display() if self.software_type else ''
        if software_display:
            return f"{self.asset.hostname} - {software_display}"
        return f"{self.asset.hostname} - {self.layer_type}"
    
    def get_software_type_display(self):
        """Retorna el nombre legible del tipo de software"""
        if not self.software_type:
            return ''
        
        # Buscar en los choices correspondientes según layer_type
        if self.layer_type == 'OS':
            choices_dict = dict(self.OS_TYPES)
        elif self.layer_type == 'WEB':
            choices_dict = dict(self.WEB_TYPES)
        elif self.layer_type == 'DB':
            choices_dict = dict(self.DB_TYPES)
        else:
            return self.software_type
        
        return choices_dict.get(self.software_type, self.software_type)
    
    def get_available_software_types(self):
        """Retorna los tipos de software disponibles según el layer_type"""
        if self.layer_type == 'OS':
            return self.OS_TYPES
        elif self.layer_type == 'WEB':
            return self.WEB_TYPES
        elif self.layer_type == 'DB':
            return self.DB_TYPES
        return []
    
    def clean(self):
        """Validación personalizada"""
        from django.core.exceptions import ValidationError
        
        # Validar que software_type sea válido para el layer_type
        if self.software_type and self.layer_type != 'OTHER':
            valid_types = [code for code, _ in self.get_available_software_types()]
            if self.software_type not in valid_types:
                raise ValidationError({
                    'software_type': f'El tipo de software "{self.software_type}" no es válido para {self.get_layer_type_display()}'
                })


# ============================================================
# ESCANEOS Y RESULTADOS
# ============================================================

class Scan(models.Model):
    """Escaneo de Nessus procesado"""
    
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scans')
    layer = models.ForeignKey(AssetLayer, on_delete=models.CASCADE, related_name='scans')
    
    # Fechas importantes
    scan_date = models.DateField(help_text="Fecha del escaneo (para comparación mensual)")
    upload_date = models.DateTimeField(auto_now_add=True, help_text="Fecha de carga al sistema")
    
    # Archivo CSV original
    csv_file = models.FileField(upload_to='scans/')
    
    # Métricas calculadas
    total_policies = models.IntegerField(default=0)
    passed_count = models.IntegerField(default=0)
    failed_count = models.IntegerField(default=0)
    warning_count = models.IntegerField(default=0)
    compliance_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    class Meta:
        ordering = ['-scan_date']
        indexes = [
            models.Index(fields=['asset', 'layer', '-scan_date']),
        ]
    
    def __str__(self):
        return f"{self.asset.hostname} - {self.layer.layer_type} - {self.scan_date}"
    
    def calculate_compliance(self):
        if self.total_policies == 0:
            return Decimal('0.00')
        
        compliance = (self.passed_count / self.total_policies) * 100
        return Decimal(str(round(compliance, 2)))


class ScanResult(models.Model):
    """Resultado individual de una política en un escaneo"""
    
    RISK_CHOICES = [
        ('PASSED', 'Passed'),
        ('FAILED', 'Failed'),
        ('WARNING', 'Warning'),
        ('INFO', 'Informational'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='results')
    policy = models.ForeignKey(BenchmarkPolicy, on_delete=models.CASCADE, related_name='results')
    
    # Datos del CSV de Nessus
    plugin_id = models.CharField(max_length=50)
    risk = models.CharField(max_length=20, choices=RISK_CHOICES)
    description = models.TextField()
    plugin_output = models.TextField(help_text="Contiene hostname y detalles técnicos")
    
    class Meta:
        unique_together = ['scan', 'policy']
        indexes = [
            models.Index(fields=['scan', 'risk']),
        ]
    
    def __str__(self):
        return f"{self.scan} - {self.policy.section} [{self.risk}]"


# ============================================================
# LÍNEAS BASE
# ============================================================

class Baseline(models.Model):
    """Línea base de compliance por asset/capa"""
    
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='baselines')
    layer = models.ForeignKey(AssetLayer, on_delete=models.CASCADE, related_name='baselines')
    
    # Valor de línea base
    compliance_percentage = models.DecimalField(max_digits=5, decimal_places=2)
    scan_reference = models.ForeignKey(Scan, on_delete=models.SET_NULL, null=True, blank=True,
                                       help_text="Escaneo que estableció esta línea base")
    
    # Control de modificación
    is_manual = models.BooleanField(default=False, help_text="¿Fue modificada manualmente?")
    set_at = models.DateTimeField(auto_now_add=True)
    set_by = models.CharField(max_length=255, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        unique_together = ['asset', 'layer']
    
    def __str__(self):
        return f"{self.asset.hostname} - {self.layer.layer_type}: {self.compliance_percentage}%"


# ============================================================
# EXCLUSIONES
# ============================================================

def exclusion_file_path(instance, filename):
    """Genera path para archivos de justificación"""
    return f'exclusions/{instance.__class__.__name__}/{instance.id}/{filename}'


class GlobalExclusion(models.Model):
    """Exclusión global de una política para todos los assets"""
    
    policy = models.ForeignKey(BenchmarkPolicy, on_delete=models.CASCADE, related_name='global_exclusions')
    benchmark = models.ForeignKey(Benchmark, on_delete=models.CASCADE)
    
    # Justificación
    reason = models.TextField(help_text="Control compensatorio u otra razón")
    justification_file = models.FileField(upload_to=exclusion_file_path, blank=True, null=True,
                                          help_text="PDF, PNG, JPG, DOCX, EML - Max 10MB")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['policy', 'benchmark']
    
    def __str__(self):
        return f"Exclusión Global: {self.policy}"


class AssetExclusion(models.Model):
    """Exclusión de una política para un asset específico"""
    
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='exclusions')
    policy = models.ForeignKey(BenchmarkPolicy, on_delete=models.CASCADE, related_name='asset_exclusions')
    layer = models.ForeignKey(AssetLayer, on_delete=models.CASCADE, related_name='exclusions')
    
    # Justificación
    reason = models.TextField(help_text="Control compensatorio u otra razón específica del asset")
    justification_file = models.FileField(upload_to=exclusion_file_path, blank=True, null=True,
                                          help_text="PDF, PNG, JPG, DOCX, EML - Max 10MB")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['asset', 'policy', 'layer']
    
    def __str__(self):
        return f"Exclusión {self.asset.hostname}: {self.policy}"


# ============================================================
# CONFIGURACIÓN Y UMBRALES
# ============================================================

class Threshold(models.Model):
    """Umbrales parametrizables del sistema"""
    
    name = models.CharField(max_length=100, unique=True)
    value = models.DecimalField(max_digits=5, decimal_places=2, 
                                validators=[MinValueValidator(0), MaxValueValidator(100)])
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name}: {self.value}%"
    
    @classmethod
    def get_hardening_threshold(cls):
        threshold, created = cls.objects.get_or_create(
            name='hardening_threshold',
            defaults={'value': Decimal('90.00'), 'description': 'Umbral mínimo para considerar un asset hardenizado'}
        )
        return Decimal(str(threshold.value))


# ============================================================
# ALERTAS
# ============================================================

class Alert(models.Model):
    """Alertas generadas por el sistema"""
    
    ALERT_TYPES = [
        ('BASELINE_DROP', 'Caída de línea base'),
        ('POLICY_FAILED', 'Política cambió a FAILED'),
        ('THRESHOLD_DROP', 'Caída bajo umbral'),
        ('CRITICAL_DROP', 'Degradación crítica (>5%)'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Baja'),
        ('MEDIUM', 'Media'),
        ('HIGH', 'Alta'),
        ('CRITICAL', 'Crítica'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Activa'),
        ('ACKNOWLEDGED', 'Reconocida'),
        ('RESOLVED', 'Resuelta'),
    ]
    
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    
    # Referencias
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='alerts')
    layer = models.ForeignKey(AssetLayer, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='alerts')
    
    # Detalles
    title = models.CharField(max_length=255)
    message = models.TextField()
    previous_value = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    current_value = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.CharField(max_length=255, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity', '-created_at']),
        ]
    
    def __str__(self):
        return f"[{self.severity}] {self.title}"