"""
Configuración del panel de administración de Django
"""
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Avg
from django import forms
from compliance.services.benchmark_service import BenchmarkImportService
from compliance.services.nessus_bulk_service import NessusBulkImportService
from compliance.services.nessus_service import NessusImportService
from compliance.models import (
    Benchmark, BenchmarkPolicy, Asset, AssetLayer, Scan, ScanResult,
    Baseline, GlobalExclusion, AssetExclusion, Threshold, Alert
)


# ============================================================
# BENCHMARKS
# ============================================================

class BenchmarkPolicyInline(admin.TabularInline):
    model = BenchmarkPolicy
    extra = 0
    fields = ('section', 'recommendation', 'profile', 'title')
    readonly_fields = fields
    can_delete = False
    show_change_link = True
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Benchmark)
class BenchmarkAdmin(admin.ModelAdmin):
    list_display = ['name', 'version', 'uploaded_at', 'policy_count', 'file_link']
    list_filter = ['name', 'uploaded_at']
    search_fields = ['name', 'version']
    readonly_fields = ['uploaded_at']
    inlines = [BenchmarkPolicyInline]
    
    def save_model(self, request, obj, form, change):
        """Override para procesar el XLSX al crear el benchmark"""
        
        if not change:
            file = form.cleaned_data.get('file_original')
            
            if file:
                try:
                    service = BenchmarkImportService()
                    benchmark, stats = service.import_benchmark(
                        file=file,
                        benchmark_name=obj.name,
                        version=obj.version,
                        uploaded_by=request.user.username
                    )
                    
                    self.message_user(
                        request,
                        f'Benchmark importado: {stats["imported"]} políticas creadas, '
                        f'{stats["skipped"]} omitidas, {stats["errors"]} errores',
                        level='SUCCESS' if stats['errors'] == 0 else 'WARNING'
                    )
                    
                    report = service.get_report()
                    if report['warnings']:
                        for warning in report['warnings'][:5]:
                            self.message_user(request, warning, level='WARNING')
                    
                    if report['errors']:
                        for error in report['errors'][:5]:
                            self.message_user(request, error, level='ERROR')
                    
                except Exception as e:
                    self.message_user(
                        request,
                        f'Error al importar benchmark: {str(e)}',
                        level='ERROR'
                    )
                    return
        else:
            super().save_model(request, obj, form, change)

    def policy_count(self, obj):
        return obj.policies.count()
    policy_count.short_description = 'Políticas'
    
    def file_link(self, obj):
        if obj.file_original:
            return format_html('<a href="{}" target="_blank">Descargar XLSX</a>', obj.file_original.url)
        return '-'
    file_link.short_description = 'Archivo'


@admin.register(BenchmarkPolicy)
class BenchmarkPolicyAdmin(admin.ModelAdmin):
    list_display = ['section', 'recommendation', 'profile', 'title_short', 'benchmark']
    list_filter = ['benchmark', 'profile', 'v8_ig1', 'v8_ig2', 'v8_ig3']
    search_fields = ['section', 'recommendation', 'title', 'description']
    readonly_fields = ['benchmark', 'section', 'recommendation', 'profile', 'title',
                       'assessment_status', 'description', 'rationale_statement', 
                       'impact_statement', 'remediation_procedure', 'audit_procedure',
                       'additional_information', 'cis_controls', 'cis_safeguards_1_v8',
                       'cis_safeguards_2_v8', 'cis_safeguards_3_v8', 'v8_ig1', 'v8_ig2', 'v8_ig3',
                       'cis_safeguards_1_v7', 'cis_safeguards_2_v7', 'cis_safeguards_3_v7',
                       'v7_ig1', 'v7_ig2', 'v7_ig3', 'references', 'default_value']
    
    fieldsets = (
        ('Identificación', {
            'fields': ('benchmark', 'section', 'recommendation', 'profile', 'title')
        }),
        ('Estado', {
            'fields': ('assessment_status',)
        }),
        ('Detalles', {
            'fields': ('description', 'rationale_statement', 'impact_statement'),
            'classes': ('collapse',)
        }),
        ('Procedimientos', {
            'fields': ('audit_procedure', 'remediation_procedure', 'additional_information'),
            'classes': ('collapse',)
        }),
        ('CIS Safeguards v8', {
            'fields': ('cis_safeguards_1_v8', 'cis_safeguards_2_v8', 'cis_safeguards_3_v8',
                      'v8_ig1', 'v8_ig2', 'v8_ig3'),
            'classes': ('collapse',)
        }),
        ('CIS Safeguards v7', {
            'fields': ('cis_safeguards_1_v7', 'cis_safeguards_2_v7', 'cis_safeguards_3_v7',
                      'v7_ig1', 'v7_ig2', 'v7_ig3'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('cis_controls', 'references', 'default_value'),
            'classes': ('collapse',)
        }),
    )
    
    def title_short(self, obj):
        return obj.title[:60] + '...' if len(obj.title) > 60 else obj.title
    title_short.short_description = 'Título'
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


# ============================================================
# ASSETS
# ============================================================

# Formulario personalizado para AssetLayer en el admin
class AssetLayerAdminForm(forms.ModelForm):
    class Meta:
        model = AssetLayer
        fields = '__all__'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Configurar opciones de software_type con optgroups (TODOS los tipos organizados)
        self._set_software_type_choices_with_optgroups()
    
    def _set_software_type_choices_with_optgroups(self):
        """
        Configura las opciones de software_type con optgroups
        para mostrar TODAS las opciones organizadas por categoría
        """
        
        # Crear choices con optgroups
        choices = [('', '--- Seleccione tipo de software ---')]
        
        # Grupo: Sistemas Operativos
        os_choices = list(AssetLayer.OS_TYPES)
        
        # Grupo: Servidores Web
        web_choices = list(AssetLayer.WEB_TYPES)
        
        # Grupo: Bases de Datos
        db_choices = list(AssetLayer.DB_TYPES)
        
        # Agregar los grupos (optgroups)
        if os_choices:
            choices.append(('🖥️ Sistemas Operativos', os_choices))
        if web_choices:
            choices.append(('🌐 Servidores Web', web_choices))
        if db_choices:
            choices.append(('🗄️ Bases de Datos', db_choices))
        
        self.fields['software_type'].widget = forms.Select(choices=choices)
    
    def clean(self):
        cleaned_data = super().clean()
        layer_type = cleaned_data.get('layer_type')
        software_type = cleaned_data.get('software_type')
        
        # Validar que software_type sea válido para el layer_type
        if layer_type and software_type:
            # Obtener códigos válidos según el layer_type
            if layer_type == 'OS':
                valid_codes = [code for code, _ in AssetLayer.OS_TYPES]
                type_name = 'Sistema Operativo'
            elif layer_type == 'WEB':
                valid_codes = [code for code, _ in AssetLayer.WEB_TYPES]
                type_name = 'Servidor Web'
            elif layer_type == 'DB':
                valid_codes = [code for code, _ in AssetLayer.DB_TYPES]
                type_name = 'Base de Datos'
            else:
                valid_codes = []
                type_name = layer_type
            
            # Validar que el software_type esté en la lista válida
            if software_type and software_type not in valid_codes:
                # Obtener el nombre del software para un mensaje más claro
                all_types = dict(AssetLayer.OS_TYPES + AssetLayer.WEB_TYPES + AssetLayer.DB_TYPES)
                software_name = all_types.get(software_type, software_type)
                
                raise forms.ValidationError({
                    'software_type': (
                        f'"{software_name}" no es válido para "{type_name}". '
                        f'Por favor seleccione una opción del grupo correcto.'
                    )
                })
        
        return cleaned_data


class AssetLayerInline(admin.TabularInline):
    model = AssetLayer
    form = AssetLayerAdminForm
    extra = 1
    fields = ('layer_type', 'software_type', 'benchmark', 'description')


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = [
        'hostname', 'ip_address', 'environment_badge', 'pci_badge', 
        'status_badge', 'layer_count', 'scan_count', 'created_at'
    ]
    list_filter = ['status', 'pci_standard', 'environment', 'administrator', 'responsible', 'created_at']
    search_fields = ['hostname', 'ip_address']
    readonly_fields = ['created_at', 'updated_at', 'deactivated_at']
    inlines = [AssetLayerInline]
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('hostname', 'ip_address', 'status')
        }),
        ('Clasificación y Responsabilidad', {
            'fields': ('pci_standard', 'environment', 'administrator', 'responsible'),
            'description': 'Información de clasificación y responsables del asset'
        }),
        ('Inactivación', {
            'fields': ('deactivation_reason', 'deactivated_at'),
            'classes': ('collapse',)
        }),
        ('Auditoría', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def status_badge(self, obj):
        if obj.status == 'ACTIVE':
            color = 'green'
            icon = '✓'
        else:
            color = 'red'
            icon = '✗'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{} {}</span>',
            color, icon, obj.get_status_display()
        )
    status_badge.short_description = 'Estado'
    
    def pci_badge(self, obj):
        """Badge para indicar si cumple con estándar PCI"""
        if obj.pci_standard:
            return format_html(
                '<span style="background-color: #2196F3; color: white; padding: 2px 8px; '
                'border-radius: 3px; font-size: 11px; font-weight: bold;">PCI</span>'
            )
        return format_html('<span style="color: #999;">-</span>')
    pci_badge.short_description = 'PCI'
    
    def environment_badge(self, obj):
        """Badge para el ambiente/entorno"""
        if not obj.environment:
            return '-'
        
        # Colores según ambiente
        color_map = {
            'PRODUCTION': '#D32F2F',      # Rojo para producción
            'CONTINGENCY': '#FF9800',      # Naranja para contingencia
            'DEVELOPMENT': '#4CAF50',      # Verde para desarrollo
            'NOPRODUCTION': '#9C27B0',          # Morado no producción
        }
        
        color = color_map.get(obj.environment, '#9E9E9E')
        display = obj.get_environment_display()
        
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; '
            'border-radius: 3px; font-size: 11px; font-weight: bold;">{}</span>',
            color, display
        )
    environment_badge.short_description = 'Ambiente'
    
    def layer_count(self, obj):
        return obj.layers.count()
    layer_count.short_description = 'Capas'
    
    def scan_count(self, obj):
        return obj.scans.count()
    scan_count.short_description = 'Escaneos'
    
    actions = ['deactivate_assets']
    
    def deactivate_assets(self, request, queryset):
        for asset in queryset:
            if asset.status == 'ACTIVE':
                asset.deactivate('Inactivado desde admin')
        self.message_user(request, f'{queryset.count()} assets inactivados')
    deactivate_assets.short_description = 'Inactivar assets seleccionados'


@admin.register(AssetLayer)
class AssetLayerAdmin(admin.ModelAdmin):
    form = AssetLayerAdminForm
    list_display = ['asset', 'layer_type', 'software_type_display', 'benchmark', 'description', 'scan_count']
    list_filter = ['layer_type', 'software_type', 'benchmark']
    search_fields = ['asset__hostname', 'description']
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('asset', 'layer_type', 'software_type', 'benchmark')
        }),
        ('Detalles', {
            'fields': ('description',)
        }),
    )
    
    def software_type_display(self, obj):
        """Muestra el nombre legible del tipo de software"""
        if obj.software_type:
            display = obj.get_software_type_display()
            # Agregar color según el tipo
            if obj.layer_type == 'OS':
                color = '#2196F3'  # Azul
            elif obj.layer_type == 'WEB':
                color = '#4CAF50'  # Verde
            elif obj.layer_type == 'DB':
                color = '#FF9800'  # Naranja
            else:
                color = '#9E9E9E'  # Gris
            
            return format_html(
                '<span style="background-color: {}; color: white; padding: 2px 8px; '
                'border-radius: 3px; font-size: 11px; font-weight: bold;">{}</span>',
                color, display
            )
        return '-'
    software_type_display.short_description = 'Tipo de Software'
    
    def scan_count(self, obj):
        return obj.scans.count()
    scan_count.short_description = 'Escaneos'


# ============================================================
# ESCANEOS
# ============================================================

class ScanResultInline(admin.TabularInline):
    model = ScanResult
    extra = 0
    fields = ('policy', 'risk', 'plugin_id')
    readonly_fields = fields
    can_delete = False
    show_change_link = True
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['asset', 'layer', 'scan_date', 'compliance_badge', 'passed', 'failed', 'warning', 'upload_date']
    list_filter = ['scan_date', 'layer__layer_type', 'asset']
    search_fields = ['asset__hostname']
    readonly_fields = ['upload_date', 'total_policies', 'passed_count', 'failed_count', 'warning_count', 'compliance_percentage']
    date_hierarchy = 'scan_date'
    inlines = [ScanResultInline]
    
    fieldsets = (
        ('Escaneo', {
            'fields': ('asset', 'layer', 'scan_date', 'csv_file')
        }),
        ('Resultados', {
            'fields': ('total_policies', 'passed_count', 'failed_count', 'warning_count', 'compliance_percentage'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('upload_date',),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        """Override para procesar el CSV de Nessus al crear el scan"""
        
        if not change:
            asset = form.cleaned_data.get('asset')
            layer = form.cleaned_data.get('layer')
            scan_date = form.cleaned_data.get('scan_date')
            csv_file = form.cleaned_data.get('csv_file')
            
            if csv_file and asset and layer and scan_date:
                try:
                    service = NessusImportService()
                    scan, stats = service.import_nessus_scan(
                        file=csv_file,
                        asset=asset,
                        layer=layer,
                        scan_date=scan_date
                    )
                    
                    self.message_user(
                        request,
                        f'Scan importado exitosamente: '
                        f'{stats["imported"]} resultados importados, '
                        f'{stats["matched"]} políticas matcheadas, '
                        f'{stats["unmatched"]} no matcheadas, '
                        f'{stats["filtered_info"]} informativos filtrados',
                        level='SUCCESS' if stats['errors'] == 0 else 'WARNING'
                    )
                    
                    if stats.get('hosts_found'):
                        self.message_user(
                            request,
                            f'Hosts encontrados en CSV: {", ".join(stats["hosts_found"])}',
                            level='INFO'
                        )
                    
                    report = service.get_report()
                    if report['warnings']:
                        warning_count = len(report['warnings'])
                        self.message_user(
                            request, 
                            f'{warning_count} advertencias durante la importación. Revisa los logs para detalles.',
                            level='WARNING'
                        )
                        for warning in report['warnings'][:3]:
                            self.message_user(request, f'⚠️ {warning}', level='WARNING')
                    
                    if report['errors']:
                        for error in report['errors'][:3]:
                            self.message_user(request, f'❌ {error}', level='ERROR')
                    
                    self.message_user(
                        request,
                        f'Compliance calculado: {scan.compliance_percentage}% '
                        f'(Passed: {scan.passed_count}, Failed: {scan.failed_count}, Warning: {scan.warning_count})',
                        level='INFO'
                    )
                    
                except Exception as e:
                    self.message_user(
                        request,
                        f'Error al importar scan: {str(e)}',
                        level='ERROR'
                    )
                    return
            else:
                self.message_user(
                    request,
                    'Faltan datos requeridos para procesar el scan',
                    level='ERROR'
                )
                return
        else:
            super().save_model(request, obj, form, change)
    
    def compliance_badge(self, obj):
        color = 'green' if obj.compliance_percentage >= 90 else 'orange' if obj.compliance_percentage >= 70 else 'red'
        formatted_value = f"{obj.compliance_percentage:.2f}"
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px; font-weight: bold;">{}%</span>',
            color, formatted_value
        )
    compliance_badge.short_description = 'Compliance'
    
    def passed(self, obj):
        return format_html('<span style="color: green; font-weight: bold;">{}</span>', obj.passed_count)
    passed.short_description = 'Passed'
    
    def failed(self, obj):
        return format_html('<span style="color: red; font-weight: bold;">{}</span>', obj.failed_count)
    failed.short_description = 'Failed'
    
    def warning(self, obj):
        return format_html('<span style="color: orange; font-weight: bold;">{}</span>', obj.warning_count)
    warning.short_description = 'Warning'
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['scan_info', 'policy_info', 'risk_badge', 'plugin_id']
    list_filter = ['risk', 'scan__scan_date', 'scan__layer__layer_type']
    search_fields = ['scan__asset__hostname', 'policy__title', 'plugin_id']
    readonly_fields = ['scan', 'policy', 'plugin_id', 'risk', 'description', 'plugin_output']
    
    def scan_info(self, obj):
        return f"{obj.scan.asset.hostname} - {obj.scan.scan_date}"
    scan_info.short_description = 'Escaneo'
    
    def policy_info(self, obj):
        return f"{obj.policy.section} {obj.policy.recommendation} - {obj.policy.title[:50]}"
    policy_info.short_description = 'Política'
    
    def risk_badge(self, obj):
        colors = {
            'PASSED': 'green',
            'FAILED': 'red',
            'WARNING': 'orange',
            'INFO': 'gray'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">{}</span>',
            colors.get(obj.risk, 'gray'), obj.get_risk_display()
        )
    risk_badge.short_description = 'Estado'


# ============================================================
# LÍNEAS BASE
# ============================================================

@admin.register(Baseline)
class BaselineAdmin(admin.ModelAdmin):
    list_display = ['asset', 'layer', 'compliance_badge', 'is_manual', 'scan_reference', 'set_at']
    list_filter = ['is_manual', 'set_at', 'layer__layer_type']
    search_fields = ['asset__hostname']
    readonly_fields = ['set_at']
    date_hierarchy = 'set_at'
    
    def compliance_badge(self, obj):
        color = 'green' if obj.compliance_percentage >= 90 else 'orange' if obj.compliance_percentage >= 70 else 'red'
        formatted_value = f"{obj.compliance_percentage:.2f}"
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px; font-weight: bold;">{}%</span>',
            color, formatted_value
        )
    compliance_badge.short_description = 'Línea Base'


# ============================================================
# EXCLUSIONES
# ============================================================

@admin.register(GlobalExclusion)
class GlobalExclusionAdmin(admin.ModelAdmin):
    list_display = ['policy_info', 'benchmark', 'is_active', 'created_at', 'file_link']
    list_filter = ['is_active', 'created_at', 'benchmark']
    search_fields = ['policy__title', 'reason']
    readonly_fields = ['created_at']
    
    fieldsets = (
        ('Política Excluida', {
            'fields': ('policy', 'benchmark', 'is_active')
        }),
        ('Justificación', {
            'fields': ('reason', 'justification_file')
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by')
        }),
    )
    
    def policy_info(self, obj):
        return f"{obj.policy.section} {obj.policy.recommendation} - {obj.policy.title[:50]}"
    policy_info.short_description = 'Política'
    
    def file_link(self, obj):
        if obj.justification_file:
            return format_html('<a href="{}" target="_blank">Ver archivo</a>', obj.justification_file.url)
        return '-'
    file_link.short_description = 'Justificación'


@admin.register(AssetExclusion)
class AssetExclusionAdmin(admin.ModelAdmin):
    list_display = ['asset', 'policy_info', 'layer', 'is_active', 'created_at', 'file_link']
    list_filter = ['is_active', 'created_at', 'layer__layer_type']
    search_fields = ['asset__hostname', 'policy__title', 'reason']
    readonly_fields = ['created_at']
    
    fieldsets = (
        ('Exclusión', {
            'fields': ('asset', 'policy', 'layer', 'is_active')
        }),
        ('Justificación', {
            'fields': ('reason', 'justification_file')
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by')
        }),
    )
    
    def policy_info(self, obj):
        return f"{obj.policy.section} {obj.policy.recommendation} - {obj.policy.title[:50]}"
    policy_info.short_description = 'Política'
    
    def file_link(self, obj):
        if obj.justification_file:
            return format_html('<a href="{}" target="_blank">Ver archivo</a>', obj.justification_file.url)
        return '-'
    file_link.short_description = 'Justificación'


# ============================================================
# CONFIGURACIÓN
# ============================================================

@admin.register(Threshold)
class ThresholdAdmin(admin.ModelAdmin):
    list_display = ['name', 'value_badge', 'description', 'updated_at']
    list_filter = ['updated_at']
    search_fields = ['name', 'description']
    readonly_fields = ['updated_at']
    
    def value_badge(self, obj):
        formatted_value = f"{obj.value:.2f}%"
        return format_html(
            '<span style="font-size: 16px; font-weight: bold; color: #2196F3;">{}</span>',
            formatted_value
        )
    value_badge.short_description = 'Valor'


# ============================================================
# ALERTAS
# ============================================================

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['severity_badge', 'status_badge', 'title', 'asset', 'layer', 'created_at']
    list_filter = ['severity', 'status', 'alert_type', 'created_at']
    search_fields = ['title', 'message', 'asset__hostname']
    readonly_fields = ['created_at', 'acknowledged_at', 'resolved_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Alerta', {
            'fields': ('alert_type', 'severity', 'status', 'title', 'message')
        }),
        ('Referencias', {
            'fields': ('asset', 'layer', 'scan')
        }),
        ('Valores', {
            'fields': ('previous_value', 'current_value')
        }),
        ('Seguimiento', {
            'fields': ('created_at', 'acknowledged_at', 'acknowledged_by', 'resolved_at')
        }),
    )
    
    def severity_badge(self, obj):
        colors = {
            'LOW': '#4CAF50',
            'MEDIUM': '#FF9800',
            'HIGH': '#FF5722',
            'CRITICAL': '#D32F2F'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">{}</span>',
            colors.get(obj.severity, 'gray'), obj.get_severity_display()
        )
    severity_badge.short_description = 'Severidad'
    
    def status_badge(self, obj):
        colors = {
            'ACTIVE': '#FF5722',
            'ACKNOWLEDGED': '#FF9800',
            'RESOLVED': '#4CAF50'
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'gray'), obj.get_status_display()
        )
    status_badge.short_description = 'Estado'
    
    actions = ['mark_acknowledged', 'mark_resolved']
    
    def mark_acknowledged(self, request, queryset):
        from django.utils import timezone
        queryset.update(status='ACKNOWLEDGED', acknowledged_at=timezone.now(), acknowledged_by=request.user.username)
        self.message_user(request, f'{queryset.count()} alertas marcadas como reconocidas')
    mark_acknowledged.short_description = 'Marcar como reconocidas'
    
    def mark_resolved(self, request, queryset):
        from django.utils import timezone
        queryset.update(status='RESOLVED', resolved_at=timezone.now())
        self.message_user(request, f'{queryset.count()} alertas marcadas como resueltas')
    mark_resolved.short_description = 'Marcar como resueltas'
