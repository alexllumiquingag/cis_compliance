"""
Formularios para el sistema de compliance CIS
"""
from django import forms
from django.core.exceptions import ValidationError
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Fieldset, Submit, Div, HTML
from crispy_forms.bootstrap import FormActions
from .models import (
    Benchmark, Asset, AssetLayer, Scan, GlobalExclusion, 
    AssetExclusion, Baseline, Threshold
)
from .validators import (
    validate_xlsx_file, validate_csv_file, 
    validate_justification_file
)
from .services.benchmark_service import auto_version_benchmark


class BenchmarkUploadForm(forms.Form):
    """Formulario para subir un nuevo benchmark XLSX"""
    
    name = forms.CharField(
        label='Nombre del Benchmark',
        max_length=255,
        help_text='Ej: CIS Red Hat Enterprise Linux 8',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'CIS Red Hat Enterprise Linux 8'
        })
    )
    
    version = forms.CharField(
        label='Versión',
        max_length=50,
        required=False,
        help_text='Dejar vacío para auto-versionar (1.0.0, 2.0.0, ...)',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ej: 1.0.0'
        })
    )
    
    file = forms.FileField(
        label='Archivo XLSX',
        help_text='Solo archivos .xlsx',
        validators=[validate_xlsx_file],
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.xlsx'
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            Fieldset(
                'Subir Benchmark CIS',
                'name',
                'version',
                'file',
                HTML('<p class="text-muted mt-2"><small><i class="bi bi-info-circle"></i> '
                     'El archivo XLSX debe contener las columnas estándar de CIS Benchmark. '
                     'Solo se importarán políticas de Server (Level 1 y Level 2).</small></p>')
            ),
            FormActions(
                Submit('submit', 'Subir Benchmark', css_class='btn btn-primary'),
                HTML('<a href="{% url \'benchmark_list\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )
    
    def clean_version(self):
        """Auto-genera versión si está vacía"""
        version = self.cleaned_data.get('version', '').strip()
        name = self.cleaned_data.get('name', '').strip()
        
        if not version and name:
            version = auto_version_benchmark(name)
        
        return version
    
    def clean(self):
        cleaned_data = super().clean()
        name = cleaned_data.get('name')
        version = cleaned_data.get('version')
        
        if name and version:
            # Verificar si ya existe esta versión
            if Benchmark.objects.filter(name=name, version=version).exists():
                raise ValidationError(
                    f'Ya existe el benchmark "{name}" versión {version}. '
                    f'Por favor usa otra versión.'
                )
        
        return cleaned_data


class NessusScanUploadForm(forms.Form):
    """Formulario para subir resultados de escaneo Nessus"""
    
    asset = forms.ModelChoiceField(
        queryset=Asset.objects.filter(status='ACTIVE'),
        label='Asset',
        help_text='Servidor a evaluar',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    layer = forms.ModelChoiceField(
        queryset=AssetLayer.objects.none(),  # Se filtra dinámicamente
        label='Capa de Hardening',
        help_text='Capa a evaluar (OS, Web, DB)',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    scan_date = forms.DateField(
        label='Fecha del Escaneo',
        help_text='Fecha en que se realizó el escaneo',
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    csv_file = forms.FileField(
        label='Archivo CSV de Nessus',
        help_text='Resultado del escaneo en formato CSV',
        validators=[validate_csv_file],
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.csv'
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            Fieldset(
                'Subir Escaneo de Nessus',
                'asset',
                'layer',
                'scan_date',
                'csv_file',
                HTML('<p class="text-muted mt-2"><small><i class="bi bi-info-circle"></i> '
                     'El CSV debe contener las columnas: Plugin ID, Risk, Host, Description, Plugin Output. '
                     'No se registrarán checks informativos (Risk = None).</small></p>')
            ),
            FormActions(
                Submit('submit', 'Procesar Escaneo', css_class='btn btn-primary'),
                HTML('<a href="{% url \'scan_list\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )
        
        # Si ya hay un asset seleccionado, filtrar las capas
        if 'asset' in self.data:
            try:
                asset_id = int(self.data.get('asset'))
                self.fields['layer'].queryset = AssetLayer.objects.filter(asset_id=asset_id)
            except (ValueError, TypeError):
                pass
        elif self.initial.get('asset'):
            self.fields['layer'].queryset = AssetLayer.objects.filter(
                asset=self.initial['asset']
            )


class AssetForm(forms.ModelForm):
    """Formulario para crear/editar Assets"""
    
    class Meta:
        model = Asset
        fields = ['hostname', 'ip_address', 'status', 'pci_standard', 'environment', 'administrator', 'responsible']
        widgets = {
            'hostname': forms.TextInput(attrs={'class': 'form-control'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'pci_standard': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'environment': forms.Select(attrs={'class': 'form-select'}),
            'administrator': forms.Select(attrs={'class': 'form-select'}),
            'responsible': forms.Select(attrs={'class': 'form-select'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Fieldset(
                'Información del Asset',
                'hostname',
                'ip_address',
                'status',
            ),
            Fieldset(
                'Clasificación y Responsabilidad',
                Div(
                    'pci_standard',
                    css_class='form-check mb-3'
                ),
                'environment',
                'administrator',
                'responsible',
            ),
            FormActions(
                Submit('submit', 'Guardar', css_class='btn btn-primary'),
                HTML('<a href="{% url \'asset_list\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )


class AssetLayerForm(forms.ModelForm):
    """Formulario para agregar capas de hardening a un asset"""
    
    class Meta:
        model = AssetLayer
        fields = ['layer_type', 'software_type', 'benchmark', 'description']
        widgets = {
            'layer_type': forms.Select(attrs={'class': 'form-select'}),
            'software_type': forms.Select(attrs={'class': 'form-select'}),
            'benchmark': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ej: Apache 2.4.52, Windows Server 2019, Oracle 19c'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        self.asset = kwargs.pop('asset', None)
        super().__init__(*args, **kwargs)
        
        # Configurar opciones de software_type con TODOS los tipos organizados por grupos
        self._set_software_type_choices_with_optgroups()
        
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Fieldset(
                'Agregar Capa de Hardening',
                'layer_type',
                HTML('<p class="text-info"><small><i class="bi bi-info-circle"></i> '
                     'Las opciones de "Tipo de Software" están organizadas por categoría. '
                     'Seleccione el tipo de software correspondiente al tipo de capa elegido.</small></p>'),
                'software_type',
                'benchmark',
                'description',
            ),
            FormActions(
                Submit('submit', 'Agregar Capa', css_class='btn btn-primary'),
                HTML('<a href="{{ request.META.HTTP_REFERER }}" class="btn btn-secondary">Cancelar</a>')
            )
        )
    
    def _set_software_type_choices_with_optgroups(self):
        """
        Configura las opciones de software_type con optgroups
        para mostrar TODAS las opciones organizadas por categoría
        """
        
        # Crear choices con optgroups
        choices = [('', '--- Primero seleccione tipo de capa ---')]
        
        # Grupo: Sistemas Operativos
        os_choices = []
        for code, name in AssetLayer.OS_TYPES:
            os_choices.append((code, name))
        
        # Grupo: Servidores Web
        web_choices = []
        for code, name in AssetLayer.WEB_TYPES:
            web_choices.append((code, name))
        
        # Grupo: Bases de Datos
        db_choices = []
        for code, name in AssetLayer.DB_TYPES:
            db_choices.append((code, name))
        
        # Agregar los grupos (optgroups)
        if os_choices:
            choices.append(('Sistemas Operativos', os_choices))
        if web_choices:
            choices.append(('Servidores Web', web_choices))
        if db_choices:
            choices.append(('Bases de Datos', db_choices))
        
        self.fields['software_type'].choices = choices
        
        # Agregar help_text dinámico según layer_type
        layer_type = None
        if self.instance and self.instance.pk:
            layer_type = self.instance.layer_type
        elif 'layer_type' in self.data:
            layer_type = self.data.get('layer_type')
        
        if layer_type:
            if layer_type == 'OS':
                self.fields['software_type'].help_text = '⚠️ Seleccione un Sistema Operativo de la lista'
            elif layer_type == 'WEB':
                self.fields['software_type'].help_text = '⚠️ Seleccione un Servidor Web de la lista'
            elif layer_type == 'DB':
                self.fields['software_type'].help_text = '⚠️ Seleccione una Base de Datos de la lista'
    
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
            if software_type not in valid_codes:
                # Obtener el nombre del software para un mensaje más claro
                all_types = dict(AssetLayer.OS_TYPES + AssetLayer.WEB_TYPES + AssetLayer.DB_TYPES)
                software_name = all_types.get(software_type, software_type)
                
                raise ValidationError({
                    'software_type': (
                        f'⚠️ "{software_name}" no es válido para "{type_name}". '
                        f'Por favor seleccione una opción del grupo correcto.'
                    )
                })
        
        return cleaned_data


class GlobalExclusionForm(forms.ModelForm):
    """Formulario para crear exclusiones globales"""
    
    class Meta:
        model = GlobalExclusion
        fields = ['policy', 'benchmark', 'reason', 'justification_file']
        widgets = {
            'policy': forms.Select(attrs={'class': 'form-select'}),
            'benchmark': forms.Select(attrs={'class': 'form-select'}),
            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Describe el control compensatorio o razón de exclusión...'
            }),
            'justification_file': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.png,.jpg,.jpeg,.docx,.eml'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['justification_file'].validators.append(validate_justification_file)
        
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            Fieldset(
                'Exclusión Global de Política',
                'benchmark',
                'policy',
                HTML('<p class="text-warning"><i class="bi bi-exclamation-triangle"></i> '
                     'Esta exclusión afectará a TODOS los assets que usen este benchmark.</p>'),
                'reason',
                'justification_file',
                HTML('<p class="text-muted"><small>Archivos permitidos: PDF, PNG, JPG, DOCX, EML. Tamaño máximo: 10MB</small></p>')
            ),
            FormActions(
                Submit('submit', 'Crear Exclusión', css_class='btn btn-warning'),
                HTML('<a href="{% url \'exclusion_list\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )


class AssetExclusionForm(forms.ModelForm):
    """Formulario para crear exclusiones por asset"""
    
    class Meta:
        model = AssetExclusion
        fields = ['asset', 'policy', 'layer', 'reason', 'justification_file']
        widgets = {
            'asset': forms.Select(attrs={'class': 'form-select'}),
            'policy': forms.Select(attrs={'class': 'form-select'}),
            'layer': forms.Select(attrs={'class': 'form-select'}),
            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Describe por qué esta política no aplica a este asset específico...'
            }),
            'justification_file': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.png,.jpg,.jpeg,.docx,.eml'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['justification_file'].validators.append(validate_justification_file)
        
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            Fieldset(
                'Exclusión por Asset',
                'asset',
                'layer',
                'policy',
                'reason',
                'justification_file',
                HTML('<p class="text-muted"><small>Archivos permitidos: PDF, PNG, JPG, DOCX, EML. Tamaño máximo: 10MB</small></p>')
            ),
            FormActions(
                Submit('submit', 'Crear Exclusión', css_class='btn btn-warning'),
                HTML('<a href="{% url \'exclusion_list\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )


class BaselineUpdateForm(forms.ModelForm):
    """Formulario para actualizar manualmente una línea base"""
    
    class Meta:
        model = Baseline
        fields = ['compliance_percentage', 'notes']
        widgets = {
            'compliance_percentage': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '0',
                'max': '100',
                'step': '0.01'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Razón del cambio manual...'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Fieldset(
                'Actualizar Línea Base Manualmente',
                HTML('<div class="alert alert-warning">'
                     '<i class="bi bi-exclamation-triangle"></i> '
                     'Cambiar la línea base manualmente deshabilitará la actualización automática.</div>'),
                'compliance_percentage',
                'notes',
            ),
            FormActions(
                Submit('submit', 'Actualizar Línea Base', css_class='btn btn-warning'),
                HTML('<a href="{{ request.META.HTTP_REFERER }}" class="btn btn-secondary">Cancelar</a>')
            )
        )
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.is_manual = True
        if commit:
            instance.save()
        return instance


class ThresholdForm(forms.ModelForm):
    """Formulario para configurar umbrales"""
    
    class Meta:
        model = Threshold
        fields = ['name', 'value', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'value': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '0',
                'max': '100',
                'step': '0.01'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Fieldset(
                'Configurar Umbral',
                'name',
                'value',
                'description',
            ),
            FormActions(
                Submit('submit', 'Guardar', css_class='btn btn-primary'),
                HTML('<a href="{% url \'threshold_list\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )

# Para subir CSV con múltiples assets

class BulkNessusScanUploadForm(forms.Form):
    """Formulario para subir CSV de Nessus con MÚLTIPLES hosts"""
    
    benchmark = forms.ModelChoiceField(
        queryset=Benchmark.objects.all(),
        label='Benchmark',
        help_text='Benchmark CIS que se aplicará a todos los hosts del CSV',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    layer_type = forms.ChoiceField(
        choices=AssetLayer.LAYER_TYPES,
        label='Tipo de Capa',
        help_text='Tipo de capa que se evaluará (OS, Web, DB)',
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    scan_date = forms.DateField(
        label='Fecha del Escaneo',
        help_text='Fecha en que se realizó el escaneo',
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    csv_file = forms.FileField(
        label='Archivo CSV de Nessus (Múltiples Hosts)',
        help_text='CSV con resultados de múltiples servidores',
        validators=[validate_csv_file],
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.csv'
        })
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            Fieldset(
                'Importación Bulk de Escaneos Nessus',
                HTML('<div class="alert alert-info">'
                     '<i class="bi bi-info-circle"></i> '
                     '<strong>Importación Masiva:</strong> Este formulario procesará múltiples hosts desde un solo CSV. '
                     'Solo se procesarán hosts que ya existan como Assets activos en el sistema.'
                     '</div>'),
                'benchmark',
                'layer_type',
                'scan_date',
                'csv_file',
                HTML('<p class="text-muted mt-3"><small>'
                     '<i class="bi bi-exclamation-triangle text-warning"></i> '
                     '<strong>Importante:</strong><br>'
                     '• El CSV debe tener una columna "Host" con los hostnames<br>'
                     '• Solo se procesarán hosts que existan como Assets ACTIVOS<br>'
                     '• Se mostrará un reporte detallado de hosts procesados y omitidos<br>'
                     '• Los checks informativos (Risk=None) serán filtrados automáticamente'
                     '</small></p>')
            ),
            FormActions(
                Submit('submit', 'Procesar CSV Bulk', css_class='btn btn-primary btn-lg'),
                HTML('<a href="{% url \'compliance_dashboard\' %}" class="btn btn-secondary">Cancelar</a>')
            )
        )