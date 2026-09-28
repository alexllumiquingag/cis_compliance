"""
Validadores y constantes del sistema de Compliance CIS
"""
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import magic
import os


# Configuración de archivos permitidos para justificaciones
ALLOWED_JUSTIFICATION_TYPES = {
    'application/pdf': ['.pdf'],
    'image/png': ['.png'],
    'image/jpeg': ['.jpg', '.jpeg'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'message/rfc822': ['.eml'],
}

MAX_JUSTIFICATION_SIZE = 10 * 1024 * 1024  # 10MB


def validate_justification_file(file):
    """
    Valida archivos de justificación de exclusiones
    - Tipos: PDF, PNG, JPG, DOCX, EML
    - Tamaño máximo: 10MB
    """
    
    # Validar tamaño
    if file.size > MAX_JUSTIFICATION_SIZE:
        raise ValidationError(
            _('El archivo es muy grande. Tamaño máximo: 10MB. Tu archivo: %(size)sMB'),
            params={'size': round(file.size / (1024 * 1024), 2)}
        )
    
    # Validar extensión
    ext = os.path.splitext(file.name)[1].lower()
    valid_extensions = [ext for exts in ALLOWED_JUSTIFICATION_TYPES.values() for ext in exts]
    
    if ext not in valid_extensions:
        raise ValidationError(
            _('Tipo de archivo no permitido: %(ext)s. Permitidos: PDF, PNG, JPG, DOCX, EML'),
            params={'ext': ext}
        )
    
    # Validar MIME type real del archivo (seguridad)
    try:
        file_mime = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)  # Reset file pointer
        
        if file_mime not in ALLOWED_JUSTIFICATION_TYPES:
            raise ValidationError(
                _('El contenido del archivo no coincide con su extensión. MIME detectado: %(mime)s'),
                params={'mime': file_mime}
            )
    except Exception as e:
        raise ValidationError(_('Error al validar el archivo: %(error)s'), params={'error': str(e)})
    
    return file


def validate_xlsx_file(file):
    """
    Valida archivos XLSX para benchmarks
    """
    ext = os.path.splitext(file.name)[1].lower()
    
    if ext != '.xlsx':
        raise ValidationError(_('Solo se permiten archivos .xlsx'))
    
    # Validar MIME type
    try:
        file_mime = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)
        
        valid_mimes = [
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip',  # XLSX son ZIP internamente
        ]
        
        if file_mime not in valid_mimes:
            raise ValidationError(
                _('El archivo no es un XLSX válido. MIME detectado: %(mime)s'),
                params={'mime': file_mime}
            )
    except Exception as e:
        raise ValidationError(_('Error al validar el XLSX: %(error)s'), params={'error': str(e)})
    
    return file

def validate_csv_file(file):
    """Valida archivos CSV (más robusto para archivos Nessus)"""
    
    # Validar extensión
    ext = os.path.splitext(file.name)[1].lower()
    if ext != '.csv':
        raise ValidationError(
            _('Tipo de archivo no permitido: %(ext)s. Solo se permiten archivos CSV'),
            params={'ext': ext}
        )
    
    # Validar tamaño (máximo 100MB para CSVs grandes de Nessus)
    max_size = 100 * 1024 * 1024  # 50MB
    if file.size > max_size:
        raise ValidationError(
            _('El archivo es muy grande. Tamaño máximo: 100MB. Tu archivo: %(size)sMB'),
            params={'size': round(file.size / (1024 * 1024), 2)}
        )
    
    # Validar que el archivo no esté vacío
    if file.size == 0:
        raise ValidationError(_('El archivo CSV está vacío'))
    
    # Intentar leer las primeras líneas para validar formato
    try:
        file.seek(0)
        # Leer solo los primeros 2048 bytes para validar
        chunk = file.read(2048)
        
        # Decodificar si es bytes
        if isinstance(chunk, bytes):
            try:
                chunk = chunk.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    chunk = chunk.decode('latin-1')
                except:
                    chunk = chunk.decode('utf-8', errors='ignore')
        
        # Verificar que tenga columnas básicas de Nessus
        chunk_lower = chunk.lower()
        required_indicators = ['plugin id', 'risk', 'description']
        
        has_required = any(indicator in chunk_lower for indicator in required_indicators)
        
        if not has_required:
            raise ValidationError(
                _('El archivo no parece ser un CSV de Nessus válido. '
                  'Debe contener las columnas: Plugin ID, Risk, Description')
            )
        
        # CRÍTICO: Resetear puntero para lectura posterior
        file.seek(0)
        
    except ValidationError:
        file.seek(0)  # Resetear en caso de error de validación
        raise
    except Exception as e:
        file.seek(0)  # Resetear en caso de error
        raise ValidationError(
            _('Error al validar el archivo CSV: %(error)s'),
            params={'error': str(e)}
        )
    
    return file

# Constantes del sistema
class SystemConstants:
    """Constantes del sistema"""
    
    # Columnas esperadas en XLSX de benchmark (case-insensitive)
    BENCHMARK_XLSX_COLUMNS = [
        'Section',
        'Recommendation',
        'Profile',
        'Title',
        'Assessment Status',
        'Description',
        'Rationale Statement',
        'Impact Statement',
        'Remediation Procedure',
        'Audit Procedure',
        'Additional Information',
        'CIS Controls',
        'CIS Safeguards 1 v8',
        'CIS Safeguards 2 v8',
        'CIS Safeguards 3 v8',
        'v8 IG1',
        'v8 IG2',
        'v8 IG3',
        'CIS Safeguards 1 v7',
        'CIS Safeguards 2 v7',
        'CIS Safeguards 3 v7',
        'v7 IG1',
        'v7 IG2',
        'v7 IG3',
        'References',
        'Default Value',
    ]
    
    # Columnas esperadas en CSV de Nessus
    NESSUS_CSV_COLUMNS = [
        'Plugin ID',
        'CVE',
        'CVSS v2.0 Base Score',
        'Risk',
        'Host',
        'Protocol',
        'Port',
        'Name',
        'Synopsis',
        'Description',
        'Solution',
        'See Also',
        'Plugin Output',
    ]
    
    # Profiles válidos de CIS (solo Server)
    VALID_PROFILES = ['Level 1 - Server', 'Level 2 - Server']
    
    # Risk levels que se registran (excluye "None")
    VALID_RISK_LEVELS = ['PASSED', 'FAILED', 'WARNING']
    
    # Umbrales por defecto
    DEFAULT_HARDENING_THRESHOLD = 90.0
    CRITICAL_DEGRADATION_THRESHOLD = 5.0  # % de caída para alerta crítica