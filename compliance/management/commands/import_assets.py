"""
Comando Django para importar Assets y AssetLayers masivamente desde CSV

Uso:
    python manage.py import_assets assets.csv
    python manage.py import_assets assets.csv --dry-run
    python manage.py import_assets assets.csv --skip-errors
    
Formato CSV esperado:
    hostname,ip_address,status,layer_type,software_type,benchmark_name,benchmark_version,description
    
Ejemplo:
    server01.example.com,192.168.1.10,ACTIVE,OS,RHEL,CIS Red Hat Enterprise Linux 8,1.0.0,RHEL 8.5
"""
import csv
import logging
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.core.exceptions import ValidationError
from compliance.models import Asset, AssetLayer, Benchmark

logger = logging.getLogger('compliance')


class Command(BaseCommand):
    help = 'Importa assets y capas desde archivo CSV'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'csv_file',
            type=str,
            help='Ruta al archivo CSV con los assets'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simula la importación sin guardar cambios en la BD'
        )
        parser.add_argument(
            '--skip-errors',
            action='store_true',
            help='Continúa importando aunque haya errores en algunas filas'
        )
        parser.add_argument(
            '--update',
            action='store_true',
            help='Actualiza assets existentes (por defecto solo crea nuevos)'
        )
    
    def handle(self, *args, **options):
        csv_file = options['csv_file']
        dry_run = options['dry_run']
        skip_errors = options['skip_errors']
        update_existing = options['update']
        
        # Header
        self.stdout.write('='*70)
        self.stdout.write(self.style.SUCCESS('IMPORTACIÓN DE ASSETS Y CAPAS DESDE CSV'))
        self.stdout.write('='*70)
        
        if dry_run:
            self.stdout.write(self.style.WARNING('\n⚠️  MODO DRY-RUN: No se guardarán cambios\n'))
        
        # Estadísticas
        stats = {
            'total_rows': 0,
            'assets_created': 0,
            'assets_updated': 0,
            'assets_skipped': 0,
            'layers_created': 0,
            'layers_skipped': 0,
            'errors': 0,
            'error_details': []
        }
        
        try:
            # Abrir archivo con encoding que maneja BOM
            with open(csv_file, 'r', encoding='utf-8-sig') as f:
                # Leer todas las líneas
                lines = f.readlines()
                
                if not lines:
                    raise CommandError('El archivo CSV está vacío')
                
                # Procesar primera línea (headers) manualmente
                header_line = lines[0].strip()
                
                # Limpiar headers: quitar BOM, espacios, y caracteres invisibles
                headers_raw = header_line.split(',')
                headers = [h.strip().replace('\ufeff', '').replace('\u200b', '') for h in headers_raw]
                
                self.stdout.write(f'Headers detectados ({len(headers)}):\n')
                for i, h in enumerate(headers):
                    self.stdout.write(f"  {i+1}. '{h}' (len={len(h)})")
                
                # Validar headers requeridos
                required_fields = [
                    'hostname', 
                    'ip_address', 
                    'layer_type',
                    'benchmark_name', 
                    'benchmark_version'
                ]
                
                # Normalizar headers para comparación (lowercase, sin espacios)
                headers_normalized = {h.lower().strip(): h for h in headers}
                required_normalized = [f.lower().strip() for f in required_fields]
                
                missing_fields = []
                for req in required_normalized:
                    if req not in headers_normalized:
                        missing_fields.append(req)
                
                if missing_fields:
                    raise CommandError(
                        f'\n❌ El CSV no tiene las columnas requeridas.\n'
                        f'Faltantes: {", ".join(missing_fields)}\n'
                        f'Encontradas: {", ".join(headers)}\n'
                        f'Requeridas: {", ".join(required_fields)}\n\n'
                        f'NOTA: Verifica que no haya espacios extras en los nombres de columnas.'
                    )
                
                self.stdout.write(self.style.SUCCESS('\n✓ Todos los headers requeridos están presentes\n'))
                
                # Crear diccionario reader manualmente
                reader = csv.DictReader(lines, fieldnames=headers)
                next(reader)  # Saltar la línea de headers
                
                # Procesar filas
                with transaction.atomic():
                    for row_num, row in enumerate(reader, start=2):
                        stats['total_rows'] += 1
                        
                        try:
                            result = self._process_row(row, row_num, update_existing, stats)
                            
                            if result['asset_created']:
                                self.stdout.write(
                                    f"  {self.style.SUCCESS('✓')} Fila {row_num}: "
                                    f"Asset creado: {result['hostname']}"
                                )
                            elif result['asset_updated']:
                                self.stdout.write(
                                    f"  {self.style.WARNING('↻')} Fila {row_num}: "
                                    f"Asset actualizado: {result['hostname']}"
                                )
                            elif result['asset_skipped']:
                                self.stdout.write(
                                    f"  {self.style.WARNING('⊘')} Fila {row_num}: "
                                    f"Asset ya existe: {result['hostname']}"
                                )
                            
                            if result['layer_created']:
                                layer_info = f"{result['layer_type']}"
                                if result.get('software_type'):
                                    layer_info += f" ({result['software_type']})"
                                self.stdout.write(f"      → Capa creada: {layer_info}")
                            elif result['layer_skipped']:
                                layer_info = f"{result['layer_type']}"
                                if result.get('software_type'):
                                    layer_info += f" ({result['software_type']})"
                                self.stdout.write(f"      ⊘ Capa ya existe: {layer_info}")
                        
                        except Exception as e:
                            error_msg = f"Fila {row_num}: {str(e)}"
                            stats['errors'] += 1
                            stats['error_details'].append(error_msg)
                            
                            self.stdout.write(
                                f"  {self.style.ERROR('✗')} {error_msg}"
                            )
                            
                            if not skip_errors:
                                raise CommandError(
                                    f'\n❌ Error en fila {row_num}. '
                                    f'Usa --skip-errors para continuar.'
                                )
                    
                    # Rollback si es dry-run
                    if dry_run:
                        transaction.set_rollback(True)
                        self.stdout.write(
                            self.style.WARNING('\n⚠️  DRY-RUN: Todos los cambios fueron revertidos\n')
                        )
            
            # Mostrar resumen
            self._print_summary(stats, dry_run)
            
            # Exit code
            if stats['errors'] > 0:
                raise CommandError(f'Importación completada con {stats["errors"]} errores')
        
        except FileNotFoundError:
            raise CommandError(f'❌ Archivo no encontrado: {csv_file}')
        
        except UnicodeDecodeError as e:
            raise CommandError(
                f'❌ Error de codificación: {str(e)}\n'
                f'Asegúrate que el archivo esté en UTF-8'
            )
    
    def _process_row(self, row, row_num, update_existing, stats):
        """Procesa una fila del CSV"""
        
        result = {
            'asset_created': False,
            'asset_updated': False,
            'asset_skipped': False,
            'layer_created': False,
            'layer_skipped': False,
            'hostname': '',
            'layer_type': '',
            'software_type': ''
        }
        
        # Función helper para obtener valor limpio
        def get_clean(key):
            # Intentar con el nombre exacto y variaciones
            for k in row.keys():
                if k.lower().strip() == key.lower().strip():
                    value = row[k]
                    return value.strip() if value else ''
            return ''
        
        # Limpiar datos usando la función helper
        hostname = get_clean('hostname')
        ip_address = get_clean('ip_address')
        status = get_clean('status') or 'ACTIVE'
        layer_type = get_clean('layer_type').upper()
        software_type = get_clean('software_type').upper()
        benchmark_name = get_clean('benchmark_name')
        benchmark_version = get_clean('benchmark_version')
        description = get_clean('description')
        
        result['hostname'] = hostname
        result['layer_type'] = layer_type
        result['software_type'] = software_type
        
        # Validar datos básicos
        if not hostname:
            raise ValueError("hostname vacío")
        
        if not ip_address:
            raise ValueError("ip_address vacío")
        
        # Validar layer_type
        valid_types = ['OS', 'WEB', 'DB', 'OTHER']
        if layer_type not in valid_types:
            raise ValueError(
                f"layer_type inválido: '{layer_type}'. "
                f"Valores permitidos: {', '.join(valid_types)}"
            )
        
        # Validar software_type según layer_type
        if software_type:
            # Obtener códigos válidos según el layer_type
            if layer_type == 'OS':
                valid_software = [code for code, _ in AssetLayer.OS_TYPES]
                type_name = 'Sistema Operativo'
            elif layer_type == 'WEB':
                valid_software = [code for code, _ in AssetLayer.WEB_TYPES]
                type_name = 'Servidor Web'
            elif layer_type == 'DB':
                valid_software = [code for code, _ in AssetLayer.DB_TYPES]
                type_name = 'Base de Datos'
            else:
                valid_software = []
                type_name = 'Otro'
            
            # Validar que el software_type esté en la lista válida
            if layer_type != 'OTHER' and software_type not in valid_software:
                raise ValueError(
                    f"software_type inválido: '{software_type}' para layer_type '{layer_type}'. "
                    f"Valores permitidos para {type_name}: {', '.join(valid_software)}"
                )
        
        # Validar status
        valid_statuses = ['ACTIVE', 'INACTIVE']
        if status not in valid_statuses:
            raise ValueError(
                f"status inválido: '{status}'. "
                f"Valores permitidos: {', '.join(valid_statuses)}"
            )
        
        # 1. Crear o actualizar Asset
        asset_exists = Asset.objects.filter(hostname=hostname).exists()
        
        if asset_exists and not update_existing:
            # Asset existe y no queremos actualizar
            asset = Asset.objects.get(hostname=hostname)
            stats['assets_skipped'] += 1
            result['asset_skipped'] = True
        else:
            # Crear o actualizar
            asset, created = Asset.objects.update_or_create(
                hostname=hostname,
                defaults={
                    'ip_address': ip_address,
                    'status': status
                }
            )
            
            if created:
                stats['assets_created'] += 1
                result['asset_created'] = True
            else:
                stats['assets_updated'] += 1
                result['asset_updated'] = True
        
        # 2. Buscar Benchmark
        benchmark = Benchmark.objects.filter(
            name=benchmark_name,
            version=benchmark_version
        ).first()
        
        if not benchmark:
            raise ValueError(
                f"Benchmark no encontrado: '{benchmark_name}' v{benchmark_version}. "
                f"Debes crear el benchmark primero."
            )
        
        # 3. Crear AssetLayer con software_type
        layer, layer_created = AssetLayer.objects.get_or_create(
            asset=asset,
            layer_type=layer_type,
            benchmark=benchmark,
            defaults={
                'software_type': software_type,
                'description': description
            }
        )
        
        if layer_created:
            stats['layers_created'] += 1
            result['layer_created'] = True
        else:
            stats['layers_skipped'] += 1
            result['layer_skipped'] = True
        
        return result
    
    def _print_summary(self, stats, dry_run):
        """Imprime resumen de la importación"""
        
        self.stdout.write('\n' + '='*70)
        self.stdout.write(self.style.SUCCESS('📊 RESUMEN DE IMPORTACIÓN'))
        self.stdout.write('='*70)
        
        self.stdout.write(f"\n{'Total de filas procesadas:':<30} {stats['total_rows']}")
        self.stdout.write(f"{'Assets creados:':<30} {self.style.SUCCESS(str(stats['assets_created']))}")
        self.stdout.write(f"{'Assets actualizados:':<30} {self.style.WARNING(str(stats['assets_updated']))}")
        self.stdout.write(f"{'Assets omitidos:':<30} {stats['assets_skipped']}")
        self.stdout.write(f"{'Capas creadas:':<30} {self.style.SUCCESS(str(stats['layers_created']))}")
        self.stdout.write(f"{'Capas omitidas:':<30} {stats['layers_skipped']}")
        
        if stats['errors'] > 0:
            self.stdout.write(f"{'Errores:':<30} {self.style.ERROR(str(stats['errors']))}")
            self.stdout.write('\n📝 Detalles de errores:')
            for error in stats['error_details'][:10]:
                self.stdout.write(f"  • {error}")
            if len(stats['error_details']) > 10:
                self.stdout.write(f"  ... y {len(stats['error_details']) - 10} errores más")
        else:
            self.stdout.write(f"{'Errores:':<30} {self.style.SUCCESS('0')}")
        
        self.stdout.write('')
        
        if stats['errors'] == 0 and not dry_run:
            self.stdout.write(self.style.SUCCESS('✅ IMPORTACIÓN COMPLETADA EXITOSAMENTE'))
        elif dry_run:
            self.stdout.write(self.style.WARNING('⚠️  DRY-RUN: Ningún cambio fue guardado'))
        else:
            self.stdout.write(self.style.ERROR('⚠️  IMPORTACIÓN COMPLETADA CON ERRORES'))
        
        self.stdout.write('='*70 + '\n')
