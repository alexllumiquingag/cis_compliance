"""
Management command para importar assets desde CSV
Ubicación: compliance/management/commands/import_assets.py
"""
import csv
import logging
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from compliance.models import Asset, AssetLayer, Benchmark

logger = logging.getLogger('compliance')


class Command(BaseCommand):
    help = 'Importa assets y sus capas desde un archivo CSV'

    def add_arguments(self, parser):
        parser.add_argument(
            'csv_file',
            type=str,
            help='Ruta al archivo CSV con los assets'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simula la importación sin guardar en la base de datos'
        )
        parser.add_argument(
            '--skip-errors',
            action='store_true',
            help='Continúa la importación aunque haya errores en algunas filas'
        )

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        dry_run = options['dry_run']
        skip_errors = options['skip_errors']

        if dry_run:
            self.stdout.write(self.style.WARNING('🔍 MODO DRY-RUN: No se guardará nada en la base de datos'))

        # Estadísticas
        stats = {
            'total_rows': 0,
            'assets_created': 0,
            'assets_updated': 0,
            'assets_skipped': 0,
            'layers_created': 0,
            'errors': [],
            'warnings': []
        }

        try:
            with open(csv_file, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                
                # Validar columnas requeridas
                required_columns = ['hostname', 'ip_address', 'status']
                missing_columns = [col for col in required_columns if col not in reader.fieldnames]
                
                if missing_columns:
                    raise CommandError(f'Columnas requeridas faltantes: {", ".join(missing_columns)}')

                self.stdout.write(f'📄 Leyendo archivo: {csv_file}')
                self.stdout.write(f'📊 Columnas encontradas: {len(reader.fieldnames)}')
                
                # Procesar cada fila
                for row_num, row in enumerate(reader, start=2):
                    stats['total_rows'] += 1
                    
                    try:
                        if dry_run:
                            self._process_row_dry_run(row, row_num, stats)
                        else:
                            self._process_row(row, row_num, stats, skip_errors)
                    
                    except Exception as e:
                        error_msg = f'Fila {row_num}: {str(e)}'
                        stats['errors'].append(error_msg)
                        
                        if not skip_errors:
                            raise CommandError(error_msg)
                        else:
                            self.stdout.write(self.style.ERROR(f'❌ {error_msg}'))

                # Mostrar resumen
                self._print_summary(stats, dry_run)

        except FileNotFoundError:
            raise CommandError(f'Archivo no encontrado: {csv_file}')
        except Exception as e:
            raise CommandError(f'Error al procesar el archivo: {str(e)}')

    @transaction.atomic
    def _process_row(self, row, row_num, stats, skip_errors):
        """Procesa una fila del CSV y crea/actualiza el asset y sus capas"""
        
        hostname = row.get('hostname', '').strip()
        
        if not hostname:
            stats['assets_skipped'] += 1
            return

        # Extraer datos del asset
        asset_data = self._extract_asset_data(row)
        
        # Crear o actualizar asset
        asset, created = Asset.objects.update_or_create(
            hostname=hostname,
            defaults=asset_data
        )
        
        if created:
            stats['assets_created'] += 1
            self.stdout.write(self.style.SUCCESS(f'✓ Asset creado: {hostname}'))
        else:
            stats['assets_updated'] += 1
            self.stdout.write(self.style.WARNING(f'⟳ Asset actualizado: {hostname}'))

        # Procesar capas (hasta 3 capas por asset)
        for layer_num in range(1, 4):
            layer_created = self._process_layer(asset, row, layer_num, stats, skip_errors)
            if layer_created:
                stats['layers_created'] += 1

    def _process_row_dry_run(self, row, row_num, stats):
        """Simula el procesamiento sin guardar en BD"""
        
        hostname = row.get('hostname', '').strip()
        
        if not hostname:
            stats['assets_skipped'] += 1
            return

        # Validar datos del asset
        asset_data = self._extract_asset_data(row)
        
        # Verificar si existe
        exists = Asset.objects.filter(hostname=hostname).exists()
        
        if exists:
            stats['assets_updated'] += 1
            self.stdout.write(f'  ⟳ Actualizaría: {hostname}')
        else:
            stats['assets_created'] += 1
            self.stdout.write(f'  ✓ Crearía: {hostname}')

        # Verificar capas
        for layer_num in range(1, 4):
            layer_type = row.get(f'layer_type_{layer_num}', '').strip()
            if layer_type:
                stats['layers_created'] += 1
                software = row.get(f'software_type_{layer_num}', '').strip()
                self.stdout.write(f'    └─ Capa {layer_num}: {layer_type} - {software}')

    def _extract_asset_data(self, row):
        """Extrae los datos del asset desde la fila del CSV"""
        
        # Convertir valores booleanos
        pci_standard = row.get('pci_standard', 'FALSE').strip().upper() in ['TRUE', '1', 'YES', 'SI']
        
        # Status por defecto
        status = row.get('status', 'ACTIVE').strip().upper()
        if status not in ['ACTIVE', 'INACTIVE']:
            status = 'ACTIVE'

        return {
            'ip_address': row.get('ip_address', '').strip(),
            'status': status,
            'pci_standard': pci_standard,
            'environment': row.get('environment', '').strip() or '',
            'administrator': row.get('administrator', '').strip() or '',
            'responsible': row.get('responsible', '').strip() or '',
        }

    def _process_layer(self, asset, row, layer_num, stats, skip_errors):
        """Procesa una capa del asset"""
        
        layer_type = row.get(f'layer_type_{layer_num}', '').strip()
        
        if not layer_type:
            return False

        software_type = row.get(f'software_type_{layer_num}', '').strip()
        benchmark_name = row.get(f'benchmark_name_{layer_num}', '').strip()
        description = row.get(f'description_{layer_num}', '').strip()

        # Validar que layer_type sea válido
        valid_layer_types = ['OS', 'WEB', 'DB', 'OTHER']
        if layer_type not in valid_layer_types:
            warning = f'Layer type inválido: {layer_type}. Debe ser uno de: {", ".join(valid_layer_types)}'
            stats['warnings'].append(warning)
            if not skip_errors:
                raise ValueError(warning)
            return False

        # Buscar benchmark
        if not benchmark_name:
            warning = f'Sin benchmark para capa {layer_num} de {asset.hostname}'
            stats['warnings'].append(warning)
            self.stdout.write(self.style.WARNING(f'  ⚠️ {warning}'))
            return False

        benchmark = self._find_benchmark(benchmark_name)
        
        if not benchmark:
            warning = f'Benchmark no encontrado: {benchmark_name}'
            stats['warnings'].append(warning)
            self.stdout.write(self.style.WARNING(f'  ⚠️ {warning}'))
            if not skip_errors:
                raise ValueError(warning)
            return False

        # Crear o actualizar layer
        try:
            layer, created = AssetLayer.objects.update_or_create(
                asset=asset,
                layer_type=layer_type,
                benchmark=benchmark,
                defaults={
                    'software_type': software_type,
                    'description': description,
                }
            )
            
            if created:
                self.stdout.write(f'  ✓ Capa creada: {layer_type} - {software_type}')
            else:
                self.stdout.write(f'  ⟳ Capa actualizada: {layer_type} - {software_type}')
            
            return created

        except Exception as e:
            error = f'Error al crear capa {layer_num}: {str(e)}'
            stats['errors'].append(error)
            if not skip_errors:
                raise
            return False

    def _find_benchmark(self, benchmark_name):
        """Busca un benchmark por nombre (busca el más reciente si hay varias versiones)"""
        
        # Búsqueda exacta
        benchmark = Benchmark.objects.filter(name=benchmark_name).order_by('-version').first()
        
        if benchmark:
            return benchmark

        # Búsqueda parcial (contiene)
        benchmark = Benchmark.objects.filter(name__icontains=benchmark_name).order_by('-version').first()
        
        return benchmark

    def _print_summary(self, stats, dry_run):
        """Imprime el resumen de la importación"""
        
        self.stdout.write('\n' + '='*60)
        
        if dry_run:
            self.stdout.write(self.style.WARNING('📋 RESUMEN (DRY-RUN - Simulación)'))
        else:
            self.stdout.write(self.style.SUCCESS('📋 RESUMEN DE IMPORTACIÓN'))
        
        self.stdout.write('='*60)
        self.stdout.write(f'📊 Filas procesadas:     {stats["total_rows"]}')
        self.stdout.write(f'✅ Assets creados:       {stats["assets_created"]}')
        self.stdout.write(f'🔄 Assets actualizados:  {stats["assets_updated"]}')
        self.stdout.write(f'⏭️  Assets omitidos:      {stats["assets_skipped"]}')
        self.stdout.write(f'🔧 Capas creadas:        {stats["layers_created"]}')
        self.stdout.write(f'⚠️  Advertencias:         {len(stats["warnings"])}')
        self.stdout.write(f'❌ Errores:              {len(stats["errors"])}')
        self.stdout.write('='*60)

        # Mostrar advertencias
        if stats['warnings']:
            self.stdout.write('\n⚠️  ADVERTENCIAS:')
            for warning in stats['warnings'][:10]:
                self.stdout.write(self.style.WARNING(f'  • {warning}'))
            if len(stats['warnings']) > 10:
                self.stdout.write(f'  ... y {len(stats["warnings"]) - 10} más')

        # Mostrar errores
        if stats['errors']:
            self.stdout.write('\n❌ ERRORES:')
            for error in stats['errors'][:10]:
                self.stdout.write(self.style.ERROR(f'  • {error}'))
            if len(stats['errors']) > 10:
                self.stdout.write(f'  ... y {len(stats["errors"]) - 10} más')

        if not dry_run and stats['errors'] == 0:
            self.stdout.write('\n' + self.style.SUCCESS('✨ Importación completada exitosamente'))
        elif dry_run:
            self.stdout.write('\n' + self.style.WARNING('💡 Para importar realmente, ejecuta sin --dry-run'))