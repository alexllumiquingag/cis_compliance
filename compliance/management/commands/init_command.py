"""
Management command para inicializar el sistema de compliance
Uso: python manage.py init_compliance
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from compliance.models import Threshold


class Command(BaseCommand):
    help = 'Inicializa el sistema de compliance con configuración por defecto'
    
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=== Inicializando Sistema de Compliance CIS ==='))
        
        with transaction.atomic():
            # 1. Crear umbrales por defecto
            self.create_default_thresholds()
            
            # 2. Crear directorios necesarios
            self.create_directories()
        
        self.stdout.write(self.style.SUCCESS('\n✓ Sistema inicializado correctamente'))
        self.stdout.write(self.style.WARNING('\nPróximos pasos:'))
        self.stdout.write('  1. Crear un superusuario: python manage.py createsuperuser')
        self.stdout.write('  2. Subir un benchmark XLSX')
        self.stdout.write('  3. Crear assets y sus capas')
        self.stdout.write('  4. Subir escaneos de Nessus')
    
    def create_default_thresholds(self):
        """Crea umbrales por defecto"""
        
        self.stdout.write('\n→ Creando umbrales por defecto...')
        
        thresholds = [
            {
                'name': 'hardening_threshold',
                'value': 90.00,
                'description': 'Umbral mínimo para considerar un asset como hardenizado'
            },
            {
                'name': 'critical_degradation',
                'value': 5.00,
                'description': 'Porcentaje de caída que genera alerta crítica'
            },
            {
                'name': 'warning_threshold',
                'value': 70.00,
                'description': 'Umbral de advertencia (por debajo genera warning)'
            },
        ]
        
        for threshold_data in thresholds:
            threshold, created = Threshold.objects.get_or_create(
                name=threshold_data['name'],
                defaults={
                    'value': threshold_data['value'],
                    'description': threshold_data['description']
                }
            )
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(
                        f'  ✓ Umbral creado: {threshold.name} = {threshold.value}%'
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'  - Umbral existente: {threshold.name} = {threshold.value}%'
                    )
                )
    
    def create_directories(self):
        """Crea directorios necesarios para media files"""
        
        import os
        from django.conf import settings
        
        self.stdout.write('\n→ Verificando directorios de archivos...')
        
        directories = [
            'media',
            'media/benchmarks',
            'media/scans',
            'media/exclusions',
            'media/exclusions/GlobalExclusion',
            'media/exclusions/AssetExclusion',
            'logs',
        ]
        
        for directory in directories:
            path = os.path.join(settings.BASE_DIR, directory)
            if not os.path.exists(path):
                os.makedirs(path)
                self.stdout.write(self.style.SUCCESS(f'  ✓ Directorio creado: {directory}/'))
            else:
                self.stdout.write(f'  - Directorio existente: {directory}/')
