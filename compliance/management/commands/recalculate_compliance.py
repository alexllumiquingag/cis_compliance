"""
Comando de management para recalcular el compliance de todos los scans

Ubicación: compliance/management/commands/recalculate_compliance.py

Para ejecutar:
    python manage.py recalculate_compliance
    python manage.py recalculate_compliance --asset-id 123
    python manage.py recalculate_compliance --layer-type OS
"""
from django.core.management.base import BaseCommand
from compliance.models import Scan, Asset, AssetLayer
from django.utils import timezone


class Command(BaseCommand):
    help = 'Recalcula el compliance de los scans considerando justificaciones activas'

    def add_arguments(self, parser):
        parser.add_argument(
            '--asset-id',
            type=int,
            help='Recalcular solo para un asset específico',
        )
        parser.add_argument(
            '--layer-type',
            type=str,
            choices=['OS', 'WEB', 'DB'],
            help='Recalcular solo para un tipo de capa',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Recalcular TODOS los scans (sin filtros)',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write(self.style.SUCCESS('RECALCULAR COMPLIANCE DE SCANS'))
        self.stdout.write(self.style.SUCCESS('=' * 70))
        
        # Construir query
        scans = Scan.objects.all().select_related('asset', 'layer')
        
        # Aplicar filtros
        if options['asset_id']:
            scans = scans.filter(asset_id=options['asset_id'])
            self.stdout.write(f"Filtro: Asset ID = {options['asset_id']}")
        
        if options['layer_type']:
            scans = scans.filter(layer__layer_type=options['layer_type'])
            self.stdout.write(f"Filtro: Layer Type = {options['layer_type']}")
        
        total_scans = scans.count()
        
        if total_scans == 0:
            self.stdout.write(self.style.WARNING('No se encontraron scans para recalcular'))
            return
        
        self.stdout.write(f"\nTotal de scans a recalcular: {total_scans}")
        self.stdout.write("")
        
        # Confirmar si no se usa --all
        if not options['all'] and not options['asset_id'] and not options['layer_type']:
            self.stdout.write(self.style.WARNING(
                'ATENCIÓN: Está a punto de recalcular TODOS los scans del sistema.'
            ))
            confirm = input('¿Desea continuar? (escriba "si" para confirmar): ')
            if confirm.lower() != 'si':
                self.stdout.write(self.style.ERROR('Operación cancelada'))
                return
        
        # Recalcular
        success_count = 0
        error_count = 0
        excluded_total = 0
        
        for idx, scan in enumerate(scans, 1):
            try:
                # Mostrar progreso cada 10 scans
                if idx % 10 == 0 or idx == 1:
                    self.stdout.write(f"Procesando scan {idx}/{total_scans}...", ending='')
                
                old_compliance = float(scan.compliance_percentage)
                
                # Recalcular métricas
                result = scan.recalculate_metrics()
                
                new_compliance = result['compliance']
                excluded_count = result['excluded']
                excluded_total += excluded_count
                
                # Mostrar cambios significativos
                diff = new_compliance - old_compliance
                if abs(diff) > 0.01:  # Si cambió más de 0.01%
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"\n  ✓ {scan.asset.hostname} - {scan.layer.get_layer_type_display()}: "
                            f"{old_compliance:.2f}% → {new_compliance:.2f}% "
                            f"(Δ {diff:+.2f}%, {excluded_count} excluidas)"
                        )
                    )
                elif idx % 10 == 0:
                    self.stdout.write(" ✓")
                
                success_count += 1
                
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(
                        f"\n  ✗ Error en scan {scan.id} ({scan.asset.hostname}): {str(e)}"
                    )
                )
        
        # Resumen final
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write(self.style.SUCCESS('RESUMEN'))
        self.stdout.write(self.style.SUCCESS('=' * 70))
        self.stdout.write(f"Total procesados: {success_count}/{total_scans}")
        self.stdout.write(f"Errores: {error_count}")
        self.stdout.write(f"Políticas excluidas (total): {excluded_total}")
        
        if success_count > 0:
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS('✓ Recalculación completada exitosamente'))
        
        if error_count > 0:
            self.stdout.write("")
            self.stdout.write(self.style.WARNING(f'⚠ Se encontraron {error_count} errores'))