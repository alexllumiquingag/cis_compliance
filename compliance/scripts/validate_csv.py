"""
Script para validar el CSV de assets antes de importar
Uso: python scripts/validate_csv.py assets.csv
"""
import csv
import sys
import ipaddress
from collections import defaultdict


def validate_csv(csv_file):
    """Valida el CSV y muestra errores/warnings"""
    
    errors = []
    warnings = []
    stats = {
        'total_rows': 0,
        'unique_assets': set(),
        'layer_types': defaultdict(int),
        'benchmarks': defaultdict(int),
        'statuses': defaultdict(int)
    }
    
    required_fields = ['hostname', 'ip_address', 'layer_type', 'benchmark_name', 'benchmark_version']
    valid_layer_types = ['OS', 'WEB', 'DB', 'OTHER']
    valid_statuses = ['ACTIVE', 'INACTIVE']
    
    # Tipos válidos de software por capa
    valid_os_types = ['WINDOWS', 'RHEL', 'AIX', 'VMWARE_ESXI', 'UBUNTU', 'CENTOS', 'DEBIAN', 'SLES', 'OTHER_OS']
    valid_web_types = ['APACHE', 'TOMCAT', 'IIS', 'NGINX', 'JBOSS', 'WEBLOGIC', 'WEBSPHERE', 'OTHER_WEB']
    valid_db_types = ['ORACLE', 'MSSQL', 'MYSQL', 'POSTGRESQL', 'MONGODB', 'DB2', 'MARIADB', 'OTHER_DB']
    
    print('='*70)
    print('VALIDACIÓN DE CSV DE ASSETS')
    print('='*70)
    print(f'\nArchivo: {csv_file}\n')
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Normalizar headers
            reader.fieldnames = [field.strip() for field in reader.fieldnames]
            
            # Validar headers
            missing = [f for f in required_fields if f not in reader.fieldnames]
            if missing:
                errors.append(f"❌ Columnas faltantes: {', '.join(missing)}")
                print('\n'.join(errors))
                return False
            
            print(f"✓ Headers válidos: {', '.join(reader.fieldnames)}\n")
            
            # Validar cada fila
            for row_num, row in enumerate(reader, start=2):
                stats['total_rows'] += 1
                
                # Limpiar datos
                hostname = row['hostname'].strip()
                ip_address = row['ip_address'].strip()
                status = row.get('status', 'ACTIVE').strip().upper()
                layer_type = row['layer_type'].strip().upper()
                software_type = row.get('software_type', '').strip().upper()
                benchmark_name = row['benchmark_name'].strip()
                benchmark_version = row['benchmark_version'].strip()
                
                # Validar hostname
                if not hostname:
                    errors.append(f"Fila {row_num}: hostname vacío")
                else:
                    stats['unique_assets'].add(hostname)
                
                # Validar IP
                if not ip_address:
                    errors.append(f"Fila {row_num}: ip_address vacío")
                else:
                    try:
                        ipaddress.ip_address(ip_address)
                    except ValueError:
                        errors.append(f"Fila {row_num}: IP inválida '{ip_address}'")
                
                # Validar status
                if status and status not in valid_statuses:
                    errors.append(
                        f"Fila {row_num}: status inválido '{status}'. "
                        f"Debe ser: {', '.join(valid_statuses)}"
                    )
                else:
                    stats['statuses'][status] += 1
                
                # Validar layer_type
                if not layer_type:
                    errors.append(f"Fila {row_num}: layer_type vacío")
                elif layer_type not in valid_layer_types:
                    errors.append(
                        f"Fila {row_num}: layer_type inválido '{layer_type}'. "
                        f"Debe ser: {', '.join(valid_layer_types)}"
                    )
                else:
                    stats['layer_types'][layer_type] += 1
                    
                    # Validar software_type según layer_type
                    if software_type:
                        if layer_type == 'OS' and software_type not in valid_os_types:
                            errors.append(
                                f"Fila {row_num}: software_type '{software_type}' inválido para OS. "
                                f"Debe ser uno de: {', '.join(valid_os_types)}"
                            )
                        elif layer_type == 'WEB' and software_type not in valid_web_types:
                            errors.append(
                                f"Fila {row_num}: software_type '{software_type}' inválido para WEB. "
                                f"Debe ser uno de: {', '.join(valid_web_types)}"
                            )
                        elif layer_type == 'DB' and software_type not in valid_db_types:
                            errors.append(
                                f"Fila {row_num}: software_type '{software_type}' inválido para DB. "
                                f"Debe ser uno de: {', '.join(valid_db_types)}"
                            )
                
                # Validar benchmark
                if not benchmark_name:
                    errors.append(f"Fila {row_num}: benchmark_name vacío")
                if not benchmark_version:
                    errors.append(f"Fila {row_num}: benchmark_version vacío")
                else:
                    stats['benchmarks'][f"{benchmark_name} v{benchmark_version}"] += 1
                
                # Warnings para datos faltantes opcionales
                if not software_type and layer_type in ['OS', 'WEB', 'DB']:
                    warnings.append(
                        f"Fila {row_num}: software_type vacío (recomendado para {layer_type})"
                    )
                if not row.get('description', '').strip():
                    warnings.append(f"Fila {row_num}: description vacía (opcional)")
            
            # Mostrar estadísticas
            print('='*70)
            print('📊 ESTADÍSTICAS')
            print('='*70)
            print(f"\nTotal de filas: {stats['total_rows']}")
            print(f"Assets únicos: {len(stats['unique_assets'])}")
            
            print(f"\nDistribución por tipo de capa:")
            for layer_type, count in sorted(stats['layer_types'].items()):
                print(f"  • {layer_type}: {count}")
            
            print(f"\nDistribución por status:")
            for status, count in sorted(stats['statuses'].items()):
                print(f"  • {status}: {count}")
            
            print(f"\nBenchmarks utilizados:")
            for benchmark, count in sorted(stats['benchmarks'].items()):
                print(f"  • {benchmark}: {count} capa(s)")
            
            # Mostrar warnings
            if warnings:
                print('\n' + '='*70)
                print(f'⚠️  WARNINGS ({len(warnings)})')
                print('='*70)
                for warning in warnings[:10]:
                    print(f"  • {warning}")
                if len(warnings) > 10:
                    print(f"  ... y {len(warnings) - 10} warnings más")
            
            # Mostrar errores
            if errors:
                print('\n' + '='*70)
                print(f'❌ ERRORES ({len(errors)})')
                print('='*70)
                for error in errors[:20]:
                    print(f"  • {error}")
                if len(errors) > 20:
                    print(f"  ... y {len(errors) - 20} errores más")
                print('\n⚠️  CORRIJE LOS ERRORES ANTES DE IMPORTAR\n')
                return False
            else:
                print('\n' + '='*70)
                print('✅ VALIDACIÓN EXITOSA - CSV LISTO PARA IMPORTAR')
                print('='*70)
                print('\nPróximo paso:')
                print(f'  python manage.py import_assets {csv_file} --dry-run')
                print()
                return True
    
    except FileNotFoundError:
        print(f'❌ Archivo no encontrado: {csv_file}')
        return False
    except UnicodeDecodeError:
        print('❌ Error de codificación. Asegúrate que el archivo esté en UTF-8')
        return False
    except Exception as e:
        print(f'❌ Error inesperado: {str(e)}')
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Uso: python validate_csv.py archivo.csv')
        sys.exit(1)
    
    success = validate_csv(sys.argv[1])
    sys.exit(0 if success else 1)