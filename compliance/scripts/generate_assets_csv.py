"""
Script para generar un CSV de ejemplo con 500 assets
Ejecutar: python generate_assets_csv.py
"""
import csv
import random

# Configuración
OUTPUT_FILE = 'assets_500_example.csv'
NUM_ASSETS = 500

# Opciones de configuración
ENVIRONMENTS = ['PRODUCTION', 'DEVELOPMENT', 'CONTINGENCY', 'TESTING', 'STAGING', 'TRAINING']
ADMINISTRATORS = [f'ADMIN_{i}' for i in range(1, 11)]
RESPONSIBLES = [f'RESP_{i}' for i in range(1, 6)]

# Configuraciones de capas comunes
LAYER_CONFIGS = [
    # Linux + Apache
    {
        'os': ('OS', 'RHEL', 'CIS Red Hat Enterprise Linux 8', 'RHEL 8.5'),
        'web': ('WEB', 'APACHE', 'CIS Apache HTTP Server 2.4', 'Apache 2.4.52'),
        'db': None
    },
    # Linux + Tomcat
    {
        'os': ('OS', 'RHEL', 'CIS Red Hat Enterprise Linux 8', 'RHEL 8.6'),
        'web': ('WEB', 'TOMCAT', 'CIS Apache Tomcat 9', 'Tomcat 9.0.50'),
        'db': None
    },
    # Linux + Oracle
    {
        'os': ('OS', 'RHEL', 'CIS Red Hat Enterprise Linux 8', 'RHEL 8.5'),
        'web': None,
        'db': ('DB', 'ORACLE', 'CIS Oracle Database 19c', 'Oracle 19c Enterprise')
    },
    # Linux + MySQL
    {
        'os': ('OS', 'RHEL', 'CIS Red Hat Enterprise Linux 8', 'RHEL 8.6'),
        'web': None,
        'db': ('DB', 'MYSQL', 'CIS MySQL 8.0', 'MySQL 8.0.28')
    },
    # Windows + IIS + SQL Server
    {
        'os': ('OS', 'WINDOWS', 'CIS Windows Server 2019', 'Windows Server 2019 Datacenter'),
        'web': ('WEB', 'IIS', 'CIS IIS 10', 'IIS 10.0'),
        'db': ('DB', 'MSSQL', 'CIS SQL Server 2019', 'SQL Server 2019')
    },
    # Ubuntu + Nginx
    {
        'os': ('OS', 'UBUNTU', 'CIS Ubuntu Linux 20.04', 'Ubuntu 20.04 LTS'),
        'web': ('WEB', 'NGINX', 'CIS Nginx 1.18', 'Nginx 1.18.0'),
        'db': None
    },
    # Ubuntu + PostgreSQL
    {
        'os': ('OS', 'UBUNTU', 'CIS Ubuntu Linux 20.04', 'Ubuntu 20.04 LTS'),
        'web': None,
        'db': ('DB', 'POSTGRESQL', 'CIS PostgreSQL 13', 'PostgreSQL 13.4')
    },
    # AIX standalone
    {
        'os': ('OS', 'AIX', 'CIS AIX 7.2', 'AIX 7.2 TL5'),
        'web': None,
        'db': None
    },
    # ESXi
    {
        'os': ('OS', 'VMWARE_ESXI', 'CIS VMware ESXi 7.0', 'ESXi 7.0 U3'),
        'web': None,
        'db': None
    },
    # CentOS + JBoss
    {
        'os': ('OS', 'CENTOS', 'CIS CentOS Linux 8', 'CentOS 8 Stream'),
        'web': ('WEB', 'JBOSS', 'CIS JBoss EAP 7', 'JBoss EAP 7.4'),
        'db': None
    },
]

# Prefijos de hostname por tipo
HOSTNAME_PREFIXES = {
    'PRODUCTION': 'srv-prod',
    'DEVELOPMENT': 'srv-dev',
    'CONTINGENCY': 'srv-cont',
    'TESTING': 'srv-test',
    'STAGING': 'srv-stg',
    'TRAINING': 'srv-train',
}


def generate_ip():
    """Genera una IP aleatoria en rangos privados"""
    subnet = random.choice([
        (192, 168, random.randint(1, 50)),  # Producción
        (192, 168, random.randint(100, 120)),  # Desarrollo
        (192, 168, random.randint(200, 220)),  # Otros
        (10, random.randint(1, 50), random.randint(1, 254)),  # Otro rango
    ])
    return f"{subnet[0]}.{subnet[1]}.{subnet[2]}.{random.randint(1, 254)}"


def generate_asset_row(asset_num):
    """Genera una fila de asset con sus capas"""
    
    # Seleccionar ambiente (más peso a producción)
    env_weights = {
        'PRODUCTION': 40,
        'DEVELOPMENT': 20,
        'TESTING': 15,
        'STAGING': 10,
        'CONTINGENCY': 10,
        'TRAINING': 5,
    }
    environment = random.choices(
        list(env_weights.keys()),
        weights=list(env_weights.values())
    )[0]
    
    # Generar hostname
    prefix = HOSTNAME_PREFIXES[environment]
    hostname = f"{prefix}-{asset_num:03d}"
    
    # PCI (50% para producción, 10% para otros)
    pci_standard = 'TRUE' if environment == 'PRODUCTION' and random.random() < 0.5 else 'FALSE'
    
    # Seleccionar configuración de capas
    config = random.choice(LAYER_CONFIGS)
    
    # Construir la fila
    row = {
        'hostname': hostname,
        'ip_address': generate_ip(),
        'status': 'ACTIVE',
        'pci_standard': pci_standard,
        'environment': environment,
        'administrator': random.choice(ADMINISTRATORS),
        'responsible': random.choice(RESPONSIBLES),
    }
    
    # Agregar capas
    layer_num = 1
    for layer_type in ['os', 'web', 'db']:
        layer_data = config.get(layer_type)
        if layer_data:
            row[f'layer_type_{layer_num}'] = layer_data[0]
            row[f'software_type_{layer_num}'] = layer_data[1]
            row[f'benchmark_name_{layer_num}'] = layer_data[2]
            row[f'description_{layer_num}'] = layer_data[3]
            layer_num += 1
        else:
            row[f'layer_type_{layer_num}'] = ''
            row[f'software_type_{layer_num}'] = ''
            row[f'benchmark_name_{layer_num}'] = ''
            row[f'description_{layer_num}'] = ''
    
    # Completar capas vacías
    while layer_num <= 3:
        row[f'layer_type_{layer_num}'] = ''
        row[f'software_type_{layer_num}'] = ''
        row[f'benchmark_name_{layer_num}'] = ''
        row[f'description_{layer_num}'] = ''
        layer_num += 1
    
    return row


def main():
    """Genera el CSV con assets de ejemplo"""
    
    print(f"🚀 Generando {NUM_ASSETS} assets en {OUTPUT_FILE}...")
    
    # Definir columnas
    fieldnames = [
        'hostname', 'ip_address', 'status', 'pci_standard', 
        'environment', 'administrator', 'responsible',
        'layer_type_1', 'software_type_1', 'benchmark_name_1', 'description_1',
        'layer_type_2', 'software_type_2', 'benchmark_name_2', 'description_2',
        'layer_type_3', 'software_type_3', 'benchmark_name_3', 'description_3',
    ]
    
    # Generar assets
    assets = []
    for i in range(1, NUM_ASSETS + 1):
        assets.append(generate_asset_row(i))
    
    # Escribir CSV
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(assets)
    
    # Estadísticas
    stats = {
        'total': len(assets),
        'by_environment': {},
        'with_pci': sum(1 for a in assets if a['pci_standard'] == 'TRUE'),
    }
    
    for asset in assets:
        env = asset['environment']
        stats['by_environment'][env] = stats['by_environment'].get(env, 0) + 1
    
    # Mostrar resumen
    print(f"\n✅ Archivo generado: {OUTPUT_FILE}")
    print(f"\n📊 ESTADÍSTICAS:")
    print(f"   Total assets: {stats['total']}")
    print(f"   Con PCI DSS: {stats['with_pci']}")
    print(f"\n   Por ambiente:")
    for env, count in sorted(stats['by_environment'].items()):
        percentage = (count / stats['total']) * 100
        print(f"   • {env:15s}: {count:3d} ({percentage:5.1f}%)")
    
    print(f"\n💡 Para importar:")
    print(f"   python manage.py import_assets {OUTPUT_FILE} --dry-run")
    print(f"   python manage.py import_assets {OUTPUT_FILE}")


if __name__ == '__main__':
    main()