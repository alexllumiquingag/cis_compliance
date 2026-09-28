"""
Script para verificar que los datos estén correctamente cargados
Ejecutar en Django shell: python manage.py shell < debug_script.py
"""

from compliance.models import Benchmark, BenchmarkPolicy, Asset, AssetLayer

print("=" * 80)
print("VERIFICACIÓN DE DATOS DEL SISTEMA")
print("=" * 80)

# 1. Verificar Benchmarks
print("\n1. BENCHMARKS:")
benchmarks = Benchmark.objects.all()
print(f"   Total benchmarks: {benchmarks.count()}")
for b in benchmarks:
    print(f"   - {b.name} v{b.version} ({b.policies.count()} políticas)")

# 2. Verificar formato de recommendations en BenchmarkPolicy
print("\n2. FORMATO DE RECOMMENDATIONS:")
if benchmarks.exists():
    benchmark = benchmarks.first()
    sample_policies = BenchmarkPolicy.objects.filter(benchmark=benchmark)[:10]
    print(f"   Benchmark: {benchmark.name}")
    print(f"   Muestras de recommendations:")
    for p in sample_policies:
        print(f"   - Section: {p.section:10} | Recommendation: {p.recommendation:10} | Title: {p.title[:60]}")
    
    # Verificar si hay recommendations vacías
    empty_recs = BenchmarkPolicy.objects.filter(
        benchmark=benchmark,
        recommendation__isnull=True
    ).count()
    empty_recs += BenchmarkPolicy.objects.filter(
        benchmark=benchmark,
        recommendation=''
    ).count()
    
    print(f"\n   ⚠️  Políticas con recommendation vacía: {empty_recs}")
    
    # Mostrar distribución de formatos
    print("\n   Distribución de formatos:")
    policies = BenchmarkPolicy.objects.filter(benchmark=benchmark)
    formats = {}
    for p in policies:
        dots = p.recommendation.count('.')
        formats[dots] = formats.get(dots, 0) + 1
    
    for dots, count in sorted(formats.items()):
        print(f"   - {dots} puntos (formato {'X' + '.X' * dots}): {count} políticas")

# 3. Verificar Assets y Layers
print("\n3. ASSETS Y LAYERS:")
assets = Asset.objects.filter(status='ACTIVE')
print(f"   Total assets activos: {assets.count()}")
for a in assets:
    layers = a.layers.all()
    print(f"   - {a.hostname} ({a.ip_address})")
    for l in layers:
        print(f"     └─ {l.get_layer_type_display()}: {l.benchmark.name}")

# 4. Test de matching con ejemplos del CSV
print("\n4. TEST DE MATCHING:")
print("   Ejemplos del CSV:")
csv_examples = [
    "1.1.1.7 Ensure udf kernel module is not available",
    "1.2.1.3 Ensure repo_gpgcheck is globally activated",
    "1.1.2.5.1 Ensure separate partition exists for /var/tmp",
]

if benchmarks.exists():
    benchmark = benchmarks.first()
    print(f"   Buscando en benchmark: {benchmark.name}\n")
    
    for example in csv_examples:
        # Extraer recommendation
        import re
        pattern = r'^([\d.]+)\s+(.+)$'
        match = re.match(pattern, example)
        
        if match:
            rec = match.group(1).strip()
            title = match.group(2).strip()
            
            # Buscar política
            policy = BenchmarkPolicy.objects.filter(
                benchmark=benchmark,
                recommendation=rec
            ).first()
            
            if policy:
                print(f"   ✓ '{rec}' → ENCONTRADA")
                print(f"     CSV:    {example}")
                print(f"     Policy: {policy.section} {policy.recommendation} - {policy.title[:50]}")
            else:
                print(f"   ✗ '{rec}' → NO ENCONTRADA")
                print(f"     CSV: {example}")
                
                # Buscar si existe con section similar
                similar = BenchmarkPolicy.objects.filter(
                    benchmark=benchmark,
                    section__startswith=rec.split('.')[0]
                ).values_list('recommendation', flat=True)[:5]
                
                if similar:
                    print(f"     Recommendations similares: {list(similar)}")
            
            print()

print("\n" + "=" * 80)
print("VERIFICACIÓN COMPLETADA")
print("=" * 80)
