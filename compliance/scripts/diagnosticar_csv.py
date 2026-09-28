import csv

with open('assets_assetslayers.csv', 'rb') as f:
    # Leer primeros 500 bytes en formato binario
    primeros_bytes = f.read(500)
    print("Primeros bytes del archivo (hex):")
    print(primeros_bytes[:50].hex())
    print()

with open('assets_assetslayers.csv', 'r', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    
    print("Headers detectados:")
    for i, fieldname in enumerate(reader.fieldnames):
        print(f"  {i}: '{fieldname}' (len={len(fieldname)}, repr={repr(fieldname)})")
    
    print("\nHeaders requeridos:")
    required = ['hostname', 'ip_address', 'layer_type', 'benchmark_name', 'benchmark_version']
    for field in required:
        presente = field in reader.fieldnames
        print(f"  {field}: {'✓' if presente else '✗'}")
