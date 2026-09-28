import csv

# Leer y limpiar el CSV
input_file = 'assets_assetslayers.csv'
output_file = 'assets_limpio.csv'

with open(input_file, 'r', encoding='utf-8-sig') as f_in:  # utf-8-sig elimina BOM
    with open(output_file, 'w', encoding='utf-8', newline='') as f_out:
        reader = csv.reader(f_in)
        writer = csv.writer(f_out)
        
        for i, row in enumerate(reader):
            if i == 0:
                # Limpiar headers: quitar espacios y caracteres invisibles
                clean_headers = [field.strip().replace('\ufeff', '') for field in row]
                writer.writerow(clean_headers)
                print(f"Headers originales: {row}")
                print(f"Headers limpios: {clean_headers}")
            else:
                writer.writerow(row)

print(f"\n✓ Archivo limpio creado: {output_file}")
