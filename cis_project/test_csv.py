#!/usr/bin/env python
"""
Script de diagnóstico para archivos CSV de Nessus
Ejecutar: python test_csv.py /ruta/al/archivo.csv
"""
import sys
import pandas as pd

def diagnose_csv(filepath):
    print(f"🔍 Diagnosticando: {filepath}\n")
    
    # Test 1: Leer archivo básico
    print("1️⃣ Intentando lectura básica...")
    try:
        df = pd.read_csv(filepath)
        print(f"   ✅ Éxito: {len(df)} filas, {len(df.columns)} columnas")
        print(f"   📋 Columnas: {list(df.columns)}\n")
    except Exception as e:
        print(f"   ❌ Error: {e}\n")
        
        # Test 2: Lectura con opciones robustas
        print("2️⃣ Intentando lectura robusta (engine=python)...")
        try:
            df = pd.read_csv(
                filepath,
                encoding='utf-8',
                sep=',',
                quotechar='"',
                escapechar='\\',
                engine='python',
                on_bad_lines='skip',
                skipinitialspace=True
            )
            print(f"   ✅ Éxito: {len(df)} filas, {len(df.columns)} columnas")
            print(f"   📋 Columnas: {list(df.columns)}\n")
        except Exception as e2:
            print(f"   ❌ Error: {e2}\n")
            
            # Test 3: Mostrar primeras líneas raw
            print("3️⃣ Mostrando primeras 5 líneas raw del archivo:")
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if i >= 5:
                            break
                        print(f"   Línea {i+1}: {line[:200]}...")
            except Exception as e3:
                print(f"   ❌ Error leyendo archivo: {e3}")
            return
    
    # Test 4: Verificar columnas requeridas
    print("4️⃣ Verificando columnas requeridas...")
    required = ['Plugin ID', 'Risk', 'Description', 'Plugin Output']
    missing = [col for col in required if col not in df.columns]
    
    if missing:
        print(f"   ⚠️  Faltan columnas: {missing}")
        print(f"   💡 Columnas disponibles: {list(df.columns)}")
    else:
        print(f"   ✅ Todas las columnas requeridas presentes\n")
        
        # Test 5: Mostrar estadísticas
        print("5️⃣ Estadísticas del CSV:")
        print(f"   Total de filas: {len(df)}")
        print(f"   Risk 'None' (informativos): {len(df[df['Risk'] == 'None'])}")
        print(f"   Filas procesables: {len(df[df['Risk'] != 'None'])}")
        print(f"\n   Distribución de Risk:")
        print(df['Risk'].value_counts().to_string())
        
        # Test 6: Mostrar muestra de Description
        print(f"\n6️⃣ Muestra de Descriptions (primeras 3):")
        for idx, desc in enumerate(df['Description'].head(3)):
            print(f"   {idx+1}. {str(desc)[:150]}...")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: python test_csv.py /ruta/al/archivo.csv")
        sys.exit(1)
    
    diagnose_csv(sys.argv[1])