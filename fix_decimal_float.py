#!/usr/bin/env python3
"""
Script para aplicar automáticamente el fix de Decimal vs Float
Ejecutar desde el directorio raíz del proyecto Django:

    python fix_decimal_float.py
"""

import os
import re
from pathlib import Path

def backup_file(filepath):
    """Crea un backup del archivo antes de modificarlo"""
    backup_path = f"{filepath}.backup"
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Backup creado: {backup_path}")
    return backup_path

def add_decimal_import(filepath):
    """Agrega import de Decimal si no existe"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Verificar si ya existe el import
    if 'from decimal import Decimal' in content:
        print(f"⚠️  Import de Decimal ya existe en {filepath}")
        return content
    
    # Buscar línea de imports de Django
    pattern = r'(from django\.[^\n]+\n)'
    match = re.search(pattern, content)
    
    if match:
        # Insertar después de los imports de Django
        insert_pos = match.end()
        new_content = (
            content[:insert_pos] +
            "from decimal import Decimal\n" +
            content[insert_pos:]
        )
        print(f"✅ Agregado import Decimal en {filepath}")
        return new_content
    else:
        # Si no hay imports de Django, agregar al inicio después de docstring
        if '"""' in content:
            # Después del docstring
            parts = content.split('"""', 2)
            if len(parts) >= 3:
                new_content = f'"""{parts[1]}"""\nfrom decimal import Decimal\n{parts[2]}'
                print(f"✅ Agregado import Decimal en {filepath}")
                return new_content
        
        # Fallback: agregar al inicio
        new_content = "from decimal import Decimal\n\n" + content
        print(f"✅ Agregado import Decimal al inicio de {filepath}")
        return new_content

def fix_models_py(filepath):
    """Fix para models.py"""
    print(f"\n🔧 Procesando {filepath}...")
    
    backup_file(filepath)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Agregar import de Decimal
    content = add_decimal_import(filepath)
    
    # 2. Fix calculate_compliance() en clase Scan
    old_pattern = r'def calculate_compliance\(self\):\s*"""[^"]*"""\s*if self\.total_policies == 0:\s*return 0\s*[^r]*return round\(\(self\.passed_count / self\.total_policies\) \* 100, 2\)'
    
    new_code = '''def calculate_compliance(self):
        """Calcula porcentaje de compliance - RETORNA Decimal"""
        if self.total_policies == 0:
            return Decimal('0.00')
        
        # Calcular compliance y convertir a Decimal
        compliance = (self.passed_count / self.total_policies) * 100
        
        # Retornar como Decimal con 2 decimales
        return Decimal(str(round(compliance, 2)))'''
    
    if re.search(old_pattern, content, re.DOTALL):
        content = re.sub(old_pattern, new_code, content, flags=re.DOTALL)
        print("✅ Modificado Scan.calculate_compliance()")
    else:
        print("⚠️  No se encontró el patrón exacto de calculate_compliance(), verificar manualmente")
    
    # 3. Fix Threshold.get_hardening_threshold()
    old_threshold = r"defaults=\{'value': 90\.00,"
    new_threshold = "defaults={'value': Decimal('90.00'),"
    
    if re.search(old_threshold, content):
        content = re.sub(old_threshold, new_threshold, content)
        print("✅ Modificado Threshold default value a Decimal")
    
    # Agregar return Decimal en get_hardening_threshold
    threshold_return = r'(def get_hardening_threshold\(cls\):.*?return\s+)threshold\.value'
    if re.search(threshold_return, content, re.DOTALL):
        content = re.sub(
            threshold_return, 
            r'\1Decimal(str(threshold.value))',
            content,
            flags=re.DOTALL
        )
        print("✅ Modificado Threshold.get_hardening_threshold() return")
    
    # Guardar cambios
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✅ {filepath} actualizado correctamente")

def fix_alert_service_py(filepath):
    """Fix para alert_service.py"""
    print(f"\n🔧 Procesando {filepath}...")
    
    backup_file(filepath)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Agregar import de Decimal
    content = add_decimal_import(filepath)
    
    # 2. Fix _check_baseline_drop
    # Buscar: if scan.compliance_percentage < baseline.compliance_percentage:
    # Reemplazar con conversión a Decimal
    
    baseline_drop_pattern = r'(def _check_baseline_drop[^:]+:.*?try:.*?baseline = Baseline\.objects\.get[^)]+\)\s*)(if scan\.compliance_percentage < baseline\.compliance_percentage:)'
    
    baseline_drop_fix = r'''\1
            # CRÍTICO: Asegurar que ambos sean Decimal
            baseline_val = Decimal(str(baseline.compliance_percentage))
            scan_val = Decimal(str(scan.compliance_percentage))
            
            if scan_val < baseline_val:'''
    
    if re.search(baseline_drop_pattern, content, re.DOTALL):
        content = re.sub(baseline_drop_pattern, baseline_drop_fix, content, flags=re.DOTALL)
        
        # Reemplazar referencias dentro del if
        content = content.replace(
            'drop = baseline.compliance_percentage - scan.compliance_percentage',
            'drop = baseline_val - scan_val'
        )
        content = re.sub(
            r"if drop >= 5:",
            "if drop >= Decimal('5'):",
            content
        )
        content = re.sub(
            r"elif drop >= 3:",
            "elif drop >= Decimal('3'):",
            content
        )
        content = re.sub(
            r"elif drop >= 1:",
            "elif drop >= Decimal('1'):",
            content
        )
        
        # Fix message formatting
        content = re.sub(
            r"f'Línea base: \{baseline\.compliance_percentage\}%\\n'",
            "f'Línea base: {baseline_val}%\\n'",
            content
        )
        content = re.sub(
            r"f'Escaneo actual: \{scan\.compliance_percentage\}%\\n'",
            "f'Escaneo actual: {scan_val}%\\n'",
            content
        )
        content = re.sub(
            r'previous_value=baseline\.compliance_percentage,\s*current_value=scan\.compliance_percentage',
            'previous_value=baseline_val,\n                    current_value=scan_val',
            content
        )
        
        print("✅ Modificado _check_baseline_drop()")
    else:
        print("⚠️  Patrón de _check_baseline_drop no encontrado")
    
    # 3. Fix _check_threshold_drop
    threshold_pattern = r'(threshold = Threshold\.get_hardening_threshold\(\)\s*)'
    threshold_fix = r'''\1threshold_decimal = Decimal(str(threshold))
        '''
    
    if re.search(threshold_pattern, content):
        content = re.sub(threshold_pattern, threshold_fix, content)
        
        # Fix comparisons
        content = re.sub(
            r'was_above = previous_scan\.compliance_percentage >= threshold',
            'prev_val = Decimal(str(previous_scan.compliance_percentage))\n        curr_val = Decimal(str(scan.compliance_percentage))\n        \n        was_above = prev_val >= threshold_decimal',
            content
        )
        content = re.sub(
            r'is_below = scan\.compliance_percentage < threshold',
            'is_below = curr_val < threshold_decimal',
            content
        )
        
        # Fix message in threshold alert
        content = re.sub(
            r"f'Umbral: \{threshold\}%\\n'",
            "f'Umbral: {threshold_decimal}%\\n'",
            content
        )
        content = re.sub(
            r"f'Escaneo anterior: \{previous_scan\.compliance_percentage\}%\\n'",
            "f'Escaneo anterior: {prev_val}%\\n'",
            content,
            count=1  # Solo en threshold_drop
        )
        content = re.sub(
            r"f'Escaneo actual: \{scan\.compliance_percentage\}%\\n\\n'",
            "f'Escaneo actual: {curr_val}%\\n\\n'",
            content,
            count=1
        )
        
        print("✅ Modificado _check_threshold_drop()")
    
    # 4. Fix _check_critical_degradation
    degradation_pattern = r'(def _check_critical_degradation[^:]+:.*?if not previous_scan:\s*return\s*)'
    degradation_fix = r'''\1
        # Asegurar que sean Decimal
        prev_val = Decimal(str(previous_scan.compliance_percentage))
        curr_val = Decimal(str(scan.compliance_percentage))
        '''
    
    if re.search(degradation_pattern, content, re.DOTALL):
        content = re.sub(degradation_pattern, degradation_fix, content, flags=re.DOTALL)
        
        # Fix calculation
        content = re.sub(
            r'degradation = previous_scan\.compliance_percentage - scan\.compliance_percentage',
            'degradation = prev_val - curr_val',
            content
        )
        
        # Fix comparison
        content = re.sub(
            r'if degradation > 5:',
            "if degradation > Decimal('5'):",
            content
        )
        
        # Fix message
        content = re.sub(
            r"f'Escaneo anterior \(\{previous_scan\.scan_date\}\): \{previous_scan\.compliance_percentage\}%\\n'",
            "f'Escaneo anterior ({previous_scan.scan_date}): {prev_val}%\\n'",
            content
        )
        content = re.sub(
            r"f'Escaneo actual \(\{scan\.scan_date\}\): \{scan\.compliance_percentage\}%\\n'",
            "f'Escaneo actual ({scan.scan_date}): {curr_val}%\\n'",
            content
        )
        
        print("✅ Modificado _check_critical_degradation()")
    
    # Guardar cambios
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✅ {filepath} actualizado correctamente")

def fix_nessus_service_py(filepath):
    """Fix para nessus_service.py"""
    print(f"\n🔧 Procesando {filepath}...")
    
    backup_file(filepath)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Agregar import de Decimal
    content = add_decimal_import(filepath)
    
    # 2. Fix _calculate_scan_metrics
    metrics_pattern = r"(scan\.compliance_percentage = scan\.calculate_compliance\(\))"
    metrics_fix = r"compliance = scan.calculate_compliance()\n        scan.compliance_percentage = Decimal(str(compliance))"
    
    if re.search(metrics_pattern, content):
        content = re.sub(metrics_pattern, metrics_fix, content)
        print("✅ Modificado _calculate_scan_metrics()")
    
    # 3. Fix _update_baseline
    baseline_pattern = r'(def _update_baseline[^:]+:.*?"""[^"]*"""[^b]*baseline, created = Baseline\.objects\.get_or_create\([^)]+\)\s*)'
    
    if re.search(baseline_pattern, content, re.DOTALL):
        # Agregar conversión antes del get_or_create
        baseline_fix = r'''\1
        # Asegurar que sea Decimal
        scan_compliance = Decimal(str(scan.compliance_percentage))
        
        baseline, created = Baseline.objects.get_or_create(
            asset=scan.asset,
            layer=scan.layer,
            defaults={
                'compliance_percentage': scan_compliance,
                'scan_reference': scan,
                'is_manual': False
            }
        )
        
        '''
        
        # Reemplazar el bloque completo
        old_block = r'baseline, created = Baseline\.objects\.get_or_create\(\s*asset=scan\.asset,\s*layer=scan\.layer,\s*defaults=\{[^}]+\}\s*\)'
        
        new_block = '''baseline, created = Baseline.objects.get_or_create(
            asset=scan.asset,
            layer=scan.layer,
            defaults={
                'compliance_percentage': scan_compliance,
                'scan_reference': scan,
                'is_manual': False
            }
        )'''
        
        content = re.sub(old_block, new_block, content, flags=re.DOTALL)
        
        # Fix comparison
        content = re.sub(
            r'if scan\.compliance_percentage > baseline\.compliance_percentage:',
            '''baseline_val = Decimal(str(baseline.compliance_percentage))
            
            if scan_compliance > baseline_val:''',
            content
        )
        
        content = re.sub(
            r"baseline\.compliance_percentage = scan\.compliance_percentage",
            "baseline.compliance_percentage = scan_compliance",
            content
        )
        
        content = re.sub(
            r"logger\.info\(f\"Línea base actualizada a \{scan\.compliance_percentage\}%\"\)",
            'logger.info(f"Línea base actualizada a {scan_compliance}%")',
            content
        )
        
        print("✅ Modificado _update_baseline()")
    
    # Guardar cambios
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✅ {filepath} actualizado correctamente")

def main():
    """Función principal"""
    print("=" * 60)
    print("🔧 FIX: Decimal vs Float - Compliance System")
    print("=" * 60)
    
    # Detectar directorio raíz del proyecto
    base_dir = Path.cwd()
    
    # Buscar directorio compliance
    compliance_dir = base_dir / 'compliance'
    
    if not compliance_dir.exists():
        print("❌ Error: No se encontró el directorio 'compliance'")
        print("   Ejecuta este script desde el directorio raíz del proyecto Django")
        return
    
    # Archivos a modificar
    files_to_fix = {
        'models.py': compliance_dir / 'models.py',
        'alert_service.py': compliance_dir / 'services' / 'alert_service.py',
        'nessus_service.py': compliance_dir / 'services' / 'nessus_service.py'
    }
    
    # Verificar que existan todos los archivos
    missing_files = [name for name, path in files_to_fix.items() if not path.exists()]
    
    if missing_files:
        print(f"❌ Error: No se encontraron los siguientes archivos:")
        for name in missing_files:
            print(f"   - {name}")
        return
    
    # Aplicar fixes
    try:
        fix_models_py(str(files_to_fix['models.py']))
        fix_alert_service_py(str(files_to_fix['alert_service.py']))
        fix_nessus_service_py(str(files_to_fix['nessus_service.py']))
        
        print("\n" + "=" * 60)
        print("✅ FIX APLICADO CORRECTAMENTE")
        print("=" * 60)
        print("\n📋 Próximos pasos:")
        print("   1. Revisar los archivos modificados")
        print("   2. Reiniciar el servidor Django:")
        print("      python manage.py runserver")
        print("   3. Probar subiendo un segundo scan")
        print("\n⚠️  Backups creados con extensión .backup")
        print("   Si algo sale mal, puedes restaurarlos")
        
    except Exception as e:
        print(f"\n❌ Error durante la aplicación del fix:")
        print(f"   {str(e)}")
        print("\n⚠️  Puedes restaurar los backups si es necesario")

if __name__ == '__main__':
    main()
