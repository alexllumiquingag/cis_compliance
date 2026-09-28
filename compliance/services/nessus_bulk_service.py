"""
Servicio para importar escaneos de Nessus con MÚLTIPLES SERVIDORES desde UN SOLO CSV
Versión mejorada con mejor tracking de hosts omitidos
"""
import logging
import pandas as pd
from typing import Dict, List, Tuple
from datetime import date
from django.db import transaction
from compliance.models import Asset, AssetLayer, Scan, ScanResult, BenchmarkPolicy
from compliance.validators import validate_csv_file
import csv
import io

logger = logging.getLogger('compliance')


class NessusBulkImportService:
    """Servicio para importar UN CSV con MÚLTIPLES servidores"""
    
    RISK_MAPPING = {
        'None': 'INFO',
        'Passed': 'PASSED',
        'Failed': 'FAILED',
        'Warning': 'WARNING',
    }
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.stats = {
            'total_rows': 0,
            'servers_found': 0,
            'servers_imported': 0,
            'servers_skipped': 0,
            'scans_created': [],
            'hosts_not_found': [],  # NUEVO: Lista de hosts que no existen
            'hosts_without_layer': [],  # NUEVO: Hosts sin layer configurado
            'errors': 0
        }
    
    def import_bulk_scan(
        self, 
        file, 
        benchmark_id: int,
        scan_date: date,
        layer_type: str = 'OS',  # OS, WEB, DB
        auto_create_assets: bool = False
    ) -> Tuple[List[Scan], Dict]:
        """
        Importa un CSV con múltiples servidores
        
        Args:
            file: Archivo CSV de Nessus
            benchmark_id: ID del benchmark a usar para TODOS los servidores
            scan_date: Fecha del escaneo
            layer_type: Tipo de capa (OS, WEB, DB)
            auto_create_assets: Si True, crea Assets automáticamente si no existen
            
        Returns:
            Tuple[List[Scan], Dict]: (lista_de_scans_creados, stats)
        """
        try:
            # Validar archivo
            file.seek(0)
            validate_csv_file(file)
            file.seek(0)
            
            # Leer y agrupar por servidor
            servers_data = self._parse_csv_by_server(file)
            
            self.stats['servers_found'] = len(servers_data)
            logger.info(f"Encontrados {len(servers_data)} servidores en el CSV")
            
            # Procesar cada servidor
            scans_created = []
            for hostname, rows_df in servers_data.items():
                try:
                    scan = self._process_server(
                        hostname=hostname,
                        rows_df=rows_df,
                        benchmark_id=benchmark_id,
                        scan_date=scan_date,
                        layer_type=layer_type,
                        auto_create_assets=auto_create_assets
                    )
                    
                    if scan:
                        scans_created.append(scan)
                        self.stats['servers_imported'] += 1
                        self.stats['scans_created'].append({
                            'hostname': hostname,
                            'scan_id': scan.id,
                            'compliance': float(scan.compliance_percentage),
                            'passed': scan.passed_count,
                            'failed': scan.failed_count
                        })
                    else:
                        self.stats['servers_skipped'] += 1
                        
                except Exception as e:
                    logger.error(f"Error procesando {hostname}: {str(e)}")
                    self.errors.append(f"{hostname}: {str(e)}")
                    self.stats['errors'] += 1
                    self.stats['servers_skipped'] += 1
            
            # Generar warnings consolidados
            self._generate_summary_warnings()
            
            return scans_created, self.stats
            
        except Exception as e:
            logger.error(f"Error en importación bulk: {str(e)}")
            self.errors.append(f"Error general: {str(e)}")
            raise
    
    def _parse_csv_by_server(self, file) -> Dict[str, pd.DataFrame]:
        """
        Lee el CSV y agrupa las filas por servidor
        Versión ROBUSTA para CSVs de Nessus con multiline strings
        
        Returns:
            Dict[hostname, DataFrame]: Diccionario con DataFrames por servidor
        """
        try:
            # CRÍTICO: Asegurar que el puntero esté al inicio
            file.seek(0)
            
            logger.info("Iniciando lectura de CSV con parser robusto...")
            
            # Intentar con diferentes encodings
            encodings_to_try = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            df = None
            successful_encoding = None
            
            for encoding in encodings_to_try:
                try:
                    file.seek(0)
                    logger.info(f"Intentando con encoding: {encoding}")
                    
                    # SOLUCIÓN: Usar python engine con quoting adecuado
                    # Esto maneja correctamente los saltos de línea dentro de comillas
                    df = pd.read_csv(
                        file,
                        encoding=encoding,
                        sep=',',
                        quotechar='"',
                        doublequote=True,  # Importante para comillas dobles
                        escapechar=None,   # No usar escape char
                        engine='python',   # Python engine es más robusto
                        on_bad_lines='warn',  # Advertir pero continuar
                        skipinitialspace=True,
                        keep_default_na=False,
                        skip_blank_lines=True,
                        # CRÍTICO: Estas opciones manejan multiline strings
                        quoting=1,  # csv.QUOTE_MINIMAL
                    )
                    
                    # Verificar que se leyó algo
                    if df is not None and len(df) > 0 and len(df.columns) > 0:
                        successful_encoding = encoding
                        logger.info(f"✓ CSV leído exitosamente con {encoding}")
                        logger.info(f"  Filas: {len(df)}, Columnas: {len(df.columns)}")
                        break
                    else:
                        logger.warning(f"CSV leído pero sin datos con {encoding}")
                        continue
                        
                except Exception as e:
                    logger.warning(f"✗ Fallo con {encoding}: {str(e)}")
                    df = None
                    continue
            
            # Si pandas falló con todos los encodings, intentar método manual
            if df is None or len(df) == 0 or len(df.columns) == 0:
                logger.warning("Pandas falló, intentando parser manual CSV...")
                df = self._manual_csv_parse(file)
                successful_encoding = 'manual'
            
            if df is None or len(df) == 0:
                raise ValueError(
                    "No se pudo leer el CSV. Verifica que el archivo no esté corrupto "
                    "y que tenga el formato correcto de Nessus."
                )
            
            # Normalizar nombres de columnas
            df.columns = df.columns.str.strip()
            
            logger.info(f"✓ CSV parseado exitosamente con {successful_encoding}")
            logger.info(f"  Total de filas: {len(df)}")
            logger.info(f"  Columnas: {list(df.columns)}")
            
            self.stats['total_rows'] = len(df)
            
            # Verificar columna 'Host'
            if 'Host' not in df.columns:
                available = ', '.join(df.columns[:10])
                raise ValueError(
                    f"El CSV debe tener una columna 'Host'. "
                    f"Columnas encontradas: {available}..."
                )
            
            # Mostrar muestra de datos
            if len(df) > 0:
                logger.info("\nPrimeras 3 filas (columnas principales):")
                cols_to_show = ['Host', 'Risk', 'Plugin ID', 'Description']
                cols_available = [c for c in cols_to_show if c in df.columns]
                if cols_available:
                    logger.info(df[cols_available].head(3).to_string())
            
            # Filtrar informativos (Risk = "None")
            initial_count = len(df)
            df = df[df['Risk'] != 'None'].copy()
            filtered_count = initial_count - len(df)
            
            logger.info(f"\nFiltrando resultados informativos:")
            logger.info(f"  Filas con Risk='None': {filtered_count}")
            logger.info(f"  Filas después de filtrar: {len(df)}")
            
            if len(df) == 0:
                raise ValueError(
                    "Después de filtrar informativos (Risk=None), no quedan filas. "
                    "Verifica que el CSV contenga checks de compliance (PASSED/FAILED/WARNING)."
                )
            
            # Agrupar por Host
            servers = {}
            
            logger.info("\nAgrupando por servidor...")
            for hostname, group_df in df.groupby('Host'):
                hostname_clean = str(hostname).strip()
                
                # Validar hostname
                if not hostname_clean or hostname_clean.lower() in ['nan', 'none', '', 'null']:
                    logger.warning(f"⚠️  Hostname inválido omitido: '{hostname}'")
                    continue
                
                servers[hostname_clean] = group_df
                logger.info(f"  • {hostname_clean}: {len(group_df)} checks")
            
            if len(servers) == 0:
                raise ValueError(
                    "No se encontraron hosts válidos en el CSV. "
                    "Verifica que la columna 'Host' contenga hostnames válidos."
                )
            
            logger.info(f"\n✓ Total de servidores agrupados: {len(servers)}")
            
            return servers
            
        except pd.errors.EmptyDataError:
            raise ValueError("El archivo CSV está vacío")
            
        except pd.errors.ParserError as e:
            logger.error(f"Error de parser: {str(e)}")
            raise ValueError(f"Error al parsear CSV: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error inesperado: {str(e)}")
            logger.error(f"Tipo: {type(e).__name__}")
            
            # Mostrar info del archivo para debug
            try:
                file.seek(0)
                first_bytes = file.read(1000).decode('utf-8', errors='ignore')
                logger.error(f"\nPrimeros 1000 caracteres:\n{first_bytes}")
            except:
                pass
            
            raise ValueError(f"Error al parsear CSV: {str(e)}")

    def _manual_csv_parse(self, file) -> pd.DataFrame:
        """
        Parser manual de CSV como fallback
        Maneja casos complejos que pandas no puede
        """
        import csv
        import io
        
        logger.info("Usando parser CSV manual...")
        
        try:
            file.seek(0)
            
            # Intentar decodificar el archivo
            content = None
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    file.seek(0)
                    content = file.read().decode(encoding)
                    logger.info(f"Archivo decodificado con {encoding}")
                    break
                except:
                    continue
            
            if content is None:
                logger.error("No se pudo decodificar el archivo")
                return None
            
            # Usar csv.reader que maneja mejor multiline strings
            reader = csv.reader(
                io.StringIO(content),
                delimiter=',',
                quotechar='"',
                doublequote=True,
                skipinitialspace=True
            )
            
            # Leer todas las filas
            rows = list(reader)
            
            if len(rows) < 2:
                logger.error("CSV no tiene suficientes filas")
                return None
            
            # Primera fila = headers
            headers = [h.strip() for h in rows[0]]
            data_rows = rows[1:]
            
            logger.info(f"Parser manual: {len(headers)} columnas, {len(data_rows)} filas")
            
            # Crear DataFrame
            df = pd.DataFrame(data_rows, columns=headers)
            
            return df
            
        except Exception as e:
            logger.error(f"Error en parser manual: {str(e)}")
            return None



    # También actualizar el método import_bulk_scan para mejor manejo
    def import_bulk_scan(
        self, 
        file, 
        benchmark_id: int,
        scan_date: date,
        layer_type: str = 'OS',
        auto_create_assets: bool = False
    ) -> Tuple[List[Scan], Dict]:
        """
        Importa un CSV con múltiples servidores
        VERSIÓN MEJORADA con mejor manejo de archivos
        """
        try:
            # PASO 1: Validar archivo
            logger.info("=" * 60)
            logger.info("INICIANDO IMPORTACIÓN BULK")
            logger.info("=" * 60)
            
            file.seek(0)
            logger.info(f"Archivo: {getattr(file, 'name', 'unknown')}")
            logger.info(f"Tamaño: {file.size if hasattr(file, 'size') else 'unknown'} bytes")
            
            # Validar
            validate_csv_file(file)
            logger.info("✓ Validación de archivo completada")
            
            # IMPORTANTE: Resetear después de validar
            file.seek(0)
            
            # PASO 2: Parsear y agrupar por servidor
            logger.info("\nPaso 1: Parseando CSV y agrupando por servidor...")
            servers_data = self._parse_csv_by_server(file)
            
            self.stats['servers_found'] = len(servers_data)
            logger.info(f"✓ Encontrados {len(servers_data)} servidores en el CSV")
            
            if len(servers_data) == 0:
                raise ValueError(
                    "No se encontraron servidores válidos en el CSV. "
                    "Verifica que la columna 'Host' contenga hostnames válidos."
                )
            
            # PASO 3: Procesar cada servidor
            logger.info("\nPaso 2: Procesando servidores individuales...")
            scans_created = []
            
            for idx, (hostname, rows_df) in enumerate(servers_data.items(), 1):
                logger.info(f"\n[{idx}/{len(servers_data)}] Procesando: {hostname}")
                
                try:
                    scan = self._process_server(
                        hostname=hostname,
                        rows_df=rows_df,
                        benchmark_id=benchmark_id,
                        scan_date=scan_date,
                        layer_type=layer_type,
                        auto_create_assets=auto_create_assets
                    )
                    
                    if scan:
                        scans_created.append(scan)
                        self.stats['servers_imported'] += 1
                        self.stats['scans_created'].append({
                            'hostname': hostname,
                            'scan_id': scan.id,
                            'compliance': float(scan.compliance_percentage),
                            'passed': scan.passed_count,
                            'failed': scan.failed_count
                        })
                        logger.info(f"  ✓ Scan creado: ID={scan.id}, Compliance={scan.compliance_percentage}%")
                    else:
                        self.stats['servers_skipped'] += 1
                        logger.warning(f"  ✗ Servidor omitido: {hostname}")
                        
                except Exception as e:
                    logger.error(f"  ✗ Error procesando {hostname}: {str(e)}")
                    self.errors.append(f"{hostname}: {str(e)}")
                    self.stats['errors'] += 1
                    self.stats['servers_skipped'] += 1
            
            # PASO 4: Generar warnings consolidados
            self._generate_summary_warnings()
            
            # PASO 5: Resumen final
            logger.info("\n" + "=" * 60)
            logger.info("RESUMEN DE IMPORTACIÓN")
            logger.info("=" * 60)
            logger.info(f"Servidores encontrados: {self.stats['servers_found']}")
            logger.info(f"Servidores importados: {self.stats['servers_imported']}")
            logger.info(f"Servidores omitidos: {self.stats['servers_skipped']}")
            logger.info(f"Errores: {self.stats['errors']}")
            logger.info("=" * 60)
            
            return scans_created, self.stats
            
        except Exception as e:
            logger.error(f"ERROR CRÍTICO en importación bulk: {str(e)}")
            logger.error(f"Tipo de error: {type(e).__name__}")
            self.errors.append(f"Error general: {str(e)}")
            raise
    
    @transaction.atomic
    def _process_server(
        self,
        hostname: str,
        rows_df: pd.DataFrame,
        benchmark_id: int,
        scan_date: date,
        layer_type: str,
        auto_create_assets: bool
    ) -> Scan:
        """
        Procesa un servidor individual y crea su Scan
        """
        # 1. Buscar o crear Asset
        asset = self._get_or_create_asset(hostname, auto_create_assets)
        if not asset:
            self.stats['hosts_not_found'].append(hostname)
            self.warnings.append(f"Host '{hostname}' no existe como Asset activo")
            return None
        
        # 2. Buscar o crear AssetLayer
        layer = self._get_or_create_layer(asset, layer_type, benchmark_id, auto_create_assets)
        if not layer:
            self.stats['hosts_without_layer'].append(hostname)
            self.warnings.append(
                f"Host '{hostname}': No se pudo crear/encontrar layer {layer_type} con benchmark #{benchmark_id}"
            )
            return None
        
        # 3. Crear Scan
        scan = Scan.objects.create(
            asset=asset,
            layer=layer,
            scan_date=scan_date
        )
        
        logger.info(f"Scan creado para {hostname}: ID={scan.id}")
        
        # 4. Procesar resultados de este servidor
        processed_policies = set()
        for idx, row in rows_df.iterrows():
            try:
                self._create_scan_result_from_row(
                    scan=scan,
                    row=row,
                    layer=layer,
                    processed_policies=processed_policies
                )
            except Exception as e:
                logger.warning(f"{hostname} - Fila {idx}: {str(e)}")
        
        # 5. Calcular métricas
        self._calculate_scan_metrics(scan)
        
        # 6. Actualizar baseline y generar alertas
        self._update_baseline(scan)
        self._generate_alerts(scan)
        
        return scan
    
    def _debug_available_assets(self):
        """Muestra lista de assets disponibles para debug"""
        logger.info("\n📋 Assets ACTIVOS disponibles en el sistema:")
        
        assets = Asset.objects.filter(status='ACTIVE')
        
        if not assets.exists():
            logger.warning("  ⚠️  No hay Assets ACTIVOS en el sistema")
            return
        
        logger.info(f"  Total: {assets.count()} assets activos")
        logger.info("\n  Lista de assets:")
        
        for asset in assets[:20]:  # Mostrar primeros 20
            logger.info(f"    • {asset.hostname} ({asset.ip_address})")
        
        if assets.count() > 20:
            logger.info(f"    ... y {assets.count() - 20} más")
        
        logger.info("")


    def _get_or_create_asset(self, hostname: str, auto_create: bool) -> Asset:
        """
        Busca o crea un Asset
        MEJORADO: Busca por hostname O por IP (común en CSVs de Nessus)
        """
        try:
            # INTENTO 1: Buscar por hostname (comportamiento original)
            try:
                asset = Asset.objects.get(hostname__iexact=hostname, status='ACTIVE')
                logger.info(f"  ✓ Asset encontrado por hostname: {asset.hostname}")
                return asset
            except Asset.DoesNotExist:
                pass
            
            # INTENTO 2: Buscar por IP (común en CSVs de Nessus)
            # El CSV puede tener IPs en vez de hostnames
            try:
                asset = Asset.objects.get(ip_address=hostname, status='ACTIVE')
                logger.info(f"  ✓ Asset encontrado por IP: {asset.hostname} ({asset.ip_address})")
                return asset
            except Asset.DoesNotExist:
                pass
            
            # INTENTO 3: Buscar si el hostname contiene la IP parcial
            # Por ejemplo, si el hostname es "server-10-10-2-16"
            if '.' in hostname:  # Parece una IP
                # Buscar por IP exacta primero
                matching_assets = Asset.objects.filter(
                    ip_address=hostname,
                    status='ACTIVE'
                )
                
                if matching_assets.exists():
                    asset = matching_assets.first()
                    logger.info(f"  ✓ Asset encontrado por IP exacta: {asset.hostname} ({asset.ip_address})")
                    return asset
            
            # No encontrado
            logger.warning(f"  ✗ Asset no encontrado: '{hostname}'")
            logger.warning(f"     Intentos: hostname='{hostname}' o ip_address='{hostname}'")
            
            if auto_create:
                # Crear asset automáticamente
                # Detectar si es IP o hostname
                import re
                ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                is_ip = re.match(ip_pattern, hostname)
                
                if is_ip:
                    # Es una IP, crear asset con hostname genérico
                    asset = Asset.objects.create(
                        hostname=f"auto-{hostname.replace('.', '-')}",
                        ip_address=hostname,
                        status='ACTIVE'
                    )
                    logger.info(f"  ✓ Asset creado automáticamente: {asset.hostname} ({asset.ip_address})")
                else:
                    # Es un hostname, usar IP placeholder
                    asset = Asset.objects.create(
                        hostname=hostname,
                        ip_address='0.0.0.0',
                        status='ACTIVE'
                    )
                    logger.info(f"  ✓ Asset creado automáticamente: {asset.hostname}")
                
                return asset
            
            return None
            
        except Exception as e:
            logger.error(f"  ✗ Error buscando asset '{hostname}': {str(e)}")
            return None
    
    def _get_or_create_layer(
        self, 
        asset: Asset, 
        layer_type: str, 
        benchmark_id: int,
        auto_create: bool
    ) -> AssetLayer:
        """Busca o crea un AssetLayer"""
        try:
            return AssetLayer.objects.get(
                asset=asset,
                layer_type=layer_type,
                benchmark_id=benchmark_id
            )
        except AssetLayer.DoesNotExist:
            if auto_create:
                layer = AssetLayer.objects.create(
                    asset=asset,
                    layer_type=layer_type,
                    benchmark_id=benchmark_id,
                    description=f"Auto-creado desde CSV bulk import"
                )
                logger.info(f"Layer creado para {asset.hostname}: {layer_type}")
                return layer
            return None
    
    def _create_scan_result_from_row(
        self, 
        scan: Scan, 
        row: pd.Series, 
        layer: AssetLayer,
        processed_policies: set
    ):
        """Crea un ScanResult desde una fila del CSV"""
        
        # Extraer datos
        description = str(row.get('Description', '')).strip()
        risk = str(row.get('Risk', '')).strip()
        plugin_id = str(row.get('Plugin ID', '')).strip()
        plugin_output = str(row.get('Plugin Output', '')).strip()
        
        if not description or not risk:
            return
        
        # Matching con política
        policy = self._match_policy(description, layer.benchmark)
        if not policy:
            return
        
        # Evitar duplicados
        if policy.id in processed_policies:
            return
        
        # Mapear risk
        risk_normalized = risk.capitalize()
        risk_mapped = self.RISK_MAPPING.get(risk_normalized, 'INFO')
        
        # Crear resultado
        ScanResult.objects.create(
            scan=scan,
            policy=policy,
            plugin_id=plugin_id,
            risk=risk_mapped,
            description=description,
            plugin_output=plugin_output
        )
        
        processed_policies.add(policy.id)
    
    def _match_policy(self, description: str, benchmark) -> BenchmarkPolicy:
        """Hace matching entre Description y políticas del benchmark"""
        import re
        
        # Limpiar description
        desc = description.strip().strip('"\'')
        desc = re.sub(r'\s*:\s*\[(?:PASSED|FAILED|WARNING|INFO)\].*$', '', desc, flags=re.IGNORECASE)
        desc = ' '.join(desc.split())
        
        # Extraer recommendation
        pattern = r'^([\d.]+)\s+(.+)$'
        match = re.match(pattern, desc)
        
        if match:
            recommendation = match.group(1).strip()
            policy = BenchmarkPolicy.objects.filter(
                benchmark=benchmark,
                recommendation=recommendation
            ).first()
            
            if policy:
                return policy
        
        return None
    
    def _calculate_scan_metrics(self, scan: Scan):
        """Calcula métricas del scan"""
        results = scan.results.all()
        
        scan.total_policies = results.count()
        scan.passed_count = results.filter(risk='PASSED').count()
        scan.failed_count = results.filter(risk='FAILED').count()
        scan.warning_count = results.filter(risk='WARNING').count()
        scan.compliance_percentage = scan.calculate_compliance()
        scan.save()
    
    def _update_baseline(self, scan: Scan):
        """Actualiza baseline si es necesario"""
        from compliance.models import Baseline
        from django.utils import timezone
        
        baseline, created = Baseline.objects.get_or_create(
            asset=scan.asset,
            layer=scan.layer,
            defaults={
                'compliance_percentage': scan.compliance_percentage,
                'scan_reference': scan,
                'is_manual': False
            }
        )
        
        if not created and not baseline.is_manual:
            if scan.compliance_percentage > baseline.compliance_percentage:
                baseline.compliance_percentage = scan.compliance_percentage
                baseline.scan_reference = scan
                baseline.set_at = timezone.now()
                baseline.save()
    
    def _generate_alerts(self, scan: Scan):
        """Genera alertas para el scan"""
        from compliance.services.alert_service import AlertService
        
        alert_service = AlertService()
        alert_service.check_and_create_alerts(scan)
    
    def _generate_summary_warnings(self):
        """Genera warnings consolidados al final del proceso"""
        if self.stats['hosts_not_found']:
            hosts_list = ', '.join(self.stats['hosts_not_found'])
            self.warnings.append(
                f"⚠️ Hosts no encontrados como Assets activos ({len(self.stats['hosts_not_found'])}): {hosts_list}"
            )
        
        if self.stats['hosts_without_layer']:
            hosts_list = ', '.join(self.stats['hosts_without_layer'])
            self.warnings.append(
                f"⚠️ Hosts sin layer configurado ({len(self.stats['hosts_without_layer'])}): {hosts_list}"
            )
    
    def get_report(self) -> dict:
        """Retorna reporte de la importación"""
        return {
            'success': self.stats['errors'] == 0,
            'stats': self.stats,
            'errors': self.errors,
            'warnings': self.warnings
        }