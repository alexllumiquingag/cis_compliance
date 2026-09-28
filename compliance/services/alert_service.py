"""
Servicio para generar y gestionar alertas del sistema
"""
import logging
from decimal import Decimal
from typing import List
from django.utils import timezone
from compliance.models import Scan, ScanResult, Baseline, Threshold, Alert

logger = logging.getLogger('compliance')


class AlertService:
    """Servicio para gestionar alertas automáticas"""
    
    def __init__(self):
        self.alerts_created = []
    
    def check_and_create_alerts(self, scan: Scan) -> List[Alert]:
        """
        Verifica todas las condiciones y crea alertas necesarias
        
        Args:
            scan: Escaneo recién procesado
            
        Returns:
            List[Alert]: Lista de alertas creadas
        """
        
        self.alerts_created = []
        
        # 1. Verificar caída de línea base
        self._check_baseline_drop(scan)
        
        # 2. Verificar políticas que cambiaron a FAILED
        self._check_new_failed_policies(scan)
        
        # 3. Verificar caída bajo umbral
        self._check_threshold_drop(scan)
        
        # 4. Verificar degradación crítica (>5%)
        self._check_critical_degradation(scan)
        
        logger.info(f"Alertas generadas: {len(self.alerts_created)}")
        return self.alerts_created
    
    def _check_baseline_drop(self, scan: Scan):
        """
        Alerta si el compliance cayó por debajo de la línea base
        
        Criterio: Línea base: 95%, Nuevo escaneo: 93% → ALERTA
        """
        
        try:
            baseline = Baseline.objects.get(asset=scan.asset, layer=scan.layer)
            
            baseline_val = Decimal(str(baseline.compliance_percentage))
            scan_val = Decimal(str(scan.compliance_percentage))

            if scan_val < baseline_val:
                drop = baseline_val - scan_val
                
                # Determinar severidad
                if drop >= 5:
                    severity = 'CRITICAL'
                elif drop >= 3:
                    severity = 'HIGH'
                elif drop >= 1:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                # Crear alerta
                alert = Alert.objects.create(
                    alert_type='BASELINE_DROP',
                    severity=severity,
                    status='ACTIVE',
                    asset=scan.asset,
                    layer=scan.layer,
                    scan=scan,
                    title=f'Compliance cayó por debajo de línea base',
                    message=(
                        f'El asset {scan.asset.hostname} en capa {scan.layer.get_layer_type_display()} '
                        f'ha caído por debajo de su línea base.\n'
                        f'Línea base: {baseline.compliance_percentage}%\n'
                        f'Escaneo actual: {scan.compliance_percentage}%\n'
                        f'Degradación: {drop:.2f}%'
                    ),
                    previous_value=baseline.compliance_percentage,
                    current_value=scan.compliance_percentage
                )
                
                self.alerts_created.append(alert)
                logger.warning(f"Alerta creada: Caída de línea base - {drop:.2f}%")
                
        except Baseline.DoesNotExist:
            # No hay línea base todavía, es el primer escaneo
            logger.info("No hay línea base previa, no se genera alerta")
    
    def _check_new_failed_policies(self, scan: Scan):
        """
        Alerta si políticas cambiaron de PASSED a FAILED
        
        Criterio: Escaneo anterior: Policy XYZ = PASSED
                  Escaneo nuevo: Policy XYZ = FAILED → ALERTA
        """
        
        # Obtener escaneo anterior del mismo asset/layer
        previous_scan = Scan.objects.filter(
            asset=scan.asset,
            layer=scan.layer,
            scan_date__lt=scan.scan_date
        ).order_by('-scan_date').first()
        
        if not previous_scan:
            logger.info("No hay escaneo previo, no se puede comparar políticas")
            return
        
        # Obtener políticas FAILED en el nuevo escaneo
        current_failed = scan.results.filter(risk='FAILED').values_list('policy_id', flat=True)
        
        # Obtener políticas PASSED en el escaneo anterior
        previous_passed = previous_scan.results.filter(
            risk='PASSED',
            policy_id__in=current_failed
        )
        
        new_failed_count = previous_passed.count()
        
        if new_failed_count > 0:
            # Obtener detalles de las políticas
            policies = []
            for result in previous_passed[:10]:  # Limitar a 10 para el mensaje
                policies.append(
                    f"• {result.policy.section} {result.policy.recommendation} - {result.policy.title[:60]}"
                )
            
            # Determinar severidad según cantidad
            if new_failed_count >= 10:
                severity = 'CRITICAL'
            elif new_failed_count >= 5:
                severity = 'HIGH'
            elif new_failed_count >= 2:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Crear alerta
            alert = Alert.objects.create(
                alert_type='POLICY_FAILED',
                severity=severity,
                status='ACTIVE',
                asset=scan.asset,
                layer=scan.layer,
                scan=scan,
                title=f'{new_failed_count} política(s) cambiaron a FAILED',
                message=(
                    f'El asset {scan.asset.hostname} en capa {scan.layer.get_layer_type_display()} '
                    f'tiene {new_failed_count} política(s) que antes pasaban y ahora fallan:\n\n'
                    + '\n'.join(policies[:10]) +
                    (f'\n\n... y {new_failed_count - 10} más' if new_failed_count > 10 else '')
                ),
                previous_value=Decimal(new_failed_count),
                current_value=Decimal(0)
            )
            
            self.alerts_created.append(alert)
            logger.warning(f"Alerta creada: {new_failed_count} nuevas políticas fallidas")
    
    def _check_threshold_drop(self, scan: Scan):
        """
        Alerta si el asset cayó por debajo del umbral de hardenización
        
        Criterio: Umbral: 90%
                  Escaneo anterior: 91%
                  Escaneo nuevo: 89% → ALERTA: "Asset dejó de estar hardenizado"
        """
        
        # Obtener umbral configurado
        threshold = Threshold.get_hardening_threshold()
        threshold_decimal = Decimal(str(threshold))

        # Obtener escaneo anterior
        previous_scan = Scan.objects.filter(
            asset=scan.asset,
            layer=scan.layer,
            scan_date__lt=scan.scan_date
        ).order_by('-scan_date').first()
        
        if not previous_scan:
            return
        
        prev_val = Decimal(str(previous_scan.compliance_percentage))
        curr_val = Decimal(str(scan.compliance_percentage))

        # Verificar si cruzó el umbral de arriba hacia abajo
        was_above = prev_val >= threshold_decimal
        is_below = curr_val < threshold_decimal
        
        if was_above and is_below:
            alert = Alert.objects.create(
                alert_type='THRESHOLD_DROP',
                severity='HIGH',
                status='ACTIVE',
                asset=scan.asset,
                layer=scan.layer,
                scan=scan,
                title=f'Asset cayó bajo el umbral de hardenización',
                message=(
                    f'El asset {scan.asset.hostname} en capa {scan.layer.get_layer_type_display()} '
                    f'ha caído por debajo del umbral de hardenización.\n'
                    f'Umbral: {threshold}%\n'
                    f'Escaneo anterior: {previous_scan.compliance_percentage}%\n'
                    f'Escaneo actual: {scan.compliance_percentage}%\n\n'
                    f'El asset ya no cumple con los estándares mínimos de hardenización.'
                ),
                previous_value=previous_scan.compliance_percentage,
                current_value=scan.compliance_percentage
            )
            
            self.alerts_created.append(alert)
            logger.warning(f"Alerta creada: Asset cayó bajo umbral")
    
    def _check_critical_degradation(self, scan: Scan):
        """
        Alerta si hay degradación crítica (>5%)
        
        Criterio: Degradación >5% entre escaneos consecutivos
        """
        
        # Obtener escaneo anterior
        previous_scan = Scan.objects.filter(
            asset=scan.asset,
            layer=scan.layer,
            scan_date__lt=scan.scan_date
        ).order_by('-scan_date').first()
        
        if not previous_scan:
            return
        
        # Calcular degradación
        prev_val = Decimal(str(previous_scan.compliance_percentage))
        curr_val = Decimal(str(scan.compliance_percentage))

        degradation = prev_val - curr_val

        if degradation > Decimal('5'):
            alert = Alert.objects.create(
                alert_type='CRITICAL_DROP',
                severity='CRITICAL',
                status='ACTIVE',
                asset=scan.asset,
                layer=scan.layer,
                scan=scan,
                title=f'Degradación crítica de compliance detectada',
                message=(
                    f'⚠️ ALERTA CRÍTICA ⚠️\n\n'
                    f'El asset {scan.asset.hostname} en capa {scan.layer.get_layer_type_display()} '
                    f'ha experimentado una degradación severa en su compliance.\n\n'
                    f'Escaneo anterior ({previous_scan.scan_date}): {previous_scan.compliance_percentage}%\n'
                    f'Escaneo actual ({scan.scan_date}): {scan.compliance_percentage}%\n'
                    f'Degradación: {degradation:.2f}%\n\n'
                    f'Se requiere acción inmediata para investigar las causas de esta degradación.'
                ),
                previous_value=previous_scan.compliance_percentage,
                current_value=scan.compliance_percentage
            )
            
            self.alerts_created.append(alert)
            logger.critical(f"Alerta CRÍTICA creada: Degradación de {degradation:.2f}%")
            
            # Enviar email si está configurado
            self._send_critical_alert_email(alert)
    
    def _send_critical_alert_email(self, alert: Alert):
        """Envía email para alertas críticas"""
        
        try:
            from django.core.mail import send_mail
            from django.conf import settings
            
            subject = f'[CRÍTICO] {alert.title}'
            message = alert.message
            
            # Lista de destinatarios (configurar en settings)
            recipients = getattr(settings, 'ALERT_EMAIL_RECIPIENTS', [])
            
            if recipients:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=recipients,
                    fail_silently=False,
                )
                logger.info(f"Email de alerta crítica enviado a {recipients}")
        
        except Exception as e:
            logger.error(f"Error al enviar email de alerta: {str(e)}")
    
    def get_active_alerts_count(self, asset=None, layer=None) -> dict:
        """
        Obtiene conteo de alertas activas
        
        Returns:
            dict con conteos por severidad
        """
        
        query = Alert.objects.filter(status='ACTIVE')
        
        if asset:
            query = query.filter(asset=asset)
        
        if layer:
            query = query.filter(layer=layer)
        
        return {
            'total': query.count(),
            'critical': query.filter(severity='CRITICAL').count(),
            'high': query.filter(severity='HIGH').count(),
            'medium': query.filter(severity='MEDIUM').count(),
            'low': query.filter(severity='LOW').count(),
        }
    
    def acknowledge_alert(self, alert_id: int, acknowledged_by: str):
        """Marca una alerta como reconocida"""
        
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.status = 'ACKNOWLEDGED'
            alert.acknowledged_at = timezone.now()
            alert.acknowledged_by = acknowledged_by
            alert.save()
            
            logger.info(f"Alerta {alert_id} reconocida por {acknowledged_by}")
            return alert
        
        except Alert.DoesNotExist:
            logger.error(f"Alerta {alert_id} no existe")
            return None
    
    def resolve_alert(self, alert_id: int):
        """Marca una alerta como resuelta"""
        
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.status = 'RESOLVED'
            alert.resolved_at = timezone.now()
            alert.save()
            
            logger.info(f"Alerta {alert_id} marcada como resuelta")
            return alert
        
        except Alert.DoesNotExist:
            logger.error(f"Alerta {alert_id} no existe")
            return None