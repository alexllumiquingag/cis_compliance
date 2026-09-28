"""
Views para el dashboard de compliance
"""
from django.shortcuts import render
from django.http import JsonResponse
from django.db.models import Avg, Count, Q, Max, F, Min
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from datetime import timedelta, datetime
from decimal import Decimal
from compliance.forms import BulkNessusScanUploadForm
from compliance.services.nessus_bulk_service import NessusBulkImportService
from compliance.auth_views import admin_required, operator_or_admin_required
from compliance.models import (
    Asset, AssetLayer, Scan, ScanResult, 
    Baseline, Alert, Threshold, BenchmarkPolicy, GlobalExclusion,
    AssetExclusion
)

# ============================================================
# VISTA PRINCIPAL DEL DASHBOARD
# ============================================================

def dashboard_view(request):
    """Renderiza el dashboard principal"""
    return render(request, 'compliance/dashboard.html')


# ============================================================
# API ENDPOINTS PARA DATOS DEL DASHBOARD
# ============================================================

def api_dashboard_stats(request):
    """
    KPIs principales del dashboard
    GET /api/dashboard/stats/
    """
    
    # Obtener último escaneo por asset/layer
    latest_scans = Scan.objects.filter(
        id__in=Scan.objects.values('asset', 'layer')
        .annotate(latest=Max('scan_date'))
        .values_list('id', flat=True)
    )
    
    # Compliance promedio
    avg_compliance = latest_scans.aggregate(
        avg=Avg('compliance_percentage')
    )['avg'] or Decimal('0')
    
    # Assets hardenizados (compliance >= threshold)
    threshold = Threshold.get_hardening_threshold()
    total_assets = Asset.objects.filter(status='ACTIVE').count()
    hardened_assets = latest_scans.filter(
        compliance_percentage__gte=threshold
    ).values('asset').distinct().count()
    
    # Alertas activas
    active_alerts = Alert.objects.filter(status='ACTIVE').count()
    
    # Políticas fallidas totales
    failed_policies = ScanResult.objects.filter(
        scan__in=latest_scans,
        risk='FAILED'
    ).count()
    
    # Calcular cambios (comparar con período anterior)
    days_ago = timezone.now() - timedelta(days=30)
    previous_scans = Scan.objects.filter(
        scan_date__lt=days_ago.date(),
        id__in=Scan.objects.filter(
            scan_date__lt=days_ago.date()
        ).values('asset', 'layer').annotate(
            latest=Max('scan_date')
        ).values_list('id', flat=True)
    )
    
    previous_avg = previous_scans.aggregate(
        avg=Avg('compliance_percentage')
    )['avg'] or Decimal('0')
    
    compliance_change = float(avg_compliance - previous_avg)
    
    return JsonResponse({
        'compliance_avg': {
            'value': float(avg_compliance),
            'change': round(compliance_change, 2),
            'trend': 'up' if compliance_change >= 0 else 'down'
        },
        'hardened_assets': {
            'value': f"{hardened_assets}/{total_assets}",
            'count': hardened_assets,
            'total': total_assets,
            'change': 0,  # Calcular si es necesario
            'trend': 'neutral'
        },
        'active_alerts': {
            'value': active_alerts,
            'change': 0,  # Calcular comparando con período anterior
            'trend': 'neutral'
        },
        'failed_policies': {
            'value': failed_policies,
            'change': 0,
            'trend': 'neutral'
        }
    })


def api_compliance_trend(request):
    """
    Tendencia de compliance en el tiempo
    GET /api/dashboard/compliance-trend/?days=90&asset_id=1
    """
    
    days = int(request.GET.get('days', 90))
    asset_id = request.GET.get('asset_id')
    layer_id = request.GET.get('layer_id')
    
    # Fecha de inicio
    start_date = timezone.now() - timedelta(days=days)
    
    # Query base
    query = Scan.objects.filter(scan_date__gte=start_date.date())
    
    if asset_id:
        query = query.filter(asset_id=asset_id)
    if layer_id:
        query = query.filter(layer_id=layer_id)
    
    # Agrupar por mes
    scans = query.order_by('scan_date').values(
        'scan_date', 'compliance_percentage', 'asset__hostname', 'layer__layer_type'
    )
    
    # Formatear datos
    data = []
    baseline = Baseline.objects.filter(
        asset_id=asset_id if asset_id else None,
        layer_id=layer_id if layer_id else None
    ).first()
    
    baseline_value = float(baseline.compliance_percentage) if baseline else 90.0
    
    for scan in scans:
        data.append({
            'date': scan['scan_date'].strftime('%Y-%m-%d'),
            'compliance': float(scan['compliance_percentage']),
            'baseline': baseline_value,
            'asset': scan['asset__hostname'],
            'layer': scan['layer__layer_type']
        })
    
    return JsonResponse({
        'data': data,
        'baseline': baseline_value
    })


def api_policy_distribution(request):
    """
    Distribución de estados de políticas (Passed/Failed/Warning)
    GET /api/dashboard/policy-distribution/?asset_id=1&layer_id=1
    """
    
    asset_id = request.GET.get('asset_id')
    layer_id = request.GET.get('layer_id')
    
    # Obtener últimos escaneos
    latest_scans = Scan.objects.all()
    
    if asset_id:
        latest_scans = latest_scans.filter(asset_id=asset_id)
    if layer_id:
        latest_scans = latest_scans.filter(layer_id=layer_id)
    
    # Filtrar solo los más recientes por asset/layer
    latest_scans = latest_scans.filter(
        id__in=Scan.objects.values('asset', 'layer')
        .annotate(latest=Max('scan_date'))
        .values_list('id', flat=True)
    )
    
    # Contar por risk
    results = ScanResult.objects.filter(
        scan__in=latest_scans
    ).values('risk').annotate(count=Count('id'))
    
    # Mapear a formato para el gráfico
    risk_colors = {
        'PASSED': '#10b981',
        'FAILED': '#ef4444',
        'WARNING': '#f59e0b',
        'INFO': '#6b7280'
    }
    
    data = []
    for result in results:
        if result['risk'] != 'INFO':  # Filtrar informativos
            data.append({
                'name': result['risk'].capitalize(),
                'value': result['count'],
                'color': risk_colors.get(result['risk'], '#6b7280')
            })
    
    return JsonResponse({'data': data})


def api_asset_compliance(request):
    """
    Compliance por asset y capa
    GET /api/dashboard/asset-compliance/
    """
    
    # Obtener últimos escaneos por asset/layer
    latest_scans = Scan.objects.filter(
        id__in=Scan.objects.values('asset', 'layer')
        .annotate(latest=Max('scan_date'))
        .values_list('id', flat=True)
    ).select_related('asset', 'layer')
    
    # Agrupar por asset
    asset_data = {}
    
    for scan in latest_scans:
        asset_name = scan.asset.hostname
        layer_type = scan.layer.layer_type.lower()
        
        if asset_name not in asset_data:
            asset_data[asset_name] = {
                'name': asset_name,
                'os': 0,
                'web': 0,
                'db': 0
            }
        
        asset_data[asset_name][layer_type] = float(scan.compliance_percentage)
    
    return JsonResponse({
        'data': list(asset_data.values())
    })


def api_recent_alerts(request):
    """
    Alertas recientes
    GET /api/dashboard/recent-alerts/?limit=10
    """
    
    limit = int(request.GET.get('limit', 10))
    status = request.GET.get('status', 'ACTIVE')
    
    alerts = Alert.objects.filter(
        status=status
    ).select_related(
        'asset', 'layer', 'scan'
    ).order_by('-created_at')[:limit]
    
    data = []
    for alert in alerts:
        # Calcular tiempo relativo
        time_diff = timezone.now() - alert.created_at
        if time_diff.days > 0:
            time_ago = f"{time_diff.days}d ago"
        elif time_diff.seconds // 3600 > 0:
            time_ago = f"{time_diff.seconds // 3600}h ago"
        else:
            time_ago = f"{time_diff.seconds // 60}m ago"
        
        data.append({
            'id': alert.id,
            'severity': alert.severity,
            'title': alert.title,
            'asset': alert.asset.hostname,
            'layer': alert.layer.get_layer_type_display() if alert.layer else 'N/A',
            'time': time_ago,
            'created_at': alert.created_at.isoformat(),
            'message': alert.message
        })
    
    return JsonResponse({'data': data})


def api_top_failed_policies(request):
    """
    Top políticas más fallidas
    GET /api/dashboard/top-failed-policies/?limit=10&days=30
    """
    
    limit = int(request.GET.get('limit', 10))
    days = int(request.GET.get('days', 30))
    
    start_date = timezone.now() - timedelta(days=days)
    
    # Contar fallos por política
    failed_results = ScanResult.objects.filter(
        risk='FAILED',
        scan__scan_date__gte=start_date.date()
    ).values(
        'policy__section',
        'policy__recommendation',
        'policy__title',
        'policy_id'
    ).annotate(
        fail_count=Count('id'),
        asset_count=Count('scan__asset', distinct=True)
    ).order_by('-fail_count')[:limit]
    
    data = []
    for result in failed_results:
        data.append({
            'section': result['policy__section'],
            'recommendation': result['policy__recommendation'],
            'title': result['policy__title'][:80],
            'fail_count': result['fail_count'],
            'asset_count': result['asset_count']
        })
    
    return JsonResponse({'data': data})


def api_compliance_by_layer(request):
    """
    Compliance promedio por tipo de capa
    GET /api/dashboard/compliance-by-layer/
    """
    
    latest_scans = Scan.objects.filter(
        id__in=Scan.objects.values('asset', 'layer')
        .annotate(latest=Max('scan_date'))
        .values_list('id', flat=True)
    )
    
    layer_stats = latest_scans.values(
        'layer__layer_type'
    ).annotate(
        avg_compliance=Avg('compliance_percentage'),
        count=Count('id')
    ).order_by('layer__layer_type')
    
    data = []
    for stat in layer_stats:
        data.append({
            'layer': stat['layer__layer_type'],
            'compliance': float(stat['avg_compliance']),
            'count': stat['count']
        })
    
    return JsonResponse({'data': data})


def api_baseline_comparison(request):
    """
    Comparación de compliance actual vs baseline
    GET /api/dashboard/baseline-comparison/
    """
    
    baselines = Baseline.objects.select_related(
        'asset', 'layer'
    ).all()
    
    data = []
    for baseline in baselines:
        # Obtener último escaneo
        latest_scan = Scan.objects.filter(
            asset=baseline.asset,
            layer=baseline.layer
        ).order_by('-scan_date').first()
        
        if latest_scan:
            data.append({
                'asset': baseline.asset.hostname,
                'layer': baseline.layer.get_layer_type_display(),
                'baseline': float(baseline.compliance_percentage),
                'current': float(latest_scan.compliance_percentage),
                'difference': float(latest_scan.compliance_percentage - baseline.compliance_percentage),
                'scan_date': latest_scan.scan_date.isoformat()
            })
    
    return JsonResponse({'data': data})


def api_alert_summary(request):
    """
    Resumen de alertas por severidad y estado
    GET /api/dashboard/alert-summary/
    """
    
    days = int(request.GET.get('days', 30))
    start_date = timezone.now() - timedelta(days=days)
    
    alerts = Alert.objects.filter(
        created_at__gte=start_date
    ).values('severity', 'status').annotate(
        count=Count('id')
    )
    
    # Organizar datos
    summary = {}
    for alert in alerts:
        severity = alert['severity']
        status = alert['status']
        
        if severity not in summary:
            summary[severity] = {'total': 0, 'active': 0, 'acknowledged': 0, 'resolved': 0}
        
        summary[severity]['total'] += alert['count']
        summary[severity][status.lower()] += alert['count']
    
    return JsonResponse({'data': summary})


# ============================================================
# VISTAS AUXILIARES
# ============================================================

def api_assets_list(request):
    """Lista de assets para filtros"""
    assets = Asset.objects.filter(
        status='ACTIVE'
    ).values('id', 'hostname', 'ip_address')
    
    return JsonResponse({'data': list(assets)})


def api_layers_list(request):
    """Lista de layers para filtros"""
    asset_id = request.GET.get('asset_id')
    
    query = AssetLayer.objects.select_related('asset', 'benchmark')
    
    if asset_id:
        query = query.filter(asset_id=asset_id)
    
    layers = query.values(
        'id', 
        'layer_type', 
        'software_type',
        'asset__hostname'
    )
    
    return JsonResponse({'data': list(layers)})


# Agregar al final de views.py (después de las vistas existentes)

from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from compliance.forms import BulkNessusScanUploadForm
from compliance.services.nessus_bulk_service import NessusBulkImportService


# ============================================================
# BULK IMPORT DE NESSUS
# ============================================================


@operator_or_admin_required
def bulk_nessus_upload_view(request):
    """Vista para subir CSV de Nessus con múltiples hosts"""
    
    if request.method == 'POST':
        form = BulkNessusScanUploadForm(request.POST, request.FILES)
        
        if form.is_valid():
            csv_file = request.FILES['csv_file']
            benchmark_id = form.cleaned_data['benchmark'].id
            layer_type = form.cleaned_data['layer_type']
            scan_date = form.cleaned_data['scan_date']
            
            try:
                # Procesar con el servicio bulk
                service = NessusBulkImportService()
                scans_created, stats = service.import_bulk_scan(
                    file=csv_file,
                    benchmark_id=benchmark_id,
                    scan_date=scan_date,
                    layer_type=layer_type,
                    auto_create_assets=False  # NO crear assets automáticamente
                )
                
                # Obtener reporte detallado
                report = service.get_report()
                
                # Guardar resultados en sesión para mostrar en página de resultados
                request.session['bulk_import_results'] = {
                    'success': report['success'],
                    'stats': stats,
                    'scans_created': stats.get('scans_created', []),
                    'errors': report['errors'],
                    'warnings': report['warnings'],
                    'benchmark_name': form.cleaned_data['benchmark'].name,
                    'layer_type': layer_type,
                    'scan_date': scan_date.strftime('%Y-%m-%d')
                }
                
                # Mensajes de resumen
                if scans_created:
                    messages.success(
                        request,
                        f'✓ Importación completada: {len(scans_created)} hosts procesados exitosamente'
                    )
                else:
                    messages.warning(
                        request,
                        'No se pudo procesar ningún host. Revisa los detalles.'
                    )
                
                if stats['servers_skipped'] > 0:
                    messages.warning(
                        request,
                        f'⚠ {stats["servers_skipped"]} hosts omitidos (no existen como Assets activos)'
                    )
                
                # Redirigir a página de resultados
                return redirect('bulk_scan_results')
                
            except Exception as e:
                messages.error(
                    request,
                    f'Error al procesar el CSV: {str(e)}'
                )
                
    else:
        form = BulkNessusScanUploadForm()
    
    return render(request, 'compliance/scans/bulk_nessus_upload.html', {
        'form': form,
        'page_title': 'Importación Bulk de Escaneos Nessus'
    })


@operator_or_admin_required
def bulk_scan_results_view(request):
    """Vista para mostrar resultados de la importación bulk"""
    
    # Recuperar resultados de la sesión
    results = request.session.get('bulk_import_results')
    
    if not results:
        messages.warning(request, 'No hay resultados de importación disponibles')
        return redirect('bulk_nessus_upload')
    
    # Limpiar sesión después de mostrar
    del request.session['bulk_import_results']
    
    # Organizar datos para el template
    context = {
        'page_title': 'Resultados de Importación Bulk',
        'success': results['success'],
        'stats': results['stats'],
        'scans_created': results['scans_created'],
        'errors': results['errors'],
        'warnings': results['warnings'],
        'benchmark_name': results['benchmark_name'],
        'layer_type': results['layer_type'],
        'scan_date': results['scan_date'],
    }
    
    return render(request, 'compliance/scans/bulk_scan_results.html', context)


@login_required
def bulk_scan_detail_api(request, scan_id):
    """API endpoint para obtener detalles de un scan específico"""
    try:
        scan = Scan.objects.get(id=scan_id)
        
        data = {
            'hostname': scan.asset.hostname,
            'layer': scan.layer.get_layer_type_display(),
            'scan_date': scan.scan_date.isoformat(),
            'compliance': float(scan.compliance_percentage),
            'total_policies': scan.total_policies,
            'passed': scan.passed_count,
            'failed': scan.failed_count,
            'warning': scan.warning_count,
            'url': f'/admin/compliance/scan/{scan.id}/change/'
        }
        
        return JsonResponse({'success': True, 'data': data})
        
    except Scan.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Scan not found'}, status=404)


@login_required
def asset_detail_view(request, asset_id):
    """Vista detallada de un asset con sus políticas fallidas y justificaciones"""
    
    try:
        asset = Asset.objects.get(id=asset_id, status='ACTIVE')
    except Asset.DoesNotExist:
        messages.error(request, 'Asset no encontrado o inactivo')
        return redirect('assets_list')
    
    # Obtener todas las capas del asset
    layers = asset.layers.all()
    
    # Obtener últimos scans por capa
    latest_scans = []
    for layer in layers:
        latest_scan = Scan.objects.filter(
            asset=asset,
            layer=layer
        ).order_by('-scan_date').first()
        
        if latest_scan:
            latest_scans.append(latest_scan)
    
    # Obtener políticas fallidas de los últimos scans con sus justificaciones
    from compliance.models import AssetExclusion
    
    failed_policies = []
    for scan in latest_scans:
        failed_results = ScanResult.objects.filter(
            scan=scan,
            risk='FAILED'
        ).select_related('policy').order_by('policy__section', 'policy__recommendation')
        
        for result in failed_results:
            # Buscar si existe justificación para esta política
            exclusion = AssetExclusion.objects.filter(
                asset=asset,
                layer=scan.layer,
                policy=result.policy
            ).first()
            
            failed_policies.append({
                'layer': scan.layer.get_layer_type_display(),
                'layer_type': scan.layer.layer_type,
                'layer_id': scan.layer.id,
                'section': result.policy.section,
                'recommendation': result.policy.recommendation,
                'title': result.policy.title,
                'profile': result.policy.get_profile_display(),
                'remediation': result.policy.remediation_procedure[:200] if result.policy.remediation_procedure else '',
                'scan_date': scan.scan_date,
                'policy_id': result.policy.id,
                'exclusion': exclusion,  # Incluir justificación si existe
            })
    
    # Obtener baseline si existe
    baselines = Baseline.objects.filter(asset=asset).select_related('layer')
    
    # Estadísticas generales
    stats = {
        'total_layers': layers.count(),
        'total_scans': asset.scans.count(),
        'failed_policies_count': len(failed_policies),
        'avg_compliance': latest_scans[0].compliance_percentage if latest_scans else 0,
    }
    
    context = {
        'asset': asset,
        'layers': layers,
        'latest_scans': latest_scans,
        'failed_policies': failed_policies,
        'baselines': baselines,
        'stats': stats,
        'page_title': f'Detalles: {asset.hostname}'
    }
    
    return render(request, 'compliance/assets/asset_detail.html', context)




# Dashboard Ejecutivo

def api_executive_kpis(request):
    """
    KPIs principales para dashboard ejecutivo
    GET /api/dashboard/executive-kpis/
    """
    
    # Obtener últimos escaneos por asset/layer
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    latest_scans = Scan.objects.filter(id__in=latest_scan_ids)
    
    # 1. Compliance Promedio
    avg_compliance = latest_scans.aggregate(
        avg=Avg('compliance_percentage')
    )['avg'] or Decimal('0')
    
    # Comparar con mes anterior
    thirty_days_ago = timezone.now() - timedelta(days=30)
    previous_scans_query = Scan.objects.filter(
        scan_date__lt=thirty_days_ago.date(),
        scan_date__gte=(thirty_days_ago - timedelta(days=30)).date()
    ).values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    previous_scan_ids = []
    for item in previous_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            previous_scan_ids.append(scan.id)
    
    previous_avg = Scan.objects.filter(
        id__in=previous_scan_ids
    ).aggregate(avg=Avg('compliance_percentage'))['avg'] or Decimal('0')
    
    compliance_change = float(avg_compliance - previous_avg)
    
    # 2. Assets Hardenizados
    threshold = Threshold.get_hardening_threshold()
    total_active_assets = Asset.objects.filter(status='ACTIVE').count()
    
    hardened_count = latest_scans.filter(
        compliance_percentage__gte=threshold
    ).values('asset').distinct().count()
    
    # 3. Cobertura de Escaneo (últimos 30 días)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    scanned_assets = Scan.objects.filter(
        scan_date__gte=thirty_days_ago.date()
    ).values('asset').distinct().count()
    
    coverage_percentage = (scanned_assets / total_active_assets * 100) if total_active_assets > 0 else 0
    
    # 4. Políticas Remediadas (este mes)
    first_day_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Contar políticas que pasaron de FAILED a PASSED este mes
    current_month_scans = Scan.objects.filter(
        scan_date__gte=first_day_month.date()
    )
    
    current_passed = ScanResult.objects.filter(
        scan__in=current_month_scans,
        risk='PASSED'
    ).count()
    
    # Comparar con mes anterior
    last_month_start = (first_day_month - timedelta(days=1)).replace(day=1)
    last_month_scans = Scan.objects.filter(
        scan_date__gte=last_month_start.date(),
        scan_date__lt=first_day_month.date()
    )
    
    last_month_passed = ScanResult.objects.filter(
        scan__in=last_month_scans,
        risk='PASSED'
    ).count()
    
    policies_remediated = max(0, current_passed - last_month_passed)
    
    return JsonResponse({
        'compliance_avg': {
            'value': float(avg_compliance),
            'change': round(compliance_change, 2),
            'trend': 'up' if compliance_change >= 0 else 'down'
        },
        'hardened_assets': {
            'count': hardened_count,
            'total': total_active_assets,
            'percentage': round((hardened_count / total_active_assets * 100), 1) if total_active_assets > 0 else 0,
            'threshold': float(threshold)
        },
        'scan_coverage': {
            'scanned': scanned_assets,
            'total': total_active_assets,
            'percentage': round(coverage_percentage, 1)
        },
        'policies_remediated': {
            'count': policies_remediated,
            'this_month': current_passed,
            'last_month': last_month_passed
        }
    })


def api_executive_compliance_trend(request):
    """
    Tendencia de compliance últimos 12 meses
    GET /api/dashboard/executive-compliance-trend/
    """
    
    # Calcular últimos 12 meses
    today = timezone.now()
    months_data = []
    
    for i in range(11, -1, -1):
        # Calcular el mes
        target_date = today - timedelta(days=30 * i)
        month_start = target_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        if i == 0:
            month_end = today
        else:
            next_month = month_start + timedelta(days=32)
            month_end = next_month.replace(day=1) - timedelta(days=1)
        
        # Obtener escaneos de ese mes
        month_scans = Scan.objects.filter(
            scan_date__gte=month_start.date(),
            scan_date__lte=month_end.date()
        )
        
        # Obtener el más reciente por asset/layer
        latest_in_month = {}
        for scan in month_scans:
            key = f"{scan.asset_id}_{scan.layer_id}"
            if key not in latest_in_month or scan.scan_date > latest_in_month[key].scan_date:
                latest_in_month[key] = scan
        
        # Calcular promedio
        if latest_in_month:
            avg_compliance = sum(s.compliance_percentage for s in latest_in_month.values()) / len(latest_in_month)
        else:
            avg_compliance = 0
        
        months_data.append({
            'month': month_start.strftime('%b %Y'),
            'compliance': round(float(avg_compliance), 2)
        })
    
    return JsonResponse({'data': months_data})


def api_executive_pci_environment(request):
    """
    Cumplimiento PCI/NO-PCI por ambiente
    GET /api/dashboard/executive-pci-environment/
    """
    
    # Obtener últimos escaneos
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    latest_scans = Scan.objects.filter(id__in=latest_scan_ids).select_related('asset')
    
    # Agrupar por PCI y Ambiente
    data = {
        'pci': {},
        'no_pci': {}
    }
    
    for scan in latest_scans:
        asset = scan.asset
        env = asset.get_environment_display() or 'Sin Clasificar'
        
        if asset.pci_standard:
            if env not in data['pci']:
                data['pci'][env] = {'total': 0, 'sum': 0}
            data['pci'][env]['total'] += 1
            data['pci'][env]['sum'] += float(scan.compliance_percentage)
        else:
            if env not in data['no_pci']:
                data['no_pci'][env] = {'total': 0, 'sum': 0}
            data['no_pci'][env]['total'] += 1
            data['no_pci'][env]['sum'] += float(scan.compliance_percentage)
    
    # Calcular promedios
    result = {
        'pci': {},
        'no_pci': {}
    }
    
    for env, stats in data['pci'].items():
        result['pci'][env] = round(stats['sum'] / stats['total'], 2) if stats['total'] > 0 else 0
    
    for env, stats in data['no_pci'].items():
        result['no_pci'][env] = round(stats['sum'] / stats['total'], 2) if stats['total'] > 0 else 0
    
    return JsonResponse(result)


def api_executive_assets_no_scan(request):
    """
    Top 10 assets sin escaneo reciente
    GET /api/dashboard/executive-assets-no-scan/
    """
    
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    # Assets con escaneos recientes
    assets_with_recent_scan = Scan.objects.filter(
        scan_date__gte=thirty_days_ago.date()
    ).values_list('asset_id', flat=True).distinct()
    
    # Assets sin escaneos recientes
    assets_no_scan = Asset.objects.filter(
        status='ACTIVE'
    ).exclude(
        id__in=assets_with_recent_scan
    ).annotate(
        last_scan_date=Max('scans__scan_date')
    ).order_by('last_scan_date')[:10]
    
    data = []
    for asset in assets_no_scan:
        if asset.last_scan_date:
            days_without_scan = (timezone.now().date() - asset.last_scan_date).days
        else:
            days_without_scan = 9999  # Nunca escaneado
        
        data.append({
            'id': asset.id,
            'hostname': asset.hostname,
            'environment': asset.get_environment_display() or '-',
            'pci_standard': asset.pci_standard,
            'last_scan_date': asset.last_scan_date.strftime('%Y-%m-%d') if asset.last_scan_date else 'Nunca',
            'days_without_scan': days_without_scan,
            'responsible': asset.get_responsible_display() or '-'
        })
    
    return JsonResponse({'data': data})


def api_executive_degraded_assets(request):
    """
    Assets hardenizados que fueron degradados
    GET /api/dashboard/executive-degraded-assets/
    """
    
    threshold = Threshold.get_hardening_threshold()
    
    # Obtener baselines
    baselines = Baseline.objects.select_related('asset', 'layer').filter(
        compliance_percentage__gte=threshold  # Solo los que estaban hardenizados
    )
    
    degraded_assets = []
    
    for baseline in baselines:
        # Obtener último escaneo
        latest_scan = Scan.objects.filter(
            asset=baseline.asset,
            layer=baseline.layer
        ).order_by('-scan_date').first()
        
        if latest_scan:
            current_compliance = float(latest_scan.compliance_percentage)
            baseline_compliance = float(baseline.compliance_percentage)
            
            # Si el actual es menor que la baseline
            if current_compliance < baseline_compliance:
                drift = current_compliance - baseline_compliance
                
                degraded_assets.append({
                    'asset_id': baseline.asset.id,
                    'hostname': baseline.asset.hostname,
                    'technology': baseline.layer.get_software_type_display() or baseline.layer.get_layer_type_display(),
                    'environment': baseline.asset.get_environment_display() or '-',
                    'pci_standard': baseline.asset.pci_standard,
                    'compliance': round(current_compliance, 2),
                    'baseline': round(baseline_compliance, 2),
                    'drift': round(drift, 2),
                    'scan_id': latest_scan.id,
                    'scan_date': latest_scan.scan_date.strftime('%Y-%m-%d')
                })
    
    # Ordenar por mayor degradación
    degraded_assets.sort(key=lambda x: x['drift'])
    
    return JsonResponse({'data': degraded_assets[:20]})  # Top 20


def api_executive_degraded_policies(request, asset_id):
    """
    Políticas que cambiaron de PASSED a FAILED para un asset
    GET /api/dashboard/executive-degraded-policies/<asset_id>/
    """
    
    try:
        asset = Asset.objects.get(id=asset_id)
    except Asset.DoesNotExist:
        return JsonResponse({'error': 'Asset no encontrado'}, status=404)
    
    # Obtener últimos 2 escaneos
    recent_scans = Scan.objects.filter(
        asset=asset
    ).order_by('-scan_date')[:2]
    
    if len(recent_scans) < 2:
        return JsonResponse({'data': []})
    
    current_scan = recent_scans[0]
    previous_scan = recent_scans[1]
    
    # Políticas que pasaron de PASSED a FAILED
    current_failed = ScanResult.objects.filter(
        scan=current_scan,
        risk='FAILED'
    ).values_list('policy_id', flat=True)
    
    previous_passed = ScanResult.objects.filter(
        scan=previous_scan,
        risk='PASSED',
        policy_id__in=current_failed
    ).select_related('policy')
    
    degraded_policies = []
    for result in previous_passed:
        degraded_policies.append({
            'policy_id': result.policy.id,
            'section': result.policy.section,
            'recommendation': result.policy.recommendation,
            'title': result.policy.title,
            'profile': result.policy.get_profile_display(),
            'previous_scan_date': previous_scan.scan_date.strftime('%Y-%m-%d'),
            'current_scan_date': current_scan.scan_date.strftime('%Y-%m-%d')
        })
    
    return JsonResponse({
        'asset': {
            'hostname': asset.hostname,
            'environment': asset.get_environment_display() or '-'
        },
        'data': degraded_policies,
        'count': len(degraded_policies)
    })

@login_required
def executive_dashboard_view(request):
    """Vista del dashboard ejecutivo"""
    return render(request, 'compliance/dashboard_executive.html', {
        'page_title': 'Dashboard Ejecutivo'
    })

# Dashboard Auditoria

from django.http import HttpResponse
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from io import BytesIO

def api_audit_kpis(request):
    """
    KPIs principales para dashboard de auditoría
    GET /api/dashboard/audit-kpis/
    """
    
    # 1. % Políticas failed sin justificación en assets hardenizados
    threshold = Threshold.get_hardening_threshold()
    
    # Obtener últimos escaneos
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    # Assets hardenizados
    hardened_scans = Scan.objects.filter(
        id__in=latest_scan_ids,
        compliance_percentage__gte=threshold
    )
    
    # Políticas FAILED en assets hardenizados
    failed_results = ScanResult.objects.filter(
        scan__in=hardened_scans,
        risk='FAILED'
    ).select_related('policy')
    
    total_failed = failed_results.count()
    
    # Políticas con exclusión (global o por asset)
    excluded_policy_ids = set()
    
    # Exclusiones globales activas
    global_exclusions = GlobalExclusion.objects.filter(is_active=True).values_list('policy_id', flat=True)
    excluded_policy_ids.update(global_exclusions)
    
    # Exclusiones por asset activas
    for result in failed_results:
        asset_exclusion = AssetExclusion.objects.filter(
            asset=result.scan.asset,
            policy=result.policy,
            is_active=True
        ).exists()
        if asset_exclusion:
            excluded_policy_ids.add(result.policy.id)
    
    # Contar failed sin justificación
    failed_without_justification = failed_results.exclude(
        policy_id__in=excluded_policy_ids
    ).count()
    
    percentage_without_justification = (failed_without_justification / total_failed * 100) if total_failed > 0 else 0
    
    # 2. Assets sin escaneo últimos 30 días
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    assets_with_recent_scan = Scan.objects.filter(
        scan_date__gte=thirty_days_ago.date()
    ).values_list('asset_id', flat=True).distinct()
    
    total_active_assets = Asset.objects.filter(status='ACTIVE').count()
    assets_no_scan = total_active_assets - len(set(assets_with_recent_scan))
    
    # 3. Exclusiones activas
    total_exclusions = GlobalExclusion.objects.filter(is_active=True).count() + \
                       AssetExclusion.objects.filter(is_active=True).count()
    
    # 4. Cambios manuales en líneas base (últimos 90 días)
    ninety_days_ago = timezone.now() - timedelta(days=90)
    manual_baseline_changes = Baseline.objects.filter(
        is_manual=True,
        set_at__gte=ninety_days_ago
    ).count()
    
    return JsonResponse({
        'failed_without_justification': {
            'percentage': round(percentage_without_justification, 1),
            'count': failed_without_justification,
            'total_failed': total_failed,
            'hardened_assets': hardened_scans.values('asset').distinct().count()
        },
        'assets_no_scan': {
            'count': assets_no_scan,
            'total': total_active_assets,
            'percentage': round((assets_no_scan / total_active_assets * 100), 1) if total_active_assets > 0 else 0
        },
        'total_exclusions': total_exclusions,
        'manual_baseline_changes': manual_baseline_changes
    })


def api_audit_pci_compliance(request):
    """
    Cumplimiento PCI vs NO-PCI
    GET /api/dashboard/audit-pci-compliance/
    """
    
    # Obtener últimos escaneos
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    latest_scans = Scan.objects.filter(id__in=latest_scan_ids).select_related('asset')
    
    # Separar por PCI
    pci_scans = latest_scans.filter(asset__pci_standard=True)
    no_pci_scans = latest_scans.filter(asset__pci_standard=False)
    
    # Calcular distribución de compliance
    def get_distribution(scans):
        total = scans.count()
        if total == 0:
            return {'excellent': 0, 'good': 0, 'fair': 0, 'poor': 0}
        
        excellent = scans.filter(compliance_percentage__gte=90).count()
        good = scans.filter(compliance_percentage__gte=80, compliance_percentage__lt=90).count()
        fair = scans.filter(compliance_percentage__gte=70, compliance_percentage__lt=80).count()
        poor = scans.filter(compliance_percentage__lt=70).count()
        
        return {
            'excellent': round((excellent / total * 100), 1),
            'good': round((good / total * 100), 1),
            'fair': round((fair / total * 100), 1),
            'poor': round((poor / total * 100), 1),
            'excellent_count': excellent,
            'good_count': good,
            'fair_count': fair,
            'poor_count': poor
        }
    
    pci_avg = pci_scans.aggregate(avg=Avg('compliance_percentage'))['avg'] or 0
    no_pci_avg = no_pci_scans.aggregate(avg=Avg('compliance_percentage'))['avg'] or 0
    
    return JsonResponse({
        'pci': {
            'average': round(float(pci_avg), 2),
            'count': pci_scans.count(),
            'distribution': get_distribution(pci_scans)
        },
        'no_pci': {
            'average': round(float(no_pci_avg), 2),
            'count': no_pci_scans.count(),
            'distribution': get_distribution(no_pci_scans)
        }
    })


def api_audit_baseline_drift(request):
    """
    Drift desde línea base (Top 20)
    GET /api/dashboard/audit-baseline-drift/
    """
    
    baselines = Baseline.objects.select_related('asset', 'layer').all()
    
    drift_data = []
    
    for baseline in baselines:
        # Obtener último escaneo
        latest_scan = Scan.objects.filter(
            asset=baseline.asset,
            layer=baseline.layer
        ).order_by('-scan_date').first()
        
        if latest_scan:
            current_compliance = float(latest_scan.compliance_percentage)
            baseline_compliance = float(baseline.compliance_percentage)
            drift = current_compliance - baseline_compliance
            
            drift_data.append({
                'hostname': baseline.asset.hostname,
                'layer': baseline.layer.get_layer_type_display(),
                'baseline': round(baseline_compliance, 2),
                'current': round(current_compliance, 2),
                'drift': round(drift, 2),
                'pci': baseline.asset.pci_standard
            })
    
    # Ordenar por drift (de más negativo a más positivo)
    drift_data.sort(key=lambda x: x['drift'])
    
    return JsonResponse({'data': drift_data[:20]})


def api_audit_exclusions_list(request):
    """
    Lista de exclusiones por asset con paginación
    GET /api/dashboard/audit-exclusions-list/?page=1&per_page=25
    """
    
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 25))
    
    # Obtener exclusiones por asset
    asset_exclusions = AssetExclusion.objects.select_related(
        'asset', 'policy', 'layer'
    ).filter(is_active=True).order_by('-created_at')
    
    # Paginación
    from django.core.paginator import Paginator
    paginator = Paginator(asset_exclusions, per_page)
    page_obj = paginator.get_page(page)
    
    data = []
    for exclusion in page_obj:
        data.append({
            'id': exclusion.id,
            'asset': exclusion.asset.hostname,
            'policy_section': exclusion.policy.section,
            'policy_recommendation': exclusion.policy.recommendation,
            'policy_title': exclusion.policy.title,
            'layer': exclusion.layer.get_layer_type_display(),
            'reason': exclusion.reason[:100] + '...' if len(exclusion.reason) > 100 else exclusion.reason,
            'has_file': bool(exclusion.justification_file),
            'created_at': exclusion.created_at.strftime('%Y-%m-%d'),
            'created_by': exclusion.created_by
        })
    
    return JsonResponse({
        'data': data,
        'pagination': {
            'current_page': page,
            'total_pages': paginator.num_pages,
            'total_items': paginator.count,
            'per_page': per_page,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous()
        }
    })


def api_audit_failed_without_justification(request):
    """
    Políticas failed sin justificación en assets hardenizados
    GET /api/dashboard/audit-failed-without-justification/
    """
    
    threshold = Threshold.get_hardening_threshold()
    
    # Obtener últimos escaneos de assets hardenizados
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    hardened_scans = Scan.objects.filter(
        id__in=latest_scan_ids,
        compliance_percentage__gte=threshold
    )
    
    # Políticas FAILED
    failed_results = ScanResult.objects.filter(
        scan__in=hardened_scans,
        risk='FAILED'
    ).select_related('policy', 'scan__asset', 'scan__layer')
    
    # Exclusiones globales activas
    global_excluded_policies = set(
        GlobalExclusion.objects.filter(is_active=True).values_list('policy_id', flat=True)
    )
    
    data = []
    
    for result in failed_results:
        # Verificar si tiene exclusión global
        if result.policy.id in global_excluded_policies:
            continue
        
        # Verificar si tiene exclusión por asset
        asset_exclusion = AssetExclusion.objects.filter(
            asset=result.scan.asset,
            policy=result.policy,
            is_active=True
        ).exists()
        
        if asset_exclusion:
            continue
        
        # No tiene justificación
        data.append({
            'asset': result.scan.asset.hostname,
            'asset_id': result.scan.asset.id,
            'layer': result.scan.layer.get_layer_type_display(),
            'policy_section': result.policy.section,
            'policy_recommendation': result.policy.recommendation,
            'policy_title': result.policy.title,
            'compliance': float(result.scan.compliance_percentage),
            'pci': result.scan.asset.pci_standard,
            'environment': result.scan.asset.get_environment_display() or '-'
        })
    
    return JsonResponse({'data': data[:50]})  # Limitar a 50


def api_audit_manual_baseline_changes(request):
    """
    Historial de cambios manuales en líneas base
    GET /api/dashboard/audit-manual-baseline-changes/
    """
    
    ninety_days_ago = timezone.now() - timedelta(days=90)
    
    manual_changes = Baseline.objects.filter(
        is_manual=True,
        set_at__gte=ninety_days_ago
    ).select_related('asset', 'layer').order_by('-set_at')
    
    data = []
    for baseline in manual_changes:
        # Obtener escaneo de referencia si existe
        previous_value = None
        if baseline.scan_reference:
            previous_value = float(baseline.scan_reference.compliance_percentage)
        
        data.append({
            'asset': baseline.asset.hostname,
            'asset_id': baseline.asset.id,
            'layer': baseline.layer.get_layer_type_display(),
            'previous_value': previous_value,
            'new_value': float(baseline.compliance_percentage),
            'set_at': baseline.set_at.strftime('%Y-%m-%d %H:%M'),
            'set_by': baseline.set_by or '-',
            'notes': baseline.notes or '-'
        })
    
    return JsonResponse({'data': data})


@operator_or_admin_required
def export_exclusions_excel(request):
    """
    Exportar todas las exclusiones a Excel
    GET /compliance/dashboard/audit/export-exclusions/
    """
    
    # Crear workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Exclusiones"
    
    # Estilos
    header_fill = PatternFill(start_color="667eea", end_color="667eea", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = [
        'Tipo', 'Asset', 'Política', 'Título', 'Capa', 'Razón',
        'Archivo Adjunto', 'Creado', 'Creado Por', 'Estado'
    ]
    
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.value = header
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Obtener exclusiones globales
    global_exclusions = GlobalExclusion.objects.select_related(
        'policy', 'benchmark'
    ).all().order_by('-created_at')
    
    row_num = 2
    for exclusion in global_exclusions:
        ws.cell(row=row_num, column=1, value='Global')
        ws.cell(row=row_num, column=2, value='Todos')
        ws.cell(row=row_num, column=3, value=f"{exclusion.policy.section} {exclusion.policy.recommendation}")
        ws.cell(row=row_num, column=4, value=exclusion.policy.title)
        ws.cell(row=row_num, column=5, value=exclusion.benchmark.name)
        ws.cell(row=row_num, column=6, value=exclusion.reason)
        ws.cell(row=row_num, column=7, value='Sí' if exclusion.justification_file else 'No')
        ws.cell(row=row_num, column=8, value=exclusion.created_at.strftime('%Y-%m-%d'))
        ws.cell(row=row_num, column=9, value=exclusion.created_by)
        ws.cell(row=row_num, column=10, value='Activa' if exclusion.is_active else 'Inactiva')
        
        for col in range(1, 11):
            ws.cell(row=row_num, column=col).border = border
        
        row_num += 1
    
    # Obtener exclusiones por asset
    asset_exclusions = AssetExclusion.objects.select_related(
        'asset', 'policy', 'layer'
    ).all().order_by('-created_at')
    
    for exclusion in asset_exclusions:
        ws.cell(row=row_num, column=1, value='Por Asset')
        ws.cell(row=row_num, column=2, value=exclusion.asset.hostname)
        ws.cell(row=row_num, column=3, value=f"{exclusion.policy.section} {exclusion.policy.recommendation}")
        ws.cell(row=row_num, column=4, value=exclusion.policy.title)
        ws.cell(row=row_num, column=5, value=exclusion.layer.get_layer_type_display())
        ws.cell(row=row_num, column=6, value=exclusion.reason)
        ws.cell(row=row_num, column=7, value='Sí' if exclusion.justification_file else 'No')
        ws.cell(row=row_num, column=8, value=exclusion.created_at.strftime('%Y-%m-%d'))
        ws.cell(row=row_num, column=9, value=exclusion.created_by)
        ws.cell(row=row_num, column=10, value='Activa' if exclusion.is_active else 'Inactiva')
        
        for col in range(1, 11):
            ws.cell(row=row_num, column=col).border = border
        
        row_num += 1
    
    # Ajustar anchos de columna
    ws.column_dimensions['A'].width = 12
    ws.column_dimensions['B'].width = 25
    ws.column_dimensions['C'].width = 15
    ws.column_dimensions['D'].width = 50
    ws.column_dimensions['E'].width = 20
    ws.column_dimensions['F'].width = 40
    ws.column_dimensions['G'].width = 15
    ws.column_dimensions['H'].width = 12
    ws.column_dimensions['I'].width = 20
    ws.column_dimensions['J'].width = 10
    
    # Guardar en BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    # Crear respuesta
    response = HttpResponse(
        output.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="exclusiones_audit_{timezone.now().strftime("%Y%m%d")}.xlsx"'
    
    return response


@login_required
def audit_dashboard_view(request):
    """Vista del dashboard de auditoría"""
    return render(request, 'compliance/dashboard_audit.html', {
        'page_title': 'Dashboard Auditoría'
    })


# Dashboard especialista

def api_operator_kpis(request):
    """
    KPIs principales para dashboard operativo
    GET /api/dashboard/operator-kpis/
    """
    
    threshold = Threshold.get_hardening_threshold()
    
    # 1. % Assets degradados (de los hardenizados)
    baselines = Baseline.objects.filter(
        compliance_percentage__gte=threshold
    ).select_related('asset', 'layer')
    
    total_hardened = baselines.count()
    degraded_count = 0
    
    for baseline in baselines:
        latest_scan = Scan.objects.filter(
            asset=baseline.asset,
            layer=baseline.layer
        ).order_by('-scan_date').first()
        
        if latest_scan:
            if float(latest_scan.compliance_percentage) < float(baseline.compliance_percentage):
                degraded_count += 1
    
    degraded_percentage = (degraded_count / total_hardened * 100) if total_hardened > 0 else 0
    
    # 2. % Políticas failed sin justificación en assets hardenizados
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    hardened_scans = Scan.objects.filter(
        id__in=latest_scan_ids,
        compliance_percentage__gte=threshold
    )
    
    failed_results = ScanResult.objects.filter(
        scan__in=hardened_scans,
        risk='FAILED'
    ).select_related('policy')
    
    total_failed = failed_results.count()
    
    # Políticas con exclusión
    excluded_policy_ids = set()
    global_exclusions = GlobalExclusion.objects.filter(is_active=True).values_list('policy_id', flat=True)
    excluded_policy_ids.update(global_exclusions)
    
    for result in failed_results:
        asset_exclusion = AssetExclusion.objects.filter(
            asset=result.scan.asset,
            policy=result.policy,
            is_active=True
        ).exists()
        if asset_exclusion:
            excluded_policy_ids.add(result.policy.id)
    
    failed_without_justification = failed_results.exclude(
        policy_id__in=excluded_policy_ids
    ).count()
    
    percentage_without_justification = (failed_without_justification / total_failed * 100) if total_failed > 0 else 0
    
    return JsonResponse({
        'degraded_assets': {
            'count': degraded_count,
            'total_hardened': total_hardened,
            'percentage': round(degraded_percentage, 1)
        },
        'failed_without_justification': {
            'percentage': round(percentage_without_justification, 1),
            'count': failed_without_justification,
            'total_failed': total_failed
        }
    })


def api_operator_degraded_assets(request):
    """
    Assets hardenizados que fueron degradados
    GET /api/dashboard/operator-degraded-assets/
    """
    
    threshold = Threshold.get_hardening_threshold()
    
    baselines = Baseline.objects.filter(
        compliance_percentage__gte=threshold
    ).select_related('asset', 'layer')
    
    degraded_assets = []
    
    for baseline in baselines:
        latest_scan = Scan.objects.filter(
            asset=baseline.asset,
            layer=baseline.layer
        ).order_by('-scan_date').first()
        
        if latest_scan:
            current_compliance = float(latest_scan.compliance_percentage)
            baseline_compliance = float(baseline.compliance_percentage)
            
            if current_compliance < baseline_compliance:
                drift = current_compliance - baseline_compliance
                
                degraded_assets.append({
                    'asset_id': baseline.asset.id,
                    'hostname': baseline.asset.hostname,
                    'technology': baseline.layer.get_software_type_display() or baseline.layer.get_layer_type_display(),
                    'layer_type': baseline.layer.layer_type,
                    'environment': baseline.asset.get_environment_display() or '-',
                    'pci_standard': baseline.asset.pci_standard,
                    'compliance': round(current_compliance, 2),
                    'baseline': round(baseline_compliance, 2),
                    'drift': round(drift, 2),
                    'scan_id': latest_scan.id,
                    'scan_date': latest_scan.scan_date.strftime('%Y-%m-%d')
                })
    
    # Ordenar por mayor degradación
    degraded_assets.sort(key=lambda x: x['drift'])
    
    return JsonResponse({'data': degraded_assets})


def api_operator_failed_without_justification(request):
    """
    Políticas failed sin justificación en assets hardenizados
    GET /api/dashboard/operator-failed-without-justification/
    """
    
    threshold = Threshold.get_hardening_threshold()
    
    # Obtener últimos escaneos de assets hardenizados
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    hardened_scans = Scan.objects.filter(
        id__in=latest_scan_ids,
        compliance_percentage__gte=threshold
    )
    
    # Políticas FAILED
    failed_results = ScanResult.objects.filter(
        scan__in=hardened_scans,
        risk='FAILED'
    ).select_related('policy', 'scan__asset', 'scan__layer')
    
    # Exclusiones globales activas
    global_excluded_policies = set(
        GlobalExclusion.objects.filter(is_active=True).values_list('policy_id', flat=True)
    )
    
    data = []
    
    for result in failed_results:
        # Verificar si tiene exclusión global
        if result.policy.id in global_excluded_policies:
            continue
        
        # Verificar si tiene exclusión por asset
        asset_exclusion = AssetExclusion.objects.filter(
            asset=result.scan.asset,
            policy=result.policy,
            is_active=True
        ).exists()
        
        if asset_exclusion:
            continue
        
        # No tiene justificación
        data.append({
            'asset': result.scan.asset.hostname,
            'asset_id': result.scan.asset.id,
            'layer': result.scan.layer.get_layer_type_display(),
            'policy_id': result.policy.id,
            'policy_section': result.policy.section,
            'policy_recommendation': result.policy.recommendation,
            'policy_title': result.policy.title,
            'profile': result.policy.get_profile_display(),
            'compliance': float(result.scan.compliance_percentage),
            'pci': result.scan.asset.pci_standard,
            'environment': result.scan.asset.get_environment_display() or '-',
            'remediation': result.policy.remediation_procedure[:150] + '...' if result.policy.remediation_procedure and len(result.policy.remediation_procedure) > 150 else result.policy.remediation_procedure or '-'
        })
    
    return JsonResponse({'data': data})


def api_operator_recurring_policies(request):
    """
    Políticas recurrentes - Problema sistémico detectado
    Políticas sin justificación que fallan en múltiples assets hardenizados
    GET /api/dashboard/operator-recurring-policies/
    """
    
    threshold = Threshold.get_hardening_threshold()
    
    # Obtener últimos escaneos de assets hardenizados
    latest_scans_query = Scan.objects.values('asset', 'layer').annotate(
        latest_date=Max('scan_date')
    )
    
    latest_scan_ids = []
    for item in latest_scans_query:
        scan = Scan.objects.filter(
            asset=item['asset'],
            layer=item['layer'],
            scan_date=item['latest_date']
        ).first()
        if scan:
            latest_scan_ids.append(scan.id)
    
    hardened_scans = Scan.objects.filter(
        id__in=latest_scan_ids,
        compliance_percentage__gte=threshold
    )
    
    # Políticas FAILED
    failed_results = ScanResult.objects.filter(
        scan__in=hardened_scans,
        risk='FAILED'
    ).select_related('policy', 'scan__asset')
    
    # Exclusiones globales activas
    global_excluded_policies = set(
        GlobalExclusion.objects.filter(is_active=True).values_list('policy_id', flat=True)
    )
    
    # Contar ocurrencias por política (solo sin justificación)
    policy_counts = {}
    
    for result in failed_results:
        # Verificar si tiene exclusión global
        if result.policy.id in global_excluded_policies:
            continue
        
        # Verificar si tiene exclusión por asset
        asset_exclusion = AssetExclusion.objects.filter(
            asset=result.scan.asset,
            policy=result.policy,
            is_active=True
        ).exists()
        
        if asset_exclusion:
            continue
        
        # No tiene justificación - contar
        policy_key = result.policy.id
        
        if policy_key not in policy_counts:
            policy_counts[policy_key] = {
                'policy_id': result.policy.id,
                'section': result.policy.section,
                'recommendation': result.policy.recommendation,
                'title': result.policy.title,
                'profile': result.policy.get_profile_display(),
                'remediation': result.policy.remediation_procedure[:200] if result.policy.remediation_procedure else '-',
                'affected_assets': [],
                'count': 0
            }
        
        policy_counts[policy_key]['affected_assets'].append(result.scan.asset.hostname)
        policy_counts[policy_key]['count'] += 1
    
    # Filtrar solo las que afectan a 3 o más assets (problema sistémico)
    recurring = [
        {
            **policy_data,
            'affected_assets': policy_data['affected_assets'][:10],  # Limitar a 10 para mostrar
            'total_affected': len(policy_data['affected_assets'])
        }
        for policy_data in policy_counts.values()
        if policy_data['count'] >= 3
    ]
    
    # Ordenar por cantidad de assets afectados
    recurring.sort(key=lambda x: x['count'], reverse=True)
    
    return JsonResponse({'data': recurring[:20]})  # Top 20


@login_required
def operator_dashboard_view(request):
    """Vista del dashboard operativo"""
    return render(request, 'compliance/dashboard_operator.html', {
        'page_title': 'Dashboard Operativo'
    })


##############################################
##############################################
@login_required
def api_asset_compliance_timeline(request, asset_id):
    """
    API endpoint para obtener timeline de compliance de un asset (últimos 3 meses)
    GET /api/dashboard/asset-compliance-timeline/<asset_id>/
    """
    from datetime import timedelta
    from django.utils import timezone
    
    try:
        asset = Asset.objects.get(id=asset_id, status='ACTIVE')
    except Asset.DoesNotExist:
        return JsonResponse({'error': 'Asset no encontrado'}, status=404)
    
    # Calcular fecha de inicio (3 meses atrás)
    three_months_ago = timezone.now() - timedelta(days=90)
    
    # Obtener todas las capas del asset
    layers = asset.layers.all()
    
    timeline_data = {}
    
    for layer in layers:
        # Obtener escaneos de los últimos 3 meses
        scans = Scan.objects.filter(
            asset=asset,
            layer=layer,
            scan_date__gte=three_months_ago.date()
        ).order_by('scan_date')
        
        if not scans.exists():
            continue
        
        # Obtener baseline
        try:
            baseline = Baseline.objects.get(asset=asset, layer=layer)
            baseline_value = float(baseline.compliance_percentage)
        except Baseline.DoesNotExist:
            baseline_value = None
        
        layer_key = f"{layer.get_layer_type_display()}"
        if layer.software_type:
            layer_key += f" ({layer.get_software_type_display()})"
        
        timeline_data[layer_key] = {
            'layer_type': layer.layer_type,
            'baseline': baseline_value,
            'scans': []
        }
        
        for scan in scans:
            timeline_data[layer_key]['scans'].append({
                'date': scan.scan_date.strftime('%Y-%m-%d'),
                'compliance': float(scan.compliance_percentage),
                'passed': scan.passed_count,
                'failed': scan.failed_count,
                'warning': scan.warning_count
            })
    
    return JsonResponse({
        'success': True,
        'asset': {
            'hostname': asset.hostname,
            'ip_address': asset.ip_address
        },
        'timeline': timeline_data
    })