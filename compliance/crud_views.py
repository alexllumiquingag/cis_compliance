"""
Vistas CRUD para Thresholds, Alerts, Exclusions y CSVs
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Count
from django.core.paginator import Paginator
from compliance.models import (
    Threshold, Alert, AssetExclusion, GlobalExclusion,
    Asset, AssetLayer, BenchmarkPolicy, Scan
)
from compliance.forms import (
    ThresholdForm, AssetExclusionForm, GlobalExclusionForm,
    NessusScanUploadForm, BulkNessusScanUploadForm
)
from compliance.auth_views import admin_required, operator_or_admin_required
from compliance.services.nessus_service import NessusImportService
from compliance.services.nessus_bulk_service import NessusBulkImportService


# ============================================================
# THRESHOLDS (SOLO ADMIN)
# ============================================================

@admin_required
def thresholds_list(request):
    """Lista de umbrales configurados"""
    
    thresholds = Threshold.objects.all().order_by('name')
    
    context = {
        'thresholds': thresholds,
        'page_title': 'Gestión de Umbrales'
    }
    
    return render(request, 'compliance/thresholds/list.html', context)


@admin_required
def threshold_create(request):
    """Crear nuevo umbral"""
    
    if request.method == 'POST':
        form = ThresholdForm(request.POST)
        if form.is_valid():
            threshold = form.save()
            messages.success(request, f'Umbral {threshold.name} creado exitosamente')
            return redirect('thresholds_list')
    else:
        form = ThresholdForm()
    
    context = {
        'form': form,
        'page_title': 'Crear Umbral',
        'action': 'create'
    }
    
    return render(request, 'compliance/thresholds/form.html', context)


@admin_required
def threshold_edit(request, threshold_id):
    """Editar umbral existente"""
    
    threshold = get_object_or_404(Threshold, id=threshold_id)
    
    if request.method == 'POST':
        form = ThresholdForm(request.POST, instance=threshold)
        if form.is_valid():
            form.save()
            messages.success(request, f'Umbral {threshold.name} actualizado exitosamente')
            return redirect('thresholds_list')
    else:
        form = ThresholdForm(instance=threshold)
    
    context = {
        'form': form,
        'threshold': threshold,
        'page_title': f'Editar Umbral: {threshold.name}',
        'action': 'edit'
    }
    
    return render(request, 'compliance/thresholds/form.html', context)


@admin_required
def threshold_delete(request, threshold_id):
    """Eliminar umbral"""
    
    threshold = get_object_or_404(Threshold, id=threshold_id)
    
    if request.method == 'POST':
        name = threshold.name
        threshold.delete()
        messages.success(request, f'Umbral {name} eliminado')
        return redirect('thresholds_list')
    
    context = {
        'threshold': threshold,
        'page_title': f'Eliminar Umbral: {threshold.name}'
    }
    
    return render(request, 'compliance/thresholds/delete_confirm.html', context)


# ============================================================
# ALERTS
# ============================================================

@login_required
def alerts_list(request):
    """Lista de alertas con filtros"""
    
    # Filtros
    status_filter = request.GET.get('status', 'ACTIVE')
    severity_filter = request.GET.get('severity', '')
    alert_type_filter = request.GET.get('alert_type', '')
    asset_search = request.GET.get('asset_search', '').strip()
    
    # Paginación
    page = request.GET.get('page', 1)
    per_page = int(request.GET.get('per_page', 25))
    
    # Query base
    alerts = Alert.objects.all().select_related('asset', 'layer', 'scan').order_by('-created_at')
    
    # Aplicar filtros
    if status_filter:
        alerts = alerts.filter(status=status_filter)
    
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    
    if alert_type_filter:
        alerts = alerts.filter(alert_type=alert_type_filter)
    
    if asset_search:
        alerts = alerts.filter(
            Q(asset__hostname__icontains=asset_search) |
            Q(asset__ip_address__icontains=asset_search)
        )
    
    # Estadísticas
    stats = {
        'total': Alert.objects.count(),
        'active': Alert.objects.filter(status='ACTIVE').count(),
        'critical': Alert.objects.filter(severity='CRITICAL', status='ACTIVE').count(),
        'high': Alert.objects.filter(severity='HIGH', status='ACTIVE').count(),
    }
    
    # Paginación
    paginator = Paginator(alerts, per_page)
    page_obj = paginator.get_page(page)
    
    context = {
        'page_obj': page_obj,
        'page_title': 'Gestión de Alertas',
        'stats': stats,
        'filters': {
            'status': status_filter,
            'severity': severity_filter,
            'alert_type': alert_type_filter,
            'asset_search': asset_search,
            'per_page': per_page,
        },
        'severity_choices': Alert.SEVERITY_CHOICES,
        'alert_type_choices': Alert.ALERT_TYPES,
    }
    
    return render(request, 'compliance/alerts/list.html', context)


@login_required
def alert_detail(request, alert_id):
    """Detalle de una alerta"""
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    context = {
        'alert': alert,
        'page_title': f'Alerta: {alert.title}'
    }
    
    return render(request, 'compliance/alerts/detail.html', context)


@operator_or_admin_required
def alert_acknowledge(request, alert_id):
    """Marcar alerta como reconocida"""
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        from django.utils import timezone
        alert.status = 'ACKNOWLEDGED'
        alert.acknowledged_at = timezone.now()
        alert.acknowledged_by = request.user.username
        alert.save()
        
        messages.success(request, 'Alerta reconocida exitosamente')
        return redirect('alert_detail', alert_id=alert.id)
    
    context = {
        'alert': alert,
        'page_title': 'Reconocer Alerta'
    }
    
    return render(request, 'compliance/alerts/acknowledge_confirm.html', context)


@operator_or_admin_required
def alert_resolve(request, alert_id):
    """Marcar alerta como resuelta"""
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        from django.utils import timezone
        alert.status = 'RESOLVED'
        alert.resolved_at = timezone.now()
        alert.save()
        
        messages.success(request, 'Alerta resuelta exitosamente')
        return redirect('alert_detail', alert_id=alert.id)
    
    context = {
        'alert': alert,
        'page_title': 'Resolver Alerta'
    }
    
    return render(request, 'compliance/alerts/resolve_confirm.html', context)


@admin_required
def alerts_bulk_action(request):
    """Acciones en masa para alertas"""
    
    if request.method == 'POST':
        action = request.POST.get('action')
        alert_ids = request.POST.getlist('alert_ids')
        
        if not alert_ids:
            messages.warning(request, 'No se seleccionaron alertas')
            return redirect('alerts_list')
        
        alerts = Alert.objects.filter(id__in=alert_ids)
        
        from django.utils import timezone
        
        if action == 'acknowledge':
            alerts.update(
                status='ACKNOWLEDGED',
                acknowledged_at=timezone.now(),
                acknowledged_by=request.user.username
            )
            messages.success(request, f'{alerts.count()} alertas reconocidas')
        
        elif action == 'resolve':
            alerts.update(
                status='RESOLVED',
                resolved_at=timezone.now()
            )
            messages.success(request, f'{alerts.count()} alertas resueltas')
        
        return redirect('alerts_list')
    
    return redirect('alerts_list')


# ============================================================
# EXCLUSIONS
# ============================================================

@login_required
def exclusions_list(request):
    """Lista de exclusiones (globales y por asset)"""
    
    # Filtros
    exclusion_type = request.GET.get('type', 'all')
    search_query = request.GET.get('search', '').strip()
    is_active = request.GET.get('is_active', 'true')
    
    page = request.GET.get('page', 1)
    
    # Global Exclusions
    global_exclusions = GlobalExclusion.objects.all().select_related('policy', 'benchmark')
    
    if is_active == 'true':
        global_exclusions = global_exclusions.filter(is_active=True)
    elif is_active == 'false':
        global_exclusions = global_exclusions.filter(is_active=False)
    
    if search_query:
        global_exclusions = global_exclusions.filter(
            Q(policy__title__icontains=search_query) |
            Q(policy__section__icontains=search_query)
        )
    
    # Asset Exclusions
    asset_exclusions = AssetExclusion.objects.all().select_related('asset', 'policy', 'layer')
    
    if is_active == 'true':
        asset_exclusions = asset_exclusions.filter(is_active=True)
    elif is_active == 'false':
        asset_exclusions = asset_exclusions.filter(is_active=False)
    
    if search_query:
        asset_exclusions = asset_exclusions.filter(
            Q(asset__hostname__icontains=search_query) |
            Q(policy__title__icontains=search_query) |
            Q(policy__section__icontains=search_query)
        )
    
    # Estadísticas
    stats = {
        'global_active': GlobalExclusion.objects.filter(is_active=True).count(),
        'global_inactive': GlobalExclusion.objects.filter(is_active=False).count(),
        'asset_active': AssetExclusion.objects.filter(is_active=True).count(),
        'asset_inactive': AssetExclusion.objects.filter(is_active=False).count(),
    }
    
    context = {
        'global_exclusions': global_exclusions[:50],  # Limitar para performance
        'asset_exclusions': asset_exclusions[:50],
        'page_title': 'Gestión de Exclusiones',
        'stats': stats,
        'filters': {
            'type': exclusion_type,
            'search': search_query,
            'is_active': is_active,
        }
    }
    
    return render(request, 'compliance/exclusions/list.html', context)


@operator_or_admin_required
def global_exclusion_create(request):
    """Crear exclusión global"""
    
    if request.method == 'POST':
        form = GlobalExclusionForm(request.POST, request.FILES)
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.created_by = request.user.username
            exclusion.save()
            messages.success(request, 'Exclusión global creada exitosamente')
            return redirect('exclusions_list')
    else:
        form = GlobalExclusionForm()
    
    context = {
        'form': form,
        'page_title': 'Crear Exclusión Global',
        'action': 'create'
    }
    
    return render(request, 'compliance/exclusions/global_form.html', context)


@operator_or_admin_required
def asset_exclusion_create(request):
    """Crear exclusión por asset"""
    
    if request.method == 'POST':
        form = AssetExclusionForm(request.POST, request.FILES)
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.created_by = request.user.username
            exclusion.save()
            messages.success(request, 'Exclusión por asset creada exitosamente')
            return redirect('exclusions_list')
    else:
        form = AssetExclusionForm()
    
    context = {
        'form': form,
        'page_title': 'Crear Exclusión por Asset',
        'action': 'create'
    }
    
    return render(request, 'compliance/exclusions/asset_form.html', context)


@operator_or_admin_required
def exclusion_toggle(request, exclusion_type, exclusion_id):
    """Activar/Desactivar exclusión"""
    
    if exclusion_type == 'global':
        exclusion = get_object_or_404(GlobalExclusion, id=exclusion_id)
    else:
        exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
    
    exclusion.is_active = not exclusion.is_active
    exclusion.save()
    
    status = 'activada' if exclusion.is_active else 'desactivada'
    messages.success(request, f'Exclusión {status} exitosamente')
    
    return redirect('exclusions_list')


@admin_required
def exclusion_delete(request, exclusion_type, exclusion_id):
    """Eliminar exclusión"""
    
    if exclusion_type == 'global':
        exclusion = get_object_or_404(GlobalExclusion, id=exclusion_id)
    else:
        exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
    
    if request.method == 'POST':
        exclusion.delete()
        messages.success(request, 'Exclusión eliminada exitosamente')
        return redirect('exclusions_list')
    
    context = {
        'exclusion': exclusion,
        'exclusion_type': exclusion_type,
        'page_title': 'Eliminar Exclusión'
    }
    
    return render(request, 'compliance/exclusions/delete_confirm.html', context)


# ============================================================
# CSV UPLOADS (Ya existentes, solo wrappers)
# ============================================================

@operator_or_admin_required
def scan_upload_single(request):
    """Subir escaneo individual (ya existe en views.py)"""
    # Esta funcionalidad ya existe en el admin o puede usar NessusScanUploadForm
    # Solo redirigir o crear wrapper si es necesario
    
    if request.method == 'POST':
        form = NessusScanUploadForm(request.POST, request.FILES)
        if form.is_valid():
            asset = form.cleaned_data['asset']
            layer = form.cleaned_data['layer']
            scan_date = form.cleaned_data['scan_date']
            csv_file = request.FILES['csv_file']
            
            try:
                service = NessusImportService()
                scan, stats = service.import_nessus_scan(
                    file=csv_file,
                    asset=asset,
                    layer=layer,
                    scan_date=scan_date
                )
                
                messages.success(
                    request,
                    f'Scan importado: {stats["imported"]} resultados procesados'
                )
                return redirect('asset_detail', asset_id=asset.id)
                
            except Exception as e:
                messages.error(request, f'Error al importar: {str(e)}')
    else:
        form = NessusScanUploadForm()
    
    context = {
        'form': form,
        'page_title': 'Subir Escaneo Individual'
    }
    
    return render(request, 'compliance/scans/upload_single.html', context)