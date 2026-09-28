"""
Vistas para gestión de Assets con filtros avanzados
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Max, F, Prefetch
from django.core.paginator import Paginator
from django.http import JsonResponse
from datetime import datetime, timedelta
from decimal import Decimal
from compliance.forms import AssetForm, AssetLayerForm
from compliance.models import (
    Asset, 
    AssetLayer, 
    Scan,  # ← IMPORTANTE: verificar que Scan esté aquí
    Baseline, 
    AssetExclusion, 
    BenchmarkPolicy
)


@login_required
def assets_list(request):
    """
    Vista principal de assets con filtros avanzados
    """
    
    # ============================================================
    # OBTENER PARÁMETROS DE FILTRO
    # ============================================================
    
    # Filtros básicos
    status_filter = request.GET.get('status', 'ACTIVE')  # Por defecto, solo activos
    search_query = request.GET.get('search', '').strip()
    
    # Filtros de clasificación
    environment_filter = request.GET.get('environment', '')
    administrator_filter = request.GET.get('administrator', '')
    responsible_filter = request.GET.get('responsible', '')
    pci_filter = request.GET.get('pci_standard', '')
    
    # Filtros de capa y compliance
    layer_type_filter = request.GET.get('layer_type', '')
    compliance_min = request.GET.get('compliance_min', '')
    compliance_max = request.GET.get('compliance_max', '')
    
    # Filtro de fecha de último escaneo
    scan_date_from = request.GET.get('scan_date_from', '')
    scan_date_to = request.GET.get('scan_date_to', '')
    
    # Filtro de cambio en compliance
    show_only_changed = request.GET.get('show_only_changed', '') == 'on'
    
    # Ordenamiento
    sort_by = request.GET.get('sort_by', 'hostname')
    sort_order = request.GET.get('sort_order', 'asc')
    
    # Paginación
    page = request.GET.get('page', 1)
    per_page = int(request.GET.get('per_page', 25))
    
    # ============================================================
    # CONSTRUIR QUERY BASE
    # ============================================================
    
    assets = Asset.objects.all().prefetch_related(
        'layers',
        'layers__benchmark',
        Prefetch('scans', queryset=Scan.objects.order_by('-scan_date'))
    )
    
    # Filtro de estado
    if status_filter:
        assets = assets.filter(status=status_filter)
    
    # Búsqueda por hostname o IP
    if search_query:
        assets = assets.filter(
            Q(hostname__icontains=search_query) | 
            Q(ip_address__icontains=search_query)
        )
    
    # Filtros de clasificación
    if environment_filter:
        assets = assets.filter(environment=environment_filter)
    
    if administrator_filter:
        assets = assets.filter(administrator=administrator_filter)
    
    if responsible_filter:
        assets = assets.filter(responsible=responsible_filter)
    
    if pci_filter:
        assets = assets.filter(pci_standard=(pci_filter == 'true'))
    
    # Filtro por tipo de capa
    if layer_type_filter:
        assets = assets.filter(layers__layer_type=layer_type_filter).distinct()
    
    # ============================================================
    # ENRIQUECER DATOS CON COMPLIANCE Y ÚLTIMO ESCANEO
    # ============================================================
    
    enriched_assets = []
    
    for asset in assets:
        asset_data = {
            'asset': asset,
            'layers_data': []
        }
        
        for layer in asset.layers.all():
            # Obtener último escaneo
            latest_scan = layer.scans.order_by('-scan_date').first()
            
            # Obtener línea base
            try:
                baseline = Baseline.objects.get(asset=asset, layer=layer)
                baseline_value = float(baseline.compliance_percentage)
            except Baseline.DoesNotExist:
                baseline_value = None
            
            layer_info = {
                'layer': layer,
                'latest_scan': latest_scan,
                'baseline': baseline_value,
                'compliance_change': None,
                'compliance_changed': False
            }
            
            # Calcular cambio de compliance
            if latest_scan and baseline_value is not None:
                current_compliance = float(latest_scan.compliance_percentage)
                layer_info['compliance_change'] = current_compliance - baseline_value
                layer_info['compliance_changed'] = abs(layer_info['compliance_change']) >= 1.0
            
            asset_data['layers_data'].append(layer_info)
        
        enriched_assets.append(asset_data)
    
    # ============================================================
    # APLICAR FILTROS AVANZADOS
    # ============================================================
    
    # Filtrar por fecha de escaneo
    if scan_date_from or scan_date_to:
        filtered_assets = []
        for asset_data in enriched_assets:
            has_valid_scan = False
            for layer_data in asset_data['layers_data']:
                if layer_data['latest_scan']:
                    scan_date = layer_data['latest_scan'].scan_date
                    
                    if scan_date_from and scan_date < datetime.strptime(scan_date_from, '%Y-%m-%d').date():
                        continue
                    if scan_date_to and scan_date > datetime.strptime(scan_date_to, '%Y-%m-%d').date():
                        continue
                    
                    has_valid_scan = True
                    break
            
            if has_valid_scan:
                filtered_assets.append(asset_data)
        
        enriched_assets = filtered_assets
    
    # Filtrar por rango de compliance
    if compliance_min or compliance_max:
        filtered_assets = []
        for asset_data in enriched_assets:
            has_valid_compliance = False
            for layer_data in asset_data['layers_data']:
                if layer_data['latest_scan']:
                    compliance = float(layer_data['latest_scan'].compliance_percentage)
                    
                    if compliance_min and compliance < float(compliance_min):
                        continue
                    if compliance_max and compliance > float(compliance_max):
                        continue
                    
                    has_valid_compliance = True
                    break
            
            if has_valid_compliance:
                filtered_assets.append(asset_data)
        
        enriched_assets = filtered_assets
    
    # Filtrar solo assets con cambio en compliance
    if show_only_changed:
        filtered_assets = []
        for asset_data in enriched_assets:
            has_changed = any(
                layer_data['compliance_changed'] 
                for layer_data in asset_data['layers_data']
            )
            if has_changed:
                filtered_assets.append(asset_data)
        
        enriched_assets = filtered_assets
    
    # ============================================================
    # ORDENAMIENTO
    # ============================================================
    
    if sort_by == 'hostname':
        enriched_assets.sort(
            key=lambda x: x['asset'].hostname.lower(),
            reverse=(sort_order == 'desc')
        )
    elif sort_by == 'compliance':
        enriched_assets.sort(
            key=lambda x: (
                max((ld['latest_scan'].compliance_percentage 
                     for ld in x['layers_data'] if ld['latest_scan']), 
                    default=0)
            ),
            reverse=(sort_order == 'desc')
        )
    elif sort_by == 'last_scan':
        enriched_assets.sort(
            key=lambda x: (
                max((ld['latest_scan'].scan_date 
                     for ld in x['layers_data'] if ld['latest_scan']), 
                    default=datetime.min.date())
            ),
            reverse=(sort_order == 'desc')
        )
    
    # ============================================================
    # PAGINACIÓN
    # ============================================================
    
    paginator = Paginator(enriched_assets, per_page)
    page_obj = paginator.get_page(page)
    
    # ============================================================
    # DATOS PARA FILTROS (OPCIONES)
    # ============================================================
    
    filter_options = {
        'environments': Asset.ENVIRONMENT_CHOICES,
        'administrators': Asset.ADMINISTRATOR_CHOICES,
        'responsibles': Asset.RESPONSIBLE_CHOICES,
        'layer_types': AssetLayer.LAYER_TYPES,
    }
    
    # Estadísticas
    stats = {
        'total_assets': len(enriched_assets),
        'active_assets': len([a for a in enriched_assets if a['asset'].status == 'ACTIVE']),
        'inactive_assets': len([a for a in enriched_assets if a['asset'].status == 'INACTIVE']),
        'pci_assets': len([a for a in enriched_assets if a['asset'].pci_standard]),
        'changed_compliance': len([a for a in enriched_assets 
                                   if any(ld['compliance_changed'] for ld in a['layers_data'])]),
    }
    
    # ============================================================
    # CONTEXTO
    # ============================================================
    
    context = {
        'page_obj': page_obj,
        'page_title': 'Gestión de Assets',
        'stats': stats,
        'filter_options': filter_options,
        
        # Filtros activos (para mantener estado)
        'filters': {
            'status': status_filter,
            'search': search_query,
            'environment': environment_filter,
            'administrator': administrator_filter,
            'responsible': responsible_filter,
            'pci_standard': pci_filter,
            'layer_type': layer_type_filter,
            'compliance_min': compliance_min,
            'compliance_max': compliance_max,
            'scan_date_from': scan_date_from,
            'scan_date_to': scan_date_to,
            'show_only_changed': show_only_changed,
            'sort_by': sort_by,
            'sort_order': sort_order,
            'per_page': per_page,
        }
    }
    
    return render(request, 'compliance/assets/list.html', context)


@login_required
def asset_detail(request, asset_id):
    """Vista de detalle de un asset"""
    
    asset = get_object_or_404(Asset, id=asset_id)
    
    # Obtener todas las capas con sus escaneos
    layers_data = []
    for layer in asset.layers.all():
        scans = layer.scans.order_by('-scan_date')[:10]  # Últimos 10 escaneos
        
        try:
            baseline = Baseline.objects.get(asset=asset, layer=layer)
        except Baseline.DoesNotExist:
            baseline = None
        
        layers_data.append({
            'layer': layer,
            'scans': scans,
            'baseline': baseline,
            'latest_scan': scans.first() if scans else None
        })
    
    # Obtener alertas activas
    alerts = asset.alerts.filter(status='ACTIVE').order_by('-created_at')[:5]
    
    context = {
        'asset': asset,
        'layers_data': layers_data,
        'alerts': alerts,
        'page_title': f'Asset: {asset.hostname}'
    }
    
    return render(request, 'compliance/assets/detail.html', context)


from compliance.auth_views import operator_or_admin_required

@operator_or_admin_required
def asset_create(request):
    """Crear nuevo asset"""
    
    if request.method == 'POST':
        form = AssetForm(request.POST)
        if form.is_valid():
            asset = form.save()
            messages.success(request, f'Asset {asset.hostname} creado exitosamente')
            return redirect('asset_detail', asset_id=asset.id)
    else:
        form = AssetForm()
    
    context = {
        'form': form,
        'page_title': 'Crear Asset',
        'action': 'create'
    }
    
    return render(request, 'compliance/assets/form.html', context)


@operator_or_admin_required
def asset_edit(request, asset_id):
    """Editar asset existente"""
    
    asset = get_object_or_404(Asset, id=asset_id)
    
    if request.method == 'POST':
        form = AssetForm(request.POST, instance=asset)
        if form.is_valid():
            form.save()
            messages.success(request, f'Asset {asset.hostname} actualizado exitosamente')
            return redirect('asset_detail', asset_id=asset.id)
    else:
        form = AssetForm(instance=asset)
    
    context = {
        'form': form,
        'asset': asset,
        'page_title': f'Editar Asset: {asset.hostname}',
        'action': 'edit'
    }
    
    return render(request, 'compliance/assets/form.html', context)


@operator_or_admin_required
def asset_delete(request, asset_id):
    """Inactivar asset"""
    
    asset = get_object_or_404(Asset, id=asset_id)
    
    if request.method == 'POST':
        reason = request.POST.get('reason', 'Inactivado desde interfaz web')
        asset.deactivate(reason)
        messages.success(request, f'Asset {asset.hostname} inactivado')
        return redirect('assets_list')
    
    context = {
        'asset': asset,
        'page_title': f'Inactivar Asset: {asset.hostname}'
    }
    
    return render(request, 'compliance/assets/delete_confirm.html', context)


@operator_or_admin_required
def asset_layer_create(request, asset_id):
    """Agregar capa a un asset"""
    
    asset = get_object_or_404(Asset, id=asset_id)
    
    if request.method == 'POST':
        form = AssetLayerForm(request.POST, asset=asset)
        if form.is_valid():
            layer = form.save(commit=False)
            layer.asset = asset
            layer.save()
            messages.success(request, f'Capa {layer.get_layer_type_display()} agregada exitosamente')
            return redirect('asset_detail', asset_id=asset.id)
    else:
        form = AssetLayerForm(asset=asset)
    
    context = {
        'form': form,
        'asset': asset,
        'page_title': f'Agregar Capa a {asset.hostname}'
    }
    
    return render(request, 'compliance/assets/layer_form.html', context)


@operator_or_admin_required
def asset_layer_edit(request, layer_id):
    """Editar capa de asset"""
    
    layer = get_object_or_404(AssetLayer, id=layer_id)
    
    if request.method == 'POST':
        form = AssetLayerForm(request.POST, instance=layer, asset=layer.asset)
        if form.is_valid():
            form.save()
            messages.success(request, f'Capa actualizada exitosamente')
            return redirect('asset_detail', asset_id=layer.asset.id)
    else:
        form = AssetLayerForm(instance=layer, asset=layer.asset)
    
    context = {
        'form': form,
        'layer': layer,
        'asset': layer.asset,
        'page_title': f'Editar Capa: {layer.get_layer_type_display()}'
    }
    
    return render(request, 'compliance/assets/layer_form.html', context)


@operator_or_admin_required
def asset_layer_delete(request, layer_id):
    """Eliminar capa de asset"""
    
    layer = get_object_or_404(AssetLayer, id=layer_id)
    asset = layer.asset
    
    if request.method == 'POST':
        layer.delete()
        messages.success(request, f'Capa {layer.get_layer_type_display()} eliminada')
        return redirect('asset_detail', asset_id=asset.id)
    
    context = {
        'layer': layer,
        'asset': asset,
        'page_title': f'Eliminar Capa: {layer.get_layer_type_display()}'
    }
    
    return render(request, 'compliance/assets/layer_delete_confirm.html', context)


# ============================================================
# JUSTIFICACIONES DE POLÍTICAS (CRUD COMPLETO)
# ============================================================

@operator_or_admin_required
def policy_justification_create(request, asset_id, layer_id, policy_id):
    """Crear justificación para una política fallida"""
    
    asset = get_object_or_404(Asset, id=asset_id)
    layer = get_object_or_404(AssetLayer, id=layer_id, asset=asset)
    policy = get_object_or_404(BenchmarkPolicy, id=policy_id)
    
    # Verificar si ya existe una justificación
    existing = AssetExclusion.objects.filter(
        asset=asset,
        layer=layer,
        policy=policy
    ).first()
    
    if existing:
        messages.warning(request, 'Ya existe una justificación para esta política. Use "Editar" para modificarla.')
        return redirect('asset_detail', asset_id=asset.id)
    
    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip()
        justification_file = request.FILES.get('justification_file')
        
        if not reason or len(reason) < 50:
            messages.error(request, 'La justificación debe tener al menos 50 caracteres')
            return redirect('policy_justification_create', asset_id=asset_id, layer_id=layer_id, policy_id=policy_id)
        
        # Crear justificación
        AssetExclusion.objects.create(
            asset=asset,
            layer=layer,
            policy=policy,
            reason=reason,
            justification_file=justification_file,
            created_by=request.user.username,
            is_active=True
        )
        
        messages.success(request, f'Justificación creada para política {policy.section} {policy.recommendation}')
        return redirect('asset_detail', asset_id=asset.id)
    
    context = {
        'asset': asset,
        'layer': layer,
        'policy': policy,
        'action': 'create',
        'page_title': f'Crear Justificación: {policy.section} {policy.recommendation}'
    }
    
    return render(request, 'compliance/assets/policy_justification_form.html', context)


@operator_or_admin_required
def policy_justification_edit(request, exclusion_id):
    """Editar justificación existente"""
    
    exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
    
    if request.method == 'POST':
        reason = request.POST.get('reason', '').strip()
        justification_file = request.FILES.get('justification_file')
        
        if not reason or len(reason) < 50:
            messages.error(request, 'La justificación debe tener al menos 50 caracteres')
            return redirect('policy_justification_edit', exclusion_id=exclusion_id)
        
        # Actualizar justificación
        exclusion.reason = reason
        if justification_file:
            exclusion.justification_file = justification_file
        exclusion.save()
        
        messages.success(request, f'Justificación actualizada para política {exclusion.policy.section} {exclusion.policy.recommendation}')
        return redirect('asset_detail', asset_id=exclusion.asset.id)
    
    context = {
        'asset': exclusion.asset,
        'layer': exclusion.layer,
        'policy': exclusion.policy,
        'exclusion': exclusion,
        'action': 'edit',
        'page_title': f'Editar Justificación: {exclusion.policy.section} {exclusion.policy.recommendation}'
    }
    
    return render(request, 'compliance/assets/policy_justification_form.html', context)


@login_required
def policy_justification_view(request, exclusion_id):
    """Ver detalles de una justificación"""
    
    exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
    
    context = {
        'asset': exclusion.asset,
        'layer': exclusion.layer,
        'policy': exclusion.policy,
        'exclusion': exclusion,
        'page_title': f'Ver Justificación: {exclusion.policy.section} {exclusion.policy.recommendation}'
    }
    
    return render(request, 'compliance/assets/policy_justification_view.html', context)


@operator_or_admin_required
def policy_justification_delete(request, exclusion_id):
    """Eliminar justificación"""
    
    exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
    asset_id = exclusion.asset.id
    
    if request.method == 'POST':
        policy_name = f"{exclusion.policy.section} {exclusion.policy.recommendation}"
        exclusion.delete()
        messages.success(request, f'Justificación eliminada para política {policy_name}')
        return redirect('asset_detail', asset_id=asset_id)
    
    context = {
        'exclusion': exclusion,
        'page_title': f'Eliminar Justificación: {exclusion.policy.section} {exclusion.policy.recommendation}'
    }
    
    return render(request, 'compliance/assets/policy_justification_delete.html', context)


@operator_or_admin_required
def policy_justification_toggle(request, exclusion_id):
    """Activar/Desactivar justificación (POST only)"""
    
    if request.method == 'POST':
        exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
        exclusion.is_active = not exclusion.is_active
        exclusion.save()
        
        status = "activada" if exclusion.is_active else "desactivada"
        messages.success(
            request, 
            f'Justificación {status} para política {exclusion.policy.section} {exclusion.policy.recommendation}'
        )
    
    return redirect(request.META.get('HTTP_REFERER', '/'))


@login_required
def policy_justification_api(request, exclusion_id):
    """API endpoint para obtener detalles de justificación (para modal)"""
    
    try:
        exclusion = get_object_or_404(AssetExclusion, id=exclusion_id)
        
        return JsonResponse({
            'success': True,
            'data': {
                'id': exclusion.id,
                'policy': f"{exclusion.policy.section} {exclusion.policy.recommendation}",
                'title': exclusion.policy.title,
                'reason': exclusion.reason,
                'created_by': exclusion.created_by,
                'created_at': exclusion.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_active': exclusion.is_active,
                'has_file': bool(exclusion.justification_file),
                'file_url': exclusion.justification_file.url if exclusion.justification_file else None,
                'file_name': exclusion.justification_file.name.split('/')[-1] if exclusion.justification_file else None
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)