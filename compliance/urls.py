"""
URLs completas del módulo de compliance
"""
from django.urls import path
from compliance import views
from compliance.export_views import export_assets_to_xlsx
from compliance.auth_views import (
    login_view, logout_view, profile_view,
    users_list, user_create, user_edit
)
from compliance.assets_views import (
    assets_list, asset_detail, asset_create, asset_edit, asset_delete,
    asset_layer_create, asset_layer_edit, asset_layer_delete,
    policy_justification_create,
    policy_justification_edit,
    policy_justification_view,
    policy_justification_delete,
    policy_justification_toggle,
    policy_justification_api,
)
from compliance.crud_views import (
    # Thresholds
    thresholds_list, threshold_create, threshold_edit, threshold_delete,
    # Alerts
    alerts_list, alert_detail, alert_acknowledge, alert_resolve, alerts_bulk_action,
    # Exclusions
    exclusions_list, global_exclusion_create, asset_exclusion_create,
    exclusion_toggle, exclusion_delete,
    # CSV Upload
    scan_upload_single
)

urlpatterns = [
    # ============================================================
    # AUTENTICACIÓN
    # ============================================================
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),
    
    # Gestión de usuarios (solo admin)
    path('users/', users_list, name='users_list'),
    path('users/create/', user_create, name='user_create'),
    path('users/<int:user_id>/edit/', user_edit, name='user_edit'),
    
    # ============================================================
    # ASSETS
    # ============================================================
    path('assets/', assets_list, name='assets_list'),
    path('assets/<int:asset_id>/', views.asset_detail_view, name='asset_detail'),
    path('assets/create/', asset_create, name='asset_create'),
    path('assets/<int:asset_id>/edit/', asset_edit, name='asset_edit'),
    path('assets/<int:asset_id>/delete/', asset_delete, name='asset_delete'),

    
    # Asset Layers
    path('assets/<int:asset_id>/layers/create/', asset_layer_create, name='asset_layer_create'),
    path('layers/<int:layer_id>/edit/', asset_layer_edit, name='asset_layer_edit'),
    path('layers/<int:layer_id>/delete/', asset_layer_delete, name='asset_layer_delete'),
    

        # ============================================================
    # JUSTIFICACIONES DE POLÍTICAS (CRUD COMPLETO)
    # ============================================================
    
    # Crear justificación
    path('assets/<int:asset_id>/layers/<int:layer_id>/policy/<int:policy_id>/justification/create/', 
         policy_justification_create, 
         name='policy_justification_create'),
    
    # Ver justificación
    path('justifications/<int:exclusion_id>/', 
         policy_justification_view, 
         name='policy_justification_view'),
    
    # Editar justificación
    path('justifications/<int:exclusion_id>/edit/', 
         policy_justification_edit, 
         name='policy_justification_edit'),
    
    # Eliminar justificación
    path('justifications/<int:exclusion_id>/delete/', 
         policy_justification_delete, 
         name='policy_justification_delete'),
    
    # Activar/Desactivar justificación
    path('justifications/<int:exclusion_id>/toggle/', 
         policy_justification_toggle, 
         name='policy_justification_toggle'),
    
    # API para modal
    path('api/justifications/<int:exclusion_id>/', 
         policy_justification_api, 
         name='policy_justification_api'),

     # Dashboard Ejecutivo
    path('dashboard/executive/', views.executive_dashboard_view, name='executive_dashboard'),
    
    # APIs Dashboard Ejecutivo
    path('api/dashboard/executive-kpis/', views.api_executive_kpis, name='api_executive_kpis'),
    path('api/dashboard/executive-compliance-trend/', views.api_executive_compliance_trend, name='api_executive_compliance_trend'),
    path('api/dashboard/executive-pci-environment/', views.api_executive_pci_environment, name='api_executive_pci_environment'),
    path('api/dashboard/executive-assets-no-scan/', views.api_executive_assets_no_scan, name='api_executive_assets_no_scan'),
    path('api/dashboard/executive-degraded-assets/', views.api_executive_degraded_assets, name='api_executive_degraded_assets'),
    path('api/dashboard/executive-degraded-policies/<int:asset_id>/', views.api_executive_degraded_policies, name='api_executive_degraded_policies'),

     # Dashboard Auditoría
    path('dashboard/audit/', views.audit_dashboard_view, name='audit_dashboard'),
    
    # APIs Dashboard Auditoría
    path('api/dashboard/audit-kpis/', views.api_audit_kpis, name='api_audit_kpis'),
    path('api/dashboard/audit-pci-compliance/', views.api_audit_pci_compliance, name='api_audit_pci_compliance'),
    path('api/dashboard/audit-baseline-drift/', views.api_audit_baseline_drift, name='api_audit_baseline_drift'),
    path('api/dashboard/audit-exclusions-list/', views.api_audit_exclusions_list, name='api_audit_exclusions_list'),
    path('api/dashboard/audit-failed-without-justification/', views.api_audit_failed_without_justification, name='api_audit_failed_without_justification'),
    path('api/dashboard/audit-manual-baseline-changes/', views.api_audit_manual_baseline_changes, name='api_audit_manual_baseline_changes'),
    
    # Export
    path('dashboard/audit/export-exclusions/', views.export_exclusions_excel, name='export_exclusions_excel'),


    # Dashboard Operativo
    path('dashboard/operator/', views.operator_dashboard_view, name='operator_dashboard'),
    
    # APIs Dashboard Operativo
    path('api/dashboard/operator-kpis/', views.api_operator_kpis, name='api_operator_kpis'),
    path('api/dashboard/operator-degraded-assets/', views.api_operator_degraded_assets, name='api_operator_degraded_assets'),
    path('api/dashboard/operator-failed-without-justification/', views.api_operator_failed_without_justification, name='api_operator_failed_without_justification'),
    path('api/dashboard/operator-recurring-policies/', views.api_operator_recurring_policies, name='api_operator_recurring_policies'),

    # ============================================================
    # THRESHOLDS
    # ============================================================
    path('thresholds/', thresholds_list, name='thresholds_list'),
    path('thresholds/create/', threshold_create, name='threshold_create'),
    path('thresholds/<int:threshold_id>/edit/', threshold_edit, name='threshold_edit'),
    path('thresholds/<int:threshold_id>/delete/', threshold_delete, name='threshold_delete'),
    
    # ============================================================
    # ALERTS
    # ============================================================
    path('alerts/', alerts_list, name='alerts_list'),
    path('alerts/<int:alert_id>/', alert_detail, name='alert_detail'),
    path('alerts/<int:alert_id>/acknowledge/', alert_acknowledge, name='alert_acknowledge'),
    path('alerts/<int:alert_id>/resolve/', alert_resolve, name='alert_resolve'),
    path('alerts/bulk-action/', alerts_bulk_action, name='alerts_bulk_action'),
    
    # ============================================================
    # EXCLUSIONS
    # ============================================================
    path('exclusions/', exclusions_list, name='exclusions_list'),
    path('exclusions/global/create/', global_exclusion_create, name='global_exclusion_create'),
    path('exclusions/asset/create/', asset_exclusion_create, name='asset_exclusion_create'),
    path('exclusions/<str:exclusion_type>/<int:exclusion_id>/toggle/', exclusion_toggle, name='exclusion_toggle'),
    path('exclusions/<str:exclusion_type>/<int:exclusion_id>/delete/', exclusion_delete, name='exclusion_delete'),
    
    # ============================================================
    # CSV UPLOADS
    # ============================================================
    path('scans/upload/', scan_upload_single, name='scan_upload_single'),
    path('bulk-upload/', views.bulk_nessus_upload_view, name='bulk_nessus_upload'),
    path('bulk-results/', views.bulk_scan_results_view, name='bulk_scan_results'),
    
    # ============================================================
    # DASHBOARD (mantener las rutas existentes)
    # ============================================================
    path('dashboard/', views.dashboard_view, name='compliance_dashboard'),
    
    # API Endpoints (mantener las existentes)
    path('api/dashboard/stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
    path('api/dashboard/compliance-trend/', views.api_compliance_trend, name='api_compliance_trend'),
    path('api/dashboard/policy-distribution/', views.api_policy_distribution, name='api_policy_distribution'),
    path('api/dashboard/asset-compliance/', views.api_asset_compliance, name='api_asset_compliance'),
    path('api/dashboard/recent-alerts/', views.api_recent_alerts, name='api_recent_alerts'),
    path('api/dashboard/top-failed-policies/', views.api_top_failed_policies, name='api_top_failed_policies'),
    path('api/dashboard/compliance-by-layer/', views.api_compliance_by_layer, name='api_compliance_by_layer'),
    path('api/dashboard/baseline-comparison/', views.api_baseline_comparison, name='api_baseline_comparison'),
    path('api/dashboard/alert-summary/', views.api_alert_summary, name='api_alert_summary'),
    path('api/dashboard/asset-compliance-timeline/<int:asset_id>/', views.api_asset_compliance_timeline, name='api_asset_compliance_timeline'),
    
    # Filtros
    path('api/assets/', views.api_assets_list, name='api_assets_list'),
    path('api/layers/', views.api_layers_list, name='api_layers_list'),
    path('api/scan/<int:scan_id>/detail/', views.bulk_scan_detail_api, name='bulk_scan_detail_api'),

    # Exportar xlsx
    path('assets/export/', export_assets_to_xlsx, name='export_assets_xlsx'),
]