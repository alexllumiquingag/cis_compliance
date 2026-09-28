from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render, redirect
from django.contrib import messages
from compliance.services.nessus_bulk_service import NessusBulkImportService
from compliance.models import Benchmark
from django import forms

class BulkImportForm(forms.Form):
    """Formulario para la vista de importación bulk en admin"""
    
    benchmark = forms.ModelChoiceField(
        queryset=Benchmark.objects.all(),
        label='Benchmark CIS',
        help_text='Todos los servidores usarán este benchmark'
    )
    
    layer_type = forms.ChoiceField(
        choices=AssetLayer.LAYER_TYPES,
        label='Tipo de Capa',
        initial='OS'
    )
    
    scan_date = forms.DateField(
        label='Fecha del Escaneo',
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    
    auto_create_assets = forms.BooleanField(
        label='Crear assets automáticamente',
        required=False,
        initial=True
    )
    
    csv_file = forms.FileField(
        label='Archivo CSV',
        help_text='CSV con múltiples servidores'
    )


@staff_member_required
def bulk_import_view(request):
    """Vista personalizada para importación bulk"""
    
    if request.method == 'POST':
        form = BulkImportForm(request.POST, request.FILES)
        
        if form.is_valid():
            try:
                service = NessusBulkImportService()
                scans, stats = service.import_bulk_scan(
                    file=form.cleaned_data['csv_file'],
                    benchmark_id=form.cleaned_data['benchmark'].id,
                    scan_date=form.cleaned_data['scan_date'],
                    layer_type=form.cleaned_data['layer_type'],
                    auto_create_assets=form.cleaned_data['auto_create_assets']
                )
                
                # Mensaje de éxito
                messages.success(
                    request,
                    f"✅ Importación completada: {stats['servers_imported']} servidores procesados"
                )
                
                # Mostrar resumen
                for scan_info in stats['scans_created']:
                    messages.info(
                        request,
                        f"📊 {scan_info['hostname']}: {scan_info['compliance']:.2f}% "
                        f"(Passed: {scan_info['passed']}, Failed: {scan_info['failed']})"
                    )
                
                # Mostrar errores si hay
                report = service.get_report()
                for error in report['errors'][:5]:
                    messages.error(request, f"❌ {error}")
                
                return redirect('admin:compliance_scan_changelist')
                
            except Exception as e:
                messages.error(request, f"❌ Error: {str(e)}")
    else:
        form = BulkImportForm()
    
    context = {
        'form': form,
        'title': 'Importación Masiva de Escaneos',
        'site_header': 'Compliance CIS - Bulk Import',
    }
    
    return render(request, 'admin/compliance/scan/bulk_import.html', context)
