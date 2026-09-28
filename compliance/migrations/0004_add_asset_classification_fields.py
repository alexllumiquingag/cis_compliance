# Generated migration file
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('compliance', '0003_assetlayer_software_type_and_more'),  # Ajustar según el nombre de tu migración anterior
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='pci_standard',
            field=models.BooleanField(default=False, help_text='¿El asset está sujeto al estándar PCI DSS?', verbose_name='Estándar PCI'),
        ),
        migrations.AddField(
            model_name='asset',
            name='administrator',
            field=models.CharField(blank=True, choices=[('ADMIN_1', 'Diners'), ('ADMIN_2', 'Kyndryl'), ('ADMIN_3', 'Pentasec'), ('ADMIN_4', 'Cit'), ('ADMIN_5', 'Teradata'), ('ADMIN_6', 'Xkale'), ('ADMIN_7', 'Telalca'), ('ADMIN_8', 'Fesa'), ('ADMIN_9', 'Century Link'), ('ADMIN_10', 'Visa'), ('ADMIN_11', 'Mastercard'), ('ADMIN_12', 'Vidortec'), ('ADMIN_13', 'Eqtek'), ('ADMIN_14', 'SecureSoft'), ('ADMIN_15', 'DinersClub-Interdin')], help_text='Administrador del asset', max_length=50, verbose_name='Administrador'),
        ),
        migrations.AddField(
            model_name='asset',
            name='responsible',
            field=models.CharField(blank=True, choices=[('RESP_1', 'Grupo BDD'), ('RESP_2', 'Grupo Web'), ('RESP_3', 'Grupo Admin Servers'), ('RESP_4', 'Seguridad'), ('RESP_5', 'Comunicaciones'), ('RESP_6', 'Pentasec/Infraestructura Diners'), ('RESP_7', 'Pentasec'), ('RESP_8', 'SegTI - Operaciones y CSIRT'), ('RESP_9', 'SEGTI - Operaciones')], help_text='Responsable del asset', max_length=50, verbose_name='Responsable'),
        ),
        migrations.AddField(
            model_name='asset',
            name='environment',
            field=models.CharField(blank=True, choices=[('PRODUCTION', 'Producción'), ('DEVELOPMENT', 'Desarrollo'), ('CONTINGENCY', 'Contingencia'), ('NOPRODUCTION', 'No producción')], help_text='Ambiente donde opera el asset', max_length=50, verbose_name='Ambiente/Entorno'),
        ),
        migrations.AlterModelOptions(
            name='asset',
            options={'ordering': ['hostname'], 'verbose_name': 'Asset', 'verbose_name_plural': 'Assets'},
        ),
    ]