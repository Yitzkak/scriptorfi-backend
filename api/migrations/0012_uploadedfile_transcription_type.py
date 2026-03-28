from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_customuser_currency'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedfile',
            name='transcription_type',
            field=models.CharField(
                choices=[('manual', 'Manual'), ('auto', 'Auto')],
                default='manual',
                max_length=10,
            ),
        ),
    ]
