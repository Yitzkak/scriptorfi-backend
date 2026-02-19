from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_transcript'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='currency',
            field=models.CharField(max_length=10, blank=True, null=True, default='USD'),
        ),
    ]
