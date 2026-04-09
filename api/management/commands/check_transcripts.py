"""
Management command to check for orphaned transcript files and optionally clean them up.

Usage:
    python manage.py check_transcripts          # List orphaned files
    python manage.py check_transcripts --fix    # Clear orphaned file references
"""

from django.core.management.base import BaseCommand
from django.core.files.storage import default_storage
from api.models import Transcript


class Command(BaseCommand):
    help = 'Check for transcript files that are referenced but do not exist in storage'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Clear orphaned file references from the database',
        )

    def handle(self, *args, **options):
        fix_mode = options['fix']
        
        self.stdout.write(self.style.NOTICE('Checking transcript files...\n'))
        
        transcripts = Transcript.objects.exclude(file='').exclude(file__isnull=True)
        total = transcripts.count()
        orphaned = []
        valid = []
        
        self.stdout.write(f'Found {total} transcripts with file references.\n')
        
        for transcript in transcripts:
            file_name = transcript.file.name
            try:
                exists = default_storage.exists(file_name)
            except Exception as e:
                self.stdout.write(self.style.WARNING(
                    f'  Error checking "{file_name}": {e}'
                ))
                exists = False
            
            if exists:
                valid.append(transcript)
                self.stdout.write(self.style.SUCCESS(f'  ✓ {file_name} - EXISTS'))
            else:
                orphaned.append(transcript)
                self.stdout.write(self.style.ERROR(
                    f'  ✗ {file_name} - MISSING (Transcript ID: {transcript.id}, '
                    f'UploadedFile: {transcript.uploaded_file.name})'
                ))
        
        self.stdout.write('\n' + '=' * 50)
        self.stdout.write(f'Valid files: {len(valid)}')
        self.stdout.write(f'Orphaned references: {len(orphaned)}')
        
        if orphaned and fix_mode:
            self.stdout.write(self.style.WARNING('\nClearing orphaned file references...'))
            for transcript in orphaned:
                old_file = transcript.file.name
                transcript.file = None
                transcript.save(update_fields=['file'])
                self.stdout.write(f'  Cleared: {old_file} (Transcript ID: {transcript.id})')
            self.stdout.write(self.style.SUCCESS(f'\n✓ Cleared {len(orphaned)} orphaned references.'))
        elif orphaned:
            self.stdout.write(self.style.NOTICE(
                '\nRun with --fix to clear orphaned file references from the database.'
            ))
        else:
            self.stdout.write(self.style.SUCCESS('\n✓ All transcript files are valid!'))
