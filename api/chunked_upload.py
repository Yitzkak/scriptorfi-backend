from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.files.base import ContentFile
from django.conf import settings
import os
from .models import UploadedFile
from .serializers import FileSerializer

class ChunkedUploadView(APIView):
    """
    Accepts file chunks and reassembles them when all are received.
    Expects: chunk (file), chunk_index (int), total_chunks (int), upload_id (str), metadata (optional)
    """
    def post(self, request):
        chunk = request.FILES.get('chunk')
        chunk_index = int(request.data.get('chunk_index', 0))
        total_chunks = int(request.data.get('total_chunks', 1))
        upload_id = request.data.get('upload_id')
        metadata = request.data.get('metadata', '{}')

        if not chunk or upload_id is None:
            return Response({'error': 'Missing chunk or upload_id'}, status=status.HTTP_400_BAD_REQUEST)

        temp_dir = os.path.join(settings.MEDIA_ROOT, 'chunked_uploads', upload_id)
        os.makedirs(temp_dir, exist_ok=True)
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index}')
        with open(chunk_path, 'wb') as f:
            f.write(chunk.read())

        # Check if all chunks are present
        chunk_files = [f for f in os.listdir(temp_dir) if f.startswith('chunk_')]
        if len(chunk_files) == total_chunks:
            # Reassemble file
            assembled_path = os.path.join(temp_dir, 'assembled_file')
            with open(assembled_path, 'wb') as assembled:
                for i in range(total_chunks):
                    with open(os.path.join(temp_dir, f'chunk_{i}'), 'rb') as c:
                        assembled.write(c.read())
            # Save to UploadedFile
            with open(assembled_path, 'rb') as assembled:
                uploaded_file = UploadedFile(
                    name=f'upload_{upload_id}',
                    file=ContentFile(assembled.read(), name=f'upload_{upload_id}.mp3'),
                    status='Pending',
                    payment_status='Unpaid',
                )
                uploaded_file.save()
            # Clean up temp files
            for f in chunk_files:
                os.remove(os.path.join(temp_dir, f))
            os.remove(assembled_path)
            os.rmdir(temp_dir)
            return Response({'id': uploaded_file.id, 'message': 'Upload complete'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': f'Chunk {chunk_index+1}/{total_chunks} received'}, status=status.HTTP_202_ACCEPTED)
