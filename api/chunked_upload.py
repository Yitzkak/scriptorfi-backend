from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.files.base import ContentFile
from django.conf import settings
from decimal import Decimal
import os
import json
from .models import UploadedFile
from .serializers import FileSerializer

class ChunkedUploadView(APIView):
    """
    Accepts file chunks and reassembles them when all are received.
    Expects: chunk (file), chunk_index (int), total_chunks (int), upload_id (str), metadata (optional)
    """
    parser_classes = (MultiPartParser, FormParser)
    
    def post(self, request):
        chunk = request.FILES.get('chunk')
        chunk_index = int(request.data.get('chunk_index', 0))
        total_chunks = int(request.data.get('total_chunks', 1))
        upload_id = request.data.get('upload_id')
        metadata_str = request.data.get('metadata', '{}')

        if not chunk or upload_id is None:
            return Response({'error': 'Missing chunk or upload_id'}, status=status.HTTP_400_BAD_REQUEST)

        temp_dir = os.path.join(settings.MEDIA_ROOT, 'chunked_uploads', upload_id)
        os.makedirs(temp_dir, exist_ok=True)
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index}')
        
        # Save chunk
        with open(chunk_path, 'wb') as f:
            f.write(chunk.read())
        
        # Save metadata if provided (first chunk)
        if chunk_index == 0 and metadata_str:
            try:
                metadata_path = os.path.join(temp_dir, 'metadata.json')
                with open(metadata_path, 'w') as f:
                    f.write(metadata_str)
            except Exception as e:
                print(f"Error saving metadata: {e}")

        # Check if all chunks are present
        chunk_files = [f for f in os.listdir(temp_dir) if f.startswith('chunk_')]
        if len(chunk_files) == total_chunks:
            # Reassemble file
            assembled_path = os.path.join(temp_dir, 'assembled_file')
            with open(assembled_path, 'wb') as assembled:
                for i in range(total_chunks):
                    chunk_file_path = os.path.join(temp_dir, f'chunk_{i}')
                    if os.path.exists(chunk_file_path):
                        with open(chunk_file_path, 'rb') as c:
                            assembled.write(c.read())
            
            # Load metadata if available
            metadata = {}
            metadata_path = os.path.join(temp_dir, 'metadata.json')
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, 'r') as f:
                        metadata = json.loads(f.read())
                except Exception as e:
                    print(f"Error loading metadata: {e}")
            
            # Get file name and extension from metadata or use defaults
            file_name = metadata.get('name', f'upload_{upload_id}')
            # Preserve original file extension if available
            if '.' in file_name:
                file_ext = os.path.splitext(file_name)[1]
            else:
                file_ext = '.mp3'  # Default extension
            
            # Save to UploadedFile with metadata
            with open(assembled_path, 'rb') as assembled_file:
                file_content = assembled_file.read()
                uploaded_file = UploadedFile(
                    name=file_name,
                    size=int(metadata.get('duration', 0)),  # duration in seconds
                    file=ContentFile(file_content, name=file_name),
                    status='Pending',
                    payment_status='Unpaid',
                    verbatim=metadata.get('verbatim', 'No'),
                    rush_order=metadata.get('rush_order', 'No'),
                    timestamp=metadata.get('timestamp', 'Yes'),
                    spelling=metadata.get('spelling', 'US'),
                    additional_info=metadata.get('instruction', ''),
                    total_cost=Decimal(str(metadata.get('total_cost', 0))),
                )
                uploaded_file.save()
            
            # Clean up temp files
            for f in chunk_files:
                chunk_file_path = os.path.join(temp_dir, f)
                if os.path.exists(chunk_file_path):
                    os.remove(chunk_file_path)
            if os.path.exists(assembled_path):
                os.remove(assembled_path)
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass  # Directory might not be empty, ignore
            
            serializer = FileSerializer(uploaded_file)
            return Response({
                'id': uploaded_file.id,
                'message': 'Upload complete',
                **serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'message': f'Chunk {chunk_index+1}/{total_chunks} received',
                'progress': round((len(chunk_files) / total_chunks) * 100, 2)
            }, status=status.HTTP_202_ACCEPTED)
