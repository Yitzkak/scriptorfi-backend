"""
Auto-transcription view using Google Cloud Speech-to-Text v2 (Chirp model).

Chirp is Google's latest, most accurate transcription model. It supports
multi-language audio and does not require specifying an audio encoding —
the API auto-detects format, sample rate, and channels.

Required environment variables:
  GOOGLE_CREDENTIALS_JSON  – JSON string of a GCP service account key that has
                             the Cloud Speech-to-Text API (v2) enabled.
  GOOGLE_CLOUD_PROJECT     – Your GCP project ID.
                             (Auto-read from GOOGLE_CREDENTIALS_JSON if present.)

Required packages (see requirements.txt):
  google-cloud-speech>=2.27.0
  pydub
  ffmpeg  (system binary – needed by pydub for non-WAV formats)
"""

import json
import os
import tempfile
import threading

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Transcript, UploadedFile
from .views import create_notification_for_customer

# Maps UploadedFile.spelling values to BCP-47 language codes supported by Chirp
ACCENT_TO_LANGUAGE = {
    "US": "en-US",
    "British": "en-GB",
    "Australia": "en-AU",
    "Canada": "en-CA",
}

# Chirp processes up to ~60 s of inline audio per request; use 50 s to be safe
CHUNK_MS = 50_000


def _get_project_id(credentials_info: dict | None = None) -> str:
    """Resolve GCP project ID from env var or the credentials JSON."""
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    if project_id:
        return project_id
    if credentials_info and "project_id" in credentials_info:
        return credentials_info["project_id"]
    raise EnvironmentError(
        "GCP project ID not found. Set GOOGLE_CLOUD_PROJECT or include "
        "project_id in GOOGLE_CREDENTIALS_JSON."
    )


def _build_speech_v2_client():
    """
    Return an authenticated Speech-to-Text v2 SpeechClient and the project ID.
    """
    from google.cloud.speech_v2 import SpeechClient  # noqa – imported lazily

    credentials_json = os.environ.get("GOOGLE_CREDENTIALS_JSON", "").strip()
    credentials_info = None

    if credentials_json:
        from google.oauth2 import service_account

        credentials_info = json.loads(credentials_json)
        credentials = service_account.Credentials.from_service_account_info(
            credentials_info,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        client = SpeechClient(credentials=credentials)
    else:
        # Falls back to GOOGLE_APPLICATION_CREDENTIALS or Application Default Credentials
        client = SpeechClient()

    project_id = _get_project_id(credentials_info)
    return client, project_id


def _run_transcription(file_id: int) -> None:
    """
    Background-thread worker: transcribes the audio file at *file_id* using
    Google Cloud Speech-to-Text v2 with the Chirp model and saves the result
    as a Transcript record.
    """
    try:
        from google.cloud.speech_v2 import SpeechClient  # noqa
        from google.cloud.speech_v2.types import cloud_speech
        from pydub import AudioSegment

        uploaded_file = UploadedFile.objects.get(id=file_id)
        language_code = ACCENT_TO_LANGUAGE.get(uploaded_file.spelling, "en-US")

        client, project_id = _build_speech_v2_client()

        # Recognizer path — use the wildcard "_" for ad-hoc (inline) recognition
        # which lets us pass the config directly without creating a named recognizer.
        recognizer = f"projects/{project_id}/locations/global/recognizers/_"

        # ------------------------------------------------------------------ #
        # 1. Load audio and split into ≤ 50-second WAV chunks                 #
        #    Chirp accepts auto_decoding_config so we normalise to 16 kHz     #
        #    mono LINEAR16 for maximum compatibility.                          #
        # ------------------------------------------------------------------ #
        file_path = uploaded_file.file.path
        audio = AudioSegment.from_file(file_path)
        audio = audio.set_channels(1).set_frame_rate(16000).set_sample_width(2)

        transcript_parts: list[str] = []

        for start_ms in range(0, len(audio), CHUNK_MS):
            chunk = audio[start_ms: start_ms + CHUNK_MS]

            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                    tmp_path = tmp.name
                chunk.export(tmp_path, format="wav")
                with open(tmp_path, "rb") as f:
                    audio_content = f.read()
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)

            # ---------------------------------------------------------------- #
            # 2. Build v2 RecognizeRequest with Chirp model                    #
            # ---------------------------------------------------------------- #
            request = cloud_speech.RecognizeRequest(
                recognizer=recognizer,
                config=cloud_speech.RecognitionConfig(
                    # auto_decoding_config lets the API detect encoding/rate.
                    auto_decoding_config=cloud_speech.AutoDetectDecodingConfig(),
                    language_codes=[language_code],
                    model="chirp",  # Google's latest, most accurate model
                    features=cloud_speech.RecognitionFeatures(
                        enable_automatic_punctuation=True,
                        enable_spoken_punctuation=True,
                    ),
                ),
                content=audio_content,
            )

            response = client.recognize(request=request)
            for result in response.results:
                if result.alternatives:
                    transcript_parts.append(result.alternatives[0].transcript)

        # ------------------------------------------------------------------ #
        # 3. Persist transcript and mark file as Completed                    #
        # ------------------------------------------------------------------ #
        transcript_text = " ".join(transcript_parts)

        transcript, _ = Transcript.objects.get_or_create(uploaded_file=uploaded_file)
        transcript.text = transcript_text
        transcript.save()

        uploaded_file.status = "Completed"
        uploaded_file.save(update_fields=["status"])

        create_notification_for_customer(uploaded_file, "Completed")

    except UploadedFile.DoesNotExist:
        pass
    except Exception as exc:  # noqa: BLE001
        print(f"[auto_transcribe] Error transcribing file {file_id}: {exc}")
        try:
            uploaded_file = UploadedFile.objects.get(id=file_id)
            uploaded_file.status = "Pending"  # Reset so user / admin can retry
            uploaded_file.save(update_fields=["status"])
        except Exception:  # noqa: BLE001
            pass


class AutoTranscribeView(APIView):
    """
    POST /api/files/<file_id>/auto-transcribe/

    Triggers Google Cloud Speech-to-Text v2 (Chirp model) transcription for a
    paid auto-transcription file.  The actual transcription runs in a background
    thread; this endpoint returns immediately with HTTP 202.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, file_id: int):
        uploaded_file = get_object_or_404(
            UploadedFile, id=file_id, user=request.user
        )

        if uploaded_file.payment_status != "Paid":
            return Response(
                {"error": "Payment is required before transcription can begin."},
                status=402,
            )

        if uploaded_file.transcription_type != "auto":
            return Response(
                {"error": "This file is not set up for auto-transcription."},
                status=400,
            )

        if not uploaded_file.file:
            return Response(
                {"error": "No audio file attached to this record."},
                status=400,
            )

        if uploaded_file.status == "Completed":
            return Response(
                {"message": "Transcription is already complete.", "status": "Completed"},
                status=200,
            )

        if uploaded_file.status == "Processing":
            return Response(
                {"message": "Transcription is already in progress.", "status": "Processing"},
                status=200,
            )

        # Mark as Processing and kick off background thread
        uploaded_file.status = "Processing"
        uploaded_file.save(update_fields=["status"])

        thread = threading.Thread(
            target=_run_transcription, args=(uploaded_file.id,), daemon=True
        )
        thread.start()

        return Response(
            {
                "message": (
                    "Auto-transcription started. "
                    "You will be notified when your transcript is ready."
                ),
                "status": "Processing",
            },
            status=202,
        )
