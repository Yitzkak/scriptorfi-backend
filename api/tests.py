from django.test import TestCase
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from django.conf import settings
from decimal import Decimal
from .models import UploadedFile, CustomUser, Transcript
class UploadAndPaymentFlowTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = CustomUser.objects.create_user(
			username="testuser",
			email="test@example.com",
			password="testpass123",
			first_name="Test",
			last_name="User",
		)
		self.client.force_authenticate(user=self.user)

	def _dummy_audio(self, content=b"fake-audio"):
		return SimpleUploadedFile("test.mp3", content, content_type="audio/mpeg")

	def test_authenticated_upload_sets_server_pricing(self):
		response = self.client.post(
			"/api/files/upload/",
			{
				"file": self._dummy_audio(),
				"size": "120",
				"total_cost": "0",
				"verbatim": "No",
				"rush_order": "No",
				"timestamp": "Yes",
				"spelling": "US",
			},
			format="multipart",
		)
		self.assertEqual(response.status_code, 201)
		uploaded = UploadedFile.objects.get(id=response.data["id"])
		self.assertGreater(uploaded.total_cost, Decimal("0.00"))

	def test_free_trial_sets_paid_status(self):
		response = self.client.post(
			"/api/files/upload/",
			{
				"file": self._dummy_audio(),
				"size": str(getattr(settings, "FREE_TRIAL_SECONDS", 300)),
				"free_trial": "true",
				"verbatim": "No",
				"rush_order": "No",
				"timestamp": "Yes",
				"spelling": "US",
			},
			format="multipart",
		)
		self.assertEqual(response.status_code, 201)
		uploaded = UploadedFile.objects.get(id=response.data["id"])
		self.assertEqual(uploaded.payment_status, "Paid")


class TranscriptApiTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = CustomUser.objects.create_user(
			username="testuser2",
			email="test2@example.com",
			password="testpass123",
			first_name="Test",
			last_name="User",
		)
		self.client.force_authenticate(user=self.user)

	def test_transcription_list_returns_completed_files(self):
		file_obj = UploadedFile.objects.create(
			user=self.user,
			name="completed.mp3",
			size=120,
			total_cost=Decimal("1.20"),
			status="Completed",
			payment_status="Paid",
		)
		Transcript.objects.create(uploaded_file=file_obj, text="Hello")

		response = self.client.get("/api/transcriptions/")
		self.assertEqual(response.status_code, 200)
		self.assertEqual(len(response.data), 1)

	def test_transcript_detail(self):
		file_obj = UploadedFile.objects.create(
			user=self.user,
			name="completed2.mp3",
			size=120,
			total_cost=Decimal("1.20"),
			status="Completed",
			payment_status="Paid",
		)
		Transcript.objects.create(uploaded_file=file_obj, text="Transcript text")

		response = self.client.get(f"/api/transcriptions/{file_obj.id}/")
		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.data.get("text"), "Transcript text")

# Create your tests here.
