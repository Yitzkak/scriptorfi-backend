import paypalrestsdk
import requests
from decimal import Decimal
import json
import hmac
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from .models import UploadedFile
from django.shortcuts import get_object_or_404

# Configure PayPal SDK
paypalrestsdk.configure({
    "mode": getattr(settings, 'PAYPAL_MODE', 'sandbox'),  # sandbox or live
    "client_id": getattr(settings, 'PAYPAL_CLIENT_ID', ''),
    "client_secret": getattr(settings, 'PAYPAL_CLIENT_SECRET', '')
})


class CreatePaymentView(APIView):
    """Create a PayPal payment for a file upload"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_id = request.data.get('file_id')
        
        if not file_id:
            return Response(
                {"error": "file_id is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the uploaded file
        uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)

        # Check if already paid
        if uploaded_file.payment_status == 'Paid':
            return Response(
                {"error": "This file has already been paid for"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if Decimal(str(uploaded_file.total_cost or 0)) <= 0:
            return Response(
                {"error": "No payment required for this file"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create PayPal payment
        amount_str = str(Decimal(str(uploaded_file.total_cost or 0)).quantize(Decimal("0.01")))
        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "redirect_urls": {
                "return_url": request.data.get('return_url', 'http://localhost:3000/dashboard/payment/success'),
                "cancel_url": request.data.get('cancel_url', 'http://localhost:3000/dashboard/payment/cancel')
            },
            "transactions": [{
                "item_list": {
                    "items": [{
                        "name": f"Transcription - {uploaded_file.name}",
                        "sku": f"file_{uploaded_file.id}",
                        "price": amount_str,
                        "currency": "USD",
                        "quantity": 1
                    }]
                },
                "amount": {
                    "total": amount_str,
                    "currency": "USD"
                },
                "description": f"Transcription service for {uploaded_file.name}"
            }]
        })

        if payment.create():
            # Save payment ID to the file
            uploaded_file.paypal_payment_id = payment.id
            uploaded_file.payment_status = 'Pending'
            uploaded_file.save()

            # Get approval URL
            for link in payment.links:
                if link.rel == "approval_url":
                    approval_url = link.href
                    return Response({
                        "payment_id": payment.id,
                        "approval_url": approval_url,
                        "file_id": uploaded_file.id
                    }, status=status.HTTP_200_OK)
        
        return Response({
            "error": "Failed to create payment",
            "details": payment.error
        }, status=status.HTTP_400_BAD_REQUEST)


class CreateBatchPaymentView(APIView):
    """Create a PayPal payment for multiple file uploads"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_ids = request.data.get('file_ids')

        if not file_ids or not isinstance(file_ids, list):
            return Response(
                {"error": "file_ids (list) is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        files = list(UploadedFile.objects.filter(id__in=file_ids, user=request.user))

        if len(files) != len(file_ids):
            return Response(
                {"error": "One or more files were not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        if any(f.payment_status == 'Paid' for f in files):
            return Response(
                {"error": "One or more files have already been paid for"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if any(Decimal(str(f.total_cost or 0)) <= 0 for f in files):
            return Response(
                {"error": "One or more files require no payment"},
                status=status.HTTP_400_BAD_REQUEST
            )

        total_amount = sum(Decimal(str(f.total_cost or 0)) for f in files)
        total_amount = total_amount.quantize(Decimal("0.01"))
        items = [
            {
                "name": f"Transcription - {f.name}",
                "sku": f"file_{f.id}",
                "price": str(Decimal(str(f.total_cost or 0)).quantize(Decimal("0.01"))),
                "currency": "USD",
                "quantity": 1
            }
            for f in files
        ]

        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "redirect_urls": {
                "return_url": request.data.get('return_url', 'http://localhost:3000/dashboard/payment/success'),
                "cancel_url": request.data.get('cancel_url', 'http://localhost:3000/dashboard/payment/cancel')
            },
            "transactions": [{
                "item_list": {
                    "items": items
                },
                "amount": {
                    "total": str(total_amount),
                    "currency": "USD"
                },
                "description": "Transcription service for multiple files"
            }]
        })

        if payment.create():
            for f in files:
                f.paypal_payment_id = payment.id
                f.payment_status = 'Pending'
                f.save()

            for link in payment.links:
                if link.rel == "approval_url":
                    approval_url = link.href
                    return Response({
                        "payment_id": payment.id,
                        "approval_url": approval_url,
                        "file_ids": [f.id for f in files]
                    }, status=status.HTTP_200_OK)

        return Response({
            "error": "Failed to create payment",
            "details": payment.error
        }, status=status.HTTP_400_BAD_REQUEST)


class ExecutePaymentView(APIView):
    """Execute/confirm a PayPal payment"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        payment_id = request.data.get('payment_id')
        payer_id = request.data.get('payer_id')
        file_id = request.data.get('file_id')

        if not all([payment_id, payer_id, file_id]):
            return Response(
                {"error": "payment_id, payer_id, and file_id are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get the uploaded file
        uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)

        # Verify payment ID matches
        if uploaded_file.paypal_payment_id != payment_id:
            return Response(
                {"error": "Payment ID mismatch"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Execute payment
        payment = paypalrestsdk.Payment.find(payment_id)
        
        if payment.execute({"payer_id": payer_id}):
            # Update file payment status
            uploaded_file.payment_status = 'Paid'
            uploaded_file.paypal_payer_id = payer_id
            uploaded_file.save()

            return Response({
                "message": "Payment successful",
                "file_id": uploaded_file.id,
                "payment_status": "Paid"
            }, status=status.HTTP_200_OK)
        
        # Payment failed
        uploaded_file.payment_status = 'Failed'
        uploaded_file.save()

        return Response({
            "error": "Payment execution failed",
            "details": payment.error
        }, status=status.HTTP_400_BAD_REQUEST)


class ExecuteBatchPaymentView(APIView):
    """Execute/confirm a PayPal payment for multiple files"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        payment_id = request.data.get('payment_id')
        payer_id = request.data.get('payer_id')
        file_ids = request.data.get('file_ids')

        if not all([payment_id, payer_id, file_ids]) or not isinstance(file_ids, list):
            return Response(
                {"error": "payment_id, payer_id, and file_ids (list) are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        files = list(UploadedFile.objects.filter(id__in=file_ids, user=request.user))

        if len(files) != len(file_ids):
            return Response(
                {"error": "One or more files were not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        if any(f.paypal_payment_id != payment_id for f in files):
            return Response(
                {"error": "Payment ID mismatch"},
                status=status.HTTP_400_BAD_REQUEST
            )

        payment = paypalrestsdk.Payment.find(payment_id)

        if payment.execute({"payer_id": payer_id}):
            for f in files:
                f.payment_status = 'Paid'
                f.paypal_payer_id = payer_id
                f.save()

            return Response({
                "message": "Payment successful",
                "file_ids": [f.id for f in files],
                "payment_status": "Paid"
            }, status=status.HTTP_200_OK)

        for f in files:
            f.payment_status = 'Failed'
            f.save()

        return Response({
            "error": "Payment execution failed",
            "details": payment.error
        }, status=status.HTTP_400_BAD_REQUEST)


class CheckPaymentStatusView(APIView):
    """Check payment status for a file"""
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):
        uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)
        
        return Response({
            "file_id": uploaded_file.id,
            "file_name": uploaded_file.name,
            "total_cost": uploaded_file.total_cost,
            "payment_status": uploaded_file.payment_status,
            "paypal_payment_id": uploaded_file.paypal_payment_id
        }, status=status.HTTP_200_OK)


class CreatePaystackPaymentView(APIView):
    """Initialize a Paystack payment for one or more files"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file_ids = request.data.get('file_ids')
        file_id = request.data.get('file_id')
        email = request.data.get('email') or getattr(request.user, 'email', None)

        if not settings.PAYSTACK_SECRET_KEY:
            return Response(
                {"error": "Paystack is not configured"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        if not email:
            return Response(
                {"error": "email is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if file_ids and isinstance(file_ids, list):
            files = list(UploadedFile.objects.filter(id__in=file_ids, user=request.user))
            if len(files) != len(file_ids):
                return Response(
                    {"error": "One or more files were not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        elif file_id:
            files = [get_object_or_404(UploadedFile, id=file_id, user=request.user)]
        else:
            return Response(
                {"error": "file_id or file_ids (list) is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if any(f.payment_status == 'Paid' for f in files):
            return Response(
                {"error": "One or more files have already been paid for"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if any(Decimal(str(f.total_cost or 0)) <= 0 for f in files):
            return Response(
                {"error": "One or more files require no payment"},
                status=status.HTTP_400_BAD_REQUEST
            )

        total_amount = sum(Decimal(str(f.total_cost or 0)) for f in files)
        amount_kobo = int(total_amount * 100)

        payload = {
            "email": email,
            "amount": amount_kobo,
            "callback_url": request.data.get('callback_url', 'http://localhost:3000/dashboard/payment/success'),
            "metadata": {
                "file_ids": [f.id for f in files],
                "user_id": request.user.id,
            },
        }

        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=20,
        )

        if response.status_code != 200:
            return Response(
                {"error": "Failed to initialize Paystack payment", "details": response.text},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = response.json()
        if not data.get("status"):
            return Response(
                {"error": data.get("message", "Failed to initialize Paystack payment")},
                status=status.HTTP_400_BAD_REQUEST
            )

        for f in files:
            f.payment_status = 'Pending'
            f.save()

        return Response(
            {
                "authorization_url": data.get("data", {}).get("authorization_url"),
                "reference": data.get("data", {}).get("reference"),
                "file_ids": [f.id for f in files],
            },
            status=status.HTTP_200_OK,
        )


class VerifyPaystackPaymentView(APIView):
    """Verify a Paystack payment reference and mark files as paid"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        reference = request.data.get('reference')
        file_ids = request.data.get('file_ids')
        file_id = request.data.get('file_id')

        if not settings.PAYSTACK_SECRET_KEY:
            return Response(
                {"error": "Paystack is not configured"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        if not reference:
            return Response(
                {"error": "reference is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if file_ids and isinstance(file_ids, list):
            files = list(UploadedFile.objects.filter(id__in=file_ids, user=request.user))
            if len(files) != len(file_ids):
                return Response(
                    {"error": "One or more files were not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        elif file_id:
            files = [get_object_or_404(UploadedFile, id=file_id, user=request.user)]
        else:
            return Response(
                {"error": "file_id or file_ids (list) is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        total_amount = sum(Decimal(str(f.total_cost or 0)) for f in files)
        expected_amount_kobo = int(total_amount * 100)

        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        verify_response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers,
            timeout=20,
        )

        if verify_response.status_code != 200:
            return Response(
                {"error": "Failed to verify Paystack payment", "details": verify_response.text},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = verify_response.json()
        if not data.get("status"):
            return Response(
                {"error": data.get("message", "Failed to verify Paystack payment")},
                status=status.HTTP_400_BAD_REQUEST
            )

        transaction = data.get("data", {})
        if transaction.get("status") != "success":
            return Response(
                {"error": "Payment not successful"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if expected_amount_kobo and transaction.get("amount") != expected_amount_kobo:
            return Response(
                {"error": "Payment amount mismatch"},
                status=status.HTTP_400_BAD_REQUEST
            )

        for f in files:
            f.payment_status = 'Paid'
            f.save()

        return Response(
            {
                "message": "Payment successful",
                "file_ids": [f.id for f in files],
                "payment_status": "Paid",
            },
            status=status.HTTP_200_OK,
        )


class PaystackWebhookView(APIView):
    permission_classes = []

    def post(self, request):
        signature = request.headers.get("x-paystack-signature")
        if not signature or not settings.PAYSTACK_SECRET_KEY:
            return Response({"error": "Invalid signature"}, status=400)

        computed = hmac.new(
            settings.PAYSTACK_SECRET_KEY.encode("utf-8"),
            msg=request.body,
            digestmod=hashlib.sha512,
        ).hexdigest()

        if not hmac.compare_digest(signature, computed):
            return Response({"error": "Signature mismatch"}, status=400)

        payload = request.data
        event = payload.get("event")
        data = payload.get("data", {})
        if event != "charge.success":
            return Response({"message": "Ignored"}, status=200)

        metadata = data.get("metadata", {}) or {}
        file_ids = metadata.get("file_ids") or []

        if not isinstance(file_ids, list) or not file_ids:
            return Response({"message": "No files to update"}, status=200)

        files = list(UploadedFile.objects.filter(id__in=file_ids))
        for f in files:
            f.payment_status = "Paid"
            f.save(update_fields=["payment_status"])

        return Response({"message": "Payment recorded"}, status=200)


class PayPalWebhookView(APIView):
    permission_classes = []

    def post(self, request):
        webhook_id = getattr(settings, "PAYPAL_WEBHOOK_ID", "")
        if not webhook_id:
            return Response({"error": "PayPal webhook not configured"}, status=500)

        headers = request.headers
        event = request.data

        try:
            is_valid = paypalrestsdk.WebhookEvent.verify(
                transmission_id=headers.get("Paypal-Transmission-Id"),
                timestamp=headers.get("Paypal-Transmission-Time"),
                webhook_id=webhook_id,
                event_body=json.dumps(event),
                cert_url=headers.get("Paypal-Cert-Url"),
                actual_sig=headers.get("Paypal-Transmission-Sig"),
                auth_algo=headers.get("Paypal-Auth-Algo"),
            )
        except Exception:
            return Response({"error": "Webhook verification failed"}, status=400)

        if not is_valid:
            return Response({"error": "Invalid webhook"}, status=400)

        event_type = event.get("event_type")
        resource = event.get("resource", {})
        if event_type == "PAYMENT.SALE.COMPLETED":
            payment_id = resource.get("parent_payment")
            if payment_id:
                UploadedFile.objects.filter(paypal_payment_id=payment_id).update(payment_status="Paid")

        return Response({"message": "Webhook processed"}, status=200)
