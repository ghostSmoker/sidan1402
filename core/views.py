from django.shortcuts import render, get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializers, FormSerializers , FormHistorySeralizer,ChangePasswordSerializer,TwoItemSerializer,UserKey,SubscriptionSerializer,ForgetPasswordSerializer
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from .models import User, Bill,Subscription
from rest_framework.exceptions import APIException,AuthenticationFailed
from .authentication import create_access_token, create_refresh_token,decode_access_token,decode_refresh_token,remove_none_values,create_keys
from rest_framework.authentication import get_authorization_header
import requests
import json
import base64
import os
from django.http import FileResponse
import re

class RegisterAPIView(APIView):
    def post(self,request):
        serializer = UserSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self,request):
        user = User.objects.filter(username=request.data['username']).first()

        if not user:
            raise APIException('invalid credentials!')
        if not user.check_password(request.data['password']):
            raise APIException('invalid cedential!')

        if user.client_id == None and user.private_key == None:
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            is_valid = False
        else:
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            is_valid = True

        response = Response()

        # response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        response.data = {
            'token' : access_token,
            'refreshtoken' : refresh_token,
            'is_valid' : is_valid
        }

        return response

class GenerateAPI(APIView):
    def post(self,request,pk):
        user = get_object_or_404(get_user_model(), pk=pk)
        private_key, public_key = create_keys()
        print(private_key)
        print(public_key)
        try:
            # user.client_id = generate_client_id()
            user.private_key = private_key
            user.save()
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        # return Response ({
        #         "publickey" : public_key
        # })
        download_view = DownloadFileView()
        return download_view.get(request)

class DownloadFileView(APIView):
    def get(self, request):
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filename = 'public_key.txt'
        filepath = os.path.join(BASE_DIR,filename)
        file = open(filepath, 'rb')
        response = FileResponse(file)
        response['Content-Disposition'] = 'attachment; filename="%s"' % filename

        return response


class UserAPIView(APIView):
    def get(self,request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)

            user = User.objects.filter(pk=id).first()

            return Response(UserSerializers(user).data)

        raise AuthenticationFailed('unauthenticated')

class RefreshAPIVeiw(APIView):
    def post(self,request):
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        access_token = create_access_token(id)
        return Response({
            'token' : access_token
        })

class LogoutAPIVeiw(APIView):
    def post(self,request):
        response = Response()
        response.delete_cookie(key='refreshToken')
        response.data = {
            'message' : 'success'
        }
        return response

class Dashboard(APIView):
    def post(self,request,pk):
        user = get_object_or_404(get_user_model(), pk=pk)
        if user.client_id == None and user.private_key == None:
            serializer = TwoItemSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            print(serializer)
            client_id = serializer.validated_data['client_id']
            private_key = serializer.validated_data['private_key']
            user.client_id = client_id
            user.private_key = private_key
            user.save()
        elif user.client_id == None and user.private_key != None:
            serializer = UserKey(data=request.data)
            serializer.is_valid(raise_exception=True)
            print(serializer)
            client_id = serializer.validated_data['client_id']
            # private_key = serializer.validated_data['private_key']
            user.client_id = client_id
            # user.private_key = private_key
            user.save()
        return Response ({
                "message" : "success"
        })

class FormAPIView(APIView):
    def post(self,request,pk):
        user = get_object_or_404(get_user_model(), pk=pk)
        subscription = Subscription.objects.filter(user=pk).first()
        if subscription.status == 'expired':
            return Response({
                "message" : "your subscription finished"
            })
        else:
            serializer = FormSerializers(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=user)
            jsons = {k:v for k,v in serializer.data.items() if k in ['header', 'body', 'payment']}
            j = remove_none_values(jsons)
            print(j)
            # print(j["payment"])
            # print(j["header"])
            # print(j["body"])
            # print(j)
            # print(jsons)
            client_id = user.client_id
            private_key = user.private_key
            headers = {
            "Content-Type": "application/json"
            }
            payload = {
                "clientId" : client_id , 
                "privateKey" : private_key,
                "header" : j["header"],
                "body" : j["body"],
                "payment" : j["payment"],
                "its_update" : False

            }

            url = "http://localhost:5000/Invoice"
            response = requests.post(url,headers=headers ,data=json.dumps(payload),verify=False)
            print(response.json())
            response_json = response.json()


            url1 = "http://localhost:5000/inquiry/byuid"
            payload1 = {
                "clientId" : client_id , 
                "privarekey" : private_key,
                "uuid" : response_json["uuid"]

            }
            response1 = requests.post(url1,headers=headers ,data=json.dumps(payload1),verify=False)
            print(response1.json())
            response_json1 = response1.json()
            # # serializer.instance.delete()
            status = response_json1[0]["status"]
            print(status)
            if status == "SUCCESS":
                taxid = response.json()["taxId"]
                serializer.instance.taxid = taxid
                serializer.instance.irtaxid = taxid
                serializer.instance.status = status
                serializer.instance.uuid = response.json()["uuid"]
                serializer.instance.refrenceid = response.json()["refrenceId"]
                serializer.instance.taxid = response.json()["taxId"]
                serializer.instance.sendtime = response.json()["sendTime"]
                serializer.instance.save()
                subscription.invoice_count += 1
                subscription.save()
                return Response ({
                    "message" : response1.json(),
                    "MESSAGE" : "sabt shod"
            })
            elif status == "FAILED":
                # serializer.instance.delete()
                instance = serializer.instance
                instance.delete() 
                return Response ({
                    "message" : response1.json(),
                    "MESSAGE" : "sabt nashod"
                })
            elif status == "PENDING":
                # serializer.instance.delete()
                taxid = response.json()["taxId"]
                serializer.instance.taxid = taxid
                serializer.instance.irtaxid = taxid
                serializer.instance.status = status
                serializer.instance.uuid = response.json()["uuid"]
                serializer.instance.refrenceid = response.json()["refrenceId"]
                serializer.instance.taxid = response.json()["taxId"]
                serializer.instance.sendtime = response.json()["sendTime"]
                serializer.instance.save()
                return Response ({
                    "message" : response1.json(),
                    "MESSAGE" : "dar hale bargharari ertebat ba samane"
            })


class UserProfileView(APIView):
    def get(self, request,pk):
        user = get_object_or_404(get_user_model(), pk=pk)
        serializer = UserSerializers(user)
        return Response(serializer.data)

class FormHistoryView(APIView):
    def get(self, request, user_id):
        user = get_object_or_404(get_user_model(), pk=user_id)
        bill_objects = Bill.objects.filter(user=user_id)
        subscription = Subscription.objects.filter(user=user_id).first()
        serializer = FormHistorySeralizer(bill_objects, many=True)
        print(len(serializer.data))
        for i in range(len(serializer.data)):
            b= serializer.data[i]["uuid"]
            headers = {
            "Content-Type": "application/json"
                }
            url1 = "http://localhost:5000/inquiry/byuid"
            payload1 = {
                "clientId" : user.client_id , 
                "privarekey" : user.private_key,
                "uuid" : b

            }
            response1 = requests.post(url1,headers=headers ,data=json.dumps(payload1),verify=False)
            response_json1 = response1.json()
            # # serializer.instance.delete()
            status = response_json1[0]["status"]
            print(status)
            bill_instance = bill_objects[i]
            if status == "SUCCESS":
                bill_instance.status = status
                bill_instance.save()
                subscription.invoice_count += 1
                subscription.save()
                # serializer1 = FormHistorySeralizer(bill_objects, many=True)
            elif status == "FAILED":
                bill_instance.status = status
                bill_instance.error = response1.json()[0]["data"]["error"]
                bill_instance.save()
                # serializer1 = FormHistorySeralizer(bill_objects, many=True)
        serializer1 = FormHistorySeralizer(bill_objects, many=True)
        return Response({
                        "bill_objects": serializer1.data,
                        "invoice_count": subscription.invoice_count,
                    })



class SubscriptionCreateAPIView(APIView):
    def post(self, request, user_id):
        user = get_object_or_404(get_user_model(), pk=user_id)

        serializer = SubscriptionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        subscription = serializer.save(user=user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class FormUpdateView(APIView):
    def put(self, request, user_id, bill_id):
        user = get_object_or_404(get_user_model(), pk=user_id)
        bill = get_object_or_404(Bill,user=user, id=bill_id)
        subscription = Subscription.objects.filter(user=user_id).first()
        if subscription.status == 'expired':
            return Response({
                "message" : "your subscription finished"
            })
        else:
            serializer = FormSerializers(bill, data=request.data ,partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            jsons = {k:v for k,v in serializer.data.items() if k in ['header', 'body', 'payment']}
            print(jsons)
            j = remove_none_values(jsons)
            print(j)
            # print(j["payment"])
            # print(j["header"])
            # print(j["body"])
            # print(j)
            # print(jsons)
            client_id = user.client_id
            private_key = user.private_key
            headers = {
                "Content-Type": "application/json"
            }
            payload = {
                "clientId" : client_id , 
                "privateKey" : private_key,
                "header" : j["header"],
                "body" : j["body"],
                "payment" : j["payment"],
                "its_update" : False

            }

            url = "http://localhost:5000/Invoice"
            response = requests.post(url,headers=headers ,data=json.dumps(payload),verify=False)
            print(response.json())
            response_json = response.json()


            url1 = "http://localhost:5000/inquiry/byuid"
            payload1 = {
                "clientId" : client_id , 
                "privarekey" : private_key,
                "uuid" : response_json["uuid"]

            }
            response1 = requests.post(url1,headers=headers ,data=json.dumps(payload1),verify=False)
            print(response1.json())
            response_json1 = response1.json()
            # # serializer.instance.delete()
            status = response_json1[0]["status"]
            print(status)
            if status == "SUCCESS":
                taxid = response.json()["taxId"]
                serializer.instance.taxid = taxid
                serializer.instance.irtaxid = taxid
                serializer.instance.status = status
                serializer.instance.error = None
                serializer.instance.uuid = response.json()["uuid"]
                serializer.instance.refrenceid = response.json()["refrenceId"]
                serializer.instance.taxid = response.json()["taxId"]
                serializer.instance.sendtime = response.json()["sendTime"]
                serializer.instance.save()
                subscription.invoice_count += 1
                subscription.save()
                return Response ({
                    "message" : response1.json(),
                    "MESSAGE" : "sabt shod"
            })
            elif status == "FAILED":
                serializer.instance.status = status
                serializer.instance.error = response1.json()[0]["data"]["error"]
                return Response ({
                    "message" : response1.json()[0]["data"]["error"],
                    "MESSAGE" : "sabt nashod"
            })
            elif status == "PENDING":
                # serializer.instance.delete()
                taxid = response.json()["taxId"]
                serializer.instance.taxid = taxid
                serializer.instance.irtaxid = taxid
                serializer.instance.status = status
                serializer.instance.error = None
                serializer.instance.uuid = response.json()["uuid"]
                serializer.instance.refrenceid = response.json()["refrenceId"]
                serializer.instance.taxid = response.json()["taxId"]
                serializer.instance.sendtime = response.json()["sendTime"]
                serializer.instance.save()
                return Response ({
                    "message" : response1.json(),
                    "MESSAGE" : "dar hale bargharari ertebat ba samane"
            })

class UserUpdateView(APIView):
    def put(self, request, pk):
        user = get_object_or_404(get_user_model(), pk=pk)
        serializer = UserSerializers(user, data=request.data ,partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class ChangePasswordView(RetrieveUpdateAPIView):
    serializer_class = ChangePasswordSerializer

    def get_object(self):
        return get_object_or_404(User, id=self.kwargs['user_id'])

    def put(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            old_password = serializer.data.get("old_password")
            new_password = serializer.data.get("new_password")
            confirm_new_password = serializer.data.get("confirm_new_password")

            if user.check_password(old_password):
                if new_password == confirm_new_password:
                    user.set_password(new_password)
                    user.save()
                    return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "New password and confirmation do not match."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "Incorrect old password."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgetPasswordView(RetrieveUpdateAPIView):
    serializer_class = ForgetPasswordSerializer

    def get_object(self):
        national_code = self.request.data.get('national_code')
        return get_object_or_404(User, national_code=national_code)

    def put(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            national_code = serializer.validated_data.get("national_code")
            new_password = serializer.validated_data.get("new_password")
            repeat_new_password = serializer.validated_data.get("repeat_new_password")

            user = get_object_or_404(User, national_code=national_code)

            if new_password == repeat_new_password:
                if not re.search(r'[A-Z]', new_password):
                    return Response({'message': 'Password must contain at least one uppercase letter.'}, status=400)
                if not re.search(r'\d', new_password):
                    return Response({'message': 'Password must contain at least one digit.'}, status=400)

                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password updated successfully'})
            else:
                return Response({'message': 'Passwords do not match'}, status=400)
        else:
            return Response(serializer.errors, status=400)

