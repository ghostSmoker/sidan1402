from rest_framework import serializers
from .models import User,Bill,Subscription
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
import re


class SubscriptionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Subscription
        fields = [ 'start_date', 'end_date', 'status', 'invoice_count']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)

class TwoItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['client_id' ,'private_key']

class UserKey(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['client_id']


class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username','password','first_name','last_name','national_code','client_id','private_key']
        # 'name', 'family', 'state', 'branch_code', 'address', 'city_name', 'postal_code', 'national_code'
        extra_kwargs = {
            'password':{'write_only':True}
        }

    def validate_password(self, value):
        if not re.search(r'[A-Z]', value):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'\d', value):
            raise ValidationError("Password must contain at least one digit.")
        return value

    def create(self,validated_data):
        password = validated_data.pop('password',None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
    
    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.national_code = validated_data.get('national_code', instance.national_code)
        instance.client_id = validated_data.get('client_id', instance.client_id)
        password = validated_data.get('password', None)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

    def get_password(self, obj):
        return None

class FormSerializers(serializers.ModelSerializer):
    header = serializers.SerializerMethodField()
    body = serializers.SerializerMethodField()
    payment = serializers.SerializerMethodField()

    def get_header(self, obj):
        return {
            "taxid": obj.taxid,
            "indatim": obj.indatim,
            "indati2m": obj.indati2m,
            "inty": obj.inty,
            "inno" : obj.inno,
            "irtaxid" : obj.irtaxid,
            "inp": obj.inp,
            "ins" : obj.ins,
            "tins" : obj.tins,
            "tob" : obj.tob,
            "bid" : obj.bid,
            "tinb" : obj.tinb,
            "sbc" : obj.sbc,
            "bpc" : obj.bpc,
            "bbc" : obj.bbc,
            "ft" : obj.ft,
            "bpn" : obj.bpn,
            "scln" : obj.scln,
            "scc" : obj.scc,
            "crn" : obj.crn,
            "billid" : obj.billid,
            "tprdis" : obj.tprdis,
            "tdis" : obj.tdis,
            "tadis" : obj.tadis,
            "tvam" : obj.tvam,
            "todam" : obj.todam,
            "tbill" : obj.tbill,
            "setm" : obj.setm,
            "cap" : obj.cap,
            "insp" : obj.insp,
            "tvop" : obj.tvop,
            "tax17" : obj.tax17,
            "cdcn" : obj.cdcn , 
            "cdcd" : obj.cdcd,
            "tonw" : obj.tonw,
            "torv" : obj.torv,
            "tocv" : obj.tocv
        }

    def get_body(self, obj):
        return {
            "sstid" : obj.sstid,
            "sstt" : obj.sstt ,
            "mu" : obj.mu,
            "am" : obj.am,
            "fee" : obj.fee,
            "cfee" : obj.cfee,
            "cut" : obj.cut,
            "exr" : obj.exr,
            "prdis" : obj.prdis,
            "dis" : obj.dis,
            "adis" : obj.adis,
            "vra" : obj.vra,
            "vam" : obj.vam,
            "odt" : obj.odt,
            "odr" : obj.odr,
            "odam" : obj.odam,
            "olt" : obj.olt,
            "olr" : obj.olr,
            "olam" : obj.olam,
            "consfee" : obj.consfee,
            "spro" : obj.spro,
            "bros" : obj.bros,
            "tcpbs" : obj.tcpbs,
            "cop" : obj.cop,
            "vop" : obj.vop,
            "bsrn" : obj.bsrn,
            "tsstam" : obj.tsstam,
            "nw" : obj.nw,
            "ssrv" : obj.ssrv,
            "sscv" : obj.sscv
        }
    def get_payment(self,obj):
        return {
            "iinn" : obj.iinn,
            "acn" : obj.acn,
            "trmn" : obj.trmn,
            "trn" : obj.trn,
            "pcn" : obj.pcn,
            "pid" : obj.pid,
            "pdt" : obj.pdt,
            "pmt" : obj.pmt, 
            "pv" : obj.pv
        }

    class Meta:
        model = Bill
        fields = ['cdcn' ,'taxid','indatim', 'indati2m','inno','irtaxid','inty','inp','ins','tins','tinb','tob','sbc','bid','bpc','bbc', 'bpn','ft', 'scln', 'scc','crn', 'sstid','sstt', 'mu','am','fee', 'cfee', 'cut', 'exr', 'iinn','acn','trmn','trn', 'pcn', 'pid', 'billid','prdis','dis', 'adis','vra','vam','odt','odr', 'odam', 'olt', 'olr','olam','consfee', 'spro', 'bros', 'tcpbs','cop', 'vop','bsrn','setm','tsstam','tprdis','tdis', 'tadis', 'tvam', 'todam','tbill','tvop','cap','insp','tax17','pdt', 'cdcd' ,'tonw' ,'torv' ,'tocv' ,'nw' ,'ssrv' ,'sscv','pmt' , 'pv','sendtime','uuid','refrenceid','status' ,'header','body','payment']

class FormHistorySeralizer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    class Meta:
        model = Bill
        fields = ['id','taxid','indatim', 'indati2m','inno','irtaxid','inty','inp','ins','tins','tinb','tob','sbc','bid','bpc','bbc', 'bpn','ft', 'scln', 'scc','crn', 'sstid','sstt', 'mu','am','fee', 'cfee', 'cut', 'exr', 'iinn','acn','trmn','trn', 'pcn', 'pid', 'billid','prdis','dis', 'adis','vra','vam','odt','odr', 'odam', 'olt', 'olr','olam','consfee', 'spro', 'bros', 'tcpbs','cop', 'vop','bsrn','setm','tsstam','tprdis','tdis', 'tadis', 'tvam', 'todam','tbill','tvop','cap','insp','tax17','pdt', 'cdcd' ,'tonw' ,'torv' ,'tocv' ,'nw' ,'ssrv' ,'sscv','pmt' , 'pv','cdcn','sendtime','uuid','refrenceid','status','error']

# class FormHistorySeralizer(serializers.ModelSerializer):
#     id = serializers.ReadOnlyField()

#     class Meta:
#         model = BillHistory
#         fields = ['id','taxid','sendtime','uuid','refrenceid']

class ForgetPasswordSerializer(serializers.Serializer):
    national_code = serializers.IntegerField(required=True)
    new_password = serializers.CharField(required=True)
    repeat_new_password = serializers.CharField(required=True)


