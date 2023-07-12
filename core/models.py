from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


class User(AbstractUser):
    username = models.CharField(max_length=255,unique=True)
    password = models.CharField(max_length=255)
    first_name = models.CharField(max_length=255,null=True)
    last_name = models.CharField(max_length=255,null=True)
    national_code = models.BigIntegerField(null=True,unique=True)
    client_id = models.CharField(max_length=255,null = True)
    private_key = models.CharField(max_length=25000,null= True) 
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

# class Dashboard(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
#     moadiusername = models.CharField(max_length=255)
#     privatekey = models.CharField(max_length=25000)

class Subscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(max_length=20, choices=(
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('canceled', 'Canceled'),
    ))
    invoice_count = models.PositiveIntegerField(default=0)
    def save(self, *args, **kwargs):
        # Check if the subscription has reached the end_date
        if self.end_date <= timezone.now().date():
            self.status = 'expired'

        super().save(*args, **kwargs)


class Bill(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    taxid = models.CharField(max_length=255,null=True,blank=True,default="A16G7G04C4800094238B64")
    indatim = models.BigIntegerField(null=True,blank=True,default=0)
    indati2m = models.BigIntegerField(null=True,blank=True,default=0)
    # indatish = jmodels.jDateTimeField(auto_now_add=True)
    # indati2sh = jmodels.jDateTimeField(auto_now_add=True)
    inno = models.CharField(max_length=255,null=True,blank=True,default="00094238B6")
    irtaxid = models.CharField(max_length=255,null=True,blank=True ,default="A16G7G04C4800094238B64")
    inty = models.PositiveIntegerField(null=True,blank=True,default="")
    inp = models.PositiveIntegerField(null=True,blank=True,default=0)
    ins = models.PositiveIntegerField(null=True,blank=True,default=0)
    tins = models.CharField(max_length=255,null=True,blank=True,default="")
    tinb = models.CharField(max_length=255,null=True,blank=True ,default="")
    tob = models.PositiveIntegerField(null=True,blank=True,default=0)
    sbc =  models.CharField(max_length=255,null=True,blank=True ,default="")
    bid = models.CharField(max_length=255,null=True,blank=True ,default="00000000000")
    bpc = models.CharField(max_length=255,null=True,blank=True ,default="0000000000")
    bbc = models.CharField(max_length=255,null=True,blank=True ,default="")
    bpn = models.CharField(max_length=255,null=True,blank=True ,default="a12345678")
    ft = models.PositiveIntegerField(null=True,blank=True,default=1)
    scln = models.CharField(max_length=255,null=True,blank=True ,default="")
    scc = models.CharField(max_length=255,null=True,blank=True ,default="00000")
    crn = models.CharField(max_length=255,null=True,blank=True ,default="")
    sstid = models.CharField(max_length=255,null=True,blank=True,default="")
    sstt = models.CharField(max_length=255,null=True,blank=True,default="")
    mu = models.CharField(max_length=255,null=True,blank=True,default="1628")
    am = models.FloatField(null=True,blank=True,default=0)
    fee = models.FloatField(null=True,blank=True,default=0)
    cfee = models.FloatField(null=True,blank=True,default=0.1)
    cut = models.CharField(max_length=255,null=True,blank=True,default="XXX")
    exr = models.FloatField(null=True,blank=True,default=1)
    iinn = models.CharField(max_length=255,null=True,blank=True,default="000000000")
    acn = models.CharField(max_length=255,null=True,blank=True,default="00000000000000")
    trmn = models.CharField(max_length=255,null=True,blank=True,default="00000000")
    trn = models.CharField(max_length=255,null=True,blank=True,default="")
    pcn = models.CharField(max_length=255,null=True,blank=True,default="0000000000000000")
    pid = models.CharField(max_length=255,null=True,blank=True,default="")
    pdt = models.BigIntegerField(null=True,blank=True,default=1000000000000)
    billid = models.CharField(max_length=255,null=True,blank=True ,default="")  
    prdis = models.BigIntegerField(null=True,blank=True,default=0)
    dis = models.FloatField(null=True,blank=True,default=0)
    adis = models.FloatField(null=True,blank=True,default=0)
    vra = models.FloatField(null=True,blank=True,default=0)
    vam = models.FloatField(null=True,blank=True,default=0)
    odt = models.CharField(max_length=255,null=True,blank=True ,default="")
    odr = models.FloatField(null=True,blank=True,default=0)
    odam = models.FloatField(null=True,blank=True,default=0)
    olt = models.CharField(max_length=255,null=True,blank=True ,default="")
    olr = models.FloatField(null=True,blank=True,default=0)
    olam = models.FloatField(null=True,blank=True,default=0)
    consfee = models.FloatField(null=True,blank=True,default=0)
    spro = models.FloatField(null=True,blank=True,default=0)
    bros = models.FloatField(null=True,blank=True,default=0)
    tcpbs = models.FloatField(null=True,blank=True,default=0)
    cop = models.FloatField(null=True,blank=True,default=0)
    vop = models.FloatField(null=True,blank=True,default=0)
    bsrn = models.CharField(max_length=255,null=True,blank=True ,default="")
    setm = models.PositiveIntegerField(null=True,blank=True,default=0)
    tsstam = models.BigIntegerField(null=True,blank=True,default=0)
    tprdis = models.BigIntegerField(null=True,blank=True,default=0)
    tdis = models.FloatField(null=True,blank=True,default=0)
    tadis = models.BigIntegerField(null=True,blank=True,default=0)
    tvam = models.FloatField(null=True,blank=True,default=0)
    todam = models.FloatField(null=True,blank=True,default=0)
    tbill = models.FloatField(null=True,blank=True,default=0)
    tvop =models.FloatField(null=True,blank=True,default=0)
    cap = models.FloatField(null=True,blank=True,default=0)
    insp = models.FloatField(null=True,blank=True,default=0)
    tax17 = models.FloatField(null=True,blank=True,default=0)
    cdcn = models.CharField(max_length=255,null=True,blank=True,default="")
    cdcd = models.BigIntegerField(null=True,blank=True,default=10000)
    tonw = models.FloatField(null=True,blank=True,default=1)
    torv = models.FloatField(null=True,blank=True,default=1)
    tocv = models.FloatField(null=True,blank=True,default=1)
    nw = models.FloatField(null=True,blank=True,default=1)
    ssrv = models.FloatField(null=True,blank=True,default=1)
    sscv = models.FloatField(null=True,blank=True,default=1)
    pmt = models.PositiveIntegerField(null=True,blank=True,default=8)
    pv = models.BigIntegerField(null=True,blank=True,default=0)
    uuid = models.CharField(max_length=255,null=True)
    refrenceid = models.CharField(max_length=255,null=True)
    sendtime = models.CharField(max_length=255,null=True)
    status = models.CharField(max_length=25,null=True)
    error = models.CharField(max_length=2555,null=True)
    


# class BillHistory(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
#     uuid = models.CharField(max_length=255)
#     refrenceid = models.CharField(max_length=255)
#     taxid = models.CharField(max_length=255)
#     sendtime = models.CharField(max_length=255)

