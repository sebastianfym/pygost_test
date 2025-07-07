import os
from pygost import gost3410
from pygost import gost34112012512, gost34112012256
from pygost.gost3410 import CURVES
from pygost.gost3410 import pub_unmarshal
from pygost.gost3410 import verify
from asn1crypto import cms


# Пути к файлам
pdffile = os.path.join(os.path.dirname(__file__), "filename.pdf")
sigfile = os.path.join(os.path.dirname(__file__), "filename.sig")

curve = CURVES["id-tc26-gost-3410-12-256-paramSetA"]
# curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
# curve = CURVES["id-tc26-gost-3410-2012-256-paramSetC"]
# curve = CURVES["id-tc26-gost-3410-2012-256-paramSetD"]

with open(sigfile, 'rb') as f:
    sig_data = f.read()

# Читаем PDF-файл в бинарном режиме
with open(pdffile, 'rb') as f:
    pdf_data = f.read()

cms_info = cms.ContentInfo.load(sig_data)
content_type = cms_info['content_type'].native

signed_data = cms_info['content']

digest_algorithm = signed_data['digest_algorithms'][0]['algorithm'].native
print(f"Алгоритм дайджеста: {digest_algorithm}")

certificate = signed_data['certificates'][0].chosen
public_key_info = certificate['tbs_certificate']['subject_public_key_info']
public_key_algorithm = public_key_info['algorithm']['algorithm'].native
public_key_bytes = public_key_info['public_key'].native

pub = pub_unmarshal(public_key_bytes)

# Вычисляем хеш PDF-файла с помощью Стрибога
dgst = gost34112012256.new(pdf_data).digest()

# Читаем подпись из файла .sig в бинарном режиме
signer_info = signed_data['signer_infos'][0]
signature = signer_info['signature'].native

print(f"pub::: {pub}")
print(f"dgst::: {dgst}")
print(f"dgst (hex): {dgst.hex()}")
print(f"curve::: {curve}")
print(f"signature::: {signature}")
print(f"signature (hex): {signature.hex()}")


# Проверяем подпись
result = verify(curve, pub, dgst, signature)
print(f"Подпись верна: {result}")