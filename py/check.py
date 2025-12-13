import firebase_admin
from firebase_admin import credentials
cred = credentials.Certificate("/home/radzi/dev/HIS-id-private-key/his-id-firebase-adminsdk-8q15k-d07ebf5034.json")
firebase_admin.initialize_app(cred)

