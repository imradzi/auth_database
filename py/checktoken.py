#!/usr/bin/env python3

import sys
import firebase_admin
from firebase_admin import credentials, initialize_app, auth
cred = credentials.Certificate(sys.argv[1])
app = firebase_admin.initialize_app(cred)
inputToken = input()
decoded = auth.verify_id_token(inputToken, app)
#print(decoded)
print(decoded['email'])
# google_account_credential="/home/radzi/dev/HIS-id-private-key/his-id-firebase-adminsdk-8q15k-d07ebf5034.json"

