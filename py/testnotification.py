#!/usr/bin/env python3

# cred, token, title
import sys
import firebase_admin
from firebase_admin import credentials, initialize_app, auth, messaging
cred = credentials.Certificate("/home/radzi/dev/HIS-id-private-key/his-id-firebase-adminsdk-8q15k-d07ebf5034.json")
app = firebase_admin.initialize_app(cred)

deviceToken = "ecn_1gcnTTuitgUK2x2S7O:APA91bEp_YEFjbvbwMtkYpZkqKqBBc2px4KtBtub_Hk6uJq-_IU6EOyFKbHVdsrEiEOssG2SA_LdEmrYgMltsGZ8LKeu9AuruFbLEPN1MwHEWpuuxiF5x_aGQMl4Hay2gn35Xw26S1Mr"
ttl = "HIS Title"
messageToSend = input()

message = messaging.Message(
    notification=messaging.Notification(
        title=ttl,
        body=messageToSend
    ),
    token=deviceToken
)

response = messaging.send(message)
print(response)
