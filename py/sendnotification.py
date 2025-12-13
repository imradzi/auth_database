#!/usr/bin/env python3

# cred, token, title
import sys
import firebase_admin
from firebase_admin import credentials, initialize_app, auth, messaging
cred = credentials.Certificate(sys.argv[1])
app = firebase_admin.initialize_app(cred)


deviceToken = input()
ttl = input()
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
