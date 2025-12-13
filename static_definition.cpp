#include "auth_database.pb.h"
#include "auth_database.grpc.pb.h"
#include "authDB.h"
#include "activityTrackkerDB.h"

std::string AuthorizationDB::default_google_credential_file = "/home/radzi/dev/firebase_keys/RPS-Online-private-key/rps-pharmacy-online-firebase-adminsdk-iodfm-5d491c41db.json";

std::string ActivityTrackkerDB::APPNAME = "RPS Pharmacy Online";
std::string ActivityTrackkerDB::HOSTNAME = "demo.pharmapos.com";
int ActivityTrackkerDB::PORT_NO = 33001;
std::string ActivityTrackkerDB::MASTERDB = "Pharmacy.sqlite3db";
std::string ActivityTrackkerDB::TRANSDB = "Pharmacy.sqlite3db-transactions";
std::string ActivityTrackkerDB::OWNER_EMAIL = "imradzi@gmail.com";
std::string ActivityTrackkerDB::OWNER_NAME = "Mohd Radzi Ibrahim";
std::string ActivityTrackkerDB::OWNER_PHONE = "0199581105";
