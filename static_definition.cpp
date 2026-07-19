#include "auth_database.pb.h"
#include "auth_database.grpc.pb.h"
#include "authDB.h"
#include "activityTrackkerDB.h"

std::string ActivityTrackkerDB::APPNAME = "RPS Pharmacy Online";
std::string ActivityTrackkerDB::HOSTNAME = "demo.pharmapos.com";
int ActivityTrackkerDB::PORT_NO = 33001;
std::string ActivityTrackkerDB::MASTERDB = "Pharmacy.sqlite3db";
std::string ActivityTrackkerDB::TRANSDB = "Pharmacy.sqlite3db-transactions";
std::string ActivityTrackkerDB::OWNER_EMAIL = "imradzi@gmail.com";
std::string ActivityTrackkerDB::OWNER_NAME = "Mohd Radzi Ibrahim";
std::string ActivityTrackkerDB::OWNER_PHONE = "0199581105";
