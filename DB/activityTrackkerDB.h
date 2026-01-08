#pragma once
#include "net.h"
#include "rDb.h"
#include <vector>
#include <filesystem>

#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

class ActivityTrackkerDB : public DB::SQLiteBase {
public:
    static std::string APPNAME;
    static std::string OWNER_EMAIL;
    static std::string OWNER_NAME;
    static std::string OWNER_PHONE;
    static std::string HOSTNAME;
    static std::string MASTERDB;
    static std::string TRANSDB;
    static int PORT_NO;

protected:
    std::vector<DB::DBObjects> objectList() const override;

public:
    ActivityTrackkerDB(const std::string& path, const std::string& name);
    ActivityTrackkerDB(const std::string& fullPath);
    virtual ~ActivityTrackkerDB();
    void CheckStructure() override;

public:
    std::string GetApplicationName() { return GetKey<std::string>("applicationName", APPNAME); }
    void SetApplicationName(const std::string& name) { SetKey("applicationName", name); }
};
