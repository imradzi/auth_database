
#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#ifdef _WIN32
#include "winsock2.h"
#endif

#ifdef __clang__
#if __has_warning("-Wdeprecated-enum-enum-conversion")
#pragma clang diagnostic ignored "-Wdeprecated-enum-enum-conversion"  // warning: bitwise operation between different enumeration types ("XXXFlags_" and "XXXFlagsPrivate_") is deprecated
#endif
#endif

#ifdef __WX__
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif
#include "wx/tokenzr.h"
#endif
#ifdef _USEPOSTGRESQL
#undef _USEPOSTGRESQL
#endif
#include "authDB.h"
#include "activityTrackkerDB.h"
#include <boost/tokenizer.hpp>

ActivityTrackkerDB::ActivityTrackkerDB(const std::string& path, const std::string& name) : DB::SQLiteBase(AuthorizationDB::GetFullName(path, name)) {}
ActivityTrackkerDB::ActivityTrackkerDB(const std::string& fullPath) : DB::SQLiteBase(fullPath) {}
ActivityTrackkerDB::~ActivityTrackkerDB() {
    Close();
}
