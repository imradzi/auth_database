
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
#include "activityTrackkerDB.h"

void ActivityTrackkerDB::CheckStructure() {
    DB::SQLiteBase::CheckStructure();
    auto x = GetSession().GetAutoCommitter();
    auto typeReg = DB::TypeRegistry(*this);
    auto typeId = typeReg.SetGroup("DemeritPointGroupID", "Demerit Points Group ID");
    typeReg.Set("", "01", "rambut panjang", "-5", typeId);
    typeReg.Set("", "02", "kuku panjang", "-5", typeId);

    typeId = typeReg.SetGroup("meritPointGroupID", "Merit Points Group ID");
    typeReg.Set("", "01", "solat awal waktu", "5", typeId);
    typeReg.Set("", "02", "kutip sampah", "5", typeId);

    typeId = typeReg.SetGroup("ActivityTypeGroupID", "Activity Types Group ID");
    typeReg.Set("activityType_attendance", "01", "Attendance", "", typeId);
    typeReg.Set("activityType_spotcheck", "02", "Spot Check", "demerit", typeId);
    typeReg.Set("activityType_amal", "03", "Amal", "merit", typeId);
    typeReg.Set("activityType_sales", "03", "Sales", "sales", typeId);
    x->SetOK();
}
