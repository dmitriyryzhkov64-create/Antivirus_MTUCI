#pragma once

#include <map>
#include <vector>
#include <string>
#include <cstdint>

#include "av_object_type.h"

struct AvSignatureRecord
{
    uint64_t objectSignaturePrefix = 0;
    uint32_t objectSignatureLength = 0;
    std::vector<unsigned char> objectSignatureHash;
    uint64_t offsetBegin = 0;
    uint64_t offsetEnd = 0;
    AvObjectType objectType = AvObjectType::Unknown;
    std::vector<unsigned char> avRecordSignature;
    std::wstring threatName;
};

class AvDatabase
{
public:
    void LoadMockDatabase();

    bool IsLoaded() const;
    size_t GetRecordCount() const;
    std::wstring GetReleaseDate() const;

    const std::map<uint64_t, std::vector<AvSignatureRecord>>& GetRecords() const;

private:
    bool loaded_ = false;
    std::wstring releaseDate_;
    std::map<uint64_t, std::vector<AvSignatureRecord>> records_;
};