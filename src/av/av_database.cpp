#include "av_database.h"

#include <string>

static uint64_t ReadPrefix(const std::string& signature)
{
    uint64_t prefix = 0;

    for (size_t i = 0; i < 8 && i < signature.size(); ++i)
    {
        prefix |= static_cast<uint64_t>(
            static_cast<unsigned char>(signature[i])
        ) << (i * 8);
    }

    return prefix;
}

static std::vector<unsigned char> SimpleHash(const std::string& data)
{
    uint32_t hash = 2166136261u;

    for (unsigned char ch : data)
    {
        hash ^= ch;
        hash *= 16777619u;
    }

    return {
        static_cast<unsigned char>((hash >> 0) & 0xFF),
        static_cast<unsigned char>((hash >> 8) & 0xFF),
        static_cast<unsigned char>((hash >> 16) & 0xFF),
        static_cast<unsigned char>((hash >> 24) & 0xFF)
    };
}

void AvDatabase::LoadMockDatabase()
{
    records_.clear();

    {
        std::string signature = "EICAR_TEST_SIGNATURE";

        AvSignatureRecord record{};
        record.objectSignaturePrefix = ReadPrefix(signature);
        record.objectSignatureLength = static_cast<uint32_t>(signature.size());
        record.objectSignatureHash = SimpleHash(signature);
        record.offsetBegin = 0;
        record.offsetEnd = 64;
        record.objectType = AvObjectType::PE;
        record.avRecordSignature = { 0xAA, 0xBB, 0xCC };
        record.threatName = L"Test.EICAR.Mock";

        records_[record.objectSignaturePrefix].push_back(record);
    }

    {
        std::string signature = "malicious_js_payload";

        AvSignatureRecord record{};
        record.objectSignaturePrefix = ReadPrefix(signature);
        record.objectSignatureLength = static_cast<uint32_t>(signature.size());
        record.objectSignatureHash = SimpleHash(signature);
        record.offsetBegin = 0;
        record.offsetEnd = 1024 * 1024;
        record.objectType = AvObjectType::JavaScript;
        record.avRecordSignature = { 0xDD, 0xEE, 0xFF };
        record.threatName = L"Script.JS.MockThreat";

        records_[record.objectSignaturePrefix].push_back(record);
    }

    releaseDate_ = L"2026-05-23";
    loaded_ = true;
}

bool AvDatabase::IsLoaded() const
{
    return loaded_;
}

size_t AvDatabase::GetRecordCount() const
{
    size_t count = 0;

    for (const auto& item : records_)
    {
        count += item.second.size();
    }

    return count;
}

std::wstring AvDatabase::GetReleaseDate() const
{
    return releaseDate_;
}

const std::map<uint64_t, std::vector<AvSignatureRecord>>& AvDatabase::GetRecords() const
{
    return records_;
}