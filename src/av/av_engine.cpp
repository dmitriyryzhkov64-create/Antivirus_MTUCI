#include "av_engine.h"

#include <fstream>
#include <vector>
#include <filesystem>

static uint64_t ReadPrefixFromBuffer(
    const std::vector<unsigned char>& data,
    size_t position)
{
    uint64_t prefix = 0;

    for (size_t i = 0; i < 8; ++i)
    {
        prefix |= static_cast<uint64_t>(data[position + i]) << (i * 8);
    }

    return prefix;
}

static std::vector<unsigned char> SimpleHashBytes(
    const std::vector<unsigned char>& data,
    size_t position,
    size_t length)
{
    uint32_t hash = 2166136261u;

    for (size_t i = 0; i < length; ++i)
    {
        hash ^= data[position + i];
        hash *= 16777619u;
    }

    return {
        static_cast<unsigned char>((hash >> 0) & 0xFF),
        static_cast<unsigned char>((hash >> 8) & 0xFF),
        static_cast<unsigned char>((hash >> 16) & 0xFF),
        static_cast<unsigned char>((hash >> 24) & 0xFF)
    };
}

AvEngine::AvEngine(const AvDatabase* database)
    : database_(database)
{
}

AvObjectType AvEngine::DetectObjectType(const std::wstring& filePath)
{
    std::filesystem::path path(filePath);
    std::wstring ext = path.extension().wstring();

    if (_wcsicmp(ext.c_str(), L".exe") == 0 ||
        _wcsicmp(ext.c_str(), L".dll") == 0)
    {
        return AvObjectType::PE;
    }

    if (_wcsicmp(ext.c_str(), L".js") == 0)
    {
        return AvObjectType::JavaScript;
    }

    return AvObjectType::Unknown;
}

bool AvEngine::ScanBuffer(
    const std::vector<unsigned char>& data,
    AvObjectType objectType,
    std::wstring* threatName)
{
    if (!database_ || !database_->IsLoaded())
    {
        return false;
    }

    if (data.size() < 8)
    {
        return false;
    }

    const auto& records = database_->GetRecords();

    size_t position = 0;

    while (position + 8 <= data.size())
    {
        uint64_t prefix = ReadPrefixFromBuffer(data, position);

        auto it = records.find(prefix); // std::map => O(log N)

        if (it == records.end())
        {
            ++position;
            continue;
        }

        for (const auto& record : it->second)
        {
            if (record.objectType != objectType)
            {
                continue;
            }

            if (position < record.offsetBegin || position > record.offsetEnd)
            {
                continue;
            }

            if (record.objectSignatureLength < 8)
            {
                continue;
            }

            if (position + record.objectSignatureLength > data.size())
            {
                continue;
            }

            auto calculatedHash = SimpleHashBytes(
                data,
                position,
                record.objectSignatureLength
            );

            if (calculatedHash == record.objectSignatureHash)
            {
                if (threatName)
                {
                    *threatName = record.threatName;
                }

                return true;
            }
        }

        ++position;
    }

    return false;
}

AvScanResult AvEngine::ScanFile(const std::wstring& filePath)
{
    AvScanResult result{};
    result.objectPath = filePath;
    result.scannedFiles = 1;

    AvObjectType objectType = DetectObjectType(filePath);

    if (objectType == AvObjectType::Unknown)
    {
        return result;
    }

    std::ifstream file(filePath, std::ios::binary);

    if (!file)
    {
        return result;
    }

    std::vector<unsigned char> data(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );

    std::wstring threatName;

    if (ScanBuffer(data, objectType, &threatName))
    {
        result.isMalicious = true;
        result.detectedThreats = 1;
        result.threatName = threatName;
    }

    return result;
}

AvScanResult AvEngine::ScanDirectory(const std::wstring& directoryPath)
{
    AvScanResult summary{};
    summary.objectPath = directoryPath;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             directoryPath,
             std::filesystem::directory_options::skip_permission_denied))
    {
        if (!entry.is_regular_file())
        {
            continue;
        }

        AvScanResult fileResult = ScanFile(entry.path().wstring());

        summary.scannedFiles += fileResult.scannedFiles;
        summary.detectedThreats += fileResult.detectedThreats;

        if (fileResult.isMalicious && !summary.isMalicious)
        {
            summary.isMalicious = true;
            summary.threatName = fileResult.threatName;
            summary.objectPath = fileResult.objectPath;
        }
    }

    return summary;
}