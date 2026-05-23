#pragma once

#include <string>
#include <vector>

#include "av_database.h"
#include "av_scan_result.h"

class AvEngine
{
public:
    explicit AvEngine(const AvDatabase* database);

    AvScanResult ScanFile(const std::wstring& filePath);
    AvScanResult ScanDirectory(const std::wstring& directoryPath);

private:
    const AvDatabase* database_;

    AvObjectType DetectObjectType(const std::wstring& filePath);

    bool ScanBuffer(
        const std::vector<unsigned char>& data,
        AvObjectType objectType,
        std::wstring* threatName
    );
};