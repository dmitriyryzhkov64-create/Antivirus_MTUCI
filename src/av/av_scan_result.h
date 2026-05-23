#pragma once
#include <string>

struct AvScanResult
{
    bool isMalicious = false;
    std::wstring objectPath;
    std::wstring threatName;
    unsigned long long scannedFiles = 0;
    unsigned long long detectedThreats = 0;
};