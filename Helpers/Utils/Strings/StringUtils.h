#pragma once
#include <string>

bool IsExcludedExtension(const wchar_t* filename);
bool CleanHexArrays(const char* src, size_t len, std::string& result);
