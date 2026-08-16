#include "StringUtils.h"
#include <windows.h>

bool IsExcludedExtension(const wchar_t* filename) {
    const wchar_t* dot = wcsrchr(filename, L'.');
    if (!dot) return false;
    static const wchar_t* const kExts[] = {
        L".bin",  L".bmp",   L".db",    L".dll",  L".exe",
        L".filters", L".gif",L".ipch",  L".iso",  L".jpg",
        L".jpeg", L".lib",   L".ncb",   L".obj",  L".opensdf",
        L".pdb",  L".png",   L".sdf",   L".sqlite",L".sln",
        L".suo",  L".tlog",  L".user",  L".vcxproj"
    };
    for (auto e : kExts)
        if (_wcsicmp(dot, e) == 0) return true;
    return false;
}

bool CleanHexArrays(const char* src, size_t len, std::string& result) {
    if (len > 500000) return false;

    bool found = false;
    const char* p = src;
    const char* end = src + len;
    while (p + 1 < end) {
        p = (const char*)memchr(p, '=', end - p);
        if (!p) break;
        if (p + 1 < end && p[1] == '{') { found = true; break; }
        if (p + 2 < end && p[1] == ' ' && p[2] == '{') { found = true; break; }
        ++p;
    }
    if (!found) return false;

    result.clear();
    result.reserve(len);

    const char* cur = src;

    while (cur < end) {
        const char* eq = (const char*)memchr(cur, '=', (size_t)(end - cur));
        if (!eq) { result.append(cur, end); break; }

        result.append(cur, (size_t)(eq - cur));
        cur = eq;

        const char* s = eq + 1;
        while (s < end && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) ++s;

        if (s >= end || *s != '{') { result += *cur++; continue; }
        ++s;

        const char* bodyStart = s;
        int  count = 0;
        bool valid = true;
        while (s < end) {
            unsigned char c = (unsigned char)*s;
            if (c == '}') break;
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
                c == 'x' || c == 'X'  || c == ',' ||
                c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++count; ++s;
            } else { valid = false; break; }
        }

        if (!valid || s >= end || *s != '}') { result += *cur++; continue; }
        ++s; 
        if (s >= end || *s != ';')           { result += *cur++; continue; }
        ++s; 

        if (count >= 50) {
            result += "= { /* HEX DATA HIDDEN */ };";
            cur = s;
        } else {
            result += *cur++;
        }
    }

    return true;
}
