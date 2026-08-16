#pragma once
#include <windows.h>
#include <deque>
#include <mutex>
#include <condition_variable>

struct OutBuf {
    HANDLE h   = INVALID_HANDLE_VALUE;
    char*  buf = nullptr;
    DWORD  cap = 0;
    DWORD  pos = 0;

    bool open(const wchar_t* path, DWORD bufSz) {
        buf = new char[bufSz];
        cap = bufSz;
        h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (h == INVALID_HANDLE_VALUE) { delete[] buf; buf = nullptr; return false; }
        return true;
    }

    __forceinline void write(const char* data, DWORD len) {
        if (len >= cap) { flush(); DWORD w; WriteFile(h, data, len, &w, NULL); return; }
        while (len > 0) {
            DWORD n = min(len, cap - pos);
            memcpy(buf + pos, data, n);
            pos += n; data += n; len -= n;
            if (pos == cap) flush();
        }
    }

    void flush() { if (pos) { DWORD w; WriteFile(h, buf, pos, &w, NULL); pos = 0; } }

    void close() {
        flush();
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
        if (buf) { delete[] buf; buf = nullptr; }
    }
    
    ~OutBuf() { close(); }
};

struct DirLevel {
    HANDLE hFind   = INVALID_HANDLE_VALUE;
    DWORD  pathEnd = 0;
    bool   first   = true;
};

template<typename T>
struct Chan {
    std::deque<T>           q;
    std::mutex              mtx;
    std::condition_variable cv_pop, cv_push;
    size_t                  cap;
    bool                    closed = false;

    explicit Chan(size_t c) : cap(c) {}

    bool send(T item) {
        std::unique_lock<std::mutex> lk(mtx);
        cv_push.wait(lk, [&]{ return q.size() < cap || closed; });
        if (closed) return false;
        q.push_back(std::move(item));
        cv_pop.notify_one();
        return true;
    }

    bool recv(T& item) {
        std::unique_lock<std::mutex> lk(mtx);
        cv_pop.wait(lk, [&]{ return !q.empty() || closed; });
        if (q.empty()) return false;
        item = std::move(q.front());
        q.pop_front();
        cv_push.notify_one();
        return true;
    }

    void close() {
        std::lock_guard<std::mutex> lk(mtx);
        closed = true;
        cv_pop.notify_all();
        cv_push.notify_all();
    }
};
