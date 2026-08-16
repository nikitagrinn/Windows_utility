#include "PasteImage.h"
#include <windows.h>
#include <atlimage.h>
#include <wincodec.h>
#include "Utils/FileSystem/FileSystemUtils.h"

#pragma comment(lib, "windowscodecs.lib")

void PasteImage(const std::wstring& folderPath) {
    if (!OpenClipboard(NULL)) return;
    HBITMAP hBitmap = (HBITMAP)GetClipboardData(CF_BITMAP);
    if (hBitmap) {
        std::wstring targetDir = folderPath;
        if (!targetDir.empty() && targetDir.back() != L'\\') targetDir += L'\\';
        std::wstring finalPath = targetDir + L"screenshot.png";
        for (int i = 2; FileExists(finalPath); ++i)
            finalPath = targetDir + L"screenshot (" + std::to_wstring(i) + L").png";

        IWICImagingFactory*    pFactory   = nullptr;
        IWICBitmap*            pWicBitmap = nullptr;
        IWICStream*            pStream    = nullptr;
        IWICBitmapEncoder*     pEncoder   = nullptr;
        IWICBitmapFrameEncode* pFrame     = nullptr;
        IPropertyBag2*         pProps     = nullptr;

        bool saved = false;
        if (SUCCEEDED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFactory))) &&
            SUCCEEDED(pFactory->CreateBitmapFromHBITMAP(hBitmap, nullptr, WICBitmapIgnoreAlpha, &pWicBitmap)) &&
            SUCCEEDED(pFactory->CreateStream(&pStream)) &&
            SUCCEEDED(pStream->InitializeFromFilename(finalPath.c_str(), GENERIC_WRITE)) &&
            SUCCEEDED(pFactory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &pEncoder)) &&
            SUCCEEDED(pEncoder->Initialize(pStream, WICBitmapEncoderNoCache)) &&
            SUCCEEDED(pEncoder->CreateNewFrame(&pFrame, &pProps)))
        {
            PROPBAG2 opt = {};
            opt.pstrName = const_cast<LPOLESTR>(L"CompressionQuality");
            VARIANT val  = {}; val.vt = VT_R4; val.fltVal = 0.0f;
            pProps->Write(1, &opt, &val);
            UINT w = 0, h = 0;
            pWicBitmap->GetSize(&w, &h);
            WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR;
            if (SUCCEEDED(pFrame->Initialize(pProps)) &&
                SUCCEEDED(pFrame->SetSize(w, h)) &&
                SUCCEEDED(pFrame->SetPixelFormat(&fmt)) &&
                SUCCEEDED(pFrame->WriteSource(pWicBitmap, nullptr)) &&
                SUCCEEDED(pFrame->Commit()) &&
                SUCCEEDED(pEncoder->Commit()))
                saved = true;
        }
        if (pProps)     pProps->Release();
        if (pFrame)     pFrame->Release();
        if (pEncoder)   pEncoder->Release();
        if (pStream)    pStream->Release();
        if (pWicBitmap) pWicBitmap->Release();
        if (pFactory)   pFactory->Release();
        if (!saved) { CImage img; img.Attach(hBitmap); img.Save(finalPath.c_str(), Gdiplus::ImageFormatPNG); img.Detach(); }
    }
    CloseClipboard();
}
