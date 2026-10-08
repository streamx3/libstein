// SPDX-License-Identifier: MIT
#include "stein/platform/device_watcher.hpp"

#include <windows.h>
#include <dbt.h>
#include <initguid.h>
#include <ntddstor.h>

#include <condition_variable>
#include <mutex>
#include <thread>

namespace stein::platform {

namespace {

class WinDeviceWatcher final : public DeviceWatcher {
public:
    explicit WinDeviceWatcher(Callback cb) : m_callback(std::move(cb)) {}
    ~WinDeviceWatcher() override { stop(); }

    Expected<void> start() {
        m_thread = std::thread([this] { run(); });
        std::unique_lock lock(m_mutex);
        m_ready.wait(lock, [this] { return m_started; });
        if (!m_hwnd) {
            m_thread.join();
            return fail(ErrorCategory::Internal, "could not create the device notification window");
        }
        return {};
    }

    void stop() override {
        HWND h = nullptr;
        {
            std::lock_guard lock(m_mutex);
            h = m_hwnd;
            m_hwnd = nullptr;
        }
        if (h) PostMessageW(h, WM_CLOSE, 0, 0);
        if (m_thread.joinable()) m_thread.join();
    }

private:
    static LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        auto* self = reinterpret_cast<WinDeviceWatcher*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_DEVICECHANGE && self) {
            std::string name;
            if (lParam) {
                auto* hdr = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
                if (hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                    auto* di = reinterpret_cast<DEV_BROADCAST_DEVICEINTERFACE_W*>(lParam);
                    const int n = WideCharToMultiByte(CP_UTF8, 0, di->dbcc_name, -1, nullptr, 0, nullptr, nullptr);
                    if (n > 1) {
                        name.resize(static_cast<std::size_t>(n - 1));
                        WideCharToMultiByte(CP_UTF8, 0, di->dbcc_name, -1, name.data(), n, nullptr, nullptr);
                    }
                }
            }
            switch (wParam) {
            case DBT_DEVICEARRIVAL: self->emit({DeviceEvent::Kind::Appeared, name}); break;
            case DBT_DEVICEREMOVECOMPLETE: self->emit({DeviceEvent::Kind::Disappeared, name}); break;
            case DBT_DEVNODES_CHANGED: self->emit({DeviceEvent::Kind::Changed, name}); break;
            default: break;
            }
            return TRUE;
        }
        if (msg == WM_CLOSE) {
            DestroyWindow(hwnd);
            return 0;
        }
        if (msg == WM_DESTROY) {
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    void emit(const DeviceEvent& e) {
        if (m_callback) m_callback(e);
    }

    void run() {
        WNDCLASSW wc{};
        wc.lpfnWndProc = wndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"stein.device.watcher";
        RegisterClassW(&wc);
        HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
        HDEVNOTIFY disk = nullptr, volume = nullptr;
        if (hwnd) {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
            DEV_BROADCAST_DEVICEINTERFACE_W filter{};
            filter.dbcc_size = sizeof filter;
            filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
            filter.dbcc_classguid = GUID_DEVINTERFACE_DISK;
            disk = RegisterDeviceNotificationW(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
            filter.dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
            volume = RegisterDeviceNotificationW(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
        }
        {
            std::lock_guard lock(m_mutex);
            m_hwnd = hwnd;
            m_started = true;
        }
        m_ready.notify_all();
        if (!hwnd) return;
        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (disk) UnregisterDeviceNotification(disk);
        if (volume) UnregisterDeviceNotification(volume);
    }

    Callback m_callback;
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_ready;
    HWND m_hwnd = nullptr;
    bool m_started = false;
};

} // namespace

Expected<std::unique_ptr<DeviceWatcher>> DeviceWatcher::create(Callback callback) {
    auto w = std::make_unique<WinDeviceWatcher>(std::move(callback));
    if (auto r = w->start(); !r) return fail(r.error());
    return std::unique_ptr<DeviceWatcher>(std::move(w));
}

} // namespace stein::platform
