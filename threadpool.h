#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <windows.h>
#include <queue>
#include <functional>
#include <vector>

#define MAX_WORKERS 4

class ThreadPool {
private:
    HANDLE workers[MAX_WORKERS];
    HANDLE workEvent;
    CRITICAL_SECTION queueLock;
    std::queue<std::function<void()>> tasks;
    bool running = true;
    bool initialized = false;
    
    static DWORD WINAPI WorkerProc(LPVOID param) {
        ThreadPool* pool = (ThreadPool*)param;
        while (pool->running) {
            WaitForSingleObject(pool->workEvent, INFINITE);
            
            if (!pool->running) break;

            std::function<void()> task;
            bool hasTask = false;

            EnterCriticalSection(&pool->queueLock);
            if (!pool->tasks.empty()) {
                task = pool->tasks.front();
                pool->tasks.pop();
                hasTask = true;
            }
            LeaveCriticalSection(&pool->queueLock);
            
            if (hasTask && task) {
                try {
                    task();
                } catch (...) {
                    // Task hatasi, pool calismaya devam etmeli
                }
            }
        }
        return 0;
    }
    
    ThreadPool() {
        InitializeCriticalSection(&queueLock);
        workEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    }

public:
    static ThreadPool& Instance() {
        static ThreadPool instance;
        return instance;
    }
    
    void Initialize() {
        if (initialized) return;
        
        running = true;
        for (int i = 0; i < MAX_WORKERS; i++) {
            workers[i] = CreateThread(NULL, 0, WorkerProc, this, 0, NULL);
        }
        initialized = true;
    }
    
    void Submit(std::function<void()> task) {
        if (!initialized) Initialize();

        EnterCriticalSection(&queueLock);
        tasks.push(task);
        LeaveCriticalSection(&queueLock);
        SetEvent(workEvent);
    }
    
    void Shutdown() {
        running = false;
        // Tum workerlari uyandir
        for (int i = 0; i < MAX_WORKERS * 2; i++) {
            SetEvent(workEvent);
        }
        WaitForMultipleObjects(MAX_WORKERS, workers, TRUE, 2000);
        
        CloseHandle(workEvent);
        DeleteCriticalSection(&queueLock);
        
        for(int i=0; i<MAX_WORKERS; i++) {
            if(workers[i]) CloseHandle(workers[i]);
        }
    }
};

// Singleton erisimi icin makro
#define POOL ThreadPool::Instance()

#endif // THREADPOOL_H
