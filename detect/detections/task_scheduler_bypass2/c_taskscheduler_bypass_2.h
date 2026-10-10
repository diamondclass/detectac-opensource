#pragma once

#include "../../pch.h"

class c_taskscheduler_bypass_2
{
public:
    struct ExecAction {
        std::wstring command;
        std::wstring arguments;
        std::wstring workDir;
    };

    struct ComAction {
        std::wstring clsid;
        std::wstring data;
    };

    struct TaskEntry {
        std::wstring fullPath;
        std::wstring name;
        std::wstring folder;

        std::wstring state;
        std::wstring lastRunTime;
        std::wstring nextRunTime;
        std::wstring author;
        std::wstring description;
        std::wstring xml;

        std::vector<ExecAction> execActions;
        std::vector<ComAction>  comActions;
        std::vector<std::wstring> otherActions;

        std::wstring regGuid;
        std::wstring regDate;
        std::wstring regAuthor;
        std::wstring regUri;
        std::wstring regCategory;
        std::wstring regActionsBin;

        std::wstring fsPath;
        FILETIME fsCreated{};
        FILETIME fsModified{};
        DWORD    fsSize = 0;

        bool inCOM = false;
        bool inFS = false;
        bool inRegTree = false;
        bool inRegTasks = false;
    };

    struct FileRef {
        std::wstring raw;
        std::wstring resolved;
        std::wstring source;
        bool exists = false;
        bool isPE = false;
        bool isPS1 = false;
        bool isBAT = false;
        bool isCMD = false;
        bool isPY = false;
        bool isSigned = false;
        bool alwaysShow = false;
        std::wstring peType;
    };

    struct FlaggedTask {
        TaskEntry task;
        std::vector<FileRef> unsignedFiles;
    };

    static void start_taskschedule_checks();
    static std::vector<FlaggedTask> Run();
    static void PrintResults(const std::vector<FlaggedTask>& results);
    static void CheckSnowBypass(const std::map<std::wstring, TaskEntry>& tasks);

private:
    static void CollectFromCOM(std::map<std::wstring, TaskEntry>& tasks);
    static void CollectFromFilesystem(std::map<std::wstring, TaskEntry>& tasks);
    static void CollectFromLegacy();
    static void CollectFromRegistry(std::map<std::wstring, TaskEntry>& tasks,
        std::map<std::wstring, std::wstring>& guidToPath,
        std::map<std::wstring, std::wstring>& guidCategory);
    static void CollectFromSchtasks(std::map<std::wstring, TaskEntry>& tasks);

    static void EnumCOMFolder(ITaskFolder* pFolder, const std::wstring& folderPath,
        std::map<std::wstring, TaskEntry>& tasks);

    static void EnumFSDir(const std::filesystem::path& dir, const std::wstring& prefix,
        std::map<std::wstring, TaskEntry>& tasks);

    static void EnumRegTree(HKEY hParent, const std::wstring& prefix,
        std::map<std::wstring, TaskEntry>& tasks,
        std::map<std::wstring, std::wstring>& guidToPath);
    static void ReadRegTasksKey(std::map<std::wstring, TaskEntry>& tasks);
    static void ReadRegCategory(const wchar_t* cat,
        std::map<std::wstring, TaskEntry>& tasks,
        std::map<std::wstring, std::wstring>& guidToPath,
        std::map<std::wstring, std::wstring>& guidCategory);

    static bool HasValidSignature(const wchar_t* filePath);
    static std::wstring GetOriginalFilename(const std::wstring& filePath);
    static bool IsAlwaysShowFile(const std::wstring& filePath);
    static bool IsPEFile(const std::wstring& path);
    static std::wstring GetPEType(const std::wstring& path);

    static std::vector<FileRef> ExtractAllFileRefs(const TaskEntry& e);
    static void ClassifyFileRef(FileRef& ref);
    static void AddSinglePath(const std::wstring& path, const std::wstring& sourceName,
        std::vector<FileRef>& refs, std::set<std::wstring>& seen);
    static void ExtractPathsFromString(const std::wstring& text, const std::wstring& sourceName,
        std::vector<FileRef>& refs, std::set<std::wstring>& seen);

    static std::wstring Lower(std::wstring s);
    static std::wstring ExpandEnv(const std::wstring& s);
    static std::wstring Trim(const std::wstring& s);
    static std::wstring SanitizePath(const std::wstring& p);
    static std::wstring ResolveCLSID(const std::wstring& clsid);
    static bool TryResolve(const std::wstring& raw, std::wstring& outResolved);
    static bool ShouldSkipPath(const std::wstring& expanded);
    static bool LooksLikeURI(const std::wstring& text, size_t pos);

    static std::wstring StateStr(TASK_STATE s);
    static std::wstring DateStr(DATE d);
    static std::wstring FTStr(FILETIME ft);
    static std::wstring XmlTag(const std::wstring& xml, const std::wstring& tag);
    static std::vector<std::wstring> XmlTagAll(const std::wstring& xml, const std::wstring& tag);
};

inline auto c_task2 = std::make_unique<c_taskscheduler_bypass_2>();