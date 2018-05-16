// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <utiltime.h>
#include <ringbuffer.h>
#include <reverselock.h>

#include <chrono>
#include <mutex>

const char * const DEFAULT_DEBUGLOGFILE = "debug.log";

/**
 * NOTE: the logger instances is leaked on exit. This is ugly, but will be
 * cleaned up by the OS/libc. Defining a logger as a global object doesn't work
 * since the order of destruction of static/global objects is undefined.
 * Consider if the logger gets destroyed, and then some later destructor calls
 * LogPrintf, maybe indirectly, and you get a core dump at shutdown trying to
 * access the logger. When the shutdown sequence is fully audited and tested,
 * explicit destruction of these objects can be implemented by changing this
 * from a raw pointer to a std::unique_ptr.
 *
 * This method of initialization was originally introduced in
 * ee3374234c60aba2cc4c5cd5cac1c0aefc2d817c.
 */
BCLog::Logger* const g_logger = new BCLog::Logger();

bool fLogIPs = DEFAULT_LOGIPS;

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

bool BCLog::Logger::OpenDebugLog()
{
    std::lock_guard<std::mutex> scoped_lock(m_file_mutex);

    assert(m_fileout == nullptr);
    assert(!m_file_path.empty());

    m_fileout = fsbridge::fopen(m_file_path, "a");
    if (!m_fileout) {
        return false;
    }

    //setbuf(m_fileout, nullptr); // unbuffered
    // dump buffered messages from before we opened the log
    while (!m_msgs_before_open.empty()) {
        FileWriteStr(m_msgs_before_open.front(), m_fileout);
        m_msgs_before_open.pop_front();
    }

    return true;
}

void BCLog::Logger::EnableCategory(BCLog::LogFlags flag)
{
    m_categories |= flag;
}

bool BCLog::Logger::EnableCategory(const std::string& str)
{
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) return false;
    EnableCategory(flag);
    return true;
}

void BCLog::Logger::DisableCategory(BCLog::LogFlags flag)
{
    m_categories &= ~flag;
}

bool BCLog::Logger::DisableCategory(const std::string& str)
{
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) return false;
    DisableCategory(flag);
    return true;
}

bool BCLog::Logger::WillLogCategory(BCLog::LogFlags category) const
{
    return (m_categories.load(std::memory_order_relaxed) & category) != 0;
}

bool BCLog::Logger::DefaultShrinkDebugFile() const
{
    return m_categories == BCLog::NONE;
}

struct CLogCategoryDesc
{
    BCLog::LogFlags flag;
    std::string category;
};

const CLogCategoryDesc LogCategories[] =
{
    {BCLog::NONE, "0"},
    {BCLog::NONE, "none"},
    {BCLog::NET, "net"},
    {BCLog::TOR, "tor"},
    {BCLog::MEMPOOL, "mempool"},
    {BCLog::HTTP, "http"},
    {BCLog::BENCH, "bench"},
    {BCLog::ZMQ, "zmq"},
    {BCLog::DB, "db"},
    {BCLog::RPC, "rpc"},
    {BCLog::ESTIMATEFEE, "estimatefee"},
    {BCLog::ADDRMAN, "addrman"},
    {BCLog::SELECTCOINS, "selectcoins"},
    {BCLog::REINDEX, "reindex"},
    {BCLog::CMPCTBLOCK, "cmpctblock"},
    {BCLog::RAND, "rand"},
    {BCLog::PRUNE, "prune"},
    {BCLog::PROXY, "proxy"},
    {BCLog::MEMPOOLREJ, "mempoolrej"},
    {BCLog::LIBEVENT, "libevent"},
    {BCLog::COINDB, "coindb"},
    {BCLog::QT, "qt"},
    {BCLog::LEVELDB, "leveldb"},
    {BCLog::ALL, "1"},
    {BCLog::ALL, "all"},
};

bool GetLogCategory(BCLog::LogFlags& flag, const std::string& str)
{
    if (str == "") {
        flag = BCLog::ALL;
        return true;
    }
    for (const CLogCategoryDesc& category_desc : LogCategories) {
        if (category_desc.category == str) {
            flag = category_desc.flag;
            return true;
        }
    }
    return false;
}

std::string ListLogCategories()
{
    std::string ret;
    int outcount = 0;
    for (const CLogCategoryDesc& category_desc : LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE && category_desc.flag != BCLog::ALL) {
            if (outcount != 0) ret += ", ";
            ret += category_desc.category;
            outcount++;
        }
    }
    return ret;
}

std::vector<CLogCategoryActive> ListActiveLogCategories()
{
    std::vector<CLogCategoryActive> ret;
    for (const CLogCategoryDesc& category_desc : LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE && category_desc.flag != BCLog::ALL) {
            CLogCategoryActive catActive;
            catActive.category = category_desc.category;
            catActive.active = LogAcceptCategory(category_desc.flag);
            ret.push_back(catActive);
        }
    }
    return ret;
}

std::string BCLog::Logger::LogTimestampStr(const std::string &str)
{
    std::string strStamped;

    if (!m_log_timestamps)
        return str;

    if (m_started_new_line) {
        int64_t nTimeMicros = GetTimeMicros();
        strStamped = FormatISO8601DateTime(nTimeMicros/1000000);
        if (m_log_time_micros) {
            strStamped.pop_back();
            strStamped += strprintf(".%06dZ", nTimeMicros%1000000);
        }
        int64_t mocktime = GetMockTime();
        if (mocktime) {
            strStamped += " (mocktime: " + FormatISO8601DateTime(mocktime) + ")";
        }
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        m_started_new_line = true;
    else
        m_started_new_line = false;

    return strStamped;
}

void BCLog::Logger::LogPrintStr(const std::string &str)
{
    std::string strTimestamped = LogTimestampStr(str);

    if (m_print_to_console) {
        // print to console
        fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    if (m_print_to_file) {
        //std::lock_guard<std::mutex> scoped_lock(m_file_mutex);

        // buffer if we haven't opened the log yet
        if (m_fileout == nullptr) {
            m_msgs_before_open.push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (m_reopen_file) {
                m_reopen_file = false;
                m_fileout = fsbridge::freopen(m_file_path, "a", m_fileout);
                if (!m_fileout) {
                    return;
                }
                //setbuf(m_fileout, nullptr); // unbuffered
            }

            FileWriteStr(strTimestamped, m_fileout);
        }
    }
}

void BCLog::Logger::FlushFile()
{
    fflush(m_fileout);
}

void BCLog::Logger::ShrinkDebugFile()
{
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;

    assert(!m_file_path.empty());

    // Scroll debug.log if it's getting too big
    FILE* file = fsbridge::fopen(m_file_path, "r");

    // Special files (e.g. device nodes) may not have a size.
    size_t log_size = 0;
    try {
        log_size = fs::file_size(m_file_path);
    } catch (boost::filesystem::filesystem_error &) {}

    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes
    if (file && log_size > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10))
    {
        // Restart the file with some of the end
        std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
        if (fseek(file, -((long)vch.size()), SEEK_END)) {
            LogPrintf("Failed to shrink debug log file: fseek(...) failed\n");
            fclose(file);
            return;
        }
        int nBytes = fread(vch.data(), 1, vch.size(), file);
        fclose(file);

        file = fsbridge::fopen(m_file_path, "w");
        if (file)
        {
            fwrite(vch.data(), 1, nBytes, file);
            fclose(file);
        }
    }
    else if (file != nullptr)
        fclose(file);
}

class AsyncLogger
{
public:
    AsyncLogger() : m_buffer_accumulating(m_capacity), m_buffer_flushing(m_capacity) {}
    ~AsyncLogger() {}

    void Start()
    {
        std::unique_lock<std::mutex> l(m_lock);
        if(!m_active) {
            m_active = true;
            m_flusher = std::thread(&AsyncLogger::Thread, this);
        }
    }

    void Stop()
    {
        bool do_join = false;

        {
            std::unique_lock<std::mutex> l(m_lock);
            if(m_active) {
                m_active = false;
                do_join = true;
            }
        }

        if(do_join) {
            m_cv.notify_one();
            m_flusher.join();
        }
    }

    void Push(std::string&& line)
    {
        {
            std::unique_lock<std::mutex> l(m_lock);

            m_buffer_accumulating[m_insert_pos()] = std::forward<std::string>(line);
            ++m_messages_written;
        }

        // doesnt matter that much if we slightly over or undernotify
        if(m_messages_written > 200)
            m_cv.notify_one();
    }

    void Thread(void)
    {
        std::unique_lock<std::mutex> l(m_lock);
        while(true)
        {
            if(!m_active) {
                break;
            }

            // if theres still a lot to do don't wait
            if(m_messages_written < 100) {
                // sleep until there's a lot to do or some time has passed
                m_cv.wait_for(l, std::chrono::milliseconds(100));
            }

            if(m_messages_written > 0) {
                std::swap(m_buffer_accumulating, m_buffer_flushing);

                buffer::size_type size = m_messages_written;
                m_messages_written = 0;

                {
                    // drop the lock while flushing
                    reverse_lock<std::unique_lock<std::mutex>> release(l);

                    if(size > m_capacity) {
                        g_logger->LogPrintStr(strprintf("WARNING: %d log messages were discarded\n", size - m_capacity));
                    }

                    buffer::size_type n_to_flush = std::min(size, m_capacity);
                    for(buffer::size_type i = size % m_capacity; n_to_flush > 0; ++i, --n_to_flush) {
                        g_logger->LogPrintStr(std::move(m_buffer_flushing[i]));
                    }
                    g_logger->FlushFile();
                }
            }
        }
    }

private:
    bool m_active;

    std::mutex m_lock;
    std::condition_variable m_cv;
    std::thread m_flusher;

    static constexpr long unsigned int m_capacity = 1024;
    using buffer = std::vector<std::string>;

    buffer m_buffer_accumulating;
    buffer m_buffer_flushing;

    buffer::size_type m_messages_written;
    inline buffer::size_type m_insert_pos(){ return m_messages_written % m_capacity; }
};

namespace async_logging {
    AsyncLogger log_buffer;

    void Init(void)
    {
        log_buffer.Start();
        LogPrintf("If you are seeing this message the async logger has started\n");
    }

    void Queue(std::string&& str)
    {
        log_buffer.Push(std::forward<std::string>(str));
    }
}
