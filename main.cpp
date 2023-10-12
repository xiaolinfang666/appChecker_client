#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iconv.h>
#include <chrono>
#include <thread>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/sem.h>
#include <unistd.h>
#include <ctime>
#include <ifaddrs.h>
#include <netdb.h>

using namespace std;
#define COMMANDFAIL "fail to run command"
#define NETWORKFAIL "network interface information fail"
#define IPV4FAIL "IPv4 address fail"
#define compHost 8087
#define compIp "172.16.107.2"

void sendToServInter();
void forkProcess();
void opChildProcessWithSignal();
string genJson();
void printId();
void writeToFile(string content);
void sigHandler(int signo);
string getIpJson();
string removeSymbol(string str, string tofind, std::string toreplace);

int semid = -1;
int main(int argc, char *argv[]) {
    // signal(SIGINT, sigHandler);
    writeToFile("start of process");
    forkProcess();
    return 0;
}

void opChildProcessWithSignal() {
    // 自定义信号量为23678
    semid = semget(1119, 1, IPC_CREAT | IPC_EXCL | 0666);
    if (semid == -1) {
        // cout<< "信号量创建失败" << endl;
        writeToFile("信号量创建失败，退出程序");
        return;
    } else {
        // cout<< "信号量创建成功" << endl;
        writeToFile("信号量创建成功");
    }
    union semun arg;
    arg.val = 1;
    int ret = semctl(semid, 0, SETVAL, arg);
    if (ret == -1) {
        // cout<< "信号量初始化失败" << endl;
        writeToFile("信号量初始化失败，退出程序");
        return;
    }
    // cout<< "信号量初始化成功" << endl;
    writeToFile("信号量初始化成功");

    struct sembuf sb;
    sb.sem_num = 0;
    sb.sem_op = -1;
    sb.sem_flg = SEM_UNDO;

    ret = semop(semid, &sb, 1);
    if (ret == -1) {
        // cout<< "信号量获取失败" << endl;
        writeToFile("信号量获取失败，退出程序");
        return;
    }
    // cout<< "信号量获取成功" << endl;
    writeToFile("信号量获取成功");

    // 在这里执行需要互斥的代码
    sendToServInter();

    sb.sem_op = 1;
    ret = semop(semid, &sb, 1);
    if (ret == -1) {
        // cout<< "信号量释放失败" << endl;
        writeToFile("信号量释放失败");
    } else {
        // cout<< "信号量释放成功" << endl;
        writeToFile("信号量释放成功");
    }

    ret = semctl(semid, 0, IPC_RMID, arg);
    if (ret == -1) {
        // cout<< "信号量删除失败" << endl;
        writeToFile("信号量删除失败");
    } else {
        // cout<< "信号量删除成功" << endl;
        writeToFile("信号量删除成功");
    }
    return;
}

void forkProcess() {
    int pid = fork();
    if (-1 == pid) {
        // cout << "call function fork() error!" << endl;
        writeToFile("create child process error!");
        return;
    } else if (0 == pid) {
        // cout << "----------in child process.----------" << endl;
        writeToFile("----------in child process.----------");
        printId();
        //将该进程的进程组ID设置为该进程的进程ID。
        setpgrp();
        //创建一个新的Session，断开与控制终端的关联。也就是说Ctrl+c的触发的SIGINT信号，该进程接收不到。
        setsid();
        //在子进程发送客户端请求
        // opChildProcessWithSignal();
        sendToServInter();
        writeToFile("end of child process");
    } else {             //return from parent process.
        // cout << "----------in parent process.----------" << endl;
        writeToFile("----------in parent process.----------");
        writeToFile("end of father process");
    }
}

void sendToServInter() {
    while(true) {
        //生成json
        string finalJson = genJson();
        if (finalJson == COMMANDFAIL) {
            writeToFile("fail to run command!");
            return;
        }
        // 通过socket传给服务端
        int times = 10;
        while (times >= 0){
            //1. 建立一个socket
            int _sock = socket(AF_INET, SOCK_STREAM, 0); 
            if (_sock == -1) {
                // printf("socket build error!\n");
                writeToFile("socket build error!");
                return;
            } else {
                // printf("socket build success!\n");
                writeToFile("socket build success!");
            }
            //2. 连接服务器
            sockaddr_in _sin = {};
            _sin.sin_family = AF_INET;
            _sin.sin_port = htons(compHost);
            _sin.sin_addr.s_addr = inet_addr(compIp);
            int ret = connect(_sock, (sockaddr*)&_sin, sizeof(sockaddr_in));
            if (ret == -1) {
                // printf("connect error!\n");
                writeToFile("connect error!");
                //7. 关闭套接字close socket
                close(_sock);
                // printf("client has quit!");
                writeToFile("client socket has quit!");
                auto now = std::chrono::system_clock::now();
                auto next = now + std::chrono::minutes(5) - std::chrono::duration_cast<std::chrono::system_clock::duration>(now.time_since_epoch()) % std::chrono::minutes(5);
                std::this_thread::sleep_until(next);
                if (times == 0) {
                    writeToFile("give up retry connect!");
                }
            }  else {
                // printf("connect success!\n");
                writeToFile("connect success!");
                //3. 用户输入请求命令
                const char * cmdBuf = finalJson.c_str();
                //4. 处理请求命令
                if (0 == strcmp(cmdBuf, "exit")) {
                    // printf("receive quit message!");
                    writeToFile("receive quit message!");
                } else {
                //5. 向服务器端发送请求
                    send(_sock, cmdBuf, strlen(cmdBuf), 0);
                    // printf("send message success!");
                    writeToFile("send message success!");
                }
                // //6. 接受服务器信息recv
                // char recvBuf[256] = {};
                // int nlen = recv(_sock, recvBuf, 256, 0); //返回接受数据的长度
                // if (nlen > 0) {
                //     DataPackage* dp = (DataPackage*)recvBuf;
                //     printf("age: %d, name: %s\n", dp->age, dp->name);
                // }
                //7. 关闭套接字close socket
                close(_sock);
                // printf("client has quit!");
                writeToFile("client socket has quit!");
                break;
            }
            times--;
         }

        // 获取当前时间
        auto now = std::chrono::system_clock::now();
        // 计算当前时间到下一个 24 小时的时间间隔
        auto next = now + std::chrono::hours(24) - std::chrono::duration_cast<std::chrono::system_clock::duration>(now.time_since_epoch()) % std::chrono::hours(24);
        // 等待到下一个执行时间
        std::this_thread::sleep_until(next);
    }
}

string genJson() {
    // 扫描电脑上的软件、获取 MAC地址
    FILE *fp;
    string command1 = "system_profiler -json SPApplicationsDataType";
    string command2 = "ifconfig| grep ether";
    // string temp = "{" + command1 + "};" + "{" + command2 + "}";
    string temp = command1 + ";" + command2;
    const char *temChar = temp.c_str();
    fp = popen(temChar, "r");
    if (!fp)
    {
        // std::cout << "popen failed" << std::endl;
        writeToFile("popen failed!");
        return COMMANDFAIL;
    }
    char *file_content = NULL;
    size_t file_size = 0;
    char buffer[1024];
    // 每次去读缓冲区里的内容，每次读1024字节，如果遇到换行就去掉换行符，而每次读取结束时会默认加上
    // 结束标识符\0，这个也是不需要的,所以将指针往前移一下
    while (fgets(buffer, 1024, fp))
    {
        size_t buffer_len = strlen(buffer);
        if (buffer[buffer_len - 1] == '\n')
        {
            buffer[buffer_len - 1] = '\0';
            buffer_len--;
        }
        // allocate memory for file_content
        file_content = (char *)realloc(file_content, file_size + buffer_len + 1);

        // append buffer to file_content
        memcpy(file_content + file_size, buffer, buffer_len);
        file_size += buffer_len;
    }
    // 添加结束标识
    file_content[file_size] = '\0';
    pclose(fp);
    string finalContent = file_content;
    int pos1 = finalContent.find_first_of("\"");
    int pos2 = finalContent.find_last_of("}");
    int len = pos2 - pos1;
    string appInfoJson = finalContent.substr(pos1, len);
    string macStr = finalContent.substr(pos2+1, finalContent.length()-1); //pos3+3
    macStr = removeSymbol(macStr, "ether", "");
    macStr = removeSymbol(macStr, "\t", "\n");

    //拼接json
    string jsonSystem = "{\"system\":\"mac\",\"mac\":\"";
    string jsonComma = "\", ";
    string jsonIp = getIpJson();
    string jsonBracket = "}";
    string finalJson = "";
    if (jsonIp == NETWORKFAIL || jsonIp == IPV4FAIL) {
        finalJson = jsonSystem + macStr + jsonComma + appInfoJson + jsonBracket + "\\0"; //“\\0”是socket结束符
    } else {
        finalJson = jsonSystem + macStr + jsonComma + getIpJson() + "," + appInfoJson + jsonBracket + "\\0";

    }
    return finalJson;
}

void printId() {
    int pid = getpid();
    int gid = getpgid(0);
    // cout << "process group id = " << gid << endl;
    writeToFile("process group id = " + to_string(gid));
    // cout << "process id = " << pid << endl;
    writeToFile("process id = " + to_string(pid));
}

void writeToFile(string content) {
    // ofstream outfile;    //定义输出流对象
    // string filePath = "/Users/Shared/logger.txt";
    // outfile.open(filePath, std::ios::app);    //打开文件
    // if (!outfile.is_open())
    // {
    //     // cout << "打开文件失败" << endl;
    //     exit(1);
    // }

    // //向文件中写入数据
    // time_t t = time(nullptr);
	// struct tm* now = localtime(&t);
    // outfile << "【" << now->tm_year + 1900 << "-" << now->tm_mon + 1 << "-" << now->tm_mday << " " << now->tm_hour << ":"<< now->tm_min << ":" << now->tm_sec << "】" << content << endl;
    // outfile.close();    //关闭文件

    FILE* file = fopen("/Users/Shared/logger.txt", "a");  // 打开文件以供写入
    if (file != NULL) {
        //向文件中写入数据
        time_t t = time(nullptr);
        struct tm* now = localtime(&t);
        string out = "【" + to_string(now->tm_year + 1900) + "-" + to_string(now->tm_mon + 1) + "-" + to_string(now->tm_mday) + " " + 
        to_string(now->tm_hour) + ":"+ to_string(now->tm_min) + ":" + to_string(now->tm_sec) + "】" + content + "\n";
        // 使用 fwrite 写入二进制数据
        const char* message = out.c_str();
        fwrite(message, sizeof(char), strlen(message), file);
        fclose(file);  // 关闭文件
    } 
}

void sigHandler(int signo) {
    writeToFile("signo = " + to_string(signo));
    writeToFile("SIGINT = " + to_string(SIGINT));
    if (signo == SIGINT) {
        // 收到终止信号时调用清理函数
        union semun arg;
        arg.val = 1;
        int ret = semctl(semid, 0, IPC_RMID, arg);
        if (ret == -1) {
            // cout<< "信号量删除失败" << endl;
            writeToFile("信号量删除失败");
        } else {
            // cout<< "信号量删除成功" << endl;
            writeToFile("信号量删除成功");
        }
        exit(1);
    }
}

string getIpJson() {
    string ipStr = "\"ip\":\"";
    string anIp = "";
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        cerr << "Failed to get network interface information" << endl;
        writeToFile("Failed to get network interface information");
        return NETWORKFAIL;
    }

    // 遍历所有网络接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            // IPv4地址
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                cerr << "Failed to get IPv4 address" << endl;
                return IPV4FAIL;
            }
            // cout << "Interface: " << ifa->ifa_name << "  "
            //      << "Address: " << host << endl;
            anIp = host;
            if(ifa->ifa_name[0] == 'e' and ifa->ifa_name[1] == 'n') {
                ipStr += anIp + "(" + ifa->ifa_name + ")" + ", ";
            }
        }
    }
    int index = ipStr.find_last_of(",");
    ipStr = ipStr.substr(0, index);
    ipStr += "\"";
    freeifaddrs(ifaddr);
    return ipStr;
}

string removeSymbol(string str, string tofind, std::string toreplace)
{
    size_t position = 0;
    for ( position = str.find(tofind); position != std::string::npos; position = str.find(tofind,position) )
    {
            str.replace(position ,tofind.length(), toreplace);
    }
    return(str);
}