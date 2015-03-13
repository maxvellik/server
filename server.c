#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <wait.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pwd.h>

#define MAX_STR_LEN 255
#define MAX_RECORD_STR_LEN 50
#define BUF_SIZE 255

#define IP_NEEDED 1
#define USERNAME_NEEDED 2
#define INPUT_USR 4
#define OUTPUT_USR 8
typedef struct List List;

struct List{
    char user[MAX_RECORD_STR_LEN];
    char password[MAX_RECORD_STR_LEN];
    char sysUser[MAX_RECORD_STR_LEN];
    char command[MAX_RECORD_STR_LEN];
    char sysCommand[MAX_RECORD_STR_LEN];
    int timeout;
    int output;    //it is just bool =)
    List * next;
} * table = NULL;

int servFd;
int clientFd = 0;

time_t changingTime = 0;
char filename[MAX_STR_LEN] = "tab";
unsigned long int ip = 0;
int port = 2323;
unsigned int timeout = 15;
int echo = 0;    //bool
FILE * stream;

char * gettime()
{
    time_t tmp;
    time(&tmp);

    char * str = ctime(&tmp);
    str[strlen(str) - 1] = '\0';
    return str;
}

void deleteList()
{
    List * tmp;
    while (table != NULL)
    {
        tmp = table -> next;
        free(table);
        table = tmp;
    }
}

void exitEvent()
{
    fprintf(stream, "%s Stop\n", gettime());
    fflush(stream);
    deleteList();
    shutdown(servFd, SHUT_RDWR);
    close(servFd);
    exit(0);
}

void closeConnection()
{
    if (clientFd)
    {
char * msg = "Connection closed by timeout\n\0";
        fprintf(stream, "%s Disconnect: timeout\n", gettime());
        fflush(stream);
        send(clientFd, msg, strlen(msg) + 1, 0);
        shutdown(clientFd, SHUT_RDWR);
        close(clientFd);
        clientFd = 0;
    }
}

void stop()
{
    fprintf(stream, "%s Command canceled: timeout\n", gettime());
    fflush(stream);
    if (clientFd)
        {
        char * msg = "Command canceled by timeout\n\0";
        send(clientFd, msg, strlen(msg) + 1, 0);
    }
    exit(-2);
}

void getStringFromIp(char * str, long int ip)
{
    sprintf(str, "%lu.%lu.%lu.%lu", ip % 256, ip / 256 % 256, ip / (256 * 256) % 256, ip / (256 * 256 * 256));
}

long int ipFromStr(const char * string)
{
    unsigned long int ip = 0;
    int a;
    char * str = strdup(string);
    char * tmp;
    int i;
    int k = 1;//16777216;    //2^24

    for (i = 0; i < 4; i++)
    {
        if (i < 3)
        {
            tmp = strchr(str, '.');
            if (!tmp) { fprintf(stream, "%s Error: wrong ip\n", gettime()); return -1; }
            *tmp = '\0';
        }
        else tmp = str;
        printf("%s\n", str);
        a = atoi(str);
        if (a > 255) { fprintf(stream, "%s Error: wrong ip\n", gettime()); return -1; }
        str = tmp + 1;
        ip += a * k;

        k *= 256;
    }

    if (strchr(str, '.')) { fprintf(stream, "%s Error: wrong ip\n", gettime()); return -1; }
    return ip;
}

void readParametrs(int argc, char * argv[])
{
    int i = 1;
    for (; i < argc - 1; i++)
        if (!strcmp(argv[i], "-l"))
        {
            stream = fopen(argv[i + 1], "a");
            if (!stream)
            {
                fprintf(stream, "%s Error: Can't open file :'%s'\n", gettime(), argv[i + 1]);
                exit(-1);
            }
            break;
        }
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-l")) { if (i < argc) i++; } else
        if (!strcmp(argv[i], "-b"))
        {

            ip = ipFromStr(argv[i]);
        } else
        if (!strcmp(argv[i], "-c"))
        {
            if (i < argc) i++;
            strcpy(filename, argv[i]);
        } else
        if (!strcmp(argv[i], "-p"))
        {
            if (i < argc) i++;
            port = atoi(argv[i]);
        } else
        if (!strcmp(argv[i], "-t"))
        {
            if (i < argc) i++;
            timeout = atoi(argv[i]);
        } else
        if (!strcmp(argv[i], "-d"))
        {
            int pid = fork();
            if (pid < 0) { fprintf(stream, "%s Error\n", gettime()); exit(-1); }
            if (pid)
            {    //parent
                int j = 0;
                for (; j < argc - 1; j++)
                    if (!strcmp(argv[j], "-pid"))
                    {
                        FILE * pidFile = fopen(argv[j + 1], "w");
                        fprintf(pidFile, "%d", pid);
                        fclose(pidFile);
                        break;
                    }
                exit(0);
            }

            fprintf(stream, "%s Start service PID %d ( daemon mode )\n", gettime(), pid);
            close(0);
            close(1);
            close(2);
            open("/dev/null", O_RDONLY); /*stdin*/
            open("/dev/null", O_WRONLY); /*stdout*/
            open("/dev/null", O_WRONLY); /*stderr*/
            setsid();
            chdir("/");
        } else
        if (!strcmp(argv[i], "-pid"))
        {
            if (i < argc) i++;
        } else
        if (!strcmp(argv[i], "-echo"))
        {
            echo = 1;
        } else
        {
            fprintf(stream, "%s Error: Invalid parameters\n", gettime());
            exit(-1);
        }
    }
}

int isChange(const char * filename)
{
    struct stat st;
    if (stat(filename, &st) == -1) return 1;
    int res = st.st_ctime != changingTime;
    if (res) changingTime = st.st_ctime;
    return res;
}

void readFile(char * filename)
{
    FILE * file = fopen(filename, "r");
    if (!file) { fprintf(stream, "%s Table read error\n", gettime()); exit(-1);}
    char str[MAX_STR_LEN];
    char tmp[MAX_RECORD_STR_LEN];
    int lineNumber = 0;

    while (1)
    {
        lineNumber++;

        fgets(str, MAX_STR_LEN, file);
        if (str[strlen(str) - 1] == '\n') str[strlen(str) - 1] = '\0';

        if (feof(file)) break;

        *tmp = '\0';
        sscanf(str, "%s", tmp);
        if (tmp[0] == '#' || tmp[0] == '\0') continue;

        List * newItem = malloc(sizeof(List));
        newItem -> next = table;
        table = newItem;

        if (sscanf(str, "%s %s %s %s %s %d %[^\n]", newItem -> user, newItem -> password, newItem -> command, newItem -> sysUser, tmp, &(newItem->timeout), newItem->sysCommand) < 6  ||
            !strlen(newItem -> user) || !strlen(newItem -> password) || !strlen(newItem -> sysUser) || !strlen(newItem -> command))
        {
            fprintf(stream, "%s Error: In config file in line %d: wrong format\n", gettime(), lineNumber);
            exitEvent();
        }
        if (!strcmp(tmp, "i"))
        {
            newItem->output = INPUT_USR;
        }
        else if (!strcmp(tmp, "o"))
        {
            newItem->output = OUTPUT_USR;
        }
        else if (!strcmp(tmp, "oi") || !strcmp(tmp, "io"))
        {
            newItem->output = INPUT_USR | OUTPUT_USR;
        }
        else if (!strcmp(tmp, "-"))
        {
            newItem->output = 0;
        }
        else
        {
                        fprintf(stream, "%s Error: In config file in line %d: wrong format\n", gettime(), lineNumber);
                        exitEvent();
                }

        if (!strlen(newItem -> sysCommand))
                {
                        fprintf(stream, "%s Warning: In config file in line %d: command with no effects\n", gettime(), lineNumber);
                        fflush(stream);
                }

        //printf("'%s' '%s' '%s' '%s' '%s'\n", newItem -> user, newItem -> password, newItem -> command, newItem -> sysUser, newItem -> sysCommand);
    }
}

int check_leters (char *str, int len, char *pat, int patlen)
{
    /**
     *   check if there is a char in str from pat.
     *   return position of coincedence or -1 if there is no match.
     */
    int i, j;
    for (i = 0; i < len && str[i]; ++i)
    {
    for (j = 0; j < patlen; ++j)
    {
        if (str[i] == str[j])
        return i;
    }
    }
    return -1;
}
/*
 * read from sd to buf until symbols from end found.
 * bufsize is the length of buf.
 */
int read_until (int sd, char *buf, int bufsize, char *end)
{
    int chk_end = 1;
    int buflen = 0;
    int end_size = strlen(end);
    do
    {
       int rc = recv(sd, buf, bufsize, MSG_PEEK);
       if (rc < 0)
       {
           fprintf(stream, "error reading from socket:\n%s",
                   strerror(errno));
           return -1;
       }

       buflen = check_leters(buf, rc, end, end_size);
      if (buflen == -1)
      {/*hole buf has no end chars.*/
         if (rc == bufsize)
         {
             char tmp[bufsize];
             recv(sd, tmp, bufsize, 0);
             chk_end = 0;
         }
      }
      else if (buflen)
      {/*there is match with end sybmols*/
          char tmp[buflen + 1];
          recv(sd, tmp, buflen + 1, 0);
          chk_end = 0;
          buf[buflen] = '\0';
          bufsize = buflen;
      }
      else
      {/* the first symbol is end sybmol */
          char c;
          recv(sd, &c, 1, 0);
          chk_end = 0;
          buf[0] = '\0';
          bufsize = 0;
      }
    } while(chk_end);
    return bufsize;
}
int skip_spaces()
{
    int num = 0;
    char buf[MAX_STR_LEN];
    int i, rc;
    do
    {
         rc = recv(clientFd, buf, MAX_STR_LEN, MSG_PEEK);
        if (rc == -1)
        {
            fprintf(stream, "error reading socket:\n%s", strerror(errno));
            return -1;
        }
        for (i = 0; i < rc; ++i)
        {
            if (buf[i] != ' ' && buf[i] != '\t')
            {
                recv(clientFd, buf, i + 1, 0);
                return num + i;
            }
        }
        recv(clientFd, buf, rc, 0);
        num += rc;
    } while (rc);
    return num;
}
void show_stat(int fd)
{
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        fprintf(stream, "%s error stat file!", gettime());
    }
           printf("File type:                ");

           switch (sb.st_mode & S_IFMT) {
           case S_IFBLK:  printf("block device\n");            break;
           irintf("File type:                ");

           switch (sb.st_mode & S_IFMT) {
           case S_IFBLK:  printf("block device\n");            break;
           case S_IFCHR:  printf("character device\n");        break;
           case S_IFDIR:  printf("directory\n");               break;
           case S_IFIFO:  printf("FIFO/pipe\n");               break;
           case S_IFLNK:  printf("symlink\n");                 break;
           case S_IFREG:  printf("regular file\n");            break;
           case S_IFSOCK: printf("socket\n");                  break;
           default:       printf("unknown?\n");                break;
           }

           printf("I-node number:            %ld\n", (long) sb.st_ino);

           printf("Mode:                     %lo (octal)\n",
                   (unsigned long) sb.st_mode);

           printf("Link count:               %ld\n", (long) sb.st_nlink);
           printf("Ownership:                UID=%ld   GID=%ld\n",
                   (long) sb.st_uid, (long) sb.st_gid);

           printf("Preferred I/O block size: %ld bytes\n",
                   (long) sb.st_blksize);
           printf("File size:                %lld bytes\n",
                   (long long) sb.st_size);
           printf("Blocks allocated:         %lld\n",
                   (long long) sb.st_blocks);

           printf("Last status change:       %s", ctime(&sb.st_ctime));
           printf("Last file access:         %s", ctime(&sb.st_atime));
           printf("Last file modification:   %s", ctime(&sb.st_mtime));

           case S_IFCHR:  printf("character device\n");        break;
           case S_IFDIR:  printf("directory\n");               break;
           case S_IFIFO:  printf("FIFO/pipe\n");               break;
           case S_IFLNK:  printf("symlink\n");                 break;
           case S_IFREG:  printf("regular file\n");            break;
           case S_IFSOCK: printf("socket\n");                  break;
           default:       printf("unknown?\n");                break;
           }

           printf("I-node number:            %ld\n", (long) sb.st_ino);

           printf("Mode:                     %lo (octal)\n",
                   (unsigned long) sb.st_mode);

           printf("Link count:               %ld\n", (long) sb.st_nlink);
           printf("Ownership:                UID=%ld   GID=%ld\n",
                   (long) sb.st_uid, (long) sb.st_gid);

           printf("Preferred I/O block size: %ld bytes\n",
                   (long) sb.st_blksize);
           printf("File size:                %lld bytes\n",
                   (long long) sb.st_size);
           printf("Blocks allocated:         %lld\n",
                   (long long) sb.st_blocks);

           printf("Last status change:       %s", ctime(&sb.st_ctime));
           printf("Last file access:         %s", ctime(&sb.st_atime));
           printf("Last file modification:   %s", ctime(&sb.st_mtime));

}
void runCommand(char *user, char *passwd, char *cmd, char *tail,
        unsigned long int ip)
{
    //char user[MAX_RECORD_STR_LEN] = "";
    //char passwd[MAX_RECORD_STR_LEN] = "";
    //char cmd[MAX_RECORD_STR_LEN] = "";
    //char tail[MAX_RECORD_STR_LEN];
    //sscanf(str, "%s %s %s", user, passwd, cmd);
    char str[MAX_STR_LEN];
    if (!strlen(user) || !strlen(passwd) || !strlen(cmd))
    {
        sprintf(str, "Wrong format. Use <User> <Password> <Command> [<Flags>]\n");
        return;
    }
    //strcpy(tail, strstr(str, cmd) + strlen(cmd));        //just work...
//    printf("'%s' '%s' '%s' '%s'\n", user, passwd, cmd, tail);

    List * currentItem = table;
    int errFlag = 0;
    while (currentItem != NULL)
    {
        if (!strcmp(currentItem -> command, cmd))
        {
            if (errFlag < 1)
            errFlag = 1;
            if (!strcmp(currentItem -> user, user))
            {
                if (errFlag < 2)
                errFlag = 2;
                if (!strcmp(currentItem -> password, passwd))
                {
                    if (errFlag < 3)
                    errFlag = 3;
                    struct passwd *pwd;
                    errno = 0;
                    pwd = getpwnam (currentItem -> sysUser);
                    if (pwd == NULL && errno == 0)
                    {
                        fprintf (stream, "%s error no such system user found: %s\n",
                                 gettime(), currentItem -> sysUser);
                        return;
                    }
                    else if (pwd == NULL)
                    {
                        fprintf (stream, "%s error in getpwnam:\n%s", gettime(), strerror(errno));
                        return;
                    }
                    int uid = pwd -> pw_uid;
                    char sysCmd[2 * MAX_RECORD_STR_LEN + strlen(tail) + 1];
                    sprintf(sysCmd, "%s", currentItem -> sysCommand);
                    char * flagPos = strstr(sysCmd, "%i");
                    if (flagPos)
                    {
                        char * tmp = strdup(flagPos + 2);
                        *flagPos = '\0';
                        char strIp[12];
                        getStringFromIp(strIp, ip);
                        sprintf(sysCmd, "%s%s%s", sysCmd, strIp, tmp);
                        free(tmp);
                    }
                    flagPos = strstr(sysCmd, "%u");
                    if (flagPos)
                    {
                        char * tmp = strdup(flagPos + 2);
                        *flagPos = '\0';
                        sprintf(sysCmd, "%s%s%s", sysCmd, user, tmp);
                        free(tmp);
                    }
                    strcat(sysCmd, tail);
                    int pipe_fd[2];
                    int pid1, pid2;
                    if (pipe(pipe_fd) == -1)
                        fprintf(stream, "%s error making pipe:\n%s",
                                gettime(),
                                strerror(errno));
                    if ((pid1 = fork()) == 0) //child to read from telnet
                    {
                        close(pipe_fd[0]);
                        dup2(pipe_fd[1], 1);
                        close(pipe_fd[1]);
                        if (currentItem->output & INPUT_USR)
                        {
                            //char buf[MAX_STR_LEN];
                            dup2(clientFd, 0);
                            close(clientFd);
                            execlp("cat", "cat", NULL);
                            fprintf(stream, "%s error on exec:\n%s", gettime(), strerror(errno));
                            exit(-1);
                        }
                    }

                    if ((pid2 = fork()) == 0)    //child to exec command
                    {
                        if (setuid(uid) == -1)
                        {
                            fprintf(stream, "%s error changing user!\n%s", gettime(), strerror(errno));
                        }
                        close(pipe_fd[1]);
                        dup2(pipe_fd[0], 0);
                        close(pipe_fd[0]);
                        if (currentItem->output & OUTPUT_USR)
                            dup2(clientFd, 1);
                        signal(SIGALRM, stop);
                        alarm(currentItem->timeout);
                        exit( system(sysCmd) );
                    }
                    close(pipe_fd[0]);
                    close(pipe_fd[1]);

                    int status = 0;
                    waitpid(pid1, &status, 0);
                    if (status != 0)
                    {
                        fprintf(stream, "%s error in output daemon", gettime());
                    }
                    waitpid(pid2, &status, 0);
                    if (status == 0)
                        sprintf(str, "Command successfully executed\n");
                    else
                        sprintf(str, "Some errors with executing command\n");
                }
            }
        }
        currentItem = currentItem -> next;
    }

    switch (errFlag)
    {
        case 0: sprintf(str, "Unknown command\n"); break;
        case 1: case 2: sprintf(str, "Unknown user or password\n"); break;
    }
}

int main(int argc, char * argv[])
{
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t clientAddrSize = sizeof(clientAddr);
    char buf[BUF_SIZE]
    int bufLength = 0;
    int breakWhile = 0;

    stream = stdout;
    readParametrs(argc, argv);

    servFd = socket(AF_INET, SOCK_STREAM, 0);

    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = ip;

    if (bind(servFd, (const struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        fprintf(stream, "%s Error: bind error\n", gettime()); exit(-1);
    }
    if (listen(servFd, 10))
    {
        fprintf(stream, "%s Error: listen error\n", gettime()); exit(-1);
    }

    signal(SIGINT, exitEvent);
    signal(SIGTERM, exitEvent);
    signal(SIGALRM, closeConnection);

    if (isChange(filename)) readFile(filename);

    while (1)
    {
        clientFd = accept(servFd, (struct sockaddr *)&clientAddr, &clientAddrSize);
        show_stat(clientFd);
        if (clientFd == -1)
            fprintf(stream, "%s error accepting client! errno = %d\n%s",
                    gettime(), errno, strerror(errno)), fflush(stream);
        //char strIp[12];
        char correctIp[INET_ADDRSTRLEN];
        const char *checkIp = inet_ntop(clientAddr.sin_family, &clientAddr.sin_addr,
                                        correctIp, INET_ADDRSTRLEN);
        if (checkIp)
            fprintf(stream, "%s Connect %s\n", gettime(), correctIp);
        else
        {
             fprintf(stream, "%s incorrect ip tried to connected! Errno = %d\n%s",
                     gettime(), errno, strerror(errno));
             fprintf(stream, "sin_family = %d,\nsin_port = %d,\nsin_addr = %d",
                     clientAddr.sin_addr, ntohs(clientAddr.sin_port), clientAddr.sin_addr.s_addr);
        }
        //getStringFromIp(strIp, clientAddr.sin_addr.s_addr);
        //fprintf(stream, "%s Connect %s\n", gettime(), strIp);
        fflush(stream);

        alarm(timeout);
        bufLength = 0;

        breakWhile = 0;

        do {
            //int recLen = recv(clientFd, buf + bufLength, BUF_SIZE - bufLength, 0);
            //if (recLen != BUF_SIZE - bufLength) breakWhile = 1;

            if (echo)
            {
                char tmp[BUF_SIZE];
                memcpy(tmp, buf + bufLength, recLen);
                tmp[recLen] = '\0';

                send(clientFd, tmp, recLen + 1, 0);
            }

            if (recLen > 0)
                bufLength += recLen;
            else
                breakWhile = 1;

            if (bufLength >= BUF_SIZE)
            {    //buffer owerflow
                fprintf(stream, "%s Disconnect: error: buffer owerflow\n", gettime());
                fflush(stream);
                char * msg = "Too long string\n\0";
                send(clientFd, msg, strlen(msg) + 1, 0);
                break;
            }

            int i = 0;
            for (; i < bufLength; i++)
                if (buf[i] == 13 || buf[i] == 10 || buf[i] == '\n')
                {    //all ok
                    buf[i] = '\0';
                    if (clientFd)
                    {
                        fprintf(stream, "%s Get Command '%s'\n", gettime(), buf);
                        fflush(stream);

                        if (isChange(filename)) readFile(filename);
                        runCommand(buf, NULL, NULL, NULL, clientAddr.sin_addr.s_addr);
                        fprintf(stream, "%s Disconnect: result: %s", gettime(), buf);
                        fflush(stream);
                        send(clientFd, buf, strlen(buf) + 1, 0);
                    }
                    breakWhile = 1;
                    break;
                }
        } while (!breakWhile);

        if (clientFd)
        {
            shutdown(clientFd, SHUT_RDWR);
            close(clientFd);
            clientFd = 0;
        }
    }

    return 0;
}
