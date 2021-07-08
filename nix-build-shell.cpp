#include <iostream>
#include <fstream>
#include <sched.h>
#include <unistd.h>
#include <vector>
#include <stdio.h>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <mutex>
#include <condition_variable>
#include "utils.h"

#define pivot_root(new_root, put_old) (syscall(SYS_pivot_root, new_root, put_old))
using namespace std;

struct terminalArg{
    int argc;
    const char** argv;
};
std::mutex m;
std::condition_variable cv;

string ParseEnv(const string& buildDir){
    bool found;
    string str;
    ifstream fin;
    fin.open(buildDir+"/env-vars");//@todo Path parse

    while (!fin.eof())
    {
        getline(fin, str);
        if(str.substr(0,17)=="declare -x SHELL="){ //@todo foolish
            found = true;
            break;
        }
    }
    fin.close();
    return found?move(str.substr(18,str.size()-19)):"";
}

/* Reference: glibc2.25/support/support_become_root.c */
void setup_uid_gid_mapping(pid_t pid, int original_uid, int original_gid) {
    char buf[100];
    snprintf (buf, sizeof (buf), "%llu %llu 1\n",
                        (unsigned long long) 1000,
                        (unsigned long long) original_uid);
    writeFile("/proc/"+to_string(pid)+"/uid_map", buf,O_WRONLY);
    /* Linux 3.19 introduced the setgroups file.  We need write "deny" to this
       file otherwise writing to gid_map will fail with EPERM.  */
    writeFile("/proc/"+to_string(pid)+"/setgroups", "deny\n",O_WRONLY);

    /* Now map our own GID */
    snprintf (buf, sizeof (buf), "%llu %llu 1\n",
                    (unsigned long long) 100,
                    (unsigned long long) original_gid);
    writeFile("/proc/"+to_string(pid)+"/gid_map", buf,O_WRONLY);
}

const bool _debug=false;
int childEntry(void* myarg){
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk);
    /* parse args */
    int argc = ((terminalArg*)myarg)->argc;
    const char** argv = ((terminalArg*)myarg)->argv;
    string buildDir(argv[1]);
    string shellParam(ParseEnv(buildDir));

    /* prepare rootfs*/
    char tmpl[] = "/tmp/nix_build_shellXXXXXX";
    if(mkdtemp(tmpl)==NULL)
        std::cout<<"failed to mk tmp dir"<<endl;
    string myroot(tmpl);
    if(_debug)std::cout<<"myroot:"<<tmpl<<endl;
    createDirs(myroot + "/build");
    if(system(("cp -a "+buildDir+"/* "+ myroot + "/build").c_str())==-1)
        std::cout<<"error called copy!"<<endl;
    if(_debug)std::cout<<"Build Dir:"<<buildDir<<endl;
    if(_debug)std::cout<<"Target Bash:"<<shellParam<<endl;

    /* As I clone a subprocesses, so no need to unshare here*/
//    if(unshare(CLONE_NEWUSER|CLONE_NEWUTS|CLONE_NEWNET|CLONE_NEWNS)==-1) {
//        std::cout<<"failed unshare namespace!"<<std::endl;
//        return 1;
//    }

    /* Set global mounting point first: This should be the first! Before mounting the proc!
       As it will influence all the mounted points!
       The private mount namespace does not guarantee the propagation */
    mount_(0, "/", 0, MS_PRIVATE | MS_REC, 0);

    /* Bind-mount chroot directory to itself, to treat it as a
       different filesystem from /, as needed for pivot_root. */
    mount_(myroot.c_str(), myroot.c_str(), 0, MS_BIND, 0);

    createDirs(myroot + "/proc"); ///> For proc
    chmod_(myroot + "/proc", 0555);
    mount_("proc", (myroot + "/proc").c_str(), "proc", 0, 0);//new proc

    /* set host namespace */
    if (sethostname("localhost", 9) == -1)
        cout<<"cannot set host name"<<endl;
    if (setdomainname("(none)",6) == -1)
        cout<<"cannot set domain name"<<endl;;

    /* Initialise the loopback interface. */
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (!fd) cout<<"cannot open IP socket"<<endl;

    struct ifreq ifr;
    strcpy(ifr.ifr_name, "lo");
    ifr.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
        cout<<"cannot set loopback interface flags";

    /* Set up /dev */
    createDirs(myroot + "/nix");
    createDirs(myroot + "/etc");

    createDirs(myroot + "/dev/shm"); ///> For POSIX shared memory
    createDirs(myroot + "/dev/pts"); ///> For the connected terminal
    createDirs(myroot + "/tmp");
    createDirs(myroot + "/bin");
    if(_debug){
        createDirs(myroot + "/lib");
        createDirs(myroot + "/lib64");
        createDirs(myroot + "/usr/lib");
    }

    mount_("/nix", (myroot+"/nix").c_str(), 0, MS_BIND, 0);//bind mount /nix not ./nix!
    mount_("none", (myroot + "/dev/shm").c_str(), "tmpfs", 0,"size=50%");//new tmpfs
    mount_((myroot + "/dev/pts").c_str(), (myroot + "/dev/pts").c_str(), 0, MS_BIND, 0);//bind mount
    if(_debug){
        mount_("/usr/lib", (myroot+"/usr/lib").c_str(), 0, MS_BIND, 0);
        mount_("/bin", (myroot+"/bin").c_str(), 0, MS_BIND, 0);
        mount_("/lib", (myroot+"/lib").c_str(), 0, MS_BIND, 0);
        mount_("/lib64", (myroot+"/lib64").c_str(), 0, MS_BIND, 0);
    }

    /* change read write mode */
    chmod_(myroot + "/dev/shm", 01777);
    chmod_(myroot + "/tmp", 01777);

    /* creating necessary files */
    createSymlink("/proc/self/fd", myroot + "/dev/fd");
    createSymlink("/proc/self/fd/0", myroot + "/dev/stdin");
    createSymlink("/proc/self/fd/1", myroot + "/dev/stdout");
    createSymlink("/proc/self/fd/2", myroot + "/dev/stderr");

    writeFile(myroot+"/bin/sh","",O_CREAT);
    mount_(shellParam.c_str(), (myroot+"/bin/sh").c_str(), 0, MS_BIND, 0);
    string ss[]={"/dev/full","/dev/kvm","/dev/null","/dev/random","/dev/tty","/dev/urandom","/dev/zero","/dev/ptmx"};
    for(string& i:ss){
        string tmpstr = myroot+i;
        writeFile(tmpstr,"",O_CREAT);
        mount_(i.c_str(), tmpstr.c_str(), "", MS_BIND, 0);
    }

    /* Create a /etc/passwd with entries for the build user and the
           nobody account. */
    char buffer[200];
    snprintf(buffer,100,
             "root:x:0:\n"
             "nixbld:!:%u:\n"
             "nogroup:x:65534:\n", 100);
    writeFile(myroot + "/etc/group", buffer,O_WRONLY | O_CREAT);
    writeFile(myroot + "/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n",O_WRONLY | O_CREAT);
    snprintf(buffer, 200,
             "root:x:0:0:Nix build user:%s:/noshell\n"
             "nixbld:x:%u:%u:Nix build user:%s:/noshell\n"
             "nobody:x:65534:65534:Nobody:/:/noshell\n",
             "/build",1000, 100, "/build");
    writeFile(myroot + "/etc/passwd", buffer, O_WRONLY | O_CREAT);

    /* Do the chroot() */
    if (chdir(myroot.c_str()) == -1)
        cout<< "cannot change directory to " << myroot<<endl;

    if (mkdir("real-root", 0) == -1)
        cout<< "cannot create real-root directory"<<endl;

    if (pivot_root(".", "real-root") == -1)
        cout<< "cannot pivot old root directory onto" << (myroot + "/real-root")<<endl;

    if (chroot("/") == -1)
        cout<< "cannot change root directory to "<< myroot<<endl;

    if (umount2("real-root", MNT_DETACH) == -1)
        cout<< "cannot unmount real root filesystem"<<endl;

    if (rmdir("real-root") == -1)
        cout<< "cannot remove real-root directory"<<endl;

    //constructing new argv
    const char* param[] = {"bash","-c", "source /build/env-vars;PATH=$PATH:/bin/;exec \"$@\"", "--"};
    char* myargs[argc+3];
    memcpy(myargs,param,sizeof(param));
    if(argc>2)
        memcpy(myargs+4,argv+2,(argc-2)*sizeof(char*));
    myargs[argc+2] = NULL;
    //const char* myargs[]={"bash",NULL};

    /* exec target shell */
    int ret = execv("/bin/sh",const_cast<char*const*>(myargs));
    std::cout<<"failed"<<endl;
    return ret;
}

int main(int argc, const char** argv) {
    if(_debug)std::cout << "Hello from " << argv[0] << ". I got " << argc << " arguments\n" << std::endl;
    terminalArg myarg={argc,argv};
    int original_uid = getuid();
    int original_gid = getgid();
    size_t stackSize = 1 * 1024 * 1024;
    char * stack = (char *) mmap(0, stackSize,
                                 PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) cout<<"error allocating stack"<<endl;

    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWUSER | SIGCHLD;

    pid_t child = clone(childEntry, stack + stackSize, flags, &myarg);

    /* set user namespace */
    setup_uid_gid_mapping(child, original_uid, original_gid);
    cv.notify_one();

    waitpid(child, NULL, 0);
    return 0;
}
