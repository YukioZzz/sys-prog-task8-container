//
// Created by yukio on 2021/7/7.
//
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <sys/mount.h>
#include "utils.h"

std::string dirOf(const std::string & path)
{
    std::string::size_type pos = path.rfind('/');
    if (pos == std::string::npos)
        return ".";
    return pos == 0 ? "/" : std::string(path, 0, pos);
}

void createDirs(const std::string & path)
{
    if (path == "/") return;

    struct stat st;
    if (lstat(path.c_str(), &st) == -1) {
        createDirs(dirOf(path));
        if (mkdir(path.c_str(), 0777) == -1 && errno != EEXIST)
            std::cout<<"error creating directory "<<path<<std::endl;
    }

    return;
}

void writeFile(const std::string & path, std::string s, mode_t mode)
{
    int fd;
    if(mode&O_CREAT)fd = open(path.c_str(), mode, 0755);
    else fd = open(path.c_str(), mode);
    if(mode&O_WRONLY && write (fd, s.data(), s.size()) == -1)
            std::cout<<"error wring to file " << path << " : "<<std::strerror(errno)<< std::endl;
    close(fd);
}

void createSymlink(const std::string & target, const std::string & link)
{
    if (symlink(target.c_str(), link.c_str()))
        std::cout << "creating symlink from " << link << " to " << target << std::endl;
}

void chmod_(const std::string & path, mode_t mode)
{
    if (chmod(path.c_str(), mode) == -1)
        std::cout<<"setting permissions on "<<path<<std::endl;
}

void mount_(const char *source, const char *target,
            const char *filesystemtype, unsigned long mountflags,
            const void *data)
{
    if(mount(source, target, filesystemtype, mountflags, data)==-1){
        std::cout<<"mounting "<<target<<std::endl;perror("error");
    }
    else{
        //std::cout<<"success mounting "<<target<<std::endl;
    }
}