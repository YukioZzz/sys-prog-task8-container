//
// Created by yukio on 2021/7/7.
//

#ifndef TASK8_CONTAINER_UTILS_H
#define TASK8_CONTAINER_UTILS_H

std::string dirOf(const std::string & path);
void createDirs(const std::string & path);
void writeFile(const std::string & path, std::string s, mode_t mode);
void createSymlink(const std::string & target, const std::string & link);
void chmod_(const std::string & path, mode_t mode);
void mount_(const char *source, const char *target,
            const char *filesystemtype, unsigned long mountflags,
            const void *data);

#endif //TASK8_CONTAINER_UTILS_H
