#include <gtest/gtest.h>
#include "core/config_file.h"

#include <fstream>
#include <cstdio>
#include <string>

namespace {

// Helper to write a temp file and return its path.
std::string writeTempFile(const std::string& content) {
    char path[] = "/tmp/test_config_XXXXXX";
    int fd = mkstemp(path);
    EXPECT_NE(fd, -1);
    FILE* f = fdopen(fd, "w");
    EXPECT_NE(f, nullptr);
    fputs(content.c_str(), f);
    fclose(f);
    return path;
}

} // namespace

TEST(ConfigFileTest, ParseBasicKeyValue) {
    auto path = writeTempFile("host = localhost\nport = 8080\n");
    auto cfg = mpsi::parseConfigFile(path);
    EXPECT_EQ(cfg["host"], "localhost");
    EXPECT_EQ(cfg["port"], "8080");
    std::remove(path.c_str());
}

TEST(ConfigFileTest, SkipsComments) {
    auto path = writeTempFile("# this is a comment\nkey = value\n");
    auto cfg = mpsi::parseConfigFile(path);
    EXPECT_EQ(cfg.size(), 1u);
    EXPECT_EQ(cfg["key"], "value");
    std::remove(path.c_str());
}

TEST(ConfigFileTest, SkipsBlankLines) {
    auto path = writeTempFile("\n\n  \nkey = value\n\n");
    auto cfg = mpsi::parseConfigFile(path);
    EXPECT_EQ(cfg.size(), 1u);
    EXPECT_EQ(cfg["key"], "value");
    std::remove(path.c_str());
}

TEST(ConfigFileTest, TrimsWhitespace) {
    auto path = writeTempFile("  key  =  value  \n");
    auto cfg = mpsi::parseConfigFile(path);
    EXPECT_EQ(cfg["key"], "value");
    std::remove(path.c_str());
}

TEST(ConfigFileTest, ThrowsOnMissingFile) {
    EXPECT_THROW(mpsi::parseConfigFile("/tmp/no_such_config_file_12345.conf"),
                 std::runtime_error);
}

TEST(ConfigFileTest, EmptyValue) {
    auto path = writeTempFile("key =\n");
    auto cfg = mpsi::parseConfigFile(path);
    EXPECT_EQ(cfg["key"], "");
    std::remove(path.c_str());
}
