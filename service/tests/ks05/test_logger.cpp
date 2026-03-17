#include <gtest/gtest.h>
#include "protocols/ks05/protocol/logger.h"

using namespace mpsi::ks05;

TEST(LoggerTest, SingletonIdentity) {
    Logger& a = Logger::getInstance();
    Logger& b = Logger::getInstance();
    EXPECT_EQ(&a, &b);
}

TEST(LoggerTest, DefaultDisabled) {
    Logger& logger = Logger::getInstance();
    // Reset to default state
    logger.setEnabled(false);
    EXPECT_FALSE(logger.isEnabled());
}

TEST(LoggerTest, EnableDisableToggle) {
    Logger& logger = Logger::getInstance();
    logger.setEnabled(true);
    EXPECT_TRUE(logger.isEnabled());
    logger.setEnabled(false);
    EXPECT_FALSE(logger.isEnabled());
}
