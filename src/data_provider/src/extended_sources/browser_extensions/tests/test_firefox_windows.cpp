/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "browser_extensions_wrapper.hpp"
#include "firefox.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <filesystem>
#include <fstream>
#include <set>

class MockBrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        MOCK_METHOD(std::string, getApplicationsPath, (), (override));
        MOCK_METHOD(std::string, getHomePath, (), (override));
        MOCK_METHOD(std::string, getUserId, (std::string), (override));
};

TEST(FirefoxAddonsTests, NumberOfExtensions)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = (std::filesystem::path(__FILE__).parent_path() / "windows").string();

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return("123"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(9));
}

TEST(FirefoxAddonsTests, CollectReturnsExpectedJson)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = (std::filesystem::path(__FILE__).parent_path() / "windows").string();

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return("123"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();

    for (const auto& jsonElement : extensionsJson)
    {
        if (jsonElement.contains("name") && jsonElement["name"] == "Add-ons Search Detection")
        {
            EXPECT_EQ(jsonElement["active"], true);
            EXPECT_EQ(jsonElement["autoupdate"], true);
            EXPECT_EQ(jsonElement["creator"], "");
            EXPECT_EQ(jsonElement["description"], "");
            EXPECT_EQ(jsonElement["disabled"], false);
            EXPECT_EQ(jsonElement["identifier"], "addons-search-detection@mozilla.com");
            EXPECT_EQ(jsonElement["location"], "app-builtin-addons");
            EXPECT_EQ(jsonElement["name"], "Add-ons Search Detection");
            EXPECT_EQ(jsonElement["path"], "");
            EXPECT_EQ(jsonElement["source_url"], "");
            EXPECT_EQ(jsonElement["type"], "extension");
            EXPECT_EQ(jsonElement["uid"], "123");
            EXPECT_EQ(jsonElement["version"], "2.0.0");
            EXPECT_EQ(jsonElement["visible"], true);
        }
    }
}

class FirefoxAddonsMultiProfileTests : public ::testing::Test
{
    protected:
        std::filesystem::path m_homePath;

        void SetUp() override
        {
            m_homePath = std::filesystem::temp_directory_path() / "firefox_multi_profile_test";
            std::filesystem::remove_all(m_homePath);
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_homePath);
        }

        void writeProfile(const std::string& profileName, const std::string& extensionsJson)
        {
            const auto dir = m_homePath / "user" / std::filesystem::path(FIREFOX_PATHS.front()) / profileName;
            std::filesystem::create_directories(dir);
            std::ofstream file(dir / FIREFOX_ADDONS_FILE);
            file << extensionsJson;
        }
};

// Regression test for wazuh/wazuh#40313: Firefox's generic add-on "location"
// values (app-builtin, app-builtin-addons, app-profile) are shared across
// profiles, so the provider must report the real profile directory and name.
// Otherwise the same built-in add-on from two profiles shares one inventory
// key and the inventory flaps.
TEST_F(FirefoxAddonsMultiProfileTests, SameBuiltinAddonInTwoProfilesHasDistinctProfilePaths)
{
    const std::string addonsJson =
        R"({"addons": [{"id": "newtab@mozilla.org", "version": "151.2",
                        "location": "app-profile", "path": "extensions/newtab@mozilla.org.xpi",
                        "defaultLocale": {"name": "New Tab"}}]})";
    writeProfile("aaaa.default", addonsJson);
    writeProfile("bbbb.default", addonsJson);

    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(m_homePath.string()));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return("0"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(2));

    std::set<std::string> profilePaths;

    for (const auto& jsonElement : extensionsJson)
    {
        EXPECT_EQ(jsonElement["identifier"], "newtab@mozilla.org");
        EXPECT_FALSE(jsonElement["profile"].get<std::string>().empty());
        EXPECT_FALSE(jsonElement["profile_path"].get<std::string>().empty());
        // The inventory profile path must be the real profile directory, never
        // Firefox's generic location label.
        EXPECT_NE(jsonElement["profile_path"], "app-profile");
        EXPECT_NE(jsonElement["profile_path"].get<std::string>().find(jsonElement["profile"].get<std::string>()),
                  std::string::npos);
        profilePaths.insert(jsonElement["profile_path"].get<std::string>());
    }

    EXPECT_EQ(profilePaths.size(), static_cast<size_t>(2));
}
