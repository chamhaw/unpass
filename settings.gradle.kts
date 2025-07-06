pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "UnPass"

// 主应用模块
include(":app")

// 核心模块
include(":core-security")
include(":core-database")
include(":core-crypto")
include(":core-ui")

// 功能模块
include(":feature-auth")
include(":feature-vault")
include(":feature-settings")
include(":feature-export") 