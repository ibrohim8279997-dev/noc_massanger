rootProject.name = "noc-client"
pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement { repositories { mavenCentral() } }
// Android modules (app, core-storage, core-net, core-security) are added once an Android SDK is available.
include(":core-crypto")
