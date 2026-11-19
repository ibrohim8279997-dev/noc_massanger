rootProject.name = "noc-client"
pluginManagement { repositories { google(); gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
include(":core-crypto", ":core-client", ":core-mesh", ":app")
