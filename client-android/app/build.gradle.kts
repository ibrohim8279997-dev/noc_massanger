plugins {
    id("com.android.application")
    kotlin("android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "noc.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "noc.messenger"
        minSdk = 30; targetSdk = 35; versionCode = 1; versionName = "0.1"
        ndk { abiFilters += listOf("arm64-v8a") }
    }
    // Sideload build: signed with the local debug key. Create your own key before wider distribution.
    buildTypes { release { isMinifyEnabled = false; signingConfig = signingConfigs.getByName("debug") } }
    compileOptions { isCoreLibraryDesugaringEnabled = true; sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true; buildConfig = true }
    packaging { jniLibs.useLegacyPackaging = true; jniLibs.excludes += "**/libsignal_jni_testing.so"
        resources.excludes += listOf("libsignal_jni*", "signal_jni*", "**/*.dylib", "**/*.dll") }
}
dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
    implementation(project(":core-client")) { exclude(group = "org.signal", module = "libsignal-client") }
    implementation("org.signal:libsignal-android:0.86.5")
    implementation("net.zetetic:sqlcipher-android:4.6.1")
    implementation("androidx.sqlite:sqlite:2.4.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.11.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    testImplementation(kotlin("test"))
}
