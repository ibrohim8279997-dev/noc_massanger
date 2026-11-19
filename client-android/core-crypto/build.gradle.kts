plugins { kotlin("jvm") }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
kotlin { jvmToolchain(21); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies {
    api("org.signal:libsignal-client:0.86.5")
    api("org.bouncycastle:bcprov-jdk18on:1.80")   // Ed25519 on every Android version
    // native library for host-side tests only (the Android app ships libsignal-android instead)
    testRuntimeOnly("org.signal:libsignal-server:0.86.5")
    testImplementation(kotlin("test"))
}
tasks.test { useJUnitPlatform(); (project.findProperty("vectorOut") as String?)?.let { systemProperty("vector.out", it) } }
