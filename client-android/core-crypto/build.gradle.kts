plugins { kotlin("jvm") }
kotlin { jvmToolchain(21) }
dependencies {
    api("org.signal:libsignal-client:0.86.5")
    // native library for host-side tests only (the Android app ships libsignal-android instead)
    testRuntimeOnly("org.signal:libsignal-server:0.86.5")
    testImplementation(kotlin("test"))
}
tasks.test { useJUnitPlatform(); (project.findProperty("vectorOut") as String?)?.let { systemProperty("vector.out", it) } }
