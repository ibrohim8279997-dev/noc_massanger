plugins { kotlin("jvm") }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
kotlin { jvmToolchain(21); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies {
    api(project(":core-crypto"))
    api("com.squareup.okhttp3:okhttp:4.12.0")
    compileOnly("org.json:json:20240303")          // Android already ships org.json
    testImplementation("org.json:json:20240303")
    testRuntimeOnly("org.signal:libsignal-server:0.86.5")
    testImplementation(kotlin("test"))
}
tasks.test { systemProperty("noc.oqs.jni", rootDir.parentFile.resolve("third_party/jni-host/libnocoqs.so").path); useJUnitPlatform(); maxHeapSize = "1g" }
