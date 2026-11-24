group = "com.bankguard.sdk"
version = "1.0-SNAPSHOT"

plugins {
    id("com.android.library")
    id("kotlin-android")
}

repositories {
    google()
    mavenCentral()
}

android {
    namespace = "com.bankguard.sdk"
    compileSdk = 34

    defaultConfig {
        minSdk = 21

        // NDK: Build native RASP library for all supported ABIs
        ndk {
            abiFilters += listOf("arm64-v8a")
        }

        // CMake: Build the C++ RASP layer
        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                arguments += "-DANDROID_STL=c++_shared"
            }
        }
    }

    // Point Gradle to the CMakeLists.txt for native builds
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.8.22")
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.16.0")
}
