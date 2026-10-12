plugins {
    // AGP 9.0 起内置 Kotlin 支持，不再需要单独的 Kotlin 插件
    id("com.android.application")
}

/**
 * 接入参数从 gradle 属性读，缺省为空。
 *
 * 本地：写进 gradle.properties（**不要提交**）
 * CI  ：在 GitHub Actions 里用 -P 传入，值来自 Repository Secrets
 */
fun prop(name: String, def: String = ""): String =
    (project.findProperty(name) as String?)?.takeIf { it.isNotBlank() } ?: def

android {
    namespace = "com.rainauth.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.rainauth.demo"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"

        // 只打 arm64 与模拟器用的 x86_64，控制体积
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-fvisibility=hidden", "-fno-exceptions")
                // 发布包剥离符号，抬高静态分析门槛
                arguments += listOf("-DCMAKE_BUILD_TYPE=Release")
            }
        }

        buildConfigField("String", "RAINAUTH_BASE_URL", "\"${prop("RAINAUTH_BASE_URL")}\"")
        buildConfigField("String", "RAINAUTH_APP_KEY", "\"${prop("RAINAUTH_APP_KEY")}\"")
        buildConfigField("String", "RAINAUTH_APP_SECRET", "\"${prop("RAINAUTH_APP_SECRET")}\"")
        buildConfigField("String", "RAINAUTH_X25519_PUB", "\"${prop("RAINAUTH_X25519_PUB")}\"")
        buildConfigField("String", "RAINAUTH_ED25519_PUB", "\"${prop("RAINAUTH_ED25519_PUB")}\"")
    }

    externalNativeBuild {
        cmake {
            path = file("CMakeLists.txt")
            version = "3.22.1"
        }
    }

    signingConfigs {
        // 演示用途：release 也用 debug 签名，便于直接安装测试。
        // 正式产品必须换成自己的 keystore。
        create("demo") {
            storeFile = file("demo.keystore")
            storePassword = "rainauth"
            keyAlias = "rainauth"
            keyPassword = "rainauth"
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            // 混淆 + 资源压缩：抬高静态分析成本（不构成防护）
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("demo")
            ndk {
                debugSymbolLevel = "none"
            }
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf(
            "META-INF/versions/**",
            "META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA",
        )
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // X25519 / Ed25519 / ChaCha20-Poly1305 / HKDF
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
}
