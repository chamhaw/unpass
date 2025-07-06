plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("kotlin-kapt")
    id("dagger.hilt.android.plugin")
}

android {
    namespace = "com.unpass.android.core.security"
    compileSdk = Versions.compileSdk

    defaultConfig {
        minSdk = Versions.minSdk
        targetSdk = Versions.targetSdk
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    // Core dependencies
    implementation(Dependencies.coreKtx)
    
    // Security
    implementation(Dependencies.biometric)
    implementation(Dependencies.androidxSecurity)
    implementation(Dependencies.bouncyCastle)
    
    // Dependency Injection
    implementation(Dependencies.hiltAndroid)
    kapt(Dependencies.hiltCompiler)
    
    // Architecture Components
    implementation(Dependencies.lifecycleRuntime)
    
    // Testing
    testImplementation(Dependencies.junit)
    testImplementation(Dependencies.mockk)
    testImplementation(Dependencies.truth)
    androidTestImplementation(Dependencies.junitExt)
    androidTestImplementation(Dependencies.espressoCore)
} 