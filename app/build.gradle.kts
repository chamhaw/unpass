plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("kotlin-kapt")
    id("dagger.hilt.android.plugin")
    id("kotlin-parcelize")
}

android {
    namespace = "com.unpass.android"
    compileSdk = Versions.compileSdk

    defaultConfig {
        applicationId = "com.unpass.android"
        minSdk = Versions.minSdk
        targetSdk = Versions.targetSdk
        versionCode = Versions.versionCode
        versionName = Versions.versionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            isMinifyEnabled = false
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    
    kotlinOptions {
        jvmTarget = "1.8"
    }
    
    buildFeatures {
        compose = true
        buildConfig = true
    }
    
    composeOptions {
        kotlinCompilerExtensionVersion = Versions.compose
    }
    
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Core modules
    implementation(project(":core-security"))
    implementation(project(":core-database"))
    implementation(project(":core-crypto"))
    implementation(project(":core-ui"))
    
    // Feature modules
    implementation(project(":feature-auth"))
    implementation(project(":feature-vault"))
    implementation(project(":feature-settings"))
    implementation(project(":feature-export"))
    
    // Android Core
    implementation(Dependencies.coreKtx)
    implementation(Dependencies.appCompat)
    implementation(Dependencies.material)
    implementation(Dependencies.activityKtx)
    
    // Architecture Components
    implementation(Dependencies.lifecycleRuntime)
    implementation(Dependencies.lifecycleViewModel)
    implementation(Dependencies.navigationFragment)
    implementation(Dependencies.navigationUi)
    
    // Compose
    implementation(platform(Dependencies.composeBom))
    implementation(Dependencies.composeUi)
    implementation(Dependencies.composeUiToolingPreview)
    implementation(Dependencies.composeMaterial3)
    implementation(Dependencies.composeActivity)
    
    // Dependency Injection
    implementation(Dependencies.hiltAndroid)
    implementation(Dependencies.hiltNavigationCompose)
    kapt(Dependencies.hiltCompiler)
    
    // Security
    implementation(Dependencies.biometric)
    implementation(Dependencies.androidxSecurity)
    
    // Testing
    testImplementation(Dependencies.junit)
    testImplementation(Dependencies.mockk)
    testImplementation(Dependencies.truth)
    testImplementation(Dependencies.robolectric)
    testImplementation(Dependencies.hiltTesting)
    
    androidTestImplementation(Dependencies.junitExt)
    androidTestImplementation(Dependencies.espressoCore)
    androidTestImplementation(Dependencies.hiltTesting)
    androidTestImplementation(platform(Dependencies.composeBom))
    androidTestImplementation(Dependencies.composeUiTest)
    
    debugImplementation(Dependencies.composeUiTooling)
    debugImplementation(Dependencies.composeUiTestManifest)
} 