plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("kotlin-kapt")
    id("dagger.hilt.android.plugin")
}

android {
    namespace = "com.unpass.android.feature.settings"
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
    
    buildFeatures {
        compose = true
    }
    
    composeOptions {
        kotlinCompilerExtensionVersion = Versions.compose
    }
}

dependencies {
    // Core modules
    implementation(project(":core-security"))
    implementation(project(":core-database"))
    implementation(project(":core-ui"))
    
    // Android Core
    implementation(Dependencies.coreKtx)
    implementation(Dependencies.appCompat)
    implementation(Dependencies.material)
    implementation(Dependencies.fragmentKtx)
    implementation(Dependencies.activityKtx)
    
    // Compose
    implementation(platform(Dependencies.composeBom))
    implementation(Dependencies.composeUi)
    implementation(Dependencies.composeUiToolingPreview)
    implementation(Dependencies.composeMaterial3)
    implementation(Dependencies.composeActivity)
    
    // Architecture Components
    implementation(Dependencies.lifecycleRuntime)
    implementation(Dependencies.lifecycleViewModel)
    implementation(Dependencies.navigationFragment)
    implementation(Dependencies.navigationUi)
    
    // Dependency Injection
    implementation(Dependencies.hiltAndroid)
    implementation(Dependencies.hiltNavigationCompose)
    kapt(Dependencies.hiltCompiler)
    
    // Testing
    testImplementation(Dependencies.junit)
    testImplementation(Dependencies.mockk)
    testImplementation(Dependencies.truth)
    testImplementation(Dependencies.hiltTesting)
    androidTestImplementation(Dependencies.junitExt)
    androidTestImplementation(Dependencies.espressoCore)
    androidTestImplementation(platform(Dependencies.composeBom))
    androidTestImplementation(Dependencies.composeUiTest)
    
    debugImplementation(Dependencies.composeUiTooling)
    debugImplementation(Dependencies.composeUiTestManifest)
} 