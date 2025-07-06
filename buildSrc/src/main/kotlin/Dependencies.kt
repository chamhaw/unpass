object Versions {
    const val compileSdk = 34
    const val targetSdk = 34
    const val minSdk = 24
    const val versionCode = 1
    const val versionName = "1.0.0"
    
    // Kotlin & Android
    const val kotlin = "1.9.10"
    const val coreKtx = "1.12.0"
    const val appCompat = "1.6.1"
    const val material = "1.9.0"
    const val constraintLayout = "2.1.4"
    const val fragmentKtx = "1.6.1"
    const val activityKtx = "1.8.0"
    
    // Architecture Components
    const val lifecycle = "2.7.0"
    const val viewModel = "2.7.0"
    const val liveData = "2.7.0"
    const val navigation = "2.7.2"
    
    // Database
    const val room = "2.5.0"
    const val sqlCipher = "4.5.4"
    
    // Dependency Injection
    const val hilt = "2.48"
    const val hiltNavigationCompose = "1.0.0"
    
    // Networking
    const val retrofit = "2.9.0"
    const val okHttp = "4.11.0"
    const val moshi = "1.15.0"
    
    // Security & Crypto
    const val biometric = "1.1.0"
    const val androidxSecurity = "1.0.0"
    const val bouncyCastle = "1.76"
    
    // UI & Design
    const val compose = "1.5.4"
    const val composeBom = "2023.10.01"
    const val accompanist = "0.32.0"
    
    // Testing
    const val junit = "4.13.2"
    const val junitExt = "1.1.5"
    const val espresso = "3.5.1"
    const val mockk = "1.13.8"
    const val truth = "1.1.4"
    const val robolectric = "4.10.3"
    
    // Build & Tools
    const val gradle = "8.1.2"
    const val detekt = "1.23.1"
    const val ktlint = "11.6.1"
    const val jacoco = "0.8.8"
}

object Dependencies {
    // Android Core
    const val coreKtx = "androidx.core:core-ktx:${Versions.coreKtx}"
    const val appCompat = "androidx.appcompat:appcompat:${Versions.appCompat}"
    const val material = "com.google.android.material:material:${Versions.material}"
    const val constraintLayout = "androidx.constraintlayout:constraintlayout:${Versions.constraintLayout}"
    const val fragmentKtx = "androidx.fragment:fragment-ktx:${Versions.fragmentKtx}"
    const val activityKtx = "androidx.activity:activity-ktx:${Versions.activityKtx}"
    
    // Architecture Components
    const val lifecycleRuntime = "androidx.lifecycle:lifecycle-runtime-ktx:${Versions.lifecycle}"
    const val lifecycleViewModel = "androidx.lifecycle:lifecycle-viewmodel-ktx:${Versions.viewModel}"
    const val lifecycleLiveData = "androidx.lifecycle:lifecycle-livedata-ktx:${Versions.liveData}"
    const val navigationFragment = "androidx.navigation:navigation-fragment-ktx:${Versions.navigation}"
    const val navigationUi = "androidx.navigation:navigation-ui-ktx:${Versions.navigation}"
    
    // Database
    const val roomRuntime = "androidx.room:room-runtime:${Versions.room}"
    const val roomCompiler = "androidx.room:room-compiler:${Versions.room}"
    const val roomKtx = "androidx.room:room-ktx:${Versions.room}"
    const val sqlCipher = "net.zetetic:android-database-sqlcipher:${Versions.sqlCipher}"
    
    // Dependency Injection
    const val hiltAndroid = "com.google.dagger:hilt-android:${Versions.hilt}"
    const val hiltCompiler = "com.google.dagger:hilt-compiler:${Versions.hilt}"
    const val hiltNavigationCompose = "androidx.hilt:hilt-navigation-compose:${Versions.hiltNavigationCompose}"
    
    // Security & Crypto
    const val biometric = "androidx.biometric:biometric:${Versions.biometric}"
    const val androidxSecurity = "androidx.security:security-crypto:${Versions.androidxSecurity}"
    const val bouncyCastle = "org.bouncycastle:bcprov-jdk15on:${Versions.bouncyCastle}"
    
    // Compose
    const val composeBom = "androidx.compose:compose-bom:${Versions.composeBom}"
    const val composeUi = "androidx.compose.ui:ui"
    const val composeUiTooling = "androidx.compose.ui:ui-tooling"
    const val composeUiToolingPreview = "androidx.compose.ui:ui-tooling-preview"
    const val composeMaterial3 = "androidx.compose.material3:material3"
    const val composeActivity = "androidx.activity:activity-compose:${Versions.activityKtx}"
    
    // Testing
    const val junit = "junit:junit:${Versions.junit}"
    const val junitExt = "androidx.test.ext:junit:${Versions.junitExt}"
    const val espressoCore = "androidx.test.espresso:espresso-core:${Versions.espresso}"
    const val mockk = "io.mockk:mockk:${Versions.mockk}"
    const val truth = "com.google.truth:truth:${Versions.truth}"
    const val robolectric = "org.robolectric:robolectric:${Versions.robolectric}"
    const val roomTesting = "androidx.room:room-testing:${Versions.room}"
    const val hiltTesting = "com.google.dagger:hilt-android-testing:${Versions.hilt}"
    const val composeUiTest = "androidx.compose.ui:ui-test-junit4"
    const val composeUiTestManifest = "androidx.compose.ui:ui-test-manifest"
} 