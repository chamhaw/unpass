// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.application") version "8.1.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.10" apply false
    id("com.android.library") version "8.1.2" apply false
    id("com.google.dagger.hilt.android") version "2.48" apply false
    id("io.gitlab.arturbosch.detekt") version "1.23.1" apply false
    id("org.jlleitschuh.gradle.ktlint") version "11.6.1" apply false
    id("org.jetbrains.kotlin.jvm") version "1.9.10" apply false
    id("kotlin-kapt") apply false
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "io.gitlab.arturbosch.detekt")
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    
    ktlint {
        android.set(true)
        ignoreFailures.set(false)
        reporters {
            reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.PLAIN)
            reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.CHECKSTYLE)
            reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.SARIF)
        }
    }
    
    detekt {
        config = files("${rootDir}/config/detekt/detekt.yml")
        buildUponDefaultConfig = true
        parallel = true
        reports {
            html.enabled = true
            xml.enabled = true
            txt.enabled = true
            sarif.enabled = true
        }
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
} 