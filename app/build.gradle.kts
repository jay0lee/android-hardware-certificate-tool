import java.text.SimpleDateFormat
import java.util.Date

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.jaylee.hardware_cert_tool"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.jaylee.hardware_cert_tool"
        minSdk = 31
        targetSdk = 34

        // --- VERSIONING LOGIC ---
        val date = Date()
        val baseFormat = SimpleDateFormat("yyMMddHH").format(date)
        val minuteTens = SimpleDateFormat("mm").format(date).toInt() / 10
        val combinedCode = "$baseFormat$minuteTens".toInt()
        
        versionCode = combinedCode
        versionName = combinedCode.toString()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    
    // Lifecycle & Coroutines (CRITICAL for Fragments)
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.fragment:fragment-ktx:1.6.2") 

    // Cryptography
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.76") 

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
