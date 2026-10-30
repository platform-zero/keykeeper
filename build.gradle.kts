plugins { kotlin("jvm") version "2.2.20" }

repositories { mavenCentral() }
kotlin { jvmToolchain(21) }
dependencies {
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}
tasks.test { useJUnitPlatform() }
