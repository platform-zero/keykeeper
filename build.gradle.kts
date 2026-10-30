plugins { kotlin("jvm") version "2.2.20"; application }

repositories { mavenCentral() }
kotlin { jvmToolchain(21) }
dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}
application { mainClass.set("net.datamancy.keykeeper.MainKt") }
tasks.test { useJUnitPlatform() }
