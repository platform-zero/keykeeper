plugins { kotlin("jvm") version "2.2.20"; application; jacoco }

repositories { mavenCentral() }
kotlin { jvmToolchain(21) }
dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}
application { mainClass.set("net.datamancy.keykeeper.MainKt") }
jacoco { toolVersion = "0.8.13" }
tasks.test { useJUnitPlatform(); finalizedBy(tasks.jacocoTestCoverageVerification) }
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports { xml.required.set(true); html.required.set(true) }
}
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.jacocoTestReport)
    violationRules {
        rule {
            element = "BUNDLE"
            limit { counter = "LINE"; value = "COVEREDRATIO"; minimum = "0.90".toBigDecimal() }
        }
    }
}
tasks.check { dependsOn(tasks.jacocoTestCoverageVerification) }

// Deliberately separate from test/check and JaCoCo's offline unit-test denominator.
val realBaoTest by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output + configurations.testRuntimeClasspath.get()
    runtimeClasspath += output + compileClasspath
}
configurations[realBaoTest.implementationConfigurationName].extendsFrom(configurations.testImplementation.get())
configurations[realBaoTest.runtimeOnlyConfigurationName].extendsFrom(configurations.testRuntimeOnly.get())
tasks.register<Test>("realBaoTest") {
    description = "Opt-in integration test against an operator-provided disposable loopback OpenBao KV-v2 mount"
    group = "verification"
    testClassesDirs = realBaoTest.output.classesDirs
    classpath = realBaoTest.runtimeClasspath
    useJUnitPlatform()
    onlyIf { providers.gradleProperty("localBaoTest").orNull == "true" }
}
