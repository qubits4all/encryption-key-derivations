name := "client-side-encryption"

version := "0.1"

scalaVersion := "2.13.3"

// https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.66"

// https://mvnrepository.com/artifact/commons-codec/commons-codec
libraryDependencies += "commons-codec" % "commons-codec" % "1.14"
// https://mvnrepository.com/artifact/org.apache.commons/commons-crypto
libraryDependencies += "org.apache.commons" % "commons-crypto" % "1.0.0"

// https://mvnrepository.com/artifact/com.google.code.findbugs/jsr305
libraryDependencies += "com.google.code.findbugs" % "jsr305" % "3.0.2"
