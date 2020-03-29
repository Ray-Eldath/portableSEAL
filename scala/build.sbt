name := "scala"

version := "0.1"

scalaVersion := "2.13.1"

PB.protoSources in Compile := Seq(file("../proto/src/main/proto"))

PB.targets in Compile := Seq(
  scalapb.gen() -> (sourceManaged in Compile).value
)

libraryDependencies ++= Seq(
  "io.grpc" % "grpc-netty" % scalapb.compiler.Version.grpcJavaVersion,
  "com.thesamet.scalapb" %% "scalapb-runtime-grpc" % scalapb.compiler.Version.scalapbVersion,
  "org.scalatest" %% "scalatest" % "3.1.1" % "test"
)