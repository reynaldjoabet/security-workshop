import Dependencies._

ThisBuild / scalaVersion := "3.3.8"
ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / semanticdbEnabled := true

ThisBuild / scalacOptions := Seq(
  "-encoding",
  "UTF-8",
  "-no-indent",
  "-deprecation",
  "-feature",
  "-unchecked",
  "-source:3.3",
  "-java-output-version:17",
  "-Werror",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Xlint:all",
  "-Ysafe-init",
  "-Xcheck-macros",
  "-Xmax-inlines:64"
)

Global / onChangedBuildSource := ReloadOnSourceChanges

// ── Publishing ────────────────────────────────────────────────────────────────
publishMavenStyle := true
licenses := Seq(License.Apache2)
homepage := Some(url("https://github.com/example/mcp-playground"))

// ── Caching ───────────────────────────────────────────────────────────────────
// All tasks are cached by default in sbt 2.x (local machine-wide disk cache).
// To add a Bazel-compatible remote cache backend, add `addRemoteCachePlugin`
// to project/plugins.sbt and set:
//   Global / remoteCache := Some(uri("grpc://your-cache-host:2024"))
// For tasks with non-serializable result types, opt out with Def.uncached:
//   myTask := Def.uncached { ... }

// ── Root project ──────────────────────────────────────────────────────────────
lazy val root = rootProject
  .settings(
    name := "security-workshop",
    libraryDependencies ++= Seq(
      munit % Test,
      bouncycastle,
      bouncycastleProvider,
      password4j,
      auth0,
      nimbusdsJoseJwt,
      nimbusdsOauth2OidcSdk,
      hedgehogSbt,
      hedgehogCore,
      pureconfig,
      pureconfigGeneric,
      flyway,
      rds
    )
    // exportJars defaults to true in sbt 2.x; set false if getResource("/") breaks
    // exportJars := false,
  )
