import sbt.*

object Dependencies {

  private object Versions {
    val munit = "0.7.29"
    val bouncycastle = "1.84"
    val password4j = "1.8.4"
    val auth0 = "4.5.1"
    val nimbusJwt = "10.9"
    val nimbusOidc = "11.37"
    val hedgehog = "0.13.0"
    val pureconfig = "0.17.10"
    val flyway = "12.5.0"
    val awsV2 = "2.25.57"
  }
  lazy val munit = "org.scalameta" %% "munit" % Versions.munit
  lazy val auth0 = "com.auth0" % "java-jwt" % Versions.auth0
  lazy val password4j = "com.password4j" % "password4j" % Versions.password4j

  lazy val bouncycastle =
    "org.bouncycastle" % "bcpkix-jdk18on" % Versions.bouncycastle
  lazy val bouncycastleProvider =
    "org.bouncycastle" % "bcprov-jdk18on" % Versions.bouncycastle

  lazy val nimbusdsJoseJwt =
    "com.nimbusds" % "nimbus-jose-jwt" % Versions.nimbusJwt
  lazy val nimbusdsOauth2OidcSdk =
    "com.nimbusds" % "oauth2-oidc-sdk" % Versions.nimbusOidc

  lazy val hedgehogSbt =
    "qa.hedgehog" %% "hedgehog-sbt" % Versions.hedgehog % Test
  // https://hedgehog.qa/
  lazy val hedgehogCore =
    "qa.hedgehog" %% "hedgehog-core" % Versions.hedgehog % Test

  lazy val pureconfig =
    "com.github.pureconfig" %% "pureconfig-core" % Versions.pureconfig
  lazy val pureconfigGeneric =
    "com.github.pureconfig" %% "pureconfig-generic-scala3" % Versions.pureconfig
  lazy val flyway = "org.flywaydb" % "flyway-core" % Versions.flyway
  lazy val rds = "software.amazon.awssdk" % "rds" % Versions.awsV2
}
