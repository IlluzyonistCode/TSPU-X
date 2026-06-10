ThisBuild / version      := "1.0.0"
ThisBuild / scalaVersion := "2.13.12"
ThisBuild / organization := "tspu"

lazy val root = (project in file("."))
  .settings(
    name := "tspu-aggregator",
    libraryDependencies ++= Seq(
      "com.typesafe.akka"          %% "akka-stream"              % "2.8.5",
      "com.typesafe.akka"          %% "akka-actor-typed"         % "2.8.5",
      "com.typesafe.akka"          %% "akka-http"                % "10.5.3",
      "com.typesafe.akka"          %% "akka-http-spray-json"     % "10.5.3",
      "com.typesafe.slick"         %% "slick"                    % "3.4.1",
      "com.typesafe.slick"         %% "slick-hikaricp"           % "3.4.1",
      "org.xerial"                  % "sqlite-jdbc"              % "3.44.1.0",
      // Jedis — стандартный Java Redis клиент, pub/sub API хорошо задокументирован
      "redis.clients"               % "jedis"                    % "5.1.0",
      "ch.qos.logback"              % "logback-classic"          % "1.4.11",
      "net.logstash.logback"        % "logstash-logback-encoder" % "7.4",
      "com.typesafe.scala-logging" %% "scala-logging"            % "3.9.5"
    ),
    assembly / mainClass := Some("tspu.Main"),
    assembly / assemblyMergeStrategy := {
      case PathList("META-INF", "MANIFEST.MF") => MergeStrategy.discard
      case PathList("META-INF", _*)            => MergeStrategy.discard
      case PathList("reference.conf")          => MergeStrategy.concat
      case _                                   => MergeStrategy.first
    }
  )
