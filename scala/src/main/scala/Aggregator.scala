package tspu

import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport._
import spray.json._
import spray.json.DefaultJsonProtocol._
import scala.concurrent.{ExecutionContext, Future, Await}
import scala.concurrent.duration._
import scala.util.{Success, Failure, Try}
import com.typesafe.scalalogging.LazyLogging
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

// ─────────────────────────────────────────────
// JSON protocol
// ─────────────────────────────────────────────

case class DomainStat(domain: String, count: Int, totalSeconds: Long)
case class IngestPayload(ip: String, ts: Long, domains: Seq[DomainStat])

// Rule envelope received from Redis pub/sub
case class RuleMsg(action: String, rule: Option[JsObject], id: Option[String])

object JsonProtocol extends DefaultJsonProtocol {
  implicit val domainStatFmt:    RootJsonFormat[DomainStat]    = jsonFormat3(DomainStat)
  implicit val ingestPayloadFmt: RootJsonFormat[IngestPayload] = jsonFormat3(IngestPayload)
}

// ─────────────────────────────────────────────
// Rule cache — thread-safe in-memory mirror
// Updated via Redis pub/sub without restart
// ─────────────────────────────────────────────

object RuleCache extends LazyLogging {
  // id -> rule JSON string
  private val rules = new ConcurrentHashMap[String, JsObject]()
  // Monotonic revision counter — ignore messages with lower version
  @volatile private var revision: Long = 0L

  def add(rule: JsObject): Unit = {
    val id = rule.fields.get("id").map(_.convertTo[String]).getOrElse(return)
    rules.put(id, rule)
    revision += 1
    logger.info(s"[RuleCache] Added rule $id (rev=$revision)")
  }

  def remove(id: String): Unit = {
    rules.remove(id)
    revision += 1
    logger.info(s"[RuleCache] Removed rule $id (rev=$revision)")
  }

  def getAll: List[JsObject] = {
    import scala.jdk.CollectionConverters._
    rules.values().asScala.toList
  }

  def currentRevision: Long = revision

  // Check if a domain has a block_after_minutes rule for this client
  // Returns limit in seconds, or None if no rule matches
  def limitSecondsFor(clientIp: String, domain: String): Option[Int] = {
    import scala.jdk.CollectionConverters._
    rules.values().asScala.find { rule =>
      val rDomain  = rule.fields.get("domain").map(_.convertTo[String]).getOrElse("")
      val rAction  = rule.fields.get("action").map(_.convertTo[String]).getOrElse("")
      val rScope   = rule.fields.get("scope").map(_.convertTo[String]).getOrElse("global")
      val rTarget  = rule.fields.get("target").map(_.convertTo[String]).getOrElse("*")
      rAction == "block_after_minutes" &&
      domainMatches(rDomain, domain) &&
      ipMatches(rScope, rTarget, clientIp)
    }.flatMap(_.fields.get("minutes").map(_.convertTo[Int] * 60))
  }

  private def domainMatches(pattern: String, domain: String): Boolean =
    if (pattern.startsWith("~"))
      domain.matches(pattern.drop(1))
    else if (pattern.startsWith("*."))
      domain.endsWith(pattern.drop(1)) || domain == pattern.drop(2)
    else
      pattern == domain || pattern == "*"

  private def ipMatches(scope: String, target: String, ip: String): Boolean = scope match {
    case "global" => true
    case "ip"     => target == ip
    case _        => true   // subnet matching omitted for brevity
  }
}

// ─────────────────────────────────────────────
// Redis pub/sub subscriber for rule updates
// ─────────────────────────────────────────────

class RuleSubscriber(redisHost: String, redisPort: Int) extends LazyLogging {

  // Jedis pub/sub listener — called on the blocking subscribe thread
  private class Listener extends redis.clients.jedis.JedisPubSub {
    override def onMessage(channel: String, message: String): Unit = {
      Try(message.parseJson.asJsObject).foreach { obj =>
        val action = obj.fields.get("action").map(_.convertTo[String]).getOrElse("")
        action match {
          case "add" =>
            obj.fields.get("rule").foreach {
              case r: JsObject => RuleCache.add(r)
              case _           =>
            }
          case "remove" =>
            obj.fields.get("id").foreach(id => RuleCache.remove(id.convertTo[String]))
          case "reload_all" =>
            obj.fields.get("rules").foreach {
              case JsArray(rs) => rs.foreach { case r: JsObject => RuleCache.add(r); case _ => }
              case _           =>
            }
          case _ =>
            logger.warn(s"[RuleSubscriber] Unknown action: $action")
        }
      }
    }
  }

  def start()(implicit ec: ExecutionContext): Unit = {
    Future {
      while (true) {
        Try {
          val jedis = new redis.clients.jedis.Jedis(redisHost, redisPort)
          logger.info("[RuleSubscriber] Connected to Redis via Jedis, subscribing to tspu_rules")
          // subscribe blocks until unsubscribed or connection drops
          jedis.subscribe(new Listener, "tspu_rules")
          jedis.close()
        }.recover { case ex =>
          logger.warn(s"[RuleSubscriber] Redis error: ${ex.getMessage}, reconnecting in 5s")
        }
        Thread.sleep(5000)
      }
    }
    ()
  }
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

object Main extends LazyLogging {
  def main(args: Array[String]): Unit = {
  import JsonProtocol._

  implicit val system: ActorSystem[Nothing] = ActorSystem(Behaviors.empty, "tspu-aggregator")
  implicit val ec: ExecutionContext = system.executionContext

  val dbPath    = sys.env.getOrElse("DB_PATH",    "/var/lib/tspu_x/stats.db")
  val redisHost = sys.env.getOrElse("REDIS_HOST", "127.0.0.1")
  val redisPort = sys.env.getOrElse("REDIS_PORT", "6379").toInt

  val repo = new Repository(dbPath)
  // Wait synchronously for DB init — must complete before Http binds
  Try(Await.result(repo.init(), 30.seconds)) match {
    case scala.util.Success(_)  => logger.info("[Main] Repository initialised")
    case scala.util.Failure(ex) => logger.error("[Main] Repository init failed: " + ex.getMessage)
  }

  // Subscribe to rule updates from Redis
  new RuleSubscriber(redisHost, redisPort).start()

  // ─── Main API routes ──────────────────────

  val mainRoutes = concat(

    path("api" / "ingest") {
      post {
        entity(as[IngestPayload]) { payload =>
          val bucketTs = (payload.ts / 3600) * 3600
          payload.domains.foreach { ds =>
            repo.upsert(payload.ip, ds.domain, ds.count, ds.totalSeconds, bucketTs)
            // Check rule: if limit exceeded, log a warning (Elixir handles the block command)
            RuleCache.limitSecondsFor(payload.ip, ds.domain).foreach { limitSecs =>
              if (ds.totalSeconds > limitSecs)
                logger.warn(s"[Main] Limit exceeded ip=${payload.ip} domain=${ds.domain} secs=${ds.totalSeconds} limit=$limitSecs")
            }
          }
          complete(JsObject("status" -> JsString("ok")))
        }
      }
    },

    // GET /api/domains?ip=...&from=...&to=...&search=...&sort=seconds|count&dir=desc|asc&page=0&size=20
    path("api" / "domains") {
      get {
        parameters(
          "ip",
          "from".as[Long].withDefault(0L),
          "to".as[Long].withDefault(9999999999L),
          "search".withDefault(""),
          "sort".withDefault("seconds"),
          "dir".withDefault("desc"),
          "page".as[Int].withDefault(0),
          "size".as[Int].withDefault(20)
        ) { (ip, fromTs, toTs, search, sort, dir, page, size) =>
          onSuccess(repo.allDomains(ip, fromTs, toTs, search, sort, dir, page, size)) {
            case (rows, total) =>
              complete(JsObject(
                "total" -> JsNumber(total),
                "page"  -> JsNumber(page),
                "size"  -> JsNumber(size),
                "rows"  -> JsArray(rows.map { case (d, s, c) =>
                  JsObject("domain" -> JsString(d), "totalSeconds" -> JsNumber(s), "count" -> JsNumber(c))
                }.toVector)
              ))
          }
        }
      }
    },

    path("api" / "top") {
      get {
        parameters("ip", "from".as[Long], "to".as[Long], "limit".as[Int].withDefault(10)) {
          (ip, fromTs, toTs, limit) =>
            onSuccess(repo.topDomains(ip, fromTs, toTs, limit)) { rows =>
              complete(JsArray(rows.map { case (d, s, c) =>
                JsObject("domain" -> JsString(d), "totalSeconds" -> JsNumber(s), "count" -> JsNumber(c))
              }.toVector))
            }
        }
      }
    },

    path("api" / "clients") {
      get {
        parameters("from".as[Long], "to".as[Long]) { (from, to) =>
          onSuccess(repo.clientSummary(from, to)) { rows =>
            complete(JsArray(rows.map { case (ip, s, c) =>
              JsObject("ip" -> JsString(ip), "totalSeconds" -> JsNumber(s), "count" -> JsNumber(c))
            }.toVector))
          }
        }
      }
    },

    path("api" / "day") {
      get {
        parameters("ip", "day".as[Long]) { (ip, dayTs) =>
          onSuccess(repo.dayBreakdown(ip, dayTs)) { rows =>
            complete(JsArray(rows.map { case (d, s, c) =>
              JsObject("domain" -> JsString(d), "totalSeconds" -> JsNumber(s), "count" -> JsNumber(c))
            }.toVector))
          }
        }
      }
    },

    path("api" / "export") {
      get {
        parameters("ip", "from".as[Long], "to".as[Long]) { (ip, from, to) =>
          onSuccess(repo.exportCsv(ip, from, to)) { csv =>
            complete(akka.http.scaladsl.model.HttpResponse(
              entity = akka.http.scaladsl.model.HttpEntity(
                akka.http.scaladsl.model.ContentTypes.`text/csv(UTF-8)`, csv
              )
            ))
          }
        }
      }
    },

    // Rules mirror (read-only)
    path("api" / "rules") {
      get {
        complete(JsArray(RuleCache.getAll.map(_.toJson).toVector))
      }
    },

    // DELETE /api/stats?ip=... — remove all records for a client IP
    path("api" / "stats") {
      delete {
        parameters("ip") { ip =>
          onSuccess(repo.deleteByIp(ip)) { count =>
            complete(JsObject("deleted" -> JsNumber(count), "ip" -> JsString(ip)))
          }
        }
      }
    },

    path("health") {
      get { complete(JsObject("status" -> JsString("ok"), "component" -> JsString("scala"))) }
    }
  )

  // ─── Metrics / health on separate port 8081 ──

  val metricsRoutes = concat(
    path("health") {
      get {
        complete(JsObject(
          "status"    -> JsString("ok"),
          "component" -> JsString("scala"),
          "rules"     -> JsNumber(RuleCache.getAll.size),
          "rule_rev"  -> JsNumber(RuleCache.currentRevision)
        ))
      }
    },
    path("metrics") {
      get {
        complete(JsObject(
          "rule_count"      -> JsNumber(RuleCache.getAll.size),
          "rule_revision"   -> JsNumber(RuleCache.currentRevision)
        ))
      }
    }
  )

  val host = sys.env.getOrElse("SCALA_HOST", "0.0.0.0")
  val port = sys.env.getOrElse("SCALA_PORT", "8080").toInt
  val metricsPort = sys.env.getOrElse("SCALA_METRICS_PORT", "8081").toInt

  Http().newServerAt(host, port).bind(mainRoutes).onComplete {
    case Success(b) => logger.info(s"[Main] Main API on ${b.localAddress}")
    case Failure(e) => logger.error("[Main] Main API failed", e); system.terminate()
  }

  Http().newServerAt(host, metricsPort).bind(metricsRoutes).onComplete {
    case Success(b) => logger.info(s"[Main] Metrics on ${b.localAddress}")
    case Failure(e) => logger.warn(s"[Main] Metrics server failed: ${e.getMessage}")
  }
  }
}