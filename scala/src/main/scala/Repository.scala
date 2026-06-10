package tspu

import slick.jdbc.SQLiteProfile.api._
import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import com.typesafe.scalalogging.LazyLogging

// ─────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────

case class DomainEvent(
  id:           Long,
  clientIp:     String,
  domain:       String,
  count:        Int,
  totalSeconds: Long,
  bucketTs:     Long    // Unix timestamp rounded to the nearest hour
)

// ─────────────────────────────────────────────
// Slick table definition
// ─────────────────────────────────────────────

class DomainEventsTable(tag: Tag) extends Table[DomainEvent](tag, "domain_events") {
  def id           = column[Long]("id", O.PrimaryKey, O.AutoInc)
  def clientIp     = column[String]("client_ip")
  def domain       = column[String]("domain")
  def count        = column[Int]("count")
  def totalSeconds = column[Long]("total_seconds")
  def bucketTs     = column[Long]("bucket_ts")

  def * = (id, clientIp, domain, count, totalSeconds, bucketTs) <>
    ((DomainEvent.apply _).tupled, DomainEvent.unapply)

  def idxClientTs  = index("idx_client_ts", (clientIp, bucketTs))
  def idxDomainTs  = index("idx_domain_ts", (domain, bucketTs))
}

// ─────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────

class Repository(dbPath: String)(implicit ec: ExecutionContext) extends LazyLogging {

  private val db = Database.forURL(
    url    = s"jdbc:sqlite:$dbPath",
    driver = "org.sqlite.JDBC"
  )

  private val events = TableQuery[DomainEventsTable]

  // Create table if it doesn't exist
  def init(): Future[Unit] = {
    val schema = events.schema
    db.run(schema.createIfNotExists).map(_ =>
      logger.info(s"[Repository] DB ready at $dbPath")
    )
  }

  // Upsert: if a row with the same (clientIp, domain, bucketTs) exists, add to it
  def upsert(clientIp: String, domain: String, count: Int, totalSeconds: Long, bucketTs: Long): Future[Unit] = {
    val q = events.filter(e => e.clientIp === clientIp && e.domain === domain && e.bucketTs === bucketTs)
    db.run(q.result.headOption).flatMap {
      case Some(existing) =>
        val updated = existing.copy(
          count        = existing.count + count,
          totalSeconds = existing.totalSeconds + totalSeconds
        )
        db.run(events.filter(_.id === existing.id).update(updated)).map(_ => ())
      case None =>
        db.run(events += DomainEvent(0, clientIp, domain, count, totalSeconds, bucketTs)).map(_ => ())
    }
  }

  // Top N domains for a client in a time range
  def topDomains(clientIp: String, fromTs: Long, toTs: Long, limit: Int = 10): Future[Seq[(String, Long, Int)]] = {
    val q = events
      .filter(e => e.clientIp === clientIp && e.bucketTs >= fromTs && e.bucketTs <= toTs)
      .groupBy(_.domain)
      .map { case (dom, rows) => (dom, rows.map(_.totalSeconds).sum, rows.map(_.count).sum) }
      .sortBy(_._2.desc.nullsLast)
      .take(limit)
    db.run(q.result).map(_.map { case (d, s, c) => (d, s.getOrElse(0L), c.getOrElse(0)) })
  }

  // Activity summary for all clients in a time range (for admin dashboard)
  def clientSummary(fromTs: Long, toTs: Long): Future[Seq[(String, Long, Int)]] = {
    val q = events
      .filter(e => e.bucketTs >= fromTs && e.bucketTs <= toTs)
      .groupBy(_.clientIp)
      .map { case (ip, rows) => (ip, rows.map(_.totalSeconds).sum, rows.map(_.count).sum) }
    db.run(q.result).map(_.map { case (ip, s, c) => (ip, s.getOrElse(0L), c.getOrElse(0)) })
  }

  // Per-domain breakdown for a given client and day
  def dayBreakdown(clientIp: String, dayStartTs: Long): Future[Seq[(String, Long, Int)]] = {
    val dayEndTs = dayStartTs + 86400L
    val q = events
      .filter(e => e.clientIp === clientIp && e.bucketTs >= dayStartTs && e.bucketTs < dayEndTs)
      .groupBy(_.domain)
      .map { case (dom, rows) => (dom, rows.map(_.totalSeconds).sum, rows.map(_.count).sum) }
      .sortBy(_._2.desc.nullsLast)
    db.run(q.result).map(_.map { case (d, s, c) => (d, s.getOrElse(0L), c.getOrElse(0)) })
  }

  // CSV export: all events for a client in a time range
  def exportCsv(clientIp: String, fromTs: Long, toTs: Long): Future[String] = {
    val q = events
      .filter(e => e.clientIp === clientIp && e.bucketTs >= fromTs && e.bucketTs <= toTs)
      .sortBy(_.bucketTs)
    db.run(q.result).map { rows =>
      val header = "client_ip,domain,count,total_seconds,bucket_ts\n"
      val body = rows.map { r =>
        s"${r.clientIp},${r.domain},${r.count},${r.totalSeconds},${r.bucketTs}"
      }.mkString("\n")
      header + body
    }
  }

  // All domains for a client with pagination
  def allDomains(clientIp: String, fromTs: Long, toTs: Long,
                 search: String, sortBy: String, sortDir: String,
                 page: Int, pageSize: Int): Future[(Seq[(String, Long, Int)], Int)] = {
    val q = events
      .filter(e => e.clientIp === clientIp && e.bucketTs >= fromTs && e.bucketTs <= toTs)
      .groupBy(_.domain)
      .map { case (dom, rows) => (dom, rows.map(_.totalSeconds).sum, rows.map(_.count).sum) }

    val filtered = if (search.nonEmpty) q.filter(_._1.like(s"%$search%")) else q
    val sorted = sortBy match {
      case "count"  => if (sortDir == "asc") filtered.sortBy(_._3.asc.nullsLast)
                       else filtered.sortBy(_._3.desc.nullsLast)
      case _        => if (sortDir == "asc") filtered.sortBy(_._2.asc.nullsLast)
                       else filtered.sortBy(_._2.desc.nullsLast)
    }

    for {
      total <- db.run(filtered.length.result)
      rows  <- db.run(sorted.drop(page * pageSize).take(pageSize).result)
    } yield (rows.map { case (d, s, c) => (d, s.getOrElse(0L), c.getOrElse(0)) }, total)
  }

  def deleteByIp(ip: String): Future[Int] = {
    db.run(events.filter(_.clientIp === ip).delete)
  }

  def close(): Unit = db.close()
}