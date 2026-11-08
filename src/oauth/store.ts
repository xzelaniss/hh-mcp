import pg from "pg";
import { hash, randomSecret } from "./security.js";

export interface Queryable {
  query(sql: string, values?: unknown[]): Promise<{ rows: any[] }>;
}
export interface Database extends Queryable {
  transaction<T>(fn: (db: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
export function postgresOptions(connection: string): pg.PoolConfig {
  try {
    const url = new URL(connection);
    if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password || url.pathname.length < 2) throw new Error();
    // Do not pass a connectionString to pg: its query options can override an
    // explicit ssl object, host, credentials and timeouts. Only these URL fields
    // are accepted, and TLS verification is always enabled.
    return { host: url.hostname.replace(/^\[|\]$/g, ""), port: Number(url.port || 5432),
      user: decodeURIComponent(url.username), password: decodeURIComponent(url.password), database: decodeURIComponent(url.pathname.slice(1)),
      ssl: { rejectUnauthorized: true }, enableChannelBinding: true,
      max: 3, connectionTimeoutMillis: 10000, idleTimeoutMillis: 10000,
      statement_timeout: 10000, query_timeout: 12000 };
  } catch { throw new Error("Set MCP_OAUTH_DATABASE_URL to a PostgreSQL connection URL."); }
}
export function postgresDatabase(connection: string): Database {
  const pool = new pg.Pool(postgresOptions(connection));
  pool.on("error", () => { console.error("[hh-mcp] OAuth database connection unavailable"); });
  return {
    query: (sql, values) => pool.query(sql, values),
    async transaction(fn) {
      const client = await pool.connect();
      try { await client.query("BEGIN"); const result = await fn(client); await client.query("COMMIT"); return result; }
      catch (error) { await client.query("ROLLBACK"); throw error; }
      finally { client.release(); }
    },
    close: () => pool.end(),
  };
}

export interface Authorization {
  redirect: string; state: string; challenge: string; scope: string; resource: string;
}
export interface Flow { params: Authorization; cookie_hash: string; csrf_hash: string }
export interface Tokens { access_token: string; token_type: "Bearer"; expires_in: number; refresh_token?: string; scope: string }

export class OAuthStore {
  constructor(readonly db: Database, readonly version: string) {}
  async init() {
    const schema = `
      CREATE TABLE IF NOT EXISTS hh_oauth_flows (
        id text PRIMARY KEY, version text NOT NULL, cookie_hash text NOT NULL,
        csrf_hash text NOT NULL, params jsonb NOT NULL, expires_at timestamptz NOT NULL);
      CREATE TABLE IF NOT EXISTS hh_oauth_families (
        id text PRIMARY KEY, version text NOT NULL, revoked boolean NOT NULL DEFAULT false,
        expires_at timestamptz NOT NULL);
      CREATE TABLE IF NOT EXISTS hh_oauth_grants (
        id text PRIMARY KEY, family text NOT NULL REFERENCES hh_oauth_families(id) ON DELETE CASCADE,
        kind text NOT NULL, payload jsonb NOT NULL, used boolean NOT NULL DEFAULT false,
        expires_at timestamptz NOT NULL);
      CREATE INDEX IF NOT EXISTS hh_oauth_grants_family ON hh_oauth_grants(family);
      CREATE TABLE IF NOT EXISTS hh_oauth_limits (
        id text PRIMARY KEY, count integer NOT NULL, expires_at timestamptz NOT NULL);
    `;
    await this.db.transaction(async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(293724617)");
      for (const statement of schema.split(";").map((s) => s.trim()).filter(Boolean)) await db.query(statement);
    });
    await this.cleanup();
  }
  async cleanup() {
    await this.db.query("DELETE FROM hh_oauth_flows WHERE expires_at <= clock_timestamp()");
    await this.db.query("DELETE FROM hh_oauth_families WHERE expires_at <= clock_timestamp()");
    await this.db.query("DELETE FROM hh_oauth_limits WHERE expires_at <= clock_timestamp()");
    // Keep consumed codes/refresh tokens until family expiry for replay detection.
    await this.db.query("DELETE FROM hh_oauth_grants WHERE kind = 'access' AND expires_at <= clock_timestamp()");
  }
  async limit(bucket: string, max: number, seconds: number): Promise<boolean> {
    const result = await this.db.query(`INSERT INTO hh_oauth_limits(id,count,expires_at)
      VALUES($1,1,clock_timestamp() + $2 * interval '1 second')
      ON CONFLICT(id) DO UPDATE SET
        count=CASE WHEN hh_oauth_limits.expires_at <= clock_timestamp() THEN 1 ELSE hh_oauth_limits.count+1 END,
        expires_at=CASE WHEN hh_oauth_limits.expires_at <= clock_timestamp() THEN EXCLUDED.expires_at ELSE hh_oauth_limits.expires_at END
      RETURNING count`, [hash(this.version + bucket), seconds]);
    return result.rows[0].count <= max;
  }
  async createFlow(id: string, cookie: string, csrf: string, params: Authorization) {
    await this.db.query(`INSERT INTO hh_oauth_flows VALUES($1,$2,$3,$4,$5,clock_timestamp() + interval '10 minutes')`,
      [hash(id), this.version, hash(cookie), hash(csrf), JSON.stringify(params)]);
  }
  async flow(id: string): Promise<Flow | undefined> {
    const result = await this.db.query(`SELECT params,cookie_hash,csrf_hash FROM hh_oauth_flows
      WHERE id=$1 AND version=$2 AND expires_at > clock_timestamp()`, [hash(id), this.version]);
    return result.rows[0];
  }
  async approve(id: string, cookie: string, csrf: string): Promise<{ code: string; params: Authorization } | undefined> {
    return this.db.transaction(async (db) => {
      const result = await db.query(`DELETE FROM hh_oauth_flows WHERE id=$1 AND version=$2 AND cookie_hash=$3 AND csrf_hash=$4
        AND expires_at > clock_timestamp() RETURNING params`, [hash(id), this.version, hash(cookie), hash(csrf)]);
      if (!result.rows.length) return undefined;
      const code = randomSecret(), family = randomSecret();
      const params = result.rows[0].params as Authorization;
      await db.query(`INSERT INTO hh_oauth_families(id,version,expires_at) VALUES($1,$2,clock_timestamp() + interval '7 days')`, [family, this.version]);
      await db.query(`INSERT INTO hh_oauth_grants(id,family,kind,payload,expires_at)
        VALUES($1,$2,'code',$3,clock_timestamp() + interval '60 seconds')`, [hash(code), family, JSON.stringify(params)]);
      return { code, params };
    });
  }
  async exchange(kind: "code" | "refresh", token: string, binding: { resource: string; redirect?: string; challenge?: string; scope?: string }): Promise<Tokens | undefined> {
    return this.db.transaction(async (db) => {
      const result = await db.query(`SELECT g.*, f.revoked, f.expires_at AS family_expires,
          (g.expires_at > clock_timestamp() AND f.expires_at > clock_timestamp()) AS live,
          CEIL(EXTRACT(EPOCH FROM (f.expires_at - clock_timestamp()))) AS remaining_seconds
        FROM hh_oauth_grants g JOIN hh_oauth_families f ON f.id=g.family
        WHERE g.id=$1 AND g.kind=$2 AND f.version=$3 FOR UPDATE OF g,f`, [hash(token), kind, this.version]);
      const grant = result.rows[0];
      if (!grant || grant.revoked) return undefined;
      const payload = grant.payload as Authorization;
      if (binding.resource !== payload.resource ||
        (kind === "code" && (binding.redirect !== payload.redirect || binding.challenge !== payload.challenge))) return undefined;
      const scope = binding.scope ?? payload.scope;
      if (!scope.split(" ").includes("mcp:tools") || scope.split(" ").some((s) => !payload.scope.split(" ").includes(s))) return undefined;
      if (grant.used) {
        await db.query("UPDATE hh_oauth_families SET revoked=true WHERE id=$1", [grant.family]);
        return undefined;
      }
      if (!grant.live) return undefined;
      // Re-check the deadline AFTER acquiring locks, using the DB's wall clock
      // rather than PostgreSQL's transaction-start timestamp.
      const consumed = await db.query(`UPDATE hh_oauth_grants SET used=true
        WHERE id=$1 AND expires_at > clock_timestamp() AND $2::timestamptz > clock_timestamp() RETURNING id`, [grant.id, grant.family_expires]);
      if (!consumed.rows.length) return undefined;
      const access = randomSecret(), refresh = randomSecret();
      await db.query(`INSERT INTO hh_oauth_grants(id,family,kind,payload,expires_at)
        VALUES($1,$2,'access',$3,LEAST(clock_timestamp() + interval '15 minutes',$4))`,
      [hash(access), grant.family, JSON.stringify({ ...payload, scope }), grant.family_expires]);
      const offline = payload.scope.split(" ").includes("offline_access");
      if (offline) await db.query(`INSERT INTO hh_oauth_grants(id,family,kind,payload,expires_at)
        VALUES($1,$2,'refresh',$3,$4)`, [hash(refresh), grant.family, JSON.stringify(payload), grant.family_expires]);
      return { access_token: access, token_type: "Bearer", expires_in: Math.min(900, Math.max(0, Number(grant.remaining_seconds))),
        ...(offline ? { refresh_token: refresh } : {}), scope };
    });
  }
  async access(token: string, resource: string): Promise<boolean> {
    const result = await this.db.query(`SELECT 1 FROM hh_oauth_grants g JOIN hh_oauth_families f ON f.id=g.family
      WHERE g.id=$1 AND g.kind='access' AND f.version=$2 AND NOT f.revoked
      AND g.expires_at > clock_timestamp() AND f.expires_at > clock_timestamp()
      AND g.payload->>'resource'=$3 AND string_to_array(g.payload->>'scope',' ') @> ARRAY['mcp:tools']`, [hash(token), this.version, resource]);
    return !!result.rows.length;
  }
  async revoke(token: string) {
    await this.db.query(`UPDATE hh_oauth_families SET revoked=true WHERE version=$2 AND id IN
      (SELECT family FROM hh_oauth_grants WHERE id=$1 AND kind IN ('access','refresh'))`, [hash(token), this.version]);
  }
  close() { return this.db.close(); }
}
