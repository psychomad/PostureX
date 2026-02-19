use axum::{
    extract::Form,
    response::{Html, Redirect},
    routing::{get, post},
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePool, Row};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tera::{Context, Tera};

#[derive(Debug, Serialize, sqlx::FromRow)]
struct SecurityEvent {
    id: i32,
    source: String,
    content: String,
    severity: String,
    detected_at: String,
}

#[derive(Deserialize)]
struct AddEmail { email: String }
#[derive(Deserialize)]
struct AddDomain { domain: String }
#[derive(Deserialize)]
struct AddIp { ip: String }

struct AppState {
    db: SqlitePool,
    templates: Tera,
}

// --- GOOGLE DORKING ENGINE ---

async fn run_google_dorks(db: &SqlitePool, domain: &str) {
    let dorks = vec![
        ("FILE_EXPOSURE", format!("site:{} filetype:pdf OR filetype:doc OR filetype:xlsx", domain)),
        ("CONFIG_LEAK", format!("site:{} ext:env OR ext:conf OR ext:log", domain)),
        ("BACKUP_FINDER", format!("site:{} ext:zip OR ext:sql OR ext:bak", domain)),
        ("ADMIN_PANELS", format!("site:{} inurl:admin OR inurl:login OR inurl:setup", domain)),
    ];

    for (code, query) in dorks {
        let dork_url = format!("https://www.google.com/search?q={}", urlencoding::encode(&query));
        let content = format!("{} -> {}", code, dork_url);

        let _ = sqlx::query("INSERT OR IGNORE INTO events (source, content, severity) VALUES (?, ?, ?)")
            .bind("GOOGLE_DORK")
            .bind(content)
            .bind("INFO")
            .execute(db).await;
    }
}

// --- MONITORAGGIO ---

async fn check_crt_sh(query: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q={}&output=json", query);
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().unwrap();
    if let Ok(resp) = client.get(url).send().await {
        if let Ok(json) = resp.json::<Vec<serde_json::Value>>().await {
            return json.iter().filter_map(|v| v["common_name"].as_str().map(|s| s.to_string())).collect();
        }
    }
    vec![]
}

async fn check_email_breaches(email: &str) -> Vec<String> {
    let mut findings = vec![];
    let client = reqwest::Client::new();
    let url_xon = format!("https://api.xposedornot.com/v1/check-email/{}", email);
    if let Ok(resp) = client.get(url_xon).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(breaches) = json["breaches"][0].as_array() {
                    for b in breaches {
                        findings.push(format!("Leak specifico: {}", b.as_str().unwrap_or("Sconosciuto")));
                    }
                }
            }
        }
    }
    findings
}

async fn run_monitoring_loop(db: SqlitePool) {
    loop {
        // Monitor Domini (SSL + Dorks)
        if let Ok(domains) = sqlx::query("SELECT domain FROM watched_domains").fetch_all(&db).await {
            for row in domains {
                let target: String = row.get(0);

                // SSL Check
                for cert in check_crt_sh(&target).await {
                    let sim = strsim::jaro_winkler(&target, &cert);
                    let severity = if sim > 0.8 && cert != target { "HIGH" } else { "INFO" };
                    let _ = sqlx::query("INSERT OR IGNORE INTO events (source, content, severity) VALUES (?, ?, ?)")
                        .bind("SSL_MONITOR").bind(format!("Cert: {} (Target: {})", cert, target)).bind(severity).execute(&db).await;
                }

                // Google Dorks
                run_google_dorks(&db, &target).await;
            }
        }

        // Monitor Email
        if let Ok(emails) = sqlx::query("SELECT email FROM watched_emails").fetch_all(&db).await {
            for row in emails {
                let email: String = row.get(0);
                for breach in check_email_breaches(&email).await {
                    let _ = sqlx::query("INSERT OR IGNORE INTO events (source, content, severity) VALUES (?, ?, ?)")
                        .bind("BREACH_DETECTOR").bind(format!("{}: {}", email, breach)).bind("HIGH").execute(&db).await;
                }
            }
        }
        sleep(Duration::from_secs(3600)).await;
    }
}

// --- HANDLERS ---

async fn dashboard_handler(Extension(state): Extension<Arc<AppState>>) -> Html<String> {
    let events = sqlx::query_as::<_, SecurityEvent>("SELECT * FROM events ORDER BY id DESC LIMIT 50").fetch_all(&state.db).await.unwrap_or_default();
    let emails: Vec<String> = sqlx::query("SELECT email FROM watched_emails").fetch_all(&state.db).await.unwrap_or_default().iter().map(|r| r.get(0)).collect();
    let domains: Vec<String> = sqlx::query("SELECT domain FROM watched_domains").fetch_all(&state.db).await.unwrap_or_default().iter().map(|r| r.get(0)).collect();
    let ips: Vec<String> = sqlx::query("SELECT ip FROM watched_ips").fetch_all(&state.db).await.unwrap_or_default().iter().map(|r| r.get(0)).collect();

    let mut ctx = Context::new();
    ctx.insert("events", &events);
    ctx.insert("watched_emails", &emails);
    ctx.insert("watched_domains", &domains);
    ctx.insert("watched_ips", &ips);
    Html(state.templates.render("index.html", &ctx).unwrap_or_else(|e| format!("Template Error: {}", e)))
}

async fn add_email_handler(Extension(state): Extension<Arc<AppState>>, Form(p): Form<AddEmail>) -> Redirect {
    let _ = sqlx::query("INSERT OR IGNORE INTO watched_emails (email) VALUES (?)").bind(p.email.to_lowercase()).execute(&state.db).await;
    Redirect::to("/")
}

async fn add_domain_handler(Extension(state): Extension<Arc<AppState>>, Form(p): Form<AddDomain>) -> Redirect {
    let _ = sqlx::query("INSERT OR IGNORE INTO watched_domains (domain) VALUES (?)").bind(p.domain.to_lowercase()).execute(&state.db).await;
    Redirect::to("/")
}

async fn add_ip_handler(Extension(state): Extension<Arc<AppState>>, Form(p): Form<AddIp>) -> Redirect {
    let _ = sqlx::query("INSERT OR IGNORE INTO watched_ips (ip) VALUES (?)").bind(p.ip).execute(&state.db).await;
    Redirect::to("/")
}

async fn clear_events_handler(Extension(state): Extension<Arc<AppState>>) -> Redirect {
    let _ = sqlx::query("DELETE FROM events").execute(&state.db).await;
    Redirect::to("/")
}

#[tokio::main]
async fn main() {
    let db = SqlitePool::connect("sqlite:posturex.db?mode=rwc").await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, content TEXT, severity TEXT, detected_at DATETIME DEFAULT CURRENT_TIMESTAMP, CONSTRAINT unique_event UNIQUE(source, content))").execute(&db).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS watched_emails (email TEXT PRIMARY KEY)").execute(&db).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS watched_domains (domain TEXT PRIMARY KEY)").execute(&db).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS watched_ips (ip TEXT PRIMARY KEY)").execute(&db).await.unwrap();

    let mut tera = Tera::default();
    tera.add_raw_template("index.html", include_str!("../templates/index.html")).unwrap();
    let state = Arc::new(AppState { db: db.clone(), templates: tera });

    let m_db = db.clone();
    tokio::spawn(async move { run_monitoring_loop(m_db).await; });

    let app = Router::new()
        .route("/", get(dashboard_handler))
        .route("/add-email", post(add_email_handler))
        .route("/add-domain", post(add_domain_handler))
        .route("/add-ip", post(add_ip_handler))
        .route("/clear-events", post(clear_events_handler))
        .layer(Extension(state));

    println!("🚀 POSTUREX Dashboard: http://localhost:3000");
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap(), app).await.unwrap();
}
