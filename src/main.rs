use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use bcrypt::{hash, DEFAULT_COST};  // Import bcrypt
use bcrypt::verify;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use dotenv::dotenv;
use std::env;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use prettytable::{Table, row, cell};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use chrono::NaiveDateTime;


#[derive(Serialize, Deserialize, Debug)]
struct TypeDataPost {
    id: i32,
    nama_lengkap: String,
    email: String,
    password: String,
    tanggal_lahir: String,
    umur: i32,
    pekerjaan: String,
    golongan_darah: String,
    jenis_kelamin: String,
    status: Option<String>,     
    is_verified: bool,
}

#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
struct TypeDataGet {
    id: i32,
    nama_lengkap: String,
    email: String,
    password: String,
    tanggal_lahir: String,
    umur: i32,
    pekerjaan: String,
    golongan_darah: String,
    jenis_kelamin: String,
    status: Option<String>, 
    is_verified: bool,

}




async fn get_users(pool: web::Data<PgPool>) -> impl Responder {
    println!("Fetching users...");

    let query = "SELECT id, nama_lengkap, email, password, tanggal_lahir, umur, pekerjaan, golongan_darah, jenis_kelamin, status, is_verified, created_at, updated_at FROM users";


    let users: Result<Vec<TypeDataGet>, sqlx::Error> = sqlx::query_as::<_, TypeDataGet>(query)
        .fetch_all(pool.get_ref())
        .await;

    match users {
        Ok(users) => {
            HttpResponse::Ok().json(users)  // Return the users as JSON
        },
        Err(e) => {
            println!("Database error: {}", e);
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        }
    }
}



async fn post_users(
    data: web::Json<TypeDataPost>,
    pool: web::Data<PgPool>
) -> impl Responder {
    println!("Received data: {:?}", data);

    // Encrypt the password
    let hashed_password = match hash(&data.password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(e) => {
            println!("Password hashing error: {}", e);
            return HttpResponse::InternalServerError().body("Password hashing failed");
        }
    };

    // Generate a numeric OTP
    let otp: String = thread_rng()
        .sample_iter(&rand::distributions::Uniform::from(0..10)) // Digits from 0 to 9
        .take(6) // Length of OTP
        .map(|d| char::from_digit(d, 10).unwrap())
        .collect();

    println!("Generated OTP: {}", otp);

    // Send OTP via email
    match send_email(&data.email, "Your OTP Code", &format!("Your OTP code is: {}", otp)).await {
        Ok(_) => println!("OTP sent to {}", data.email),
        Err(e) => {
            println!("Failed to send OTP: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to send OTP");
        }
    };

    let query = "
        INSERT INTO users (id, nama_lengkap, email, password, tanggal_lahir, umur, pekerjaan, golongan_darah, jenis_kelamin, otp, status, is_verified)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING created_at, updated_at
    ";
    println!("Executing query: {}", query);

    let result = sqlx::query(query)
        .bind(data.id)
        .bind(&data.nama_lengkap)
        .bind(&data.email)
        .bind(&hashed_password)  // Simpan password yang sudah di-hash
        .bind(&data.tanggal_lahir)
        .bind(data.umur)
        .bind(&data.pekerjaan)
        .bind(&data.golongan_darah)
        .bind(&data.jenis_kelamin)
        .bind(&otp)  // Simpan OTP yang sudah dihasilkan
        .bind(&data.status)
        .bind(data.is_verified)
        .execute(pool.get_ref()).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(data.into_inner()),
        Err(e) => {
            println!("Database error: {}", e);
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        },
    }
}


async fn put_user(
    user_id: web::Path<i32>,
    data: web::Json<TypeDataPost>,
    pool: web::Data<PgPool>
) -> impl Responder {
    println!("Updating user with ID: {:?}", user_id);

    // Encrypt the password
    let hashed_password = match hash(&data.password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(e) => {
            println!("Password hashing error: {}", e);
            return HttpResponse::InternalServerError().body("Password hashing failed");
        }
    };

    let query = "UPDATE users SET nama_lengkap = $1, email = $2, password = $3, tanggal_lahir = $4, umur = $5, pekerjaan = $6, golongan_darah = $7, jenis_kelamin = $8, status = $9, is_verified = $10 WHERE id = $11 RETURNING updated_at";

    match sqlx::query(query)
        .bind(&data.nama_lengkap)
        .bind(&data.email)
        .bind(&hashed_password)  // Simpan password yang sudah di-hash
        .bind(&data.tanggal_lahir)
        .bind(data.umur)
        .bind(&data.pekerjaan)
        .bind(&data.golongan_darah)
        .bind(&data.jenis_kelamin)
        .bind(&data.status)
        .bind(&data.is_verified)
        .bind(user_id.into_inner())
        .execute(pool.get_ref()).await {
            Ok(_) => {
                println!("User updated successfully");
                HttpResponse::Ok().json(data.into_inner())
            },
            Err(e) => {
                println!("Database error: {}", e);
                HttpResponse::InternalServerError().body(format!("Database error: {}", e))
            },
    }
}

async fn patch_user(
    user_id: web::Path<i32>,
    data: web::Json<Value>,
    pool: web::Data<PgPool>
) -> impl Responder {
    println!("Patching user with ID: {:?}", user_id);

    let mut query = String::from("UPDATE users SET ");
    let mut params: Vec<String> = Vec::new();
    let mut idx = 1;

    for (key, value) in data.as_object().unwrap() {
        if key == "password" {
            // Handle password encryption
            let hashed_password = match hash(value.as_str().unwrap(), DEFAULT_COST) {
                Ok(hashed) => hashed,
                Err(e) => {
                    println!("Password hashing error: {}", e);
                    return HttpResponse::InternalServerError().body("Password hashing failed");
                }
            };
            params.push(hashed_password);
        } else {
            params.push(value.to_string());
        }

        if idx > 1 {
            query.push_str(", ");
        }
        query.push_str(&format!("{} = ${}", key, idx));
        idx += 1;
    }

    query.push_str(&format!(" WHERE id = ${}", idx));

    let mut sql_query = sqlx::query(&query);
    for (i, param) in params.iter().enumerate() {
        sql_query = sql_query.bind(param);
    }
    sql_query = sql_query.bind(user_id.into_inner());

    match sql_query.execute(pool.get_ref()).await {
        Ok(_) => {
            println!("User patched successfully");
            HttpResponse::Ok().finish()
        },
        Err(e) => {
            println!("Database error: {}", e);
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        }
    }
}

async fn delete_user(
    user_id: web::Path<i32>,  // Ganti TypeDataGet dengan Path<i32> untuk menerima ID dari URL
    pool: web::Data<PgPool>
) -> impl Responder {
    let user_id = user_id.into_inner();
    println!("Deleting user with ID: {}", user_id);

    let query = "DELETE FROM users WHERE id = $1";

    match sqlx::query(query)
        .bind(user_id)
        .execute(pool.get_ref())
        .await {
            Ok(_) => {
                println!("User deleted successfully");
                HttpResponse::Ok().body(format!("User with ID {} deleted", user_id))
            },
            Err(e) => {
                println!("Database error: {}", e);
                HttpResponse::InternalServerError().body(format!("Database error: {}", e))
            },
    }
}

#[derive(Deserialize)]
struct VerifyOtp {
    email: String,
    otp: String,
}

async fn verify_user(
    data: web::Json<VerifyOtp>,
    pool: web::Data<PgPool>
) -> impl Responder {
    let email = &data.email;
    let otp = &data.otp;

    // Query to fetch the user's OTP and verification status from the database
    let query = "SELECT otp, is_verified FROM users WHERE email = $1";
    let result: Result<(String, bool), sqlx::Error> = sqlx::query_as(query)
        .bind(email)
        .fetch_one(pool.get_ref()).await;

    match result {
        Ok((stored_otp, is_verified)) if stored_otp == *otp && !is_verified => {
            // Update the is_verified field to true
            let update_query = "UPDATE users SET is_verified = TRUE WHERE email = $1";
            match sqlx::query(update_query)
                .bind(email)
                .execute(pool.get_ref()).await {
                    Ok(_) => HttpResponse::Ok().body("user berhasil terverifikasi"),
                    Err(e) => {
                        println!("Database error: {}", e);
                        HttpResponse::InternalServerError().body(format!("Database error: {}", e))
                    }
            }
        },
        Ok((_, true)) => HttpResponse::BadRequest().body("Already verified"),
        _ => HttpResponse::BadRequest().body("Invalid OTP or email"),
    }
}

async fn send_email(to: &str, subject: &str, body: &str) -> Result<(), lettre::transport::smtp::Error> {
    let email = Message::builder()
        .from("eridayalma999@gmail.com".parse().unwrap())
        .to(to.parse().unwrap()) // Use the provided recipient email
        .subject(subject)
        .body(body.to_string())
        .unwrap();

    let creds = Credentials::new(
        String::from("eridayalma999@gmail.com"),
        String::from("qqzjftjsxmlqxgul"), // Ensure this is the correct application-specific password
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .port(465) // Port for SSL
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => {
            println!("Email sent successfully to {}", to);
            Ok(())
        },
        Err(e) => {
            eprintln!("Failed to send email: {:?}", e);
            Err(e)
        }
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();


    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    println!("Connecting to database at {}", database_url);
    let pool = PgPool::connect(&database_url).await.expect("Failed to connect to database");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/users", web::get().to(get_users))
            .route("/users", web::post().to(post_users))
            .route("/users/{id}", web::put().to(put_user))
            .route("/users/{id}", web::patch().to(patch_user))
            .route("/users/{id}", web::delete().to(delete_user))
            .route("/verify_otp", web::post().to(verify_user))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}