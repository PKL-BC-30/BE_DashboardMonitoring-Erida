use actix_web::{web, App, HttpServer, HttpResponse, Responder, Error as ActixError};
use serde::{Serialize, Deserialize};
use tokio_postgres::{NoTls, Client, Error};
use bcrypt::{hash, verify, DEFAULT_COST};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use actix_cors::Cors;
use serde_json::json;
use std::collections::HashMap;


// Structs

#[derive(Serialize)]
struct ResponseMessage {
    message: String,
}

#[derive(Serialize)]
struct AgeCategory {
    category_0_5: i64,
    category_6_12: i64,
    category_13_17: i64,
    category_18_20: i64,
    category_21_59: i64,
    category_60_plus: i64,
}


#[derive(Serialize)]
struct UserDetails {
    total_users: i64,
    male: i64,
    female: i64,
}

#[derive(Serialize)]
struct User {
    id: i32,
    nama_lengkap: String,
    email: String,
    password: String,
    tanggal_lahir: String,
    umur: i32,
    pekerjaan: String,
    golongan_darah: String,
    jenis_kelamin: String,
    pertanyaan: String,
    jawaban: String,
    status: String, 
    provinsi: Option<String>,         // Added
    kabupaten: Option<String>,        // Added
    kecamatan: Option<String> 
}

#[derive(Deserialize)]
struct NewUser {
    nama_lengkap: String,
    email: String,
    password: String,
    tanggal_lahir: String,
    umur: i32,
    pekerjaan: String,
    golongan_darah: String,
    jenis_kelamin: String,
    pertanyaan: String,
    jawaban: String,
    provinsi: Option<String>,         // Added
    kabupaten: Option<String>,        // Added
    kecamatan: Option<String> 
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    email_verified: bool,
    nama_lengkap: String,
}

#[derive(Deserialize)]
struct ForgotPasswordRequest {
    email: String,
    pertanyaan: String,
}

#[derive(Deserialize)]
struct ResetPasswordRequest {
    email: String,
    pertanyaan: String,
    jawaban: String,
    new_password: String,
}


#[derive(Deserialize)]
struct VerifyRequest {
    otp: String,
}


// Functions
fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect()
}

async fn fetch_umur_chart() -> impl Responder {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match get_umur_chart(&client).await {
        Ok(chart) => HttpResponse::Ok().json(chart),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn get_umur_chart(client: &Client) -> Result<AgeCategory, Error> {
    // Query for each umur category
    let category_0_5 = client
        .query_one("SELECT COUNT(*) FROM users WHERE umur BETWEEN 0 AND 5", &[])
        .await?
        .get(0);

    let category_6_12 = client
        .query_one("SELECT COUNT(*) FROM users WHERE umur BETWEEN 6 AND 12", &[])
        .await?
        .get(0);

    let category_13_17 = client
        .query_one("SELECT COUNT(*) FROM users WHERE umur BETWEEN 13 AND 17", &[])
        .await?
        .get(0);

    let category_18_20 = client
        .query_one("SELECT COUNT(*) FROM users WHERE umur BETWEEN 18 AND 20", &[])
        .await?
        .get(0);

    let category_21_59 = client
        .query_one("SELECT COUNT(*) FROM users WHERE umur BETWEEN 21 AND 59", &[])
        .await?
        .get(0);

    let category_60_plus = client
        .query_one("SELECT COUNT(*) FROM users WHERE umur >= 60", &[])
        .await?
        .get(0);

    Ok(AgeCategory {
        category_0_5,
        category_6_12,
        category_13_17,
        category_18_20,
        category_21_59,
        category_60_plus,
    })
}


async fn fetch_user_details() -> impl Responder {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match get_user_details(&client).await {
        Ok(details) => HttpResponse::Ok().json(details),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
  
async fn get_user_details(client: &Client) -> Result<UserDetails, Error> {
    // Query to count total users
    let total_users = client
        .query_one("SELECT COUNT(*) FROM users", &[])
        .await?
        .get(0);

    // Query to count female users
    let female = client
        .query_one("SELECT COUNT(*) FROM users WHERE jenis_kelamin = 'Perempuan'", &[])
        .await?
        .get(0);

    // Query to count male users
    let male = client
        .query_one("SELECT COUNT(*) FROM users WHERE jenis_kelamin = 'Laki-Laki'", &[])
        .await?
        .get(0);

    Ok(UserDetails {
        total_users,
        male,
        female,
    })
}

// Fungsi untuk mengubah password dengan validasi email, pertanyaan, dan jawaban
async fn change_password(data: web::Json<ResetPasswordRequest>) -> Result<HttpResponse, ActixError> {
    let email = &data.email;
    let pertanyaan = &data.pertanyaan;
    let jawaban = &data.jawaban; // gunakan otp field untuk menyimpan jawaban
    let new_password = &data.new_password;

    let hashed_password = match hash(&new_password, DEFAULT_COST) {
        Ok(hp) => hp,
        Err(_) => return Ok(HttpResponse::InternalServerError().json("Error hashing password")),
    };

    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let statement = client.prepare("UPDATE users SET password = $1 WHERE email = $2 AND pertanyaan = $3 AND jawaban = $4").await.unwrap();
    match client.execute(&statement, &[&hashed_password, &email, &pertanyaan, &jawaban]).await {
        Ok(count) if count > 0 => Ok(HttpResponse::Ok().json("Password successfully changed")),
        _ => Ok(HttpResponse::NotFound().json("Invalid email, question, or answer")),
    }
}

async fn send_registration_email(email: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from("eridayalma999@gmail.com".parse()?)
        .to(email.parse()?)
        .subject("Registration Confirmation")
        .body(format!(
            "Thank you for registering! Your OTP is: {}",
            otp,
        ))
        .unwrap();

    let creds = Credentials::new("eridayalma999@gmail.com".to_string(), "qqzjftjsxmlqxgul".to_string());

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

async fn forgot_password(data: web::Json<ForgotPasswordRequest>) -> Result<HttpResponse, ActixError> {
    let email = &data.email;

    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Generate OTP or token
    let otp = generate_otp(); // You can also use a token if preferred

    let statement = client.prepare("UPDATE users SET reset_token = $1, otp = $2 WHERE email = $3").await.unwrap();
    match client.execute(&statement, &[&Uuid::new_v4().to_string(), &otp, &email]).await {
        Ok(count) if count > 0 => {
            if let Err(e) = send_reset_password_email(email, &otp).await {
                eprintln!("Error sending email: {}", e);
            }
            Ok(HttpResponse::Ok().json("Reset password email sent"))
        },
        _ => Ok(HttpResponse::NotFound().json("Email not found")),
    }
}

async fn send_reset_password_email(email: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from("eridayalma999@gmail.com".parse()?)
        .to(email.parse()?)
        .subject("Password Reset Request")
        .body(format!(
            "You requested to reset your password. Your OTP is: {}",
            otp,
        ))
        .unwrap();

    let creds = Credentials::new("eridayalma999@gmail.com".to_string(), "qqzjftjsxmlqxgul".to_string());

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}


async fn get_users(client: &Client) -> Result<Vec<User>, Error> {
    let mut users = Vec::new();

    let rows = client.query(
        "SELECT id, nama_lengkap, email, password, tanggal_lahir, umur, pekerjaan, golongan_darah, jenis_kelamin, pertanyaan, jawaban, status, provinsi, kabupaten, kecamatan
        FROM users 
        WHERE email_verified = TRUE", 
        &[]
    ).await?;

    for row in rows {
        let user = User {
            id: row.get(0),
            nama_lengkap: row.get(1),
            email: row.get(2),
            password: row.get(3),
            tanggal_lahir: row.get(4),
            umur: row.get(5),
            pekerjaan: row.get(6),
            golongan_darah: row.get(7),
            jenis_kelamin: row.get(8),
            pertanyaan: row.get(9),
            jawaban: row.get(10),
            status: row.get(11), // Add this line
            provinsi: row.get(12),
            kabupaten:row.get(13),
            kecamatan: row.get(14)

        };
        users.push(user);
    }

    Ok(users)
}


async fn fetch_users() -> impl Responder {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match get_users(&client).await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn verify_otp(data: web::Json<VerifyRequest>) -> Result<HttpResponse, ActixError> {
    let otp = &data.otp;

    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let statement = client.prepare(
        "UPDATE users 
         SET email_verified = TRUE
         WHERE otp = $1"
    ).await.map_err(|e| {
        eprintln!("Failed to prepare statement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to prepare statement")
    })?;

    match client.execute(&statement, &[&otp]).await {
        Ok(count) if count > 0 => Ok(HttpResponse::Ok().json(ResponseMessage {
            message: "Email verified successfully".into(),
        })),
        Ok(_) => Ok(HttpResponse::NotFound().json(ResponseMessage {
            message: "Invalid OTP".into(),
        })),
        Err(e) => {
            eprintln!("Error executing query: {}", e);
            Ok(HttpResponse::InternalServerError().json(ResponseMessage {
                message: "Failed to verify OTP".into(),
            }))
        }
    }
}

#[derive(Serialize)]
struct BloodTypeCategory {
    A: i64,
    B: i64,
    AB: i64,
    O: i64,
}

async fn get_blood_type_chart(client: &Client) -> Result<BloodTypeCategory, Error> {
    let A: i64 = client
        .query_one("SELECT COUNT(*) FROM users WHERE golongan_darah = 'A'", &[])
        .await?
        .get(0);

    let B: i64 = client
        .query_one("SELECT COUNT(*) FROM users WHERE golongan_darah = 'B'", &[])
        .await?
        .get(0);

    let AB: i64 = client
        .query_one("SELECT COUNT(*) FROM users WHERE golongan_darah = 'AB'", &[])
        .await?
        .get(0);

    let O: i64 = client
        .query_one("SELECT COUNT(*) FROM users WHERE golongan_darah = 'O'", &[])
        .await?
        .get(0);


    Ok(BloodTypeCategory {
        A,
        B,
        AB,
        O,
    })
}

#[derive(Serialize)]
struct GenderCategory {
    perempuan: i64,
    laki_laki: i64,
}

async fn get_gender_chart(client: &Client) -> Result<GenderCategory, tokio_postgres::Error> {
    // Query untuk menghitung jumlah pengguna perempuan
    let perempuan: i64 = client
        .query_one("SELECT COUNT(*) FROM users WHERE jenis_kelamin = 'Perempuan'", &[])
        .await?
        .get(0);

    // Query untuk menghitung jumlah pengguna laki-laki
    let laki_laki: i64 = client
        .query_one("SELECT COUNT(*) FROM users WHERE jenis_kelamin = 'Laki-laki'", &[])
        .await?
        .get(0);

    Ok(GenderCategory {
        perempuan,
        laki_laki,
    })
}

async fn fetch_gender_chart() -> impl Responder {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match get_gender_chart(&client).await {
        Ok(chart) => HttpResponse::Ok().json(chart),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn fetch_blood_type_chart() -> impl Responder {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match get_blood_type_chart(&client).await {
        Ok(chart) => HttpResponse::Ok().json(chart),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn insert_user(new_user: web::Json<NewUser>) -> Result<HttpResponse, ActixError> {
    // Hash the password
    let hashed_password = match hash(&new_user.password, DEFAULT_COST) {
        Ok(hp) => hp,
        Err(_) => return Ok(HttpResponse::InternalServerError().json("Error hashing password")),
    };

    // Generate verification token and OTP
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    let otp = generate_otp(); // Generate OTP

    // Establish the database connection
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.unwrap();

    // Handle connection in the background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Prepare and execute the SQL statement with the new fields
    let statement = client.prepare(
        "INSERT INTO users (nama_lengkap, email, password, tanggal_lahir, umur, pekerjaan, golongan_darah, jenis_kelamin, otp, token, pertanyaan, jawaban, provinsi, kabupaten, kecamatan) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
        RETURNING id"
    ).await.unwrap();

    match client.query_one(
        &statement, 
        &[
            &new_user.nama_lengkap, 
            &new_user.email, 
            &hashed_password, 
            &new_user.tanggal_lahir, 
            &new_user.umur, 
            &new_user.pekerjaan, 
            &new_user.golongan_darah, 
            &new_user.jenis_kelamin, 
            &otp, 
            &token, 
            &new_user.pertanyaan, 
            &new_user.jawaban, 
            &new_user.provinsi, 
            &new_user.kabupaten, 
            &new_user.kecamatan
        ]
    ).await {
        Ok(row) => {
            let user_id: i32 = row.get(0);
            if let Err(e) = send_registration_email(&new_user.email, &otp).await {
                eprintln!("Error sending email: {}", e);
            }
            Ok(HttpResponse::Created().json(format!("User successfully added with ID: {}", user_id)))
        },
        Err(e) => {
            eprintln!("Error inserting user: {}", e);
            Ok(HttpResponse::InternalServerError().json("Error adding user"))
        },
    }
}


async fn delete_user(user_id: web::Path<i32>) -> Result<HttpResponse, ActixError> {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let statement = client.prepare("DELETE FROM users WHERE id = $1").await.unwrap();
    match client.execute(&statement, &[&user_id.into_inner()]).await {
        Ok(_) => Ok(HttpResponse::Ok().json("User successfully deleted")),
        Err(e) => {
            eprintln!("Error deleting user: {}", e);
            Ok(HttpResponse::InternalServerError().json("Error deleting user"))
        },
    }
}

async fn update_user(
    user_id: web::Path<i32>, 
    updated_user: web::Json<NewUser>,
) -> Result<HttpResponse, ActixError> {
    // Hash the password
    let hashed_password = match hash(&updated_user.password, DEFAULT_COST) {
        Ok(hp) => hp,
        Err(_) => return Ok(HttpResponse::InternalServerError().json("Error hashing password")),
    };

    // Establish the database connection
    let (client, connection) = match tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await {
        Ok(conn) => conn,
        Err(_) => return Ok(HttpResponse::InternalServerError().json("Database connection error")),
    };

    // Handle connection in the background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Prepare and execute the SQL statement
    let statement = match client.prepare(
        "UPDATE users SET 
            nama_lengkap = $1, 
            password = $2, 
            tanggal_lahir = $3,
            umur = $4, 
            pekerjaan = $5,
            golongan_darah = $6
            jenis_kelamin = $7, 
            pertanyaan = $8,
            jawaban = $9,
            provinsi = $10, 
            kabupaten = $11, 
            kecamatan = $12
        WHERE id = $13"
    ).await {
        Ok(stmt) => stmt,
        Err(_) => return Ok(HttpResponse::InternalServerError().json("Error preparing SQL statement")),
    };

    match client.execute(
        &statement, 
        &[
            &updated_user.nama_lengkap, 
            &updated_user.email,
            &hashed_password, 
            &updated_user.tanggal_lahir,
            &updated_user.umur, 
            &updated_user.pekerjaan,
            &updated_user.golongan_darah,
            &updated_user.jenis_kelamin, 
            &updated_user.pertanyaan,
            &updated_user.jawaban,
            &updated_user.provinsi, 
            &updated_user.kabupaten, 
            &updated_user.kecamatan, 
            &user_id.into_inner(),
        ]
    ).await {
        Ok(_) => Ok(HttpResponse::Ok().json("User successfully updated")),
        Err(e) => {
            eprintln!("Error updating user: {}", e);
            Ok(HttpResponse::InternalServerError().json("Error updating user"))
        },
    }
}


async fn login(data: web::Json<LoginRequest>) -> Result<HttpResponse, actix_web::Error> {
    let email = &data.email;
    let password = &data.password;

    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let statement = client.prepare("SELECT id, password, email_verified, nama_lengkap FROM users WHERE email = $1").await.unwrap();
    let row = client.query_opt(&statement, &[&email]).await.unwrap();

    if let Some(row) = row {
        let user_id: i32 = row.get(0);
        let stored_password: String = row.get(1);
        let email_verified: bool = row.get(2);
        let nama_lengkap: String = row.get(3); // Fetch the full name

        if verify(password, &stored_password).unwrap() {
            if email_verified {
                // Generate token with length 10 characters
                let token: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(10)
                    .map(char::from)
                    .collect();

                // Update token and status in the database
                let update_status_statement = client.prepare("UPDATE users SET status = 'Online', token = $1 WHERE email = $2").await.unwrap();
                client.execute(&update_status_statement, &[&token, &email]).await.unwrap();

                return Ok(HttpResponse::Ok().json(LoginResponse {
                    email_verified: true,
                    nama_lengkap, // Include the full name in the response
                }));
            } else {
                return Ok(HttpResponse::Unauthorized().json(ResponseMessage {
                    message: "Email belum terverifikasi. Silakan cek email Anda untuk verifikasi.".into(),
                }));
            }
        }
    }

    Ok(HttpResponse::Unauthorized().json(ResponseMessage {
        message: "Email atau password salah.".into(),
    }))
}


async fn logout(user_id: web::Path<i32>) -> Result<HttpResponse, ActixError> {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.map_err(|e| {
        eprintln!("Connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Update status menjadi 'Offline' dan hapus token
    let statement = client.prepare("UPDATE users SET token = NULL, status = 'Offline' WHERE id = $1").await.map_err(|e| {
        eprintln!("Prepare statement error: {}", e);
        actix_web::error::ErrorInternalServerError("Database statement preparation error")
    })?;

    client.execute(&statement, &[&*user_id]).await.map_err(|e| {
        eprintln!("Execute statement error: {}", e);
        actix_web::error::ErrorInternalServerError("Database execution error")
    })?;

    Ok(HttpResponse::Ok().json(ResponseMessage {
        message: "Successfully logged out and status set to Offline".into(),
    }))
}

#[derive(Serialize)]
struct PekerjaanCategory {
    name: String,
    value: i64,
}

async fn get_pekerjaan_chart(client: &Client) -> Result<Vec<PekerjaanCategory>, Error> {
    let pelajar = client
        .query_one("SELECT COUNT(*) FROM users WHERE pekerjaan = 'Pelajar'", &[])
        .await?
        .get(0);

    let mahasiswa = client
        .query_one("SELECT COUNT(*) FROM users WHERE pekerjaan = 'Mahasiswa'", &[])
        .await?
        .get(0);

    let pekerja = client
        .query_one("SELECT COUNT(*) FROM users WHERE pekerjaan = 'Pekerja'", &[])
        .await?
        .get(0);

    Ok(vec![
        PekerjaanCategory { name: "Pelajar".to_string(), value: pelajar },
        PekerjaanCategory { name: "Mahasiswa".to_string(), value: mahasiswa },
        PekerjaanCategory { name: "Pekerja".to_string(), value: pekerja },
    ])
}

async fn fetch_pekerjaan_chart() -> impl Responder {
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    match get_pekerjaan_chart(&client).await {
        Ok(chart) => HttpResponse::Ok().json(chart),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[derive(Serialize)]
struct GenderData {
    laki_laki: usize,
    perempuan: usize,
}

// Fungsi umum untuk mengambil data gender berdasarkan field (provinsi, kabupaten, kecamatan)
async fn get_gender_by_field(field: &str, value: &str) -> Result<GenderData, ActixError> {
    // Koneksi ke database
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=postgres password=erida999 dbname=postgres",
        NoTls,
    ).await.map_err(|e| {
        eprintln!("Database connection error: {}", e);
        actix_web::error::ErrorInternalServerError("Database connection error")
    })?;

    // Jalankan koneksi di task terpisah
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    // Siapkan query dinamis berdasarkan field (provinsi, kabupaten, kecamatan)
    let query = format!("SELECT jenis_kelamin, COUNT(*) FROM users WHERE {} = $1 GROUP BY jenis_kelamin", field);

    // Eksekusi query
    let statement = client.prepare(&query).await.map_err(|e| {
        eprintln!("Failed to prepare SQL statement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to prepare SQL statement")
    })?;
    
    let rows = client.query(&statement, &[&value.to_string()]).await.map_err(|e| {
        eprintln!("Failed to execute SQL query: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to execute SQL query")
    })?;

    // Proses hasil query
    let mut gender_count = HashMap::new();
    for row in rows {
        let gender: String = row.get(0);
        let count: i64 = row.get(1);
        gender_count.insert(gender, count as usize);
    }

    // Ambil data gender dari hasil query
    let laki_laki = gender_count.get("Laki-laki").cloned().unwrap_or(0);
    let perempuan = gender_count.get("Perempuan").cloned().unwrap_or(0);

    // Kembalikan hasilnya
    Ok(GenderData { laki_laki, perempuan })
}

// Handler untuk mendapatkan data gender berdasarkan provinsi
async fn get_gender_by_provinsi(provinsi: web::Path<String>) -> Result<HttpResponse, ActixError> {
    let data = get_gender_by_field("provinsi", &provinsi).await?;
    Ok(HttpResponse::Ok().json(data))
}

// Handler untuk mendapatkan data gender berdasarkan kabupaten
async fn get_gender_by_kabupaten(kabupaten: web::Path<String>) -> Result<HttpResponse, ActixError> {
    let data = get_gender_by_field("kabupaten", &kabupaten).await?;
    Ok(HttpResponse::Ok().json(data))
}

// Handler untuk mendapatkan data gender berdasarkan kecamatan
async fn get_gender_by_kecamatan(kecamatan: web::Path<String>) -> Result<HttpResponse, ActixError> {
    let data = get_gender_by_field("kecamatan", &kecamatan).await?;
    Ok(HttpResponse::Ok().json(data))
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(Cors::permissive()) // Add this line
            .route("/users", web::get().to(fetch_users))
            .route("/register", web::post().to(insert_user))
            .route("/delete/{id}", web::delete().to(delete_user))
            .route("/users/{id}", web::put().to(update_user))
            .route("/verify_otp", web::post().to(verify_otp))
            .route("/login", web::post().to(login))
            .route("/logout/{user_id}", web::post().to(logout))
            .route("/forgot_password", web::post().to(forgot_password))
            .route("/change_password", web::post().to(change_password)) // Tambahkan endpoint baru untuk mengubah password
            .route("/bloodtypechart", web::get().to(fetch_blood_type_chart))
            .route("/genderchart", web::get().to(fetch_gender_chart))
            .route("/occupationchart",web::get().to(fetch_pekerjaan_chart))
            .route("/agechart", web::get().to(fetch_umur_chart)) // Menambahkan route baru
            .route("/totaluser_gender", web::get().to(fetch_user_details)) 
            .route("/gender/provinsi/{provinsi}", web::get().to(get_gender_by_provinsi))
            .route("/gender/kabupaten/{kabupaten}", web::get().to(get_gender_by_kabupaten))
            .route("/gender/kecamatan/{kecamatan}", web::get().to(get_gender_by_kecamatan)) // Menambahkan route baru
    })  
    .bind("127.0.0.1:8080")?
    .run()
    .await  
}
