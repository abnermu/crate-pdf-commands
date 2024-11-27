use base64::Engine;
use jyframe::{AppState, JsonOut};
use tauri::State;
use std::{path::PathBuf, str::FromStr, sync::{Arc, Mutex}};
use log as logger;
use serde::{Serialize, Deserialize};

/// pdf输出类型
enum PdfOutType {
    /// 验签
    Verify,
    /// 签名相关操作
    Sign,
    /// 获取无签章的页面结果
    NoPage,
}
impl PdfOutType {
    /// 输出类型是否为验签
    fn is_4verify(&self) -> bool {
        match self {
            PdfOutType::Verify => true,
            _ => false,
        }
    }
    /// 输出类型是否为无签章页面
    fn is_4nopage(&self) -> bool {
        match self {
            PdfOutType::NoPage => true,
            _ =>  false,
        }
    }
}

/// PDF文件临时信息
struct PdfTempFile {
    /// pdf临时文件目录
    pdf_save_path: PathBuf,
    /// pdf文件bytes
    file_bytes: Vec<u8>,
}

/// pdf验签结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfVerifyOut {
    /// 文件id，前端传的
    file_id: String,
    /// 临时目录
    temp_path: String,
    /// 签章信息
    signs: serde_json::Value,
}
impl jyframe::JsonOut for PdfVerifyOut {}

/// CFCA实体锁以及PC证书模式下的预签章|哈希结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfSignPreOut {
    /// 文件id，前端传的
    file_id: String,
    /// 临时目录
    temp_path: String,
    /// 预签临时文件路径
    middle_path: String,
    /// 文件哈希原值
    pdf_hash_data: Vec<u8>,
    /// 文件哈希值base64
    pdf_hash: String,
    /// 签名算法名
    key_alg: String,
    /// 哈希算法名
    hash_alg: String,
    /// 签名域名
    sign_file_name: String,
    /// 证书base64
    x509_cert: String,
}
impl jyframe::JsonOut for PdfSignPreOut {}

/// CFCA实体锁以及PC证书模式下的终签
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfSignFinanOut {
    /// 文件id，前端传的
    file_id: String,
    /// 临时目录
    temp_path: String,
    /// 文件路径
    file_path: String,
    /// 文件外网地址
    file_url: String,
    /// 文件byte转base64
    file_base64: String,
    /// 业务系统响应值（这个值没有，给空值）
    out_resp: String,
}
impl jyframe::JsonOut for PdfSignFinanOut {}

/// PDF文件验签
#[tauri::command]
pub async fn jy_pdf_verify(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, file_path: &str, file_url: &str, file_base64: &str) -> Result<serde_json::Value, String> {
    let mut out = PdfVerifyOut::default();
    out.file_id = file_id.to_string();
    let pdf_temp_info = init_pdf_temp_file(state.clone(), PdfOutType::Verify, file_id, file_path, file_url, file_base64).await;
    if write_pdf_temp_file(&pdf_temp_info) {
        out.temp_path = pdf_temp_info.pdf_save_path.to_string_lossy().to_string();
        let func_params = serde_json::json!({
            "pdfPath": &pdf_temp_info.pdf_save_path,
        });
        let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "verifypdf", func_params));
        match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
            Ok(java_json) => {
                out.signs = java_json["data"].clone();
            },
            Err(err) => {
                logger::error!("error occured when convert java return string to json【{}】: {}", &java_rtn, err);
            },
        };
    }
    Ok(out.to_json())
}

/// CFCA实体或PC证书模式下的预签|计算哈希值
#[tauri::command]
pub async fn jy_pdf_sign_pre(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, file_path: &str, file_url: &str, file_base64: &str, 
    cert: &str, image: &str, position: serde_json::Value, ext: serde_json::Value) -> Result<serde_json::Value, String> 
{
    let mut out = PdfSignPreOut::default();
    out.file_id = file_id.to_string();
    let pdf_temp_info = init_pdf_temp_file(state.clone(), PdfOutType::Sign, file_id, file_path, file_url, file_base64).await;
    if write_pdf_temp_file(&pdf_temp_info) {
        out.temp_path = pdf_temp_info.pdf_save_path.to_string_lossy().to_string();
        if let Some(parent_dir) = pdf_temp_info.pdf_save_path.parent() {
            let time_stamp = chrono::Utc::now().timestamp_millis();
            let file_name = jyframe::FileUtil::get_file_name_from_path(pdf_temp_info.pdf_save_path.clone(), false);
            let file_ext = jyframe::FileUtil::get_extension_from_path(pdf_temp_info.pdf_save_path.clone());
            let target_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}_presign_{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
            out.middle_path = target_path.to_string_lossy().to_string();
            let func_params = serde_json::json!({
                "srcFile": pdf_temp_info.pdf_save_path.to_string_lossy().to_string(),
                "targetPath": target_path.to_string_lossy().to_string(),
                "signCert": cert.to_string(),
                "signImg": image.to_string(),
                "signs": position,
                "ext": ext,
            });
            let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "presignpdf", func_params));
            match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
                Ok(java_json) => {
                    out.pdf_hash_data = java_json["data"]["pdfHashData"].as_array().unwrap().iter().map(|item| item.as_i64().unwrap() as u8).collect::<Vec<u8>>();
                    out.pdf_hash = java_json["data"]["pdfHash"].as_str().unwrap_or("").to_string();
                    out.key_alg = java_json["data"]["keyAlg"].as_str().unwrap_or("").to_string();
                    out.hash_alg = java_json["data"]["hashAlg"].as_str().unwrap_or("").to_string();
                    out.sign_file_name = java_json["data"]["signFileName"].as_str().unwrap_or("").to_string();
                    out.x509_cert = java_json["data"]["x509Cert"].as_str().unwrap_or("").to_string();
                },
                Err(err) => {
                    logger::error!("error occured when convert java return string to json【{}】: {}", &java_rtn, err);
                },
            };
        }
    }
    Ok(out.to_json())
}

/// CFCA实体或PC证书模式下的终签
#[tauri::command]
pub async fn jy_pdf_sign_final(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, temp_path: &str, middle_path: &str, 
    key_alg: &str, hash_alg: &str, signed: &str, sign_field_name: &str, cert: &str, timestamp_config: &str, 
    out_with_bytes: bool, out_path: &str, out_url: &str) -> Result<serde_json::Value, String> 
{
    let mut out = PdfSignFinanOut::default();
    out.file_id = file_id.to_string();
    match PathBuf::from_str(temp_path) {
        Ok(file_path) => {
            if let Some(parent_dir) = file_path.parent() {
                let time_stamp = chrono::Utc::now().timestamp_millis();
                let file_name = jyframe::FileUtil::get_file_name_from_path(file_path.clone(), false);
                let file_ext = jyframe::FileUtil::get_extension_from_path(file_path.clone());
                let target_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}_signed_{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
                let bak_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}_ori_{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
                let func_params = serde_json::json!({
                    "srcFile": middle_path.to_string(),
                    "targetPath": target_path.to_string_lossy().to_string(),
                    "signCert": cert.to_string(),
                    "signed": signed.to_string(),
                    "signFieldName": sign_field_name.to_string(),
                    "keyAlg": key_alg.to_string(),
                    "hashAlg": hash_alg.to_string(),
                    "timestampConfig": timestamp_config.to_string(),
                });
                let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "finalsignpdf", func_params));
                match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
                    Ok(_java_json) => {
                        // 原始文件复制为bak地址
                        match std::fs::copy(file_path.clone(), bak_path.clone()) {
                            Ok(_) => (),
                            Err(err) => {
                                logger::error!("error occured when copy original file to bak path: {}", err);
                            },
                        }
                        // 签名后文件复制为原文件
                        match std::fs::copy(target_path.clone(), file_path.clone()) {
                            Ok(_) => (),
                            Err(err) => {
                                logger::error!("error occured when copy signed file to original path: {}", err);
                            },
                        }
                        // 删除签名后文件以及中间文件
                        match std::fs::remove_file(target_path.clone()) {
                            Ok(_) => (),
                            Err(err) => {
                                logger::error!("error occured when remove signed target file: {}", err);
                            }
                        }
                        match PathBuf::from_str(middle_path) {
                            Ok(middle_path_buf) => {
                                match std::fs::remove_file(middle_path_buf) {
                                    Ok(_) => (),
                                    Err(err) => {
                                        logger::error!("error occured when remove middle presign file: {}", err);
                                    }
                                }
                            },
                            Err(err) => {
                                logger::error!("error occured when convert middle dir to pathbuf: {}", err);
                            }
                        }
                        out.file_path = temp_path.to_string();
                        // 文件流输出
                        if out_with_bytes {
                            match std::fs::read(temp_path) {
                                Ok(byets) => out.file_base64 = base64::engine::general_purpose::STANDARD.encode(byets),
                                Err(err) => {
                                    logger::error!("error occured when read file to bytes: {}", err);
                                },
                            }
                        }
                        // 本地模式下的重签文件复制，复制之前先备份原文件
                        if out_path != "" {
                            match PathBuf::from_str(out_path) {
                                Ok(out_path_buf) => {
                                    let out_bak: PathBuf = PathBuf::from(out_path.to_owned() + ".bak");
                                    match std::fs::copy(out_path_buf.clone(), out_bak.clone()) {
                                        Ok(_) => (),
                                        Err(err) => logger::error!("error occured when copy out path to out bak: {}", err)
                                    }
                                    match std::fs::copy(file_path.clone(), out_path_buf.clone()) {
                                        Ok(_) => (),
                                        Err(err) => logger::error!("error occured when copy out path to out bak: {}", err)
                                    }
                                },
                                Err(err) => {
                                    logger::error!("error occured when convert out dir to path: {}", err);
                                }
                            }
                        }
                        // 联网模式下文件上传
                        if out_url != "" {
                            match reqwest::multipart::Form::new().text("fileId", file_id.to_string()).file("file", file_path.clone()).await {
                                Ok(form) => {
                                    let client = reqwest::Client::new();
                                    match client.post(out_url).multipart(form).send().await {
                                        Ok(res) => {
                                            match res.text().await {
                                                Ok(body) => out.out_resp = body,
                                                Err(err) => logger::error!("error occured when get response body: {}", err)
                                            }
                                        },
                                        Err(err) => logger::error!("error occured when upload file: {}", err)
                                    }
                                },
                                Err(err) => logger::error!("error occured when create multipart form: {}", err)
                            }
                        }
                    },
                    Err(err) => {
                        logger::error!("error occured when convert java return string to json【{}】: {}", &java_rtn, err);
                    },
                };
            }
        },
        Err(err) => {
            logger::error!("error occured when convert file dir to file path: {}", err);
        }
    }
    Ok(out.to_json())
}

/// 初始化临时文件信息
async fn init_pdf_temp_file(state: State<'_, Arc<Mutex<AppState>>>, outtype: PdfOutType, file_id: &str, file_path: &str, file_url: &str, file_base64: &str) -> PdfTempFile {
    let base_dir: String = if outtype.is_4verify() || outtype.is_4nopage() {AppState::get_pdf_verify_dir(&state)} else {AppState::get_pdf_digest_sign_dir(&state)};
    let mut pdf_save_path: PathBuf = PathBuf::default();
    let mut file_bytes: Vec<u8> = Vec::new();
    if file_base64 != "" {
        match base64::engine::general_purpose::STANDARD.decode(file_base64) {
            Ok(bytes) => {
                file_bytes = bytes;
                pdf_save_path = [base_dir.as_str(), file_id, &format!("{}.pdf", file_id)].iter().collect();
            },
            Err(err) => {
                logger::error!("error occured when decode pdf base64 to bytes: {}", err);
            }
        }
    }
    else if file_path != "" {
        match PathBuf::from_str(file_path) {
            Ok(src_path) => {
                if let Some(file_name) = src_path.file_name() {
                    match std::fs::read(src_path.clone()) {
                        Ok(bytes) => {
                            file_bytes = bytes;
                        },
                        Err(err) => {
                            logger::error!("error occured when read file path to bytes: {}", err);
                        }
                    }
                    pdf_save_path = [base_dir.as_str(), file_id, &file_name.to_string_lossy().to_string()].iter().collect();
                }
                else {
                    logger::warn!("can not get the file name from file path of: {}", file_path);
                }
            },
            Err(err) => {
                logger::error!("error occured when convert file path【{}】 to pathbuf: {}", file_path, err);
            }
        }
    }
    else if file_url != "" {
        match reqwest::get(file_url).await {
            Ok(res) => {
                let file_name = jyframe::FileUtil::get_file_name_from_header(res.headers());
                if file_name != "" {
                    pdf_save_path = [base_dir.as_str(), file_id, &file_name].iter().collect();
                    match res.bytes().await {
                        Ok(bytes) => {
                            file_bytes = bytes.to_vec();
                        },
                        Err(err) => {
                            logger::error!("error occured when read bytes from response: {}", err);
                        },
                    }
                }
                else {
                    logger::error!("can not get file name from response, so the file url is unvalid");
                }
            },
            Err(err) => {
                logger::error!("error occured when get file from file url【{}】: {}", file_url, err);
            },
        }
    }
    PdfTempFile {
        pdf_save_path,
        file_bytes,
    }
}

/// 临时文件写入
fn write_pdf_temp_file(pdf_temp_info: &PdfTempFile) -> bool {
    if pdf_temp_info.file_bytes.len() > 0 {
        let mut can_write = true;
        if let Some(parent_dir) = pdf_temp_info.pdf_save_path.parent() {
            if !parent_dir.exists() {
                match std::fs::create_dir_all(parent_dir) {
                    Ok(_) => (),
                    Err(err) => {
                        can_write = false;
                        logger::error!("error occured when create parent dir: {}", err);
                    }
                }
            }
        }
        if can_write {
            match std::fs::write(&pdf_temp_info.pdf_save_path, &pdf_temp_info.file_bytes) {
                Ok(_) => {
                    return true;
                },
                Err(err) => {
                    logger::error!("error occured when write file bytes to path【{}】: {}", &pdf_temp_info.pdf_save_path.to_string_lossy(), err);
                }
            }
        }
    }
    else {
        logger::info!("get file bytes failed");
    }
    false
}