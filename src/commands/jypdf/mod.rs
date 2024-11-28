use base64::Engine;
use jyframe::{AppState, FileUtil, JsonOut};
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

/// CFCA实体锁以及PC证书模式下的终签结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfSignFinalOut {
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
impl jyframe::JsonOut for PdfSignFinalOut {}
impl jyframe::SingOut for PdfSignFinalOut {
    fn set_file_path(&mut self, file_path: &str) {
        self.file_path = file_path.to_string();
    }
    fn get_file_path(&self) -> String {
        self.file_path.clone()
    }
    fn set_file_url(&mut self, file_url: &str) {
        self.file_url = file_url.to_string();
    }
    fn get_file_url(&self) -> String {
        self.file_url.clone()
    }
    fn set_file_base64(&mut self, file_base64: &str) {
        self.file_base64 = file_base64.to_string();
    }
    fn get_file_base64(&self) -> String {
        self.file_base64.clone()
    }
    fn set_out_resp(&mut self, out_resp: &str) {
        self.out_resp = out_resp.to_string();
    }
    fn get_out_resp(&self) -> String {
        self.out_resp.clone()
    }
}

/// 中招共享互认扫码签章结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfSignShareOut {
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
impl jyframe::JsonOut for PdfSignShareOut {}
impl jyframe::SingOut for PdfSignShareOut {
    fn set_file_path(&mut self, file_path: &str) {
        self.file_path = file_path.to_string();
    }
    fn get_file_path(&self) -> String {
        self.file_path.clone()
    }
    fn set_file_url(&mut self, file_url: &str) {
        self.file_url = file_url.to_string();
    }
    fn get_file_url(&self) -> String {
        self.file_url.clone()
    }
    fn set_file_base64(&mut self, file_base64: &str) {
        self.file_base64 = file_base64.to_string();
    }
    fn get_file_base64(&self) -> String {
        self.file_base64.clone()
    }
    fn set_out_resp(&mut self, out_resp: &str) {
        self.out_resp = out_resp.to_string();
    }
    fn get_out_resp(&self) -> String {
        self.out_resp.clone()
    }
}

/// 新点驱动模式下的哈希结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfDigestOut {
    /// 文件id，前端传的
    file_id: String,
    /// 临时目录
    temp_path: String,
    /// 哈希值
    digest: String,
}
impl jyframe::JsonOut for PdfDigestOut {}

/// 新点驱动模式下的合并签章结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfSignMergeOut {
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
impl jyframe::JsonOut for PdfSignMergeOut {}
impl jyframe::SingOut for PdfSignMergeOut {
    fn set_file_path(&mut self, file_path: &str) {
        self.file_path = file_path.to_string();
    }
    fn get_file_path(&self) -> String {
        self.file_path.clone()
    }
    fn set_file_url(&mut self, file_url: &str) {
        self.file_url = file_url.to_string();
    }
    fn get_file_url(&self) -> String {
        self.file_url.clone()
    }
    fn set_file_base64(&mut self, file_base64: &str) {
        self.file_base64 = file_base64.to_string();
    }
    fn get_file_base64(&self) -> String {
        self.file_base64.clone()
    }
    fn set_out_resp(&mut self, out_resp: &str) {
        self.out_resp = out_resp.to_string();
    }
    fn get_out_resp(&self) -> String {
        self.out_resp.clone()
    }
}

/// 无签缩略图结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfNoSignOut {
    /// 文件id，前端传的
    file_id: String,
    /// 临时目录
    temp_path: String,
    /// 无签缩略图
    no_sign_pages: serde_json::Value,
}
impl jyframe::JsonOut for PdfNoSignOut {}

/// 签章历史记录结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfResignHisOut {
    /// 文件id，前端传的
    file_id: String,
    /// 临时目录
    temp_path: String,
    /// 签章历史记录
    files: serde_json::Value,
}
impl jyframe::JsonOut for PdfResignHisOut {}

/// 重新签章结果输出
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PdfResignOut {
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
impl jyframe::JsonOut for PdfResignOut {}
impl jyframe::SingOut for PdfResignOut {
    fn set_file_path(&mut self, file_path: &str) {
        self.file_path = file_path.to_string();
    }
    fn get_file_path(&self) -> String {
        self.file_path.clone()
    }
    fn set_file_url(&mut self, file_url: &str) {
        self.file_url = file_url.to_string();
    }
    fn get_file_url(&self) -> String {
        self.file_url.clone()
    }
    fn set_file_base64(&mut self, file_base64: &str) {
        self.file_base64 = file_base64.to_string();
    }
    fn get_file_base64(&self) -> String {
        self.file_base64.clone()
    }
    fn set_out_resp(&mut self, out_resp: &str) {
        self.out_resp = out_resp.to_string();
    }
    fn get_out_resp(&self) -> String {
        self.out_resp.clone()
    }
}


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
            let time_stamp = chrono::Local::now().format("%Y%m%d%H%M%S%3f").to_string();
            let file_name = jyframe::FileUtil::get_file_name_from_path(pdf_temp_info.pdf_save_path.clone(), false);
            let file_ext = jyframe::FileUtil::get_extension_from_path(pdf_temp_info.pdf_save_path.clone());
            let target_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-presign-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
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
    let mut out = PdfSignFinalOut::default();
    out.file_id = file_id.to_string();
    match PathBuf::from_str(temp_path) {
        Ok(file_path) => {
            if let Some(parent_dir) = file_path.parent() {
                let time_stamp = chrono::Local::now().format("%Y%m%d%H%M%S%3f").to_string();
                let file_name = jyframe::FileUtil::get_file_name_from_path(file_path.clone(), false);
                let file_ext = jyframe::FileUtil::get_extension_from_path(file_path.clone());
                let target_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-signed-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
                let bak_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-ori-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
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
                common_after_sign(&mut out, java_rtn.as_str(), file_id, file_path.clone(), Some(bak_path.clone()), Some(target_path.clone()), middle_path, 
                    out_with_bytes, out_path, out_url).await;
            }
        },
        Err(err) => {
            logger::error!("error occured when convert file dir to file path: {}", err);
        }
    }
    Ok(out.to_json())
}

/// 中招共享互享互认模式下的扫码签章
#[tauri::command]
pub async fn jy_pdf_sign_share(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, file_path: &str, file_url: &str, file_base64: &str,
    sign_cert: &str, position: serde_json::Value, ext: serde_json::Value, out_with_bytes: bool, out_path: &str, out_url: &str) -> Result<serde_json::Value, String> 
{
    let mut out = PdfSignShareOut::default();
    out.file_id = file_id.to_string();
    let pdf_temp_info = init_pdf_temp_file(state.clone(), PdfOutType::Sign, file_id, file_path, file_url, file_base64).await;
    if write_pdf_temp_file(&pdf_temp_info) {
        out.temp_path = pdf_temp_info.pdf_save_path.to_string_lossy().to_string();
        // 1. 获取用户sealInfo
        let body_obj = serde_json::json!({
                "tid": ext["tid"].as_str().unwrap_or(""),
                "sealSn": ext["sealSn"].as_str().unwrap_or(""),
                "signatureCertSn": ext["signatureCertSn"].as_str().unwrap_or(""),
                "accessToken": ext["accessToken"].as_str().unwrap_or(""),
                "caOrgCode": ext["caOrgCode"].as_str().unwrap_or(""),
        });
        let user_seal_info = jyframe::ZhongZhaoUtil::zz_common_request(body_obj.to_string().as_str(), "getUserSealInfo").await;
        // 2. 调用jar包签章
        if let Some(parent_dir) = pdf_temp_info.pdf_save_path.parent() {
            let time_stamp = chrono::Local::now().format("%Y%m%d%H%M%S%3f").to_string();
            let file_name = jyframe::FileUtil::get_file_name_from_path(pdf_temp_info.pdf_save_path.clone(), false);
            let file_ext = jyframe::FileUtil::get_extension_from_path(pdf_temp_info.pdf_save_path.clone());
            let middle_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-middle-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
            let target_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-signed-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
            let bak_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-ori-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
            let func_params = serde_json::json!({
                "srcPath": pdf_temp_info.pdf_save_path.to_string_lossy().to_string(),
                "middlePath": middle_path.to_string_lossy().to_string(),
                "targetPath": target_path.to_string_lossy().to_string(),
                "sealInfo": user_seal_info["data"]["sealInfo"].as_str().unwrap_or(""),
                "signCert": sign_cert.to_string(),
                "signs": position,
                "ext": ext,
                "cebsProperties": jyframe::ZhongZhaoUtil::zz_build_cebs(),
            });
            let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "signPdfByZZ", func_params));
            common_after_sign(&mut out, java_rtn.as_str(), file_id, pdf_temp_info.pdf_save_path.clone(), Some(bak_path.clone()), Some(target_path.clone()), middle_path.to_str().unwrap_or(""), 
                out_with_bytes, out_path, out_url).await;
        }
    }
    Ok(out.to_json())
}

/// 新点驱动模式下的哈希计算
#[tauri::command]
pub async fn jy_pdf_digest(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, file_path: &str, file_url: &str, file_base64: &str) -> Result<serde_json::Value, String> {
    let mut out = PdfDigestOut::default();
    out.file_id = file_id.to_string();
    let pdf_temp_info = init_pdf_temp_file(state.clone(), PdfOutType::Sign, file_id, file_path, file_url, file_base64).await;
    if write_pdf_temp_file(&pdf_temp_info) {
        out.temp_path = pdf_temp_info.pdf_save_path.to_string_lossy().to_string();
        let func_params = serde_json::json!({
            "pdfPath": pdf_temp_info.pdf_save_path.to_string_lossy().to_string()
        });
        let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "digestpdf", func_params));
        match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
            Ok(java_json) => {
                out.digest = java_json["data"]["org"].as_str().unwrap_or("").to_string();
            },
            Err(err) => logger::error!("error occured when convert java return string to json【{}】: {}", &java_rtn, err),
        }
    }
    Ok(out.to_json())
}

/// 新点驱动模式下的签章
#[tauri::command]
#[allow(unused_variables)]
pub async fn jy_pdf_sign_merge(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, temp_path: &str, sign_cert: &str, sign_img: &str, org_hash: &str, signature: &str, 
    out_with_bytes: bool, out_path: &str, out_url: &str, position: serde_json::Value, ext: serde_json::Value) -> Result<serde_json::Value, String> 
{
    let mut out = PdfSignMergeOut::default();
    out.file_id = file_id.to_string();
    match PathBuf::from_str(temp_path) {
        Ok(file_path) => {
            if let Some(parent_dir) = file_path.parent() {
                let time_stamp = chrono::Local::now().format("%Y%m%d%H%M%S%3f").to_string();
                let file_name = jyframe::FileUtil::get_file_name_from_path(file_path.clone(), false);
                let file_ext = jyframe::FileUtil::get_extension_from_path(file_path.clone());
                let target_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-signed-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
                let bak_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-ori-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
                let func_params = serde_json::json!({
                    "srcFile": file_path.to_string_lossy().to_string(),
                    "targetPath": target_path.to_string_lossy().to_string(),
                    "signCert": sign_cert.to_string(),
                    "signed": signature.to_string(),
                    "signImg": sign_img.to_string(),
                    "signs": position,
                    "ext": ext,
                });
                let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "signpdf", func_params));
                common_after_sign(&mut out, java_rtn.as_str(), file_id, file_path.clone(), Some(bak_path.clone()), Some(target_path.clone()), "", 
                out_with_bytes, out_path, out_url).await;
            }
        },
        Err(err) => logger::error!("error occured when convert file dir to file path: {}", err),
    }
    Ok(out.to_json())
}

/// 云签|刷脸模式下直接签章，不需要前端再次操作
#[tauri::command]
pub async fn jy_pdf_sign_direct(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, file_path: &str, file_url: &str, file_base64: &str, 
    sign_cert: &str, sign_cert_org: &str, sign_img: &str, 
    out_with_bytes: bool, out_path: &str, out_url: &str, position: serde_json::Value, ext: serde_json::Value) -> Result<serde_json::Value, String> 
{
    // 第一步计算哈希值
    match jy_pdf_sign_pre(state.clone(), file_id, file_path, file_url, file_base64, sign_cert, sign_img, position, ext).await {
        Ok(sign_pre_result) => {
            match serde_json::from_value::<PdfSignPreOut>(sign_pre_result) {
                Ok(sign_pre_out) => {
                    // 第二步计算签名
                    let func_params = serde_json::json!({
                        "org": sign_pre_out.pdf_hash.as_str(),
                        "signCert": sign_cert,
                        "signCertOrg": sign_cert_org,
                    });
                    let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "makeSignature", func_params.clone()));
                    match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
                        Ok(java_json) => {
                            // 第三步合并签章
                            return jy_pdf_sign_final(state.clone(), file_id, sign_pre_out.temp_path.as_str(), sign_pre_out.middle_path.as_str(), 
                                sign_pre_out.key_alg.as_str(), sign_pre_out.hash_alg.as_str(), java_json["data"]["signed"].as_str().unwrap_or(""), 
                                sign_pre_out.sign_file_name.as_str(), sign_cert, "", out_with_bytes, out_path, out_url).await;
                        },
                        Err(err) => logger::error!("error occured when convert java result to json object: {}", err),
                    }
                },
                Err(err) => logger::error!("error occured when convert digest result to struct in direct sign: {}", err),
            }
        },
        // 方法里不会返回Err，所以这个不考虑
        Err(_) => (),
    }
    
    Ok(serde_json::json!({}))
}

/// 打印使用：获取无签章缩略图
#[tauri::command]
pub async fn jy_pdf_nosign_pages(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, file_path: &str, file_url: &str, file_base64: &str) -> Result<serde_json::Value, String> {
    let mut out = PdfNoSignOut::default();
    out.file_id = file_id.to_string();
    let pdf_temp_info = init_pdf_temp_file(state.clone(), PdfOutType::NoPage, file_id, file_path, file_url, file_base64).await;
    if write_pdf_temp_file(&pdf_temp_info) {
        out.temp_path = pdf_temp_info.pdf_save_path.to_string_lossy().to_string();
        if let Some(parent_dir) = pdf_temp_info.pdf_save_path.parent() {
            let time_stamp = chrono::Local::now().format("%Y%m%d%H%M%S%3f").to_string();
            let file_name = jyframe::FileUtil::get_file_name_from_path(pdf_temp_info.pdf_save_path.clone(), false);
            let file_ext = jyframe::FileUtil::get_extension_from_path(pdf_temp_info.pdf_save_path.clone());
            let middle_path: PathBuf = [&parent_dir.to_string_lossy().to_string(), format!("{}-middle-{}.{}", file_name, time_stamp, file_ext).as_str()].iter().collect();
            let func_params = serde_json::json!({
                "srcPath": &pdf_temp_info.pdf_save_path.to_str().unwrap_or(""),
                "middlePath": middle_path.to_str().unwrap_or(""),
            });
            let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "noSignPages", func_params));
            // 最后删除中间文件
            match std::fs::remove_file(middle_path.clone()) {
                Ok(_) => (),
                Err(err) => logger::error!("error occured when remove middle file: {}", err),
            }
            match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
                Ok(java_json) => out.no_sign_pages = java_json["data"].clone(),
                Err(err) => logger::error!("error occured when convert java rtn value to json: {}", err),
            }
        }
    }
    Ok(out.to_json())
}

/// 重新签章获取签章历史文件
#[tauri::command]
pub fn jy_pdf_resign_his(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str) -> Result<serde_json::Value, String> {
    let mut out = PdfResignHisOut::default();
    out.file_id = file_id.to_string();
    let ds_dir: PathBuf = [AppState::get_pdf_digest_sign_dir(&state), file_id.to_string()].iter().collect();
    let func_params = serde_json::json!({
        "srcPath": ds_dir.to_str().unwrap_or(""),
    });
    let java_rtn = jyframe::JavaUtil::spawn_java(jyframe::JavaUtil::make_spawn_command(&state, "resignHis", func_params));
    match serde_json::from_str::<serde_json::Value>(java_rtn.as_str()) {
        Ok(java_json) => out.files = java_json["data"].clone(),
        Err(err) => logger::error!("error occured when convert java rtn value to json: {}", err),
    }
    Ok(out.to_json())
}

/// 重新签章
#[tauri::command]
pub async fn jy_pdf_resign_with_file(state: State<'_, Arc<Mutex<AppState>>>, file_id: &str, time: &str, 
    out_with_bytes: bool, out_path: &str, out_url: &str) -> Result<serde_json::Value, String> 
{
    let mut out = PdfResignOut::default();
    out.file_id = file_id.to_string();
    let mut file_path: Option<PathBuf> = None;
    let ds_path: PathBuf = [AppState::get_pdf_digest_sign_dir(&state), file_id.to_string()].iter().collect();
    // 轮询文件夹处理符合条件的文件
    match std::fs::read_dir(ds_path.clone()) {
        Ok(files) => {
            for file in files {
                match file {
                    Ok(file_item) => {
                        let reg = regex::Regex::new(r"[-_]ori[-_](\d{17})$").unwrap();
                        let file_name = FileUtil::get_file_name_from_path(file_item.path(), false);
                        if file_path.is_none() {
                            let file_ext = FileUtil::get_extension_from_path(file_item.path());
                            file_path = Some([&ds_path.to_str().unwrap_or(""), format!("{}.{}", reg.replace_all(file_name.as_str(), ""), file_ext).as_str()].iter().collect());
                        }
                        if let Some(captures) = reg.captures(file_name.as_str()) {
                            match captures.get(1) {
                                Some(file_time_matcher) => {
                                    let file_time = file_time_matcher.as_str();
                                    match file_time.cmp(time) {
                                        // 时间大于指定时间的直接删除
                                        std::cmp::Ordering::Greater => {
                                            match std::fs::remove_file(file_item.path()) {
                                                Ok(_) => (),
                                                Err(err) => logger::error!("error occured when remove expired file: {}", err),
                                            }
                                        },
                                        // 时间等于指定时间的替换现有文件
                                        std::cmp::Ordering::Equal => {
                                            match std::fs::copy(file_item.path(), file_path.as_ref().unwrap().clone()) {
                                                Ok(_) =>  {
                                                    match std::fs::remove_file(file_item.path()) {
                                                        Ok(_) => (),
                                                        Err(err) => logger::error!("error occured when remove expired file: {}", err),
                                                    }
                                                },
                                                Err(err) => logger::error!("error occured when copy spefic file to final path: {}", err),
                                            }
                                        },
                                        _ => (),
                                    }
                                },
                                None => logger::warn!("failed to get file timestamp"),
                            }
                        }
                    },
                    Err(err) => logger::error!("error occured when get file in directory: {}", err),
                }
            }
        },
        Err(err) => logger::error!("error occured when read directory【{}】: {}", ds_path.to_string_lossy().to_string(), err),
    }
    // 最后调整输出
    if file_path.is_some() {
        common_after_sign(&mut out, "{\"code\":200, \"msg\": \"\", \"data\": \"\"}", file_id, file_path.as_ref().unwrap().clone(), None, None, "", 
            out_with_bytes, out_path, out_url).await;
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

/// 签章后通用处理方法
async fn common_after_sign<T: jyframe::SingOut>(out: &mut T, java_rtn: &str, file_id: &str, 
    file_path: PathBuf, bak_path: Option<PathBuf>, target_path: Option<PathBuf>, middle_path: &str, 
    out_with_bytes: bool, out_path: &str, out_url: &str) 
{
    match serde_json::from_str::<serde_json::Value>(java_rtn) {
        Ok(_java_json) => {
            // 指定了备份地址和最终地址的做替换
            if bak_path.is_some() && target_path.is_some() {
                // 原始文件复制为bak地址
                match std::fs::copy(file_path.clone(), bak_path.as_ref().unwrap().clone()) {
                    Ok(_) => (),
                    Err(err) => {
                        logger::error!("error occured when copy original file to bak path: {}", err);
                    },
                }
                // 签名后文件复制为原文件
                match std::fs::copy(target_path.as_ref().unwrap().clone(), file_path.clone()) {
                    Ok(_) => (),
                    Err(err) => {
                        logger::error!("error occured when copy signed file to original path: {}", err);
                    },
                }
            }
            // 删除签名后文件以及中间文件
            if target_path.is_some() {
                match std::fs::remove_file(target_path.as_ref().unwrap().clone()) {
                    Ok(_) => (),
                    Err(err) => {
                        logger::error!("error occured when remove signed target file: {}", err);
                    }
                }
            }
            if middle_path != "" {
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
            }
            out.set_file_path(file_path.to_str().unwrap_or(""));
            // 文件流输出
            if out_with_bytes {
                match std::fs::read(file_path.clone()) {
                    Ok(byets) => out.set_file_base64(base64::engine::general_purpose::STANDARD.encode(byets).as_str()),
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
                                    Ok(body) => out.set_out_resp(body.as_str()),
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
