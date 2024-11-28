use std::{sync::{Arc, Mutex}, path::PathBuf, net::SocketAddr};
use log as logger;
use http_body_util::BodyExt;

static HELLOWORLD: &[u8] = b"Hello World!";
static NOTFOUND: &[u8] = b"Not Found";
type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

/// 启动httpserver
pub fn create_http_server(app_state_reuse: Arc<Mutex<jyframe::AppState>>) {
    // 创建http服务
    tokio::spawn(async move {
        let mut port = 20080;
        loop {
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    logger::info!("http server listening on http://localhost:{}", port);
                    // 记录本地端口号
                    jyframe::state::AppState::set_local_port(port, &app_state_reuse);
                    loop {
                        let app_state_clone = Arc::clone(&app_state_reuse);
                        match listener.accept().await {
                            Ok((stream , _)) => {
                                let io = hyper_util::rt::TokioIo::new(stream);
                                tokio::spawn(async move {
                                    let service = hyper::service::service_fn(move |req| resquest_filter(app_state_clone.clone(), req));
                                    if let Err(err) = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await {
                                        logger::error!("response failed: {}", err);
                                    }
                                });
                            },
                            Err(err) => {
                                logger::error!("listener accept streams failed: {}", err);
                            },
                        };
                    }
                },
                Err(err) => {
                    logger::error!("bind addr with port【{}】 failed: {}", port, err);
                    port += 1;
                },
            };
        }
    });
}

/// 请求路由
async fn resquest_filter(state: Arc<Mutex<jyframe::AppState>>, req: hyper::Request<hyper::body::Incoming>) -> Result<hyper::Response<BoxBody>> {
    let mut res = not_found();
    let reg_files = regex::Regex::new(r"^/files/").unwrap();
    if reg_files.is_match(req.uri().path()) {
        logger::info!("访问/files: {}", req.uri().path());
        let state_clone = state.clone();
        if let Ok(response) = api_files_list_auto(state_clone, &reg_files.replace(req.uri().path(), "").to_string()).await {
            res = response;
        }
    }
    else if let Ok(response) = match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/test") => {
            api_test(state).await
        },
        (&hyper::Method::GET, "/pdf/server/worker") => {
            api_pdf_worker(state).await
        },
        _ => {
            Ok(hyper::Response::builder().status(hyper::StatusCode::OK).body(full(HELLOWORLD)).unwrap())
        }
    } {
        res = response;
    }
    // 设置允许跨域请求头
    res.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, hyper::header::HeaderValue::from_static("*"));
    res.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, hyper::header::HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
    Ok(res)
}
async fn api_files_list_auto(state: Arc<Mutex<jyframe::AppState>>, file_name: &str) -> Result<hyper::Response<BoxBody>> {
    let state_clone = state.clone();
    api_files_list(state_clone, file_name, &jyframe::state::AppState::get_data_dir(&state)).await
}
/// app_data_dir/files文件夹代理接口
async fn api_files_list(_state: Arc<Mutex<jyframe::AppState>>, file_name: &str, parent_path: &str) -> Result<hyper::Response<BoxBody>> {
    match urlencoding::decode(file_name) {
        Ok(file_name_dec) => {
            let file_path: PathBuf = [parent_path, "files", &file_name_dec.to_string()].iter().collect();
            match std::fs::read(&file_path) {
                Ok(file_bytes) => {
                    let mime_type = mime_guess::from_path(&file_path).first_or_octet_stream();
                    let res = hyper::Response::builder()
                    .header(hyper::header::CONTENT_TYPE, mime_type.as_ref())
                    .body(full(file_bytes))
                    .unwrap();
                return Ok(res);
                },
                Err(err) => {
                    logger::error!("error occured when open file【{}】: {}", file_path.to_string_lossy(), err);
                }
            }
        },
        Err(err) => {
            logger::error!("error occured do url decode with file name: {}", err);
        }
    }
    Ok(not_found())
}
/// 代理pdf.worker文件接口
async fn api_pdf_worker(state: Arc<Mutex<jyframe::AppState>>) -> Result<hyper::Response<BoxBody>> {
    let resource_dir = jyframe::AppState::get_resource_dir(&state);
    let worker_path: PathBuf = [&resource_dir, "extraResources", "pdf.worker.min.mjs"].iter().collect();
    match std::fs::read(worker_path) {
        Ok(file_bytes) => {
            // let reader_stream = tokio_util::io::ReaderStream::new(file);
            // let stream_body = http_body_util::StreamBody::new(reader_stream);
            let res = hyper::Response::builder()
                .header(hyper::header::CONTENT_TYPE, "application/javascript")
                .body(full(file_bytes))
                .unwrap();
            return Ok(res);
        },
        Err(err) => {
            logger::error!("error occured when open pdf-worker: {}", err);
        }
    }
    Ok(not_found())
}
/// 测试接口
async fn api_test(_state: Arc<Mutex<jyframe::AppState>>) -> Result<hyper::Response<BoxBody>> {
    let test_json = serde_json::json!(chrono::Local::now().format("%Y/%m/%d %H:%M:%S").to_string());
    let res = hyper::Response::builder()
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(full(test_json.to_string()))
        .unwrap();
    Ok(res)
}
/// HTTP status code 404
fn not_found() -> hyper::Response<BoxBody> {
    hyper::Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .body(full(NOTFOUND))
        .unwrap()
}
/// 通用生成body内容
fn full<T: Into<bytes::Bytes>>(chunk: T) -> BoxBody {
    http_body_util::Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}