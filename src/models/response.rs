use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub status: String,
    pub message: Option<String>,
    pub data: Option<T>,
}

impl<T> fmt::Display for ApiResponse<T> where T: Serialize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.status, self.message.as_deref().unwrap_or(""))
    }
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "success".to_string(),
            message: None,
            data: Some(data),
        }
    }

    pub fn success_with_message(data: T, message: &str) -> Self {
        Self {
            status: "success".to_string(),
            message: Some(message.to_string()),
            data: Some(data),
        }
    }

    pub fn message(message: &str) -> Self {
        Self {
            status: "success".to_string(),
            message: Some(message.to_string()),
            data: None,
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "error".to_string(),
            message: Some(message.to_string()),
            data: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub status: String,
    pub message: Option<String>,
    pub data: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
    pub total_pages: u64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, total: u64, page: u64, page_size: u64) -> Self {
        let total_pages = (total as f64 / page_size as f64).ceil() as u64;
        
        Self {
            status: "success".to_string(),
            message: None,
            data,
            total,
            page,
            page_size,
            total_pages,
        }
    }
    // // Função não utilizada
    // pub fn with_message(data: Vec<T>, total: u64, page: u64, page_size: u64, message: &str) -> Self {
    //     let total_pages = (total as f64 / page_size as f64).ceil() as u64;
        
    //     Self {
    //         status: "success".to_string(),
    //         message: Some(message.to_string()),
    //         data,
    //         total,
    //         page,
    //         page_size,
    //         total_pages,
    //     }
    // }
}
