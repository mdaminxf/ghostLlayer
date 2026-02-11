use std::path::{Path, PathBuf};
use std::fs;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use windows::{
    core::*,
    Win32::Storage::Vhd::*,
    Win32::Foundation::*,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub golden_image_path: PathBuf,
    pub differencing_disk_path: PathBuf,
    pub mount_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxStatus {
    pub is_active: bool,
    pub mount_point: Option<String>,
    pub session_id: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let base_path = PathBuf::from(app_data).join("GhostLayer");
        
        Self {
            golden_image_path: base_path.join("golden.vhdx"),
            differencing_disk_path: base_path.join("session.vhdx"),
            mount_point: "G:\\".to_string(),
        }
    }
}

pub struct Sandbox {
    config: SandboxConfig,
    status: SandboxStatus,
}

impl Sandbox {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let config = SandboxConfig::default();
        
        // Ensure base directory exists
        if let Some(parent) = config.golden_image_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        Ok(Self {
            config,
            status: SandboxStatus {
                is_active: false,
                mount_point: None,
                session_id: chrono::Utc::now().timestamp().to_string(),
            },
        })
    }
    
    /// Create the golden image VHDX if it doesn't exist
    pub fn ensure_golden_image(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config.golden_image_path.exists() {
            println!("Golden image already exists: {:?}", self.config.golden_image_path);
            return Ok(());
        }
        
        println!("Creating golden image VHDX...");
        
        #[cfg(target_os = "windows")]
        {
            self.create_vhdx(&self.config.golden_image_path, 1024 * 1024 * 1024)?; // 1GB
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // Fallback: Create a dummy file for non-Windows platforms
            fs::write(&self.config.golden_image_path, b"GOLDEN_IMAGE_PLACEHOLDER")?;
        }
        
        println!("Golden image created successfully");
        Ok(())
    }
    
    /// Create a differencing VHDX linked to the golden image
    pub fn create_ephemeral_disk(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Creating ephemeral differencing disk...");
        
        // Ensure golden image exists
        self.ensure_golden_image()?;
        
        // Remove old session disk if exists
        if self.config.differencing_disk_path.exists() {
            fs::remove_file(&self.config.differencing_disk_path)?;
        }
        
        #[cfg(target_os = "windows")]
        {
            self.create_differencing_vhdx(
                &self.config.differencing_disk_path,
                &self.config.golden_image_path,
            )?;
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // Fallback: Create a dummy differencing file
            fs::write(&self.config.differencing_disk_path, b"DIFF_DISK_PLACEHOLDER")?;
        }
        
        println!("Ephemeral disk created: {:?}", self.config.differencing_disk_path);
        Ok(())
    }
    
    /// Mount the ghost layer (differencing disk)
    pub fn mount_ghost_layer(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        if self.status.is_active {
            return Ok(self.status.mount_point.clone().unwrap_or_default());
        }
        
        println!("Mounting ghost layer...");
        
        #[cfg(target_os = "windows")]
        {
            // Note: Actual mounting requires admin privileges and complex Win32 APIs
            // This is a simplified implementation
            println!("VHDX mounting requires elevated privileges");
            println!("Mount point would be: {}", self.config.mount_point);
        }
        
        self.status.is_active = true;
        self.status.mount_point = Some(self.config.mount_point.clone());
        
        Ok(self.config.mount_point.clone())
    }
    
    /// Purge the session (unmount and delete differencing disk)
    pub fn purge_session(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Purging ghost layer session...");
        
        if self.status.is_active {
            #[cfg(target_os = "windows")]
            {
                // Unmount logic would go here
                println!("Unmounting VHDX...");
            }
            
            self.status.is_active = false;
            self.status.mount_point = None;
        }
        
        // Delete differencing disk
        if self.config.differencing_disk_path.exists() {
            fs::remove_file(&self.config.differencing_disk_path)?;
            println!("Differencing disk deleted");
        }
        
        // Generate new session ID
        self.status.session_id = chrono::Utc::now().timestamp().to_string();
        
        println!("Session purged successfully");
        Ok(())
    }
    
    pub fn get_status(&self) -> SandboxStatus {
        self.status.clone()
    }
    
    #[cfg(target_os = "windows")]
    fn create_vhdx(&self, path: &Path, size_bytes: u64) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let path_wide: Vec<u16> = path.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            
            let mut params = CREATE_VIRTUAL_DISK_PARAMETERS::default();
            params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
            params.Anonymous.Version2.MaximumSize = size_bytes;
            
            let mut handle = HANDLE::default();
            
            let storage_type = VIRTUAL_STORAGE_TYPE {
                DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
                VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
            };
            
            let result = CreateVirtualDisk(
                &storage_type,
                PCWSTR(path_wide.as_ptr()),
                VIRTUAL_DISK_ACCESS_MASK(0x003f0000 | 0x00000001 | 0x00000002), // GENERIC_ALL
                None,
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                Some(&params),
                None,
                &mut handle,
            );
            
            if result.is_err() {
                return Err(format!("Failed to create VHDX: {:?}", result).into());
            }
            
            let _ = CloseHandle(handle);
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn create_differencing_vhdx(
        &self,
        diff_path: &Path,
        parent_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let diff_wide: Vec<u16> = diff_path.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            
            let parent_wide: Vec<u16> = parent_path.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            
            let mut params = CREATE_VIRTUAL_DISK_PARAMETERS::default();
            params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
            params.Anonymous.Version2.ParentPath = PCWSTR(parent_wide.as_ptr());
            
            let mut handle = HANDLE::default();
            
            let storage_type = VIRTUAL_STORAGE_TYPE {
                DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
                VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
            };
            
            let result = CreateVirtualDisk(
                &storage_type,
                PCWSTR(diff_wide.as_ptr()),
                VIRTUAL_DISK_ACCESS_MASK(0x003f0000 | 0x00000001 | 0x00000002),
                None,
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                Some(&params),
                None,
                &mut handle,
            );
            
            if result.is_err() {
                return Err(format!("Failed to create differencing VHDX: {:?}", result).into());
            }
            
            let _ = CloseHandle(handle);
        }
        
        Ok(())
    }
}
