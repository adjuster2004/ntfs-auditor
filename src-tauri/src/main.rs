#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rust_xlsxwriter::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::ffi::c_void;

// Для отправки событий и управления состоянием
use tauri::{Emitter, State};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// Работа с процессами (PowerShell)
use std::process::Command;
use std::os::windows::process::CommandExt;

// --- ИМПОРТЫ WIN32 API ---
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, ConvertSidToStringSidW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    LookupAccountNameW, LookupAccountSidW, GetAclInformation, GetAce,
    GetSecurityDescriptorControl, // Чтение контроля безопасности
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, 
    ACL_SIZE_INFORMATION, AclSizeInformation, ACE_HEADER,
    ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, 
    SID_NAME_USE, ACL, PSID
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

// --- СОСТОЯНИЕ ПРИЛОЖЕНИЯ ---
struct AppState {
    cancel_flag: Arc<AtomicBool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AccessType { Allow, Deny }

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AccessRight { FullControl, Modify, ReadAndExecute, Read, Write }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AclEntry {
    pub sid: String,
    pub account_name: String,
    pub rights: AccessRight,
    pub access_type: AccessType,
    pub is_inherited: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FolderNode {
    pub path: String,
    pub name: String,
    pub acl: Vec<AclEntry>,
    pub inheritance_blocked: bool,
    pub children: Option<Vec<FolderNode>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSidsInfo {
    pub username: String,
    pub user_sid: String,
    pub member_of_sids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditSession {
    pub username: String,
    pub target_path: String,
    pub active_user_sids: Vec<String>,
    pub tree: FolderNode,
}

// --- ПОЛУЧЕНИЕ SID И ИМЕН ---
fn get_real_user_sid(username: &str) -> String {
    unsafe {
        let mut sid_size = 0;
        let mut domain_size = 0;
        let mut sid_use = SID_NAME_USE(0);
        let name_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();

        let _ = LookupAccountNameW(None, PCWSTR(name_w.as_ptr()), PSID::default(), &mut sid_size, PWSTR::null(), &mut domain_size, &mut sid_use);
        if sid_size == 0 { return "".to_string(); }

        let mut sid_buf = vec![0u8; sid_size as usize];
        let mut domain_buf = vec![0u16; domain_size as usize];

        if LookupAccountNameW(None, PCWSTR(name_w.as_ptr()), PSID(sid_buf.as_mut_ptr() as *mut _), &mut sid_size, PWSTR(domain_buf.as_mut_ptr()), &mut domain_size, &mut sid_use).is_ok() {
            let mut string_sid = PWSTR::null();
            if ConvertSidToStringSidW(PSID(sid_buf.as_mut_ptr() as *mut _), &mut string_sid).is_ok() {
                let result = string_sid.to_string().unwrap_or_default();
                let _ = LocalFree(HLOCAL(string_sid.0 as *mut _));
                return result;
            }
        }
        "".to_string()
    }
}

unsafe fn get_account_name_from_sid(sid: PSID) -> String {
    let mut name_size = 0;
    let mut domain_size = 0;
    let mut sid_use = SID_NAME_USE(0);
    let _ = LookupAccountSidW(None, sid, PWSTR::null(), &mut name_size, PWSTR::null(), &mut domain_size, &mut sid_use);
    if name_size == 0 { return "Неизвестно".to_string(); }

    let mut name_buf = vec![0u16; name_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    if LookupAccountSidW(None, sid, PWSTR(name_buf.as_mut_ptr()), &mut name_size, PWSTR(domain_buf.as_mut_ptr()), &mut domain_size, &mut sid_use).is_ok() {
        let account = String::from_utf16_lossy(&name_buf[..name_size as usize]);
        let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);
        if domain.is_empty() { return account; } else { return format!("{}\\{}", domain, account); }
    }
    "Неизвестно".to_string()
}

// --- ЧТЕНИЕ ACL И СТАТУСА НАСЛЕДОВАНИЯ ---
fn get_real_acl(path: &str) -> (Vec<AclEntry>, bool) {
    let mut entries = Vec::new();
    let mut inheritance_blocked = false;

    unsafe {
        let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let mut p_sd = PSECURITY_DESCRIPTOR::default();

        if GetNamedSecurityInfoW(PCWSTR(path_w.as_ptr()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, Some(&mut p_dacl), None, &mut p_sd).is_ok() && !p_dacl.is_null() {
            
            // ПРОВЕРКА РАЗРЫВА НАСЛЕДОВАНИЯ (исправлено для u16/u32)
            let mut control: u16 = 0;
            let mut rev: u32 = 0;
            if GetSecurityDescriptorControl(p_sd, &mut control, &mut rev).is_ok() {
                if (control & 0x1000) != 0 {
                    inheritance_blocked = true;
                }
            }

            let mut acl_info = ACL_SIZE_INFORMATION::default();
            if GetAclInformation(p_dacl, &mut acl_info as *mut _ as *mut c_void, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation).is_ok() {
                for i in 0..acl_info.AceCount {
                    let mut p_ace: *mut c_void = std::ptr::null_mut();
                    if GetAce(p_dacl, i, &mut p_ace).is_ok() {
                        let header = &*(p_ace as *const ACE_HEADER);
                        
                        let is_inherited = (header.AceFlags & 0x10) != 0;

                        let (sid_ptr, mask, ace_type) = if header.AceType == ACCESS_ALLOWED_ACE_TYPE {
                            let ace = &*(p_ace as *const ACCESS_ALLOWED_ACE);
                            (PSID(&ace.SidStart as *const _ as *mut _), ace.Mask, AccessType::Allow)
                        } else if header.AceType == ACCESS_DENIED_ACE_TYPE {
                            let ace = &*(p_ace as *const ACCESS_DENIED_ACE);
                            (PSID(&ace.SidStart as *const _ as *mut _), ace.Mask, AccessType::Deny)
                        } else { continue; };

                        let mut string_sid = PWSTR::null();
                        if ConvertSidToStringSidW(sid_ptr, &mut string_sid).is_ok() {
                            let sid_str = string_sid.to_string().unwrap_or_default();
                            let _ = LocalFree(HLOCAL(string_sid.0 as *mut _));
                            let account_name = get_account_name_from_sid(sid_ptr);
                            // Более точное вычисление прав по битовым маскам Windows
							let rights = if (mask & 0x1F01FF) == 0x1F01FF || (mask & 0x10000000) != 0 {
								AccessRight::FullControl
							} else if (mask & 0x00010000) != 0 && (mask & 0x0002) != 0 {
								// 0x10000 (Delete) + 0x0002 (Write Data) = Изменение
								AccessRight::Modify 
							} else if (mask & 0x0002) != 0 {
								// Есть только право на запись
								AccessRight::Write
							} else if (mask & 0x0020) != 0 && (mask & 0x0001) != 0 {
								// 0x0020 (Execute) + 0x0001 (Read Data) = Чтение и выполнение
								AccessRight::ReadAndExecute
							} else {
								AccessRight::Read // Базовое чтение
							};
                            
                            entries.push(AclEntry { sid: sid_str, account_name, rights, access_type: ace_type, is_inherited });
                        }
                    }
                }
            }
            let _ = LocalFree(HLOCAL(p_sd.0 as *mut _));
        }
    }
    (entries, inheritance_blocked)
}

// Добавили параметр `scan_files` (bool)
fn build_folder_tree(window: &tauri::Window, dir_path: &Path, current_depth: u32, max_depth: u32, scan_files: bool, cancel_flag: &Arc<AtomicBool>) -> Result<FolderNode, String> {
    let path_str = dir_path.to_string_lossy().to_string();
    let name = dir_path.file_name().unwrap_or_default().to_string_lossy().to_string();
    
    let _ = window.emit("scan-progress", &path_str);

    let (acl, inheritance_blocked) = get_real_acl(&path_str);

    let mut node = FolderNode {
        path: path_str.clone(),
        name: if name.is_empty() { path_str.clone() } else { name },
        acl,
        inheritance_blocked, 
        children: Some(vec![]),
    };

    if current_depth >= max_depth || cancel_flag.load(Ordering::Relaxed) { return Ok(node); }

    if let Ok(entries) = fs::read_dir(dir_path) {
        let mut children = Vec::new();
        for entry in entries.flatten() {
            if cancel_flag.load(Ordering::Relaxed) { break; }

            let p = entry.path();
            if p.is_dir() {
                // Рекурсивный вызов с новыми параметрами
                if let Ok(c) = build_folder_tree(window, &p, current_depth + 1, max_depth, scan_files, cancel_flag) {
                    children.push(c);
                }
            } else if scan_files { // Проверяем флаг, прежде чем сканировать файл
                let file_path = p.to_string_lossy().to_string();
                let _ = window.emit("scan-progress", &file_path);
                
                let (acl, inheritance_blocked) = get_real_acl(&file_path);
                
                children.push(FolderNode {
                    path: file_path,
                    name: format!("📄 {}", p.file_name().unwrap_or_default().to_string_lossy()),
                    acl,
                    inheritance_blocked, 
                    children: None,
                });
            }
        }
        node.children = Some(children);
    }
    Ok(node)
}

// Добавили параметры `max_depth` (u32) и `scan_files` (bool)
#[tauri::command]
async fn scan_directory_tree(window: tauri::Window, path: String, max_depth: u32, scan_files: bool, state: State<'_, AppState>) -> Result<FolderNode, String> {
    let p = Path::new(&path);
    if !p.exists() { return Err("Путь не найден".into()); }
    
    state.cancel_flag.store(false, Ordering::Relaxed);
    build_folder_tree(&window, p, 0, max_depth, scan_files, &state.cancel_flag) 
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) {
    state.cancel_flag.store(true, Ordering::Relaxed);
}

#[tauri::command]
async fn get_user_sids(username: String) -> Result<UserSidsInfo, String> {
    let user_sid = get_real_user_sid(&username);
    if user_sid.is_empty() { return Err("Пользователь или группа не найдены".into()); }

    let mut groups = Vec::new();
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let ps_cmd = format!(
        "Add-Type -AssemblyName System.DirectoryServices.AccountManagement; \
         $name = '{}'; \
         $sids = @(); \
         try {{ \
             $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Machine'); \
             $u = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $name); \
             if ($u) {{ $u.GetAuthorizationGroups() | ForEach-Object {{ $sids += $_.Sid.Value }} }} \
         }} catch {{}} \
         try {{ \
             $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Domain'); \
             $u = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $name); \
             if ($u) {{ $u.GetAuthorizationGroups() | ForEach-Object {{ $sids += $_.Sid.Value }} }} \
         }} catch {{}} \
         $sids | Select-Object -Unique",
        username
    );

    if let Ok(output) = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(&["-NoProfile", "-Command", &ps_cmd])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let sid = line.trim();
            if sid.starts_with("S-1-") {
                groups.push(sid.to_string());
            }
        }
    }

    Ok(UserSidsInfo { username, user_sid, member_of_sids: groups })
}

#[tauri::command]
async fn save_session(session: AuditSession, save_path: String) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&session).map_err(|e| e.to_string())?;
    fs::write(&save_path, json).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn load_session(load_path: String) -> Result<AuditSession, String> {
    let json = fs::read_to_string(&load_path).map_err(|e| e.to_string())?;
    let session: AuditSession = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    Ok(session)
}

#[tauri::command]
async fn export_to_excel(tree: FolderNode, save_path: String) -> Result<(), String> {
    let mut workbook = Workbook::new();
    let header_format = Format::new().set_bold().set_background_color(Color::RGB(0xD3D3D3));
    
    // --- ЛИСТ 1: ДЕТАЛЬНЫЙ СПИСОК ---
    let worksheet1 = workbook.add_worksheet();
    worksheet1.set_name("Детальный список").map_err(|e| e.to_string())?;

    let headers = ["Путь", "Тип", "Учетная запись", "SID", "Права", "Доступ", "Унаследовано"];
    for (i, h) in headers.iter().enumerate() {
        worksheet1.write_string_with_format(0, i as u16, *h, &header_format).map_err(|e| e.to_string())?;
    }

    let mut all_paths = Vec::new();
    let mut all_accounts = std::collections::HashSet::new();
    let mut matrix_data: std::collections::HashMap<String, std::collections::HashMap<String, String>> = std::collections::HashMap::new();

    let mut row = 1;
    fn process_node(
        node: &FolderNode, 
        ws: &mut Worksheet, 
        r: &mut u32, 
        paths: &mut Vec<String>, 
        accs: &mut std::collections::HashSet<String>,
        matrix: &mut std::collections::HashMap<String, std::collections::HashMap<String, String>>
    ) -> Result<(), String> {
        let node_type = if node.children.is_some() { "Папка" } else { "Файл" };
        paths.push(node.path.clone());
        let mut path_permissions = std::collections::HashMap::new();

        for entry in &node.acl {
            ws.write_string(*r, 0, &node.path).map_err(|e| e.to_string())?;
            ws.write_string(*r, 1, node_type).map_err(|e| e.to_string())?;
            ws.write_string(*r, 2, &entry.account_name).map_err(|e| e.to_string())?;
            ws.write_string(*r, 3, &entry.sid).map_err(|e| e.to_string())?;
            ws.write_string(*r, 4, format!("{:?}", entry.rights)).map_err(|e| e.to_string())?;
            ws.write_string(*r, 5, format!("{:?}", entry.access_type)).map_err(|e| e.to_string())?;
            ws.write_string(*r, 6, if entry.is_inherited { "Да" } else { "Нет" }).map_err(|e| e.to_string())?;
            *r += 1;

            if entry.access_type == AccessType::Allow {
                accs.insert(entry.account_name.clone());
                path_permissions.insert(entry.account_name.clone(), format!("{:?}", entry.rights));
            }
        }
        matrix.insert(node.path.clone(), path_permissions);

        if let Some(children) = &node.children {
            for child in children { process_node(child, ws, r, paths, accs, matrix)?; }
        }
        Ok(())
    }

    process_node(&tree, worksheet1, &mut row, &mut all_paths, &mut all_accounts, &mut matrix_data)?;

    // --- ЛИСТ 2: МАТРИЦА ПРАВ ---
    let worksheet2 = workbook.add_worksheet();
    worksheet2.set_name("Матрица прав").map_err(|e| e.to_string())?;
    
    let mut sorted_accounts: Vec<String> = all_accounts.into_iter().collect();
    sorted_accounts.sort();

    worksheet2.write_string(0, 0, "Путь / Группа").map_err(|e| e.to_string())?;
    for (col, acc) in sorted_accounts.iter().enumerate() {
        worksheet2.write_string_with_format(0, (col + 1) as u16, acc, &header_format).map_err(|e| e.to_string())?;
    }

    for (r_idx, path) in all_paths.iter().enumerate() {
        worksheet2.write_string((r_idx + 1) as u32, 0, path).map_err(|e| e.to_string())?;
        if let Some(perms) = matrix_data.get(path) {
            for (c_idx, acc) in sorted_accounts.iter().enumerate() {
                if let Some(right) = perms.get(acc) {
                    worksheet2.write_string((r_idx + 1) as u32, (c_idx + 1) as u16, right).map_err(|e| e.to_string())?;
                }
            }
        }
    }

    // --- ЛИСТ 3: СОСТАВ ГРУПП ---
    let worksheet3 = workbook.add_worksheet();
    worksheet3.set_name("Состав групп").map_err(|e| e.to_string())?;

    worksheet3.write_string_with_format(0, 0, "Группа", &header_format).map_err(|e| e.to_string())?;
    worksheet3.write_string_with_format(0, 1, "Участник", &header_format).map_err(|e| e.to_string())?;

    let mut row3 = 1;
    for acc in &sorted_accounts {
        if acc.contains("СИСТЕМА") || acc.contains("ВЛАДЕЛЕЦ") { continue; }
        
        let members = get_group_members(acc);
        if !members.is_empty() {
            for m in members {
                worksheet3.write_string(row3, 0, acc).map_err(|e| e.to_string())?;
                worksheet3.write_string(row3, 1, &m).map_err(|e| e.to_string())?;
                row3 += 1;
            }
        } else {
            // Если это конкретный пользователь (или пустая группа), тоже зафиксируем его
            worksheet3.write_string(row3, 0, acc).map_err(|e| e.to_string())?;
            worksheet3.write_string(row3, 1, "(Нет вложенных участников)").map_err(|e| e.to_string())?;
            row3 += 1;
        }
    }

    workbook.save(&save_path).map_err(|e| e.to_string())?;
    Ok(())
}

// 1. ВОССТАНОВЛЕНИЕ С ВОЗВРАТОМ SDDL
#[tauri::command]
async fn restore_inheritance_with_sddl(path: String) -> Result<String, String> {
    // Используем чистый .NET вместо Get-Acl / Set-Acl
    let ps_cmd = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         $path = '{}'; \
         $item = Get-Item -LiteralPath $path -Force; \
         $acl = $item.GetAccessControl('Access'); \
         $oldSddl = $acl.Sddl; \
         $acl.SetAccessRuleProtection($false, $true); \
         $item.SetAccessControl($acl); \
         Write-Output $oldSddl",
        path.replace("'", "''")
    );

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("powershell").creation_flags(CREATE_NO_WINDOW).args(&["-NoProfile", "-Command", &ps_cmd]).output().map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

// 2. ОТМЕНА ИЗМЕНЕНИЙ (БЕЗ ИСПОЛЬЗОВАНИЯ SET-ACL)
#[tauri::command]
async fn revert_acl(path: String, sddl: String) -> Result<(), String> {
    let ps_cmd = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         $path = '{}'; \
         $sddl = '{}'; \
         $item = Get-Item -LiteralPath $path -Force; \
         $acl = $item.GetAccessControl('Access'); \
         $acl.SetSecurityDescriptorSddlForm($sddl, 'Access'); \
         $item.SetAccessControl($acl);",
        path.replace("'", "''"), sddl.replace("'", "''")
    );

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("powershell").creation_flags(CREATE_NO_WINDOW).args(&["-NoProfile", "-Command", &ps_cmd]).output().map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

// 3. ДОБАВЛЕНИЕ НОВЫХ ПРАВ
#[tauri::command]
async fn add_permission(path: String, account: String, right: String, access_type: String, is_dir: bool) -> Result<(), String> {
    let inherit = if is_dir { "ContainerInherit,ObjectInherit" } else { "None" };
    
    let ps_cmd = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         $path = '{}'; \
         $item = Get-Item -LiteralPath $path -Force; \
         $acl = $item.GetAccessControl('Access'); \
         $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('{}', '{}', '{}', 'None', '{}'); \
         $acl.AddAccessRule($rule); \
         $item.SetAccessControl($acl);",
        path.replace("'", "''"), account.replace("'", "''"), right, inherit, access_type
    );

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = Command::new("powershell").creation_flags(CREATE_NO_WINDOW).args(&["-NoProfile", "-Command", &ps_cmd]).output().map_err(|e| e.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(())
}

fn get_group_members(name: &str) -> Vec<String> {
    let mut members = Vec::new();
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // ДОБАВЛЕНА КОДИРОВКА UTF-8 В НАЧАЛО СКРИПТА
    let ps_cmd = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         Add-Type -AssemblyName System.DirectoryServices.AccountManagement; \
         $name = '{}'; $m = @(); \
         try {{ \
             $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Machine'); \
             $g = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, $name); \
             if ($g) {{ $m = $g.GetMembers($true) | ForEach-Object {{ $_.Name + ' (' + $_.SamAccountName + ')' }} }} \
         }} catch {{}} \
         if (-not $m) {{ \
             try {{ \
                 $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Domain'); \
                 $g = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, $name); \
                 if ($g) {{ $m = $g.GetMembers($true) | ForEach-Object {{ $_.Name + ' (' + $_.SamAccountName + ')' }} }} \
             }} catch {{}} \
         }} \
         $m | Select-Object -Unique",
        name.replace("'", "''")
    );

    if let Ok(output) = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(&["-NoProfile", "-Command", &ps_cmd])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let member = line.trim();
            if !member.is_empty() { members.push(member.to_string()); }
        }
    }
    members
}

fn main() {
    tauri::Builder::default()
        .manage(AppState { 
            cancel_flag: Arc::new(AtomicBool::new(false)) 
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            scan_directory_tree, 
            get_user_sids, 
            export_to_excel,
            cancel_scan,
            save_session,
            load_session,
            // НОВЫЕ КОМАНДЫ ЗДЕСЬ:
            restore_inheritance_with_sddl, 
            revert_acl, 
            add_permission
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
