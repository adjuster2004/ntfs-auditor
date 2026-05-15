import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save, ask } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type AccessType = "Allow" | "Deny";
type AccessRight = "FullControl" | "Modify" | "ReadAndExecute" | "Read" | "Write";

interface AclEntry {
  sid: string; account_name: string; rights: AccessRight; access_type: AccessType; is_inherited: boolean;
}
interface FolderNodeData {
  path: string; name: string; acl: AclEntry[]; inheritance_blocked: boolean; children: FolderNodeData[] | null;
}
interface UserSidsInfo {
  username: string; user_sid: string; member_of_sids: string[];
}

const calculateEffectiveAccess = (folderAcl: AclEntry[], userSids: string[]): string | null => {
  if (!userSids || userSids.length === 0) return null;
  if (!folderAcl || folderAcl.length === 0) return "ACL пуст";
  
  let hasFullControl = false, hasModify = false, hasWrite = false, hasRead = false, isDenied = false;
  
  for (const entry of folderAcl) {
    if (userSids.includes(entry.sid)) {
      if (entry.access_type === "Deny") { isDenied = true; break; }
      if (entry.rights === "FullControl") hasFullControl = true;
      if (entry.rights === "Modify") hasModify = true;
      if (entry.rights === "Write") hasWrite = true;
      if (entry.rights === "ReadAndExecute" || entry.rights === "Read") hasRead = true;
    }
  }
  
  if (isDenied) return "Запрещено";
  if (hasFullControl) return "Полный доступ";
  if (hasModify) return "Изменение";
  if (hasWrite) return "Запись";
  if (hasRead) return "Чтение";
  
  return "Нет доступа";
};

function FolderNode({ folder, userSids }: { folder: FolderNodeData, userSids: string[] }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isBlocked, setIsBlocked] = useState(folder.inheritance_blocked);
  const [undoSddl, setUndoSddl] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [showRawAcl, setShowRawAcl] = useState(false);
  const [newAcc, setNewAcc] = useState("");
  const [newRight, setNewRight] = useState("ReadAndExecute");
  const [newType, setNewType] = useState("Allow");

  const handleError = (e: any) => {
    const errorStr = String(e);
    if (errorStr.includes("UnauthorizedAccess") || errorStr.includes("PermissionDenied") || errorStr.includes("Отказано в доступе")) {
      alert(
        `❌ Отказано в доступе!\n\n` +
        `Чтобы изменять права на системные папки (например, Program Files или корень диска C:\\), ` +
        `необходимо перезапустить программу от имени Администратора.\n\n` +
        `Техническая деталь: ${errorStr.split('\n')[0]}`
      );
    } else {
      alert(`Ошибка: ${errorStr}`);
    }
  };

  const handleRestore = async () => {
    const yes = await ask(
      `Вы собираетесь восстановить наследование от родительской папки для:\n\n${folder.path}\n\nУнаследованные права "прольются" на этот объект. Вы сможете отменить это действие позже.\n\nПродолжить?`, 
      { title: '⚠️ ВНИМАНИЕ: СНЯТИЕ ЗАЩИТЫ', kind: 'warning' }
    );
    if (!yes) return;
    
    setIsProcessing(true);
    try {
      const oldSddl: string = await invoke("restore_inheritance_with_sddl", { path: folder.path });
      setUndoSddl(oldSddl); 
      setIsBlocked(false);  
    } catch (e) { handleError(e); } 
    setIsProcessing(false);
  };

  const handleRevert = async () => {
    if (!undoSddl) return;
    setIsProcessing(true);
    try {
      await invoke("revert_acl", { path: folder.path, sddl: undoSddl });
      setUndoSddl(null); 
      setIsBlocked(true); 
    } catch (e) { handleError(e); }
    setIsProcessing(false);
  };

  const handleAddPerm = async () => {
    if (!newAcc) return alert("Введите имя пользователя или группы!");
    setIsProcessing(true);
    try {
      await invoke("add_permission", { 
        path: folder.path, account: newAcc, right: newRight, accessType: newType, isDir: folder.children !== null 
      });
      alert(`Права для ${newAcc} успешно добавлены!\nНажмите "Собрать данные", чтобы обновить дерево.`);
      setNewAcc(""); 
    } catch (e) { handleError(e); }
    setIsProcessing(false);
  };

  const isFile = folder.children === null;
  const accessLevel = calculateEffectiveAccess(folder.acl, userSids);
  
  const badgeStyle = {
    "Полный доступ": { backgroundColor: "#dcfce7", color: "#166534" },
    "Изменение": { backgroundColor: "#cffafe", color: "#0891b2" },
    "Запись": { backgroundColor: "#ffedd5", color: "#c2410c" },
    "Чтение": { backgroundColor: "#fef08a", color: "#854d0e" },
    "Запрещено": { backgroundColor: "#fee2e2", color: "#991b1b" }
  }[accessLevel || ""] || { backgroundColor: "#f3f4f6", color: "#6b7280" };

  return (
    <div style={{ marginLeft: "18px", marginTop: "2px", fontFamily: "Segoe UI" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "4px 2px" }}>
        {!isFile && (
          <button onClick={() => setIsExpanded(!isExpanded)} style={{ width: "20px", height: "20px", minWidth: "20px", padding: 0, margin: 0, cursor: "pointer", border: "1px solid #ccc", borderRadius: "4px", backgroundColor: "#fff", lineHeight: 1 }}>
            {isExpanded ? "-" : "+"}
          </button>
        )}
        {isFile && <div style={{ width: "20px", minWidth: "20px" }} />}
        <span>{isFile ? "📄" : "📁"}</span>
        <span style={{ fontSize: "14px", fontWeight: isFile ? "400" : "600", wordBreak: "break-all" }}>{folder.name}</span>
        
        {isBlocked ? (
          <>
            <span title="Наследование разорвано (Явные права)" style={{ color: "#d32f2f", cursor: "help" }}>✂️</span>
            {undoSddl ? (
              <button onClick={handleRevert} disabled={isProcessing} title="Отменить: Вернуть разрыв наследования" style={{ cursor: "pointer", fontSize: "12px", background: "#fff9c4", border: "1px solid #fbc02d", borderRadius: "4px", padding: "1px 6px" }}>↩️ Отмена</button>
            ) : (
              <button onClick={handleRestore} disabled={isProcessing} title="Нажмите, чтобы восстановить наследование от родителя" style={{ cursor: "pointer", fontSize: "12px", background: "#ffebee", border: "1px solid #ffcdd2", borderRadius: "4px", padding: "1px 4px" }}>🔄 Восстановить</button>
            )}
          </>
        ) : (
          <span title="Права наследуются от родителя" style={{ color: "#388e3c", cursor: "help" }}>🔗</span>
        )}
        
        {accessLevel && <span style={{ padding: "2px 8px", borderRadius: "10px", fontSize: "11px", fontWeight: "600", ...badgeStyle }}>{accessLevel}</span>}
        
        <button onClick={() => setShowRawAcl(!showRawAcl)} style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "4px", border: "1px solid #ddd", background: showRawAcl ? "#e0e0e0" : "#fff", cursor: "pointer" }}>
          ACL ({folder.acl.length})
        </button>
      </div>

      {showRawAcl && (
        <div style={{ marginLeft: "30px", marginBottom: "5px", padding: "10px", backgroundColor: "#fdfdfd", border: "1px dashed #ccc", borderRadius: "6px", fontSize: "11px" }}>
          <strong style={{ color: "#333" }}>Список доступа (DACL):</strong>
          <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "5px", marginBottom: "10px" }}>
            <tbody>
              {folder.acl.map((entry, idx) => (
                <tr key={idx} style={{ borderBottom: "1px solid #eee" }}>
                  <td style={{ padding: "3px", color: entry.access_type === "Allow" ? "#27ae60" : "#c0392b", fontWeight: "bold" }}>{entry.access_type === "Allow" ? "РАЗРЕШИТЬ" : "ЗАПРЕТИТЬ"}</td>
                  <td style={{ padding: "3px", fontWeight: "500" }}>{entry.account_name}</td>
                  <td style={{ padding: "3px", color: "#666" }}>
                    {{ FullControl: "Полный доступ", Modify: "Изменение", ReadAndExecute: "Чтение и запуск", Write: "Запись", Read: "Чтение" }[entry.rights] || entry.rights}
                  </td>
                  <td style={{ padding: "3px", fontWeight: "bold", color: entry.is_inherited ? "#bdc3c7" : "#2980b9" }}>{entry.is_inherited ? "Унаследовано" : "ЯВНОЕ"}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ background: "#f0f8ff", padding: "8px", borderRadius: "4px", border: "1px solid #bbdefb", display: "flex", gap: "5px", alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ fontWeight: "bold", color: "#1565c0" }}>+ Добавить:</span>
            <input list="known-accounts" placeholder="Имя (например, Users)" value={newAcc} onChange={(e) => setNewAcc(e.target.value)} style={{ padding: "4px", border: "1px solid #ccc", borderRadius: "3px", width: "150px" }} />
            <select value={newRight} onChange={(e) => setNewRight(e.target.value)} style={{ padding: "4px" }}>
              <option value="FullControl">Полный доступ</option>
              <option value="Modify">Изменение</option>
              <option value="ReadAndExecute">Чтение и запуск</option>
              <option value="Write">Запись</option>
            </select>
            <select value={newType} onChange={(e) => setNewType(e.target.value)} style={{ padding: "4px" }}>
              <option value="Allow">Разрешить</option>
              <option value="Deny">Запретить</option>
            </select>
            <button onClick={handleAddPerm} disabled={isProcessing} style={{ padding: "4px 10px", background: "#1565c0", color: "#fff", border: "none", borderRadius: "3px", cursor: "pointer" }}>
              Применить
            </button>
          </div>
        </div>
      )}

      {isExpanded && !isFile && folder.children && (
        <div style={{ borderLeft: "1px solid #e0e0e0", marginLeft: "9px" }}>
          {folder.children.map((child, idx) => <FolderNode key={idx} folder={child} userSids={userSids} />)}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [targetPath, setTargetPath] = useState("C:\\Users");
  const [filterUser, setFilterUser] = useState("");
  const [treeData, setTreeData] = useState<FolderNodeData | null>(null);
  const [status, setStatus] = useState("Готов");
  const [activeUserSids, setActiveUserSids] = useState<string[]>([]);
  const [knownAccounts, setKnownAccounts] = useState<string[]>([]);
  
  const [isScanning, setIsScanning] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [currentPath, setCurrentPath] = useState("");
  const [scanDepth, setScanDepth] = useState<number>(3);
  const [scanFiles, setScanFiles] = useState<boolean>(false);

  const [adSuggestions, setAdSuggestions] = useState<string[]>([]);

  useEffect(() => {
    let unlistenScan: any;
    let unlistenExport: any;
    async function setupListen() { 
      unlistenScan = await listen<string>("scan-progress", (e) => setCurrentPath(e.payload)); 
      unlistenExport = await listen<string>("export-progress", (e) => setStatus(e.payload)); 
    }
    setupListen();
    return () => { 
      if (unlistenScan) unlistenScan(); 
      if (unlistenExport) unlistenExport();
    };
  }, []);

  // АВТОМАТИЧЕСКИЙ ПОИСК В AD ПРИ НАБОРЕ ТЕКСТА
  useEffect(() => {
    // Ищем в AD только если введено хотя бы 3 символа
    if (filterUser.length < 3) {
      setAdSuggestions([]);
      return;
    }
    const timeoutId = setTimeout(async () => {
      try {
        const results: string[] = await invoke("search_ad_accounts", { query: filterUser });
        setAdSuggestions(results);
      } catch (e) {
        console.error("Ошибка поиска в AD:", e);
      }
    }, 500);

    return () => clearTimeout(timeoutId); 
  }, [filterUser]);

  const selectDirectory = async () => {
    const selected = await open({ directory: true });
    if (selected) setTargetPath(selected as string);
  };

  const handleScan = async () => {
    if (!targetPath) return;
    try {
      setTreeData(null); setIsScanning(true); setStatus("Сбор данных ACL...");
      const tree: FolderNodeData = await invoke("scan_directory_tree", { 
        path: targetPath, maxDepth: scanDepth, scanFiles: scanFiles 
      });
      setTreeData(tree);
      
      const accs = new Set<string>();
      const extractAccounts = (node: FolderNodeData) => {
        node.acl.forEach(a => accs.add(a.account_name));
        node.children?.forEach(extractAccounts);
      };
      extractAccounts(tree);
      setKnownAccounts(Array.from(accs).sort());
      
      setStatus("Сканирование завершено.");
    } catch (e) { setStatus(`Ошибка: ${e}`); } 
    finally { setIsScanning(false); setCurrentPath(""); }
  };

  const handleApplyFilter = async () => {
    if (!filterUser) return setActiveUserSids([]);
    try {
      let searchAcc = filterUser;
      const match = filterUser.match(/\(([^)]+)\)$/); 
      if (match) {
        searchAcc = match[1]; 
      }
      
      setStatus(`Опрос системы для: ${searchAcc}...`);
      const info: UserSidsInfo = await invoke("get_user_sids", { username: searchAcc });
      setActiveUserSids([info.user_sid, ...info.member_of_sids]);
      setStatus(`Фильтр применен: ${info.username} (Групп: ${info.member_of_sids.length})`);
    } catch (e) {
      setStatus(`Ошибка: Пользователь/Группа не найдены`);
      setActiveUserSids([]);
    }
  };

  const handleExport = async () => {
    if (!treeData) return;
    try {
      const filePath = await save({ filters: [{ name: "Excel", extensions: ["xlsx"] }], defaultPath: "audit_report.xlsx" });
      if (filePath) {
        setIsExporting(true);
        setStatus("Подготовка к выгрузке...");
        await invoke("export_to_excel", { tree: treeData, savePath: filePath });
        alert("Файл успешно сохранен! В нем содержатся ВСЕ собранные права и матрицы.");
      }
    } catch (e) {
      alert(`Ошибка при сохранении: ${e}`);
      setStatus("Ошибка экспорта.");
    } finally {
      setIsExporting(false);
    }
  };

  // Объединяем локальные аккаунты из сканирования и результаты из AD, исключая дубликаты
  const combinedAccounts = Array.from(new Set([...knownAccounts, ...adSuggestions]));

  return (
    <div style={{ padding: "20px", height: "100vh", display: "flex", flexDirection: "column", backgroundColor: "#f0f2f5", boxSizing: "border-box" }}>
      
      <datalist id="known-accounts">
        {combinedAccounts.map(acc => <option key={acc} value={acc} />)}
      </datalist>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "15px" }}>
        <h2 style={{ color: "#1a237e", margin: 0 }}>NTFS Auditor v2.2 <span style={{fontSize:"14px", color:"#666", fontWeight:"normal"}}>| Управление и работа с доменными записями</span></h2>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", background: "#fff", padding: "15px", borderRadius: "8px", alignItems: "center", boxShadow: "0 2px 4px rgba(0,0,0,0.05)" }}>
        <strong style={{ color: "#555", minWidth: "90px" }}>1. Источник:</strong>
        <div style={{ display: "flex", flex: "1 1 300px", gap: "5px", alignItems: "center" }}>
          <input placeholder="Путь" value={targetPath} onChange={(e) => setTargetPath(e.target.value)} style={{ padding: "8px", flex: 1, border: "1px solid #ddd", borderRadius: "4px", minWidth: "120px" }} />
          <button onClick={selectDirectory} style={{ padding: "0 12px", height: "34px", flexShrink: 0 }}>📂</button>
          
          <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", marginLeft: "10px", alignItems: "center", borderLeft: "1px solid #ddd", paddingLeft: "15px" }}>
            <label style={{ fontSize: "12px", color: "#555", display: "flex", alignItems: "center", gap: "5px", whiteSpace: "nowrap" }}>
              Глубина:
              <select value={scanDepth} onChange={(e) => setScanDepth(Number(e.target.value))} disabled={isScanning} style={{ padding: "4px", borderRadius: "4px", border: "1px solid #ccc" }}>
                <option value={1}>1 уровень</option>
                <option value={2}>2 уровня</option>
                <option value={3}>3 уровня</option>
                <option value={5}>5 уровней</option>
                <option value={10}>10 уровней</option>
                <option value={99}>Без лимита</option>
              </select>
            </label>
            
            <label style={{ fontSize: "12px", color: "#555", display: "flex", alignItems: "center", gap: "5px", cursor: isScanning ? "default" : "pointer", whiteSpace: "nowrap" }}>
              <input type="checkbox" checked={scanFiles} onChange={(e) => setScanFiles(e.target.checked)} disabled={isScanning} />
              Проверять файлы
            </label>
          </div>
        </div>

        {isScanning ? (
          <button onClick={async () => await invoke("cancel_scan")} style={{ padding: "8px 20px", backgroundColor: "#e74c3c", color: "#fff", border: "none", cursor: "pointer", borderRadius: "6px", fontWeight: "bold", flex: "0 0 160px" }}>Остановить</button>
        ) : (
          <button onClick={handleScan} style={{ padding: "8px 20px", backgroundColor: "#1976d2", color: "#fff", border: "none", cursor: "pointer", borderRadius: "6px", fontWeight: "bold", flex: "0 0 160px" }}>Собрать данные</button>
        )}
      </div>

      {isScanning && <div style={{ fontSize: "11px", color: "#1565c0", margin: "5px 0", padding: "4px 8px" }}>🔍 {currentPath}</div>}

      <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", margin: "10px 0", background: "#fff", padding: "15px", borderRadius: "8px", alignItems: "center", boxShadow: "0 2px 4px rgba(0,0,0,0.05)", opacity: treeData ? 1 : 0.6 }}>
        <strong style={{ color: "#555", minWidth: "90px" }}>2. Фильтр:</strong>
        <input list="known-accounts" disabled={!treeData} placeholder="Учетная запись или Группа" value={filterUser} onChange={(e) => setFilterUser(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleApplyFilter()} style={{ padding: "8px", flex: "1 1 200px", border: "1px solid #ddd", borderRadius: "4px", minWidth: "150px" }} />
        
        <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", alignItems: "center" }}>
          <button disabled={!treeData} onClick={handleApplyFilter} style={{ padding: "8px 15px", backgroundColor: "#2e7d32", color: "#fff", border: "none", cursor: treeData ? "pointer" : "default", borderRadius: "6px", fontWeight: "bold", whiteSpace: "nowrap" }}>Применить</button>
          {activeUserSids.length > 0 && <button onClick={() => {setFilterUser(""); setActiveUserSids([]);}} style={{ padding: "8px 15px", border: "1px solid #ccc", cursor: "pointer", borderRadius: "6px", whiteSpace: "nowrap" }}>Сбросить</button>}

          <div style={{ borderLeft: "1px solid #ddd", height: "30px", margin: "0 5px" }} />
          
          <button onClick={handleExport} disabled={!treeData || isScanning || isExporting} style={{ padding: "8px 20px", borderRadius: "6px", border: "none", backgroundColor: (!treeData || isScanning || isExporting) ? "#e0e0e0" : "#fb8c00", color: "#fff", cursor: (!treeData || isScanning || isExporting) ? "default" : "pointer", fontWeight: "bold", whiteSpace: "nowrap" }}>
            {isExporting ? "⏳ Сохранение..." : "Выгрузить Excel"}
          </button>
        </div>
      </div>

      <div style={{ flex: 1, border: "1px solid #cfd8dc", padding: "20px", overflow: "auto", backgroundColor: "#fff", borderRadius: "8px" }}>
        {treeData ? <FolderNode folder={treeData} userSids={activeUserSids} /> : <div style={{ textAlign: "center", color: "#90a4ae", marginTop: "100px" }}>Нажмите «Собрать данные».</div>}
      </div>
      
      <div style={{ fontSize: "12px", color: "#78909c", marginTop: "10px" }}>ℹ️ {status}</div>
      
      <div style={{ textAlign: "center", marginTop: "15px", paddingTop: "10px", fontSize: "12px", color: "#7f8c8d", borderTop: "1px solid #e0e0e0" }}>
        Продукт разработан <strong style={{ color: "#2c3e50" }}>Adjuster2004</strong> | {" "}
        <a href="https://github.com/adjuster2004/ntfs-auditor" target="_blank" rel="noreferrer" style={{ color: "#3498db", textDecoration: "none", fontWeight: "bold" }}>
          GitHub Репозиторий
        </a>
      </div>
    </div>
  );
}
