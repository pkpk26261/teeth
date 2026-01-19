// ===== 病患管理系統 =====
const patientState = {
  patients: [], // 病患列表
  currentPatient: null, // 當前選中/編輯的病患
  isEditing: false, // 是否正在編輯
  draft: null, // 暫存的草稿資料
};

// DOM 元素 - 病患模式
const patientMode = document.getElementById('patientMode');
const teethMode = document.getElementById('teethMode');
const addPatientBtn = document.getElementById('addPatientBtn');
const patientSearch = document.getElementById('patientSearch');
const patientListEl = document.getElementById('patientList');
const patientFormContainer = document.getElementById('patientFormContainer');
const patientFormTemplate = document.getElementById('patientFormTemplate');
const backToPatientBtn = document.getElementById('backToPatientBtn');
const currentPatientNameEl = document.getElementById('currentPatientName');
const currentPatientIdEl = document.getElementById('currentPatientId');

// DOM 元素 - 匯入匯出
const importDataBtn = document.getElementById('importDataBtn');
const exportDataBtn = document.getElementById('exportDataBtn');
const localStorageBtn = document.getElementById('localStorageBtn');
const importExportModal = document.getElementById('importExportModal');
const modalTitle = document.getElementById('modalTitle');
const modalContent = document.getElementById('modalContent');
const closeModalBtn = document.getElementById('closeModalBtn');
const importFileInput = document.getElementById('importFileInput');

// DOM 元素 - 草稿指示器
const draftIndicator = document.getElementById('draftIndicator');
const restoreDraftBtn = document.getElementById('restoreDraftBtn');
const clearDraftBtn = document.getElementById('clearDraftBtn');

// ===== IndexedDB 本地儲存系統 =====
const DB_NAME = 'DentalColorAnalysisDB';
const DB_VERSION = 1;
let db = null;

// 初始化 IndexedDB
function initIndexedDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    
    request.onerror = () => {
      console.error('IndexedDB 開啟失敗');
      reject(request.error);
    };
    
    request.onsuccess = () => {
      db = request.result;
      console.log('IndexedDB 初始化成功');
      resolve(db);
    };
    
    request.onupgradeneeded = (event) => {
      const database = event.target.result;
      
      // 建立病患資料表
      if (!database.objectStoreNames.contains('patients')) {
        database.createObjectStore('patients', { keyPath: 'id' });
      }
      
      // 建立圖片資料表
      if (!database.objectStoreNames.contains('images')) {
        database.createObjectStore('images', { keyPath: 'id' });
      }
      
      // 建立設定資料表
      if (!database.objectStoreNames.contains('settings')) {
        database.createObjectStore('settings', { keyPath: 'key' });
      }
    };
  });
}

// 儲存資料到 IndexedDB
function saveToIndexedDB(storeName, data) {
  return new Promise((resolve, reject) => {
    if (!db) {
      reject(new Error('IndexedDB 尚未初始化'));
      return;
    }
    
    const transaction = db.transaction([storeName], 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = store.put(data);
    
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// 從 IndexedDB 讀取資料
function loadFromIndexedDB(storeName, key) {
  return new Promise((resolve, reject) => {
    if (!db) {
      reject(new Error('IndexedDB 尚未初始化'));
      return;
    }
    
    const transaction = db.transaction([storeName], 'readonly');
    const store = transaction.objectStore(storeName);
    const request = key ? store.get(key) : store.getAll();
    
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// 刪除 IndexedDB 中的資料
function deleteFromIndexedDB(storeName, key) {
  return new Promise((resolve, reject) => {
    if (!db) {
      reject(new Error('IndexedDB 尚未初始化'));
      return;
    }
    
    const transaction = db.transaction([storeName], 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = key ? store.delete(key) : store.clear();
    
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// 儲存所有資料到本機
async function saveAllToLocal() {
  try {
    // 儲存病患資料
    for (const patient of patientState.patients) {
      await saveToIndexedDB('patients', patient);
    }
    
    // 儲存圖片資料，加入安全檢查
    for (const img of state.images) {
      // 確保圖片資料有效
      if (!img || !img.id) {
        console.warn('saveAllToLocal: 略過無效的圖片資料');
        continue;
      }
      
      // 確保至少有一個有效的 dataUrl
      const dataUrl = img.dataUrl || img.croppedDataUrl || '';
      const croppedDataUrl = img.croppedDataUrl || img.dataUrl || '';
      
      if (!dataUrl && !croppedDataUrl) {
        console.warn('saveAllToLocal: 圖片缺少 dataUrl:', img.id);
        continue;
      }
      
      const imageData = {
        id: img.id,
        name: img.name || '未命名圖片',
        dataUrl: dataUrl,
        croppedDataUrl: croppedDataUrl,
        records: img.records || {}
      };
      await saveToIndexedDB('images', imageData);
    }
    
    // 儲存最後更新時間
    await saveToIndexedDB('settings', {
      key: 'lastSaved',
      value: new Date().toISOString()
    });
    
    return true;
  } catch (e) {
    console.error('儲存到本機失敗:', e);
    throw e;
  }
}

// 從本機載入所有資料
async function loadAllFromLocal(silent = false) {
  try {
    // 載入病患資料
    const patients = await loadFromIndexedDB('patients');
    if (patients && patients.length > 0) {
      patientState.patients = patients;
      savePatients(); // 同步到 localStorage
    }
    
    // 載入圖片資料
    const images = await loadFromIndexedDB('images');
    let loadedImageCount = 0;
    if (images && images.length > 0) {
      for (const imgData of images) {
        // 檢查是否已存在
        const existing = state.images.find(i => i.id === imgData.id);
        if (!existing) {
          try {
            // 取得圖片 data URL（優先使用原始圖片）
            const originalDataUrl = imgData.dataUrl;
            const croppedDataUrl = imgData.croppedDataUrl;
            const dataUrl = originalDataUrl || croppedDataUrl;
            
            if (!dataUrl || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:')) {
              console.warn('圖片資料缺少有效的 dataUrl:', imgData.id);
              continue;
            }
            
            // 重新建立原始 Image 物件
            const originalImg = new Image();
            await new Promise((resolve, reject) => {
              originalImg.onload = resolve;
              originalImg.onerror = () => reject(new Error('原始圖片載入失敗'));
              originalImg.src = originalDataUrl || dataUrl;
            });
            
            // 如果有裁切版本且不同，另外建立
            let croppedImg = null;
            if (croppedDataUrl && typeof croppedDataUrl === 'string' && croppedDataUrl.startsWith('data:')) {
              if (croppedDataUrl !== originalDataUrl) {
                croppedImg = new Image();
                await new Promise((resolve, reject) => {
                  croppedImg.onload = resolve;
                  croppedImg.onerror = () => {
                    console.warn('裁切圖片載入失敗，使用原始圖片');
                    croppedImg = originalImg;
                    resolve();
                  };
                  croppedImg.src = croppedDataUrl;
                });
              } else {
                croppedImg = originalImg;
              }
            } else {
              // 如果沒有有效的裁切圖片 URL，使用原始圖片
              croppedImg = null;
            }
            
            state.images.push({
              id: imgData.id,
              name: imgData.name || '未命名圖片',
              original: originalImg,
              cropped: croppedImg,
              dataUrl: originalDataUrl || dataUrl,
              croppedDataUrl: croppedDataUrl || originalDataUrl || dataUrl,
              records: imgData.records || {}
            });
            loadedImageCount++;
          } catch (imgError) {
            console.error('載入圖片失敗:', imgData.id, imgError);
          }
        }
      }
    }
    
    // 載入最後儲存時間
    const lastSaved = await loadFromIndexedDB('settings', 'lastSaved');
    
    const result = { 
      patientsCount: patients?.length || 0, 
      imagesCount: loadedImageCount,
      lastSaved: lastSaved?.value 
    };
    
    if (!silent && (result.patientsCount > 0 || result.imagesCount > 0)) {
      console.log(`已自動載入本機資料：${result.patientsCount} 位病患，${result.imagesCount} 張圖片`);
    }
    
    return result;
  } catch (e) {
    console.error('從本機載入失敗:', e);
    throw e;
  }
}

// 清除本機所有資料
async function clearAllLocal() {
  try {
    await deleteFromIndexedDB('patients');
    await deleteFromIndexedDB('images');
    await deleteFromIndexedDB('settings');
    return true;
  } catch (e) {
    console.error('清除本機資料失敗:', e);
    throw e;
  }
}

// 開啟本機儲存對話框
function openLocalStorageModal() {
  modalTitle.textContent = '💾 本機儲存管理';
  
  // 檢查目前狀態
  const patientCount = patientState.patients.length;
  const imageCount = state.images.length;
  let totalTeethRecords = 0;
  state.images.forEach(img => {
    if (img.records) {
      totalTeethRecords += Object.keys(img.records).length;
    }
  });
  
  modalContent.innerHTML = `
    <div class="local-storage-options">
      <p class="modal-desc">管理本機儲存的資料，包含病患資訊、照片和牙齒分析結果。</p>
      
      <div class="storage-status">
        <h4>📊 目前資料狀態</h4>
        <div class="status-grid">
          <div class="status-item">
            <span class="status-icon">👥</span>
            <span class="status-value">${patientCount}</span>
            <span class="status-label">位病患</span>
          </div>
          <div class="status-item">
            <span class="status-icon">🖼️</span>
            <span class="status-value">${imageCount}</span>
            <span class="status-label">張照片</span>
          </div>
          <div class="status-item">
            <span class="status-icon">🦷</span>
            <span class="status-value">${totalTeethRecords}</span>
            <span class="status-label">筆牙位記錄</span>
          </div>
        </div>
        <div id="lastSavedInfo" class="last-saved-info">載入中...</div>
      </div>
      
      <div class="storage-actions">
        <div class="action-card save-card" id="saveToLocalCard">
          <div class="action-icon">💾</div>
          <div class="action-info">
            <h5>儲存到本機</h5>
            <p>將目前所有資料（病患、照片、牙齒分析）儲存到瀏覽器本機</p>
          </div>
          <button id="saveToLocalBtn" class="btn primary">儲存</button>
        </div>
        
        <div class="action-card load-card" id="loadFromLocalCard">
          <div class="action-icon">📂</div>
          <div class="action-info">
            <h5>從本機載入</h5>
            <p>載入之前儲存在本機的所有資料</p>
          </div>
          <button id="loadFromLocalBtn" class="btn">載入</button>
        </div>
        
        <div class="action-card clear-card" id="clearLocalCard">
          <div class="action-icon">🗑️</div>
          <div class="action-info">
            <h5>清除本機資料</h5>
            <p>刪除所有儲存在瀏覽器的本機資料</p>
          </div>
          <button id="clearLocalBtn" class="btn ghost danger">清除</button>
        </div>
      </div>
      
      <div class="storage-note">
        <p>💡 <strong>提示：</strong>本機儲存使用瀏覽器的 IndexedDB，資料僅保存在此電腦的此瀏覽器中。如需跨裝置或備份，請使用「匯出」功能。</p>
      </div>
      
      <div class="modal-actions">
        <button id="closeLocalStorageBtn" class="btn ghost">關閉</button>
      </div>
    </div>
  `;
  
  importExportModal.classList.remove('hidden');
  
  // 綁定事件
  document.getElementById('closeLocalStorageBtn').addEventListener('click', closeModal);
  document.getElementById('saveToLocalBtn').addEventListener('click', handleSaveToLocal);
  document.getElementById('loadFromLocalBtn').addEventListener('click', handleLoadFromLocal);
  document.getElementById('clearLocalBtn').addEventListener('click', handleClearLocal);
  
  // 載入最後儲存時間
  loadLastSavedInfo();
}

// 載入最後儲存時間
async function loadLastSavedInfo() {
  const infoEl = document.getElementById('lastSavedInfo');
  if (!infoEl) return;
  
  try {
    const lastSaved = await loadFromIndexedDB('settings', 'lastSaved');
    if (lastSaved?.value) {
      const date = new Date(lastSaved.value);
      infoEl.innerHTML = `<span class="saved-time">✅ 上次儲存：${date.toLocaleString('zh-TW')}</span>`;
    } else {
      infoEl.innerHTML = '<span class="no-saved">尚未儲存過資料</span>';
    }
  } catch (e) {
    infoEl.innerHTML = '<span class="no-saved">無法讀取儲存記錄</span>';
  }
}

// 處理儲存到本機
async function handleSaveToLocal() {
  const btn = document.getElementById('saveToLocalBtn');
  const originalText = btn.textContent;
  
  try {
    btn.disabled = true;
    btn.textContent = '儲存中...';
    
    await saveAllToLocal();
    
    btn.textContent = '✓ 已儲存';
    loadLastSavedInfo();
    
    setTimeout(() => {
      btn.textContent = originalText;
      btn.disabled = false;
    }, 2000);
    
  } catch (e) {
    alert('儲存失敗：' + e.message);
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

// 處理從本機載入
async function handleLoadFromLocal() {
  const btn = document.getElementById('loadFromLocalBtn');
  const originalText = btn.textContent;
  
  try {
    btn.disabled = true;
    btn.textContent = '載入中...';
    
    const result = await loadAllFromLocal();
    
    // 更新 UI
    savePatients();
    renderPatientList();
    renderImageList();
    
    // 如果有圖片，自動選擇第一張
    if (state.images.length > 0 && !state.currentImageId) {
      selectImage(state.images[0].id);
    }
    
    btn.textContent = '✓ 已載入';
    
    // 重新開啟對話框以更新狀態
    setTimeout(() => {
      closeModal();
      openLocalStorageModal();
    }, 1000);
    
    alert(`載入成功！\n病患：${result.patientsCount} 筆\n照片：${result.imagesCount} 張`);
    
  } catch (e) {
    alert('載入失敗：' + e.message);
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

// 處理清除本機資料
async function handleClearLocal() {
  if (!confirm('確定要清除所有本機儲存的資料嗎？\n此操作無法復原！')) {
    return;
  }
  
  const btn = document.getElementById('clearLocalBtn');
  const originalText = btn.textContent;
  
  try {
    btn.disabled = true;
    btn.textContent = '清除中...';
    
    await clearAllLocal();
    
    btn.textContent = '✓ 已清除';
    loadLastSavedInfo();
    
    setTimeout(() => {
      btn.textContent = originalText;
      btn.disabled = false;
    }, 2000);
    
    alert('本機資料已清除！');
    
  } catch (e) {
    alert('清除失敗：' + e.message);
    btn.textContent = originalText;
    btn.disabled = false;
  }
}

// 生成唯一 ID
function generateId() {
  return 'p_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// 從 localStorage 載入病患資料
function loadPatients() {
  try {
    const data = localStorage.getItem('dental_patients');
    if (data) {
      patientState.patients = JSON.parse(data);
    }
    // 載入草稿
    loadDraft();
  } catch (e) {
    console.error('載入病患資料失敗:', e);
    patientState.patients = [];
  }
}

// 儲存病患資料到 localStorage
function savePatients() {
  try {
    localStorage.setItem('dental_patients', JSON.stringify(patientState.patients));
  } catch (e) {
    console.error('儲存病患資料失敗:', e);
  }
}

// ===== 草稿/暫存區功能 =====

// 儲存草稿到 localStorage
function saveDraft(formData) {
  try {
    const draft = {
      ...formData,
      savedAt: new Date().toISOString(),
      isDraft: true
    };
    localStorage.setItem('dental_patient_draft', JSON.stringify(draft));
    patientState.draft = draft;
    updateDraftIndicator();
  } catch (e) {
    console.error('儲存草稿失敗:', e);
  }
}

// 載入草稿
function loadDraft() {
  try {
    const data = localStorage.getItem('dental_patient_draft');
    if (data) {
      patientState.draft = JSON.parse(data);
      updateDraftIndicator();
    }
  } catch (e) {
    console.error('載入草稿失敗:', e);
    patientState.draft = null;
  }
}

// 清除草稿
function clearDraft() {
  try {
    localStorage.removeItem('dental_patient_draft');
    patientState.draft = null;
    updateDraftIndicator();
  } catch (e) {
    console.error('清除草稿失敗:', e);
  }
}

// 更新草稿指示器
function updateDraftIndicator() {
  if (!draftIndicator) return;
  if (patientState.draft) {
    draftIndicator.classList.remove('hidden');
  } else {
    draftIndicator.classList.add('hidden');
  }
}

// 從表單收集資料（用於暫存）
function collectFormData() {
  const form = document.getElementById('patientForm');
  if (!form) return null;
  
  return {
    id: form.querySelector('#patientIdField')?.value || '',
    patientNo: form.querySelector('#patientNo')?.value?.trim() || '',
    patientName: form.querySelector('#patientName')?.value?.trim() || '',
    patientGender: form.querySelector('#patientGender')?.value || '',
    patientBirth: form.querySelector('#patientBirth')?.value || '',
    patientPhone: form.querySelector('#patientPhone')?.value?.trim() || '',
    patientEmail: form.querySelector('#patientEmail')?.value?.trim() || '',
    patientAddress: form.querySelector('#patientAddress')?.value?.trim() || '',
    doctorName: form.querySelector('#doctorName')?.value?.trim() || '',
    doctorDept: form.querySelector('#doctorDept')?.value?.trim() || '',
    doctorNote: form.querySelector('#doctorNote')?.value?.trim() || '',
    treatmentType: form.querySelector('#treatmentType')?.value || '',
    treatmentDate: form.querySelector('#treatmentDate')?.value || '',
    treatmentNote: form.querySelector('#treatmentNote')?.value?.trim() || '',
  };
}

// 自動儲存草稿（防抖）
let draftSaveTimeout = null;
function autoSaveDraft() {
  if (draftSaveTimeout) clearTimeout(draftSaveTimeout);
  draftSaveTimeout = setTimeout(() => {
    const formData = collectFormData();
    if (formData && (formData.patientNo || formData.patientName)) {
      saveDraft(formData);
    }
  }, 1000); // 1秒後自動儲存
}

// ===== 匯入/匯出功能 =====

// 開啟匯出對話框
function openExportModal() {
  modalTitle.textContent = '📤 匯出資料';
  modalContent.innerHTML = `
    <div class="export-options">
      <p class="modal-desc">選擇要匯出的內容和格式：</p>
      
      <div class="export-section">
        <h4>📋 匯出範圍</h4>
        <label class="checkbox-label">
          <input type="checkbox" id="exportAllPatients" checked>
          <span>所有病患資料 (${patientState.patients.length} 筆)</span>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" id="exportCurrentPatient" ${patientState.currentPatient ? '' : 'disabled'}>
          <span>僅目前選擇的病患 ${patientState.currentPatient ? '(' + patientState.currentPatient.patientName + ')' : '(未選擇)'}</span>
        </label>
      </div>
      
      <div class="export-section">
        <h4>🖼️ 圖片選項</h4>
        <label class="checkbox-label">
          <input type="checkbox" id="exportWithImages" checked>
          <span>包含牙齒照片</span>
        </label>
        <p class="hint">包含照片會增加檔案大小</p>
      </div>
      
      <div class="export-section">
        <h4>📁 匯出格式</h4>
        <div class="format-options">
          <label class="radio-label">
            <input type="radio" name="exportFormat" value="json" checked>
            <span>JSON 檔案 (.json)</span>
            <small>適合備份和還原</small>
          </label>
          <label class="radio-label">
            <input type="radio" name="exportFormat" value="zip">
            <span>ZIP 壓縮包 (.zip)</span>
            <small>包含圖片時建議使用</small>
          </label>
        </div>
      </div>
      
      <div class="modal-actions">
        <button id="cancelExportBtn" class="btn ghost">取消</button>
        <button id="confirmExportBtn" class="btn primary">📤 開始匯出</button>
      </div>
    </div>
  `;
  
  importExportModal.classList.remove('hidden');
  
  // 綁定事件
  document.getElementById('cancelExportBtn').addEventListener('click', closeModal);
  document.getElementById('confirmExportBtn').addEventListener('click', handleExport);
  
  // 互斥選項
  const allCheck = document.getElementById('exportAllPatients');
  const currentCheck = document.getElementById('exportCurrentPatient');
  allCheck.addEventListener('change', () => {
    if (allCheck.checked) currentCheck.checked = false;
  });
  currentCheck.addEventListener('change', () => {
    if (currentCheck.checked) allCheck.checked = false;
  });
}

// 開啟匯入對話框
function openImportModal() {
  modalTitle.textContent = '📥 匯入資料';
  modalContent.innerHTML = `
    <div class="import-options">
      <p class="modal-desc">選擇要匯入的檔案：</p>
      
      <div class="import-dropzone" id="importDropzone">
        <div class="dropzone-icon">📁</div>
        <div class="dropzone-text">
          <p>拖放檔案到此處</p>
          <p class="hint">或點擊選擇檔案</p>
        </div>
        <p class="dropzone-formats">支援格式：.json, .zip</p>
      </div>
      
      <div id="importFileInfo" class="import-file-info hidden">
        <div class="file-icon">📄</div>
        <div class="file-details">
          <span id="importFileName">-</span>
          <span id="importFileSize">-</span>
        </div>
        <button id="removeImportFile" class="btn ghost sm">✕</button>
      </div>
      
      <div class="export-section">
        <h4>⚙️ 匯入選項</h4>
        <label class="checkbox-label">
          <input type="checkbox" id="importMerge" checked>
          <span>合併現有資料（相同病歷號會更新）</span>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" id="importReplace">
          <span>取代全部資料（會清除現有資料）</span>
        </label>
      </div>
      
      <div class="modal-actions">
        <button id="cancelImportBtn" class="btn ghost">取消</button>
        <button id="confirmImportBtn" class="btn primary" disabled>📥 開始匯入</button>
      </div>
    </div>
  `;
  
  importExportModal.classList.remove('hidden');
  
  // 綁定事件
  document.getElementById('cancelImportBtn').addEventListener('click', closeModal);
  document.getElementById('confirmImportBtn').addEventListener('click', handleImport);
  
  const dropzone = document.getElementById('importDropzone');
  const fileInfo = document.getElementById('importFileInfo');
  
  // 點擊開啟檔案選擇
  dropzone.addEventListener('click', () => importFileInput.click());
  
  // 拖放處理
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  
  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });
  
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleImportFileSelect(files[0]);
    }
  });
  
  // 檔案選擇處理
  importFileInput.onchange = (e) => {
    if (e.target.files.length > 0) {
      handleImportFileSelect(e.target.files[0]);
    }
  };
  
  // 移除檔案
  document.getElementById('removeImportFile').addEventListener('click', () => {
    importFileInput.value = '';
    window.pendingImportFile = null;
    fileInfo.classList.add('hidden');
    dropzone.classList.remove('hidden');
    document.getElementById('confirmImportBtn').disabled = true;
  });
  
  // 互斥選項
  const mergeCheck = document.getElementById('importMerge');
  const replaceCheck = document.getElementById('importReplace');
  mergeCheck.addEventListener('change', () => {
    if (mergeCheck.checked) replaceCheck.checked = false;
  });
  replaceCheck.addEventListener('change', () => {
    if (replaceCheck.checked) mergeCheck.checked = false;
  });
}

// 處理匯入檔案選擇
function handleImportFileSelect(file) {
  const validTypes = ['.json', '.zip', 'application/json', 'application/zip', 'application/x-zip-compressed'];
  const ext = file.name.toLowerCase().slice(file.name.lastIndexOf('.'));
  
  if (!validTypes.includes(ext) && !validTypes.includes(file.type)) {
    alert('不支援的檔案格式，請選擇 .json 或 .zip 檔案');
    return;
  }
  
  window.pendingImportFile = file;
  
  const dropzone = document.getElementById('importDropzone');
  const fileInfo = document.getElementById('importFileInfo');
  
  dropzone.classList.add('hidden');
  fileInfo.classList.remove('hidden');
  
  document.getElementById('importFileName').textContent = file.name;
  document.getElementById('importFileSize').textContent = formatFileSize(file.size);
  document.getElementById('confirmImportBtn').disabled = false;
}

// 格式化檔案大小
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// 執行匯出
async function handleExport() {
  const exportAll = document.getElementById('exportAllPatients').checked;
  const exportCurrent = document.getElementById('exportCurrentPatient').checked;
  const withImages = document.getElementById('exportWithImages').checked;
  const format = document.querySelector('input[name="exportFormat"]:checked').value;
  
  let dataToExport = [];
  
  if (exportAll) {
    dataToExport = patientState.patients;
  } else if (exportCurrent && patientState.currentPatient) {
    dataToExport = [patientState.currentPatient];
  }
  
  if (dataToExport.length === 0) {
    alert('沒有可匯出的資料');
    return;
  }
  
  try {
    // 準備匯出資料
    const exportData = {
      version: '1.0',
      exportDate: new Date().toISOString(),
      appName: '牙齒色彩分析系統',
      totalPatients: dataToExport.length,
      patients: dataToExport,
      images: {},
      teethRecords: {}
    };
    
    // 收集圖片資料和牙齒記錄
    if (withImages) {
      state.images.forEach(img => {
        if (img.croppedDataUrl || img.dataUrl) {
          exportData.images[img.id] = {
            id: img.id,
            name: img.name,
            dataUrl: img.croppedDataUrl || img.dataUrl,
            records: img.records || {}
          };
        }
      });
    }
    
    // 也收集牙齒記錄（即使不含圖片）
    state.images.forEach(img => {
      if (img.records && Object.keys(img.records).length > 0) {
        exportData.teethRecords[img.id] = img.records;
      }
    });
    
    if (format === 'json') {
      // JSON 格式匯出
      const jsonStr = JSON.stringify(exportData, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      downloadBlob(blob, `dental_export_${formatDateForFilename()}.json`);
      closeModal();
      alert(`成功匯出 ${dataToExport.length} 筆病患資料！`);
    } else if (format === 'zip') {
      // ZIP 格式匯出（使用 JSZip）
      if (typeof JSZip === 'undefined') {
        alert('JSZip 函式庫載入失敗，將改用 JSON 格式匯出');
        const jsonStr = JSON.stringify(exportData, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        downloadBlob(blob, `dental_export_${formatDateForFilename()}.json`);
        closeModal();
        return;
      }
      
      const zip = new JSZip();
      
      // 添加主資料檔
      const mainData = {
        ...exportData,
        images: {} // ZIP 中圖片分開存放
      };
      
      // 如果包含圖片，分別儲存
      if (withImages && Object.keys(exportData.images).length > 0) {
        const imagesFolder = zip.folder('images');
        
        for (const [imgId, imgData] of Object.entries(exportData.images)) {
          // 將 base64 圖片加入 ZIP
          if (imgData.dataUrl) {
            const base64Data = imgData.dataUrl.split(',')[1];
            const ext = imgData.dataUrl.includes('png') ? 'png' : 'jpg';
            imagesFolder.file(`${imgId}.${ext}`, base64Data, { base64: true });
            
            // 在主資料中記錄圖片資訊（不含 base64）
            mainData.images[imgId] = {
              id: imgData.id,
              name: imgData.name,
              filename: `${imgId}.${ext}`,
              records: imgData.records || {}
            };
          }
        }
      }
      
      zip.file('data.json', JSON.stringify(mainData, null, 2));
      
      // 生成 ZIP 並下載
      const zipBlob = await zip.generateAsync({ 
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 }
      });
      
      downloadBlob(zipBlob, `dental_export_${formatDateForFilename()}.zip`);
      closeModal();
      alert(`成功匯出 ${dataToExport.length} 筆病患資料！\n（ZIP 格式，含 ${Object.keys(exportData.images).length} 張照片）`);
    }
    
  } catch (e) {
    console.error('匯出失敗:', e);
    alert('匯出失敗：' + e.message);
  }
}

// 執行匯入
async function handleImport() {
  const file = window.pendingImportFile;
  if (!file) {
    alert('請先選擇檔案');
    return;
  }
  
  const isMerge = document.getElementById('importMerge').checked;
  const isReplace = document.getElementById('importReplace').checked;
  const isZip = file.name.toLowerCase().endsWith('.zip');
  
  try {
    let importData;
    
    if (isZip) {
      // ZIP 格式匯入
      if (typeof JSZip === 'undefined') {
        throw new Error('JSZip 函式庫未載入，無法處理 ZIP 檔案');
      }
      
      const zip = await JSZip.loadAsync(file);
      
      // 讀取主資料檔
      const dataFile = zip.file('data.json');
      if (!dataFile) {
        throw new Error('ZIP 檔案中找不到 data.json');
      }
      
      const dataText = await dataFile.async('string');
      importData = JSON.parse(dataText);
      
      // 讀取圖片
      const imagesFolder = zip.folder('images');
      if (imagesFolder && importData.images) {
        for (const [imgId, imgInfo] of Object.entries(importData.images)) {
          if (imgInfo.filename) {
            const imgFile = imagesFolder.file(imgInfo.filename);
            if (imgFile) {
              const imgBase64 = await imgFile.async('base64');
              const ext = imgInfo.filename.split('.').pop().toLowerCase();
              const mimeType = ext === 'png' ? 'image/png' : 'image/jpeg';
              const dataUrl = `data:${mimeType};base64,${imgBase64}`;
              importData.images[imgId].dataUrl = dataUrl;
              // 確保 croppedDataUrl 也有值
              if (!importData.images[imgId].croppedDataUrl) {
                importData.images[imgId].croppedDataUrl = dataUrl;
              }
            }
          }
        }
      }
    } else {
      // JSON 格式匯入
      const text = await file.text();
      importData = JSON.parse(text);
    }
    
    // 驗證資料格式
    if (!importData.patients || !Array.isArray(importData.patients)) {
      throw new Error('無效的資料格式');
    }
    
    const importCount = importData.patients.length;
    
    if (isReplace) {
      // 取代模式
      if (!confirm(`確定要取代所有資料嗎？\n目前有 ${patientState.patients.length} 筆資料將被清除，\n匯入 ${importCount} 筆新資料。`)) {
        return;
      }
      patientState.patients = importData.patients;
    } else if (isMerge) {
      // 合併模式
      let updated = 0;
      let added = 0;
      
      importData.patients.forEach(importPatient => {
        const existingIndex = patientState.patients.findIndex(p => 
          p.patientNo === importPatient.patientNo
        );
        
        if (existingIndex >= 0) {
          // 更新現有病患
          patientState.patients[existingIndex] = {
            ...patientState.patients[existingIndex],
            ...importPatient,
            id: patientState.patients[existingIndex].id, // 保留原 ID
            updatedAt: new Date().toISOString()
          };
          updated++;
        } else {
          // 新增病患
          importPatient.id = generateId();
          importPatient.createdAt = new Date().toISOString();
          patientState.patients.push(importPatient);
          added++;
        }
      });
      
      alert(`匯入完成！\n新增：${added} 筆\n更新：${updated} 筆`);
    }
    
    // 匯入圖片資料
    let imageImportCount = 0;
    if (importData.images && Object.keys(importData.images).length > 0) {
      for (const imgData of Object.values(importData.images)) {
        // 取得原始和裁切圖片的 URL，並驗證格式
        const originalDataUrl = (imgData.dataUrl && typeof imgData.dataUrl === 'string' && imgData.dataUrl.startsWith('data:')) ? imgData.dataUrl : null;
        const croppedDataUrl = (imgData.croppedDataUrl && typeof imgData.croppedDataUrl === 'string' && imgData.croppedDataUrl.startsWith('data:')) ? imgData.croppedDataUrl : originalDataUrl;
        const displayUrl = croppedDataUrl || originalDataUrl;
        
        if (displayUrl) {
          try {
            // 載入主要顯示圖片
            const mainImg = new Image();
            await new Promise((resolve, reject) => {
              mainImg.onload = resolve;
              mainImg.onerror = () => reject(new Error('圖片載入失敗'));
              mainImg.src = displayUrl;
            });
            
            // 如果原始圖和裁切圖不同，也載入原始圖
            let originalImg = mainImg;
            if (originalDataUrl && originalDataUrl !== croppedDataUrl && originalDataUrl.startsWith('data:')) {
              originalImg = new Image();
              await new Promise((resolve) => {
                originalImg.onload = resolve;
                originalImg.onerror = () => { 
                  console.warn('匯入原始圖片失敗，使用主圖片');
                  originalImg = mainImg; 
                  resolve(); 
                };
                originalImg.src = originalDataUrl;
              });
            }
            
            const existing = state.images.find(i => i.id === imgData.id);
            if (!existing) {
              const newImage = {
                id: imgData.id || generateId(),
                name: imgData.name || '匯入圖片',
                original: originalImg,
                cropped: mainImg,
                dataUrl: originalDataUrl || displayUrl,
                croppedDataUrl: croppedDataUrl || displayUrl,
                records: imgData.records || {}
              };
              state.images.push(newImage);
              imageImportCount++;
              
              // 同時儲存到 IndexedDB
              if (db) {
                await saveToIndexedDB('images', {
                  id: newImage.id,
                  name: newImage.name,
                  dataUrl: newImage.dataUrl,
                  croppedDataUrl: newImage.croppedDataUrl,
                  records: newImage.records
                });
              }
            }
          } catch (imgErr) {
            console.error('匯入圖片失敗:', imgData.id, imgErr);
          }
        }
      }
    }
    
    // 匯入牙齒記錄（如果存在於 teethRecords 中但不在 images 中）
    if (importData.teethRecords) {
      for (const [imgId, records] of Object.entries(importData.teethRecords)) {
        const targetImg = state.images.find(i => i.id === imgId);
        if (targetImg && records) {
          targetImg.records = { ...targetImg.records, ...records };
        }
      }
    }
    
    savePatients();
    renderPatientList();
    renderImageList();
    
    // 如果有圖片，選擇第一張
    if (state.images.length > 0 && !state.currentImageId) {
      selectImage(state.images[0].id);
    }
    
    closeModal();
    
    window.pendingImportFile = null;
    importFileInput.value = '';
    
  } catch (e) {
    console.error('匯入失敗:', e);
    alert('匯入失敗：' + e.message + '\n請確認檔案格式正確');
  }
}

// 下載 Blob
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// 格式化日期為檔名
function formatDateForFilename() {
  const now = new Date();
  return `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
}

// 關閉彈窗
function closeModal() {
  if (importExportModal) {
    importExportModal.classList.add('hidden');
  }
  window.pendingImportFile = null;
}

// 渲染病患列表
function renderPatientList(filter = '') {
  const filtered = patientState.patients.filter(p => {
    if (!filter) return true;
    const search = filter.toLowerCase();
    return p.patientName.toLowerCase().includes(search) ||
           p.patientNo.toLowerCase().includes(search);
  });

  if (filtered.length === 0) {
    patientListEl.innerHTML = `<div class="list-empty">${filter ? '找不到符合的病患' : '尚無病患資料，請點擊「新增病患」'}</div>`;
    return;
  }

  patientListEl.innerHTML = filtered.map(p => {
    const teethCount = p.teethData ? Object.keys(p.teethData).length : 0;
    const isActive = patientState.currentPatient?.id === p.id;
    return `
      <div class="patient-card ${isActive ? 'active' : ''}" data-id="${p.id}">
        <div class="avatar">👤</div>
        <div class="info">
          <div class="name">${escapeHtml(p.patientName)}</div>
          <div class="meta">
            <span>${escapeHtml(p.patientNo)}</span>
            <span>${p.doctorName ? '醫師: ' + escapeHtml(p.doctorName) : ''}</span>
          </div>
        </div>
        <span class="teeth-badge ${teethCount === 0 ? 'no-teeth' : ''}">${teethCount > 0 ? `🦷 ${teethCount}` : '未建檔'}</span>
        <button class="delete-patient-btn" data-id="${p.id}" title="刪除病患">🗑️</button>
      </div>
    `;
  }).join('');

  // 綁定點擊事件
  patientListEl.querySelectorAll('.patient-card').forEach(card => {
    card.addEventListener('click', (e) => {
      // 如果點擊的是刪除按鈕，不選擇病患
      if (e.target.classList.contains('delete-patient-btn')) return;
      
      const id = card.dataset.id;
      const patient = patientState.patients.find(p => p.id === id);
      if (patient) {
        selectPatient(patient);
      }
    });

    // 綁定雙擊事件 - 直接進入牙齒編輯頁面
    card.addEventListener('dblclick', (e) => {
      // 如果點擊的是刪除按鈕，不處理
      if (e.target.classList.contains('delete-patient-btn')) return;
      
      const id = card.dataset.id;
      const patient = patientState.patients.find(p => p.id === id);
      if (patient) {
        switchToTeethMode(patient);
      }
    });
  });

  // 綁定刪除按鈕事件
  patientListEl.querySelectorAll('.delete-patient-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      deletePatient(id);
    });
  });
}

// 刪除病患
async function deletePatient(patientId) {
  const patient = patientState.patients.find(p => p.id === patientId);
  if (!patient) return;

  const confirmMsg = `確定要刪除病患「${patient.patientName}」嗎？\n\n此操作將刪除該病患的所有資料（包含牙齒分析記錄和圖片），且無法復原！`;
  if (!confirm(confirmMsg)) return;

  // 從列表中移除
  patientState.patients = patientState.patients.filter(p => p.id !== patientId);
  
  // 如果刪除的是當前選中的病患，清除選中狀態
  if (patientState.currentPatient?.id === patientId) {
    patientState.currentPatient = null;
    // 清空表單區域
    patientFormContainer.innerHTML = `
      <div class="form-placeholder">
        <div class="placeholder-icon">👈</div>
        <p>請從左側選擇病患或新增病患</p>
      </div>
    `;
  }

  // 儲存到 localStorage
  savePatients();

  // 嘗試從 IndexedDB 刪除
  try {
    await deleteFromIndexedDB('patients', patientId);
  } catch (e) {
    console.warn('從 IndexedDB 刪除病患失敗:', e);
  }

  // 重新渲染列表
  renderPatientList(patientSearch?.value || '');
}

// HTML 轉義
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// 選擇病患
function selectPatient(patient) {
  patientState.currentPatient = patient;
  patientState.isEditing = true;
  renderPatientList(patientSearch?.value || '');
  showPatientForm(patient);
}

// 顯示病患表單
function showPatientForm(patient = null) {
  const template = patientFormTemplate.content.cloneNode(true);
  patientFormContainer.innerHTML = '';
  patientFormContainer.appendChild(template);

  const form = patientFormContainer.querySelector('#patientForm');
  const formTitle = patientFormContainer.querySelector('#formTitle');
  const editTeethBtn = patientFormContainer.querySelector('#editTeethBtn');
  const cancelBtns = patientFormContainer.querySelectorAll('.cancel-btn');

  if (patient) {
    formTitle.textContent = '編輯病患資料';
    // 填入資料
    form.querySelector('#patientIdField').value = patient.id || '';
    form.querySelector('#patientNo').value = patient.patientNo || '';
    form.querySelector('#patientName').value = patient.patientName || '';
    form.querySelector('#patientGender').value = patient.patientGender || '';
    form.querySelector('#patientBirth').value = patient.patientBirth || '';
    form.querySelector('#patientPhone').value = patient.patientPhone || '';
    form.querySelector('#patientEmail').value = patient.patientEmail || '';
    form.querySelector('#patientAddress').value = patient.patientAddress || '';
    form.querySelector('#doctorName').value = patient.doctorName || '';
    form.querySelector('#doctorDept').value = patient.doctorDept || '';
    form.querySelector('#doctorNote').value = patient.doctorNote || '';
    form.querySelector('#treatmentType').value = patient.treatmentType || '';
    form.querySelector('#treatmentDate').value = patient.treatmentDate || '';
    form.querySelector('#treatmentNote').value = patient.treatmentNote || '';
    
    // 顯示編輯牙齒按鈕
    editTeethBtn.classList.remove('hidden');
  } else {
    formTitle.textContent = '新增病患';
    // 設定預設日期
    form.querySelector('#treatmentDate').value = new Date().toISOString().split('T')[0];
    editTeethBtn.classList.add('hidden');
  }

  // 綁定取消按鈕
  cancelBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      patientState.currentPatient = null;
      patientState.isEditing = false;
      renderPatientList(patientSearch?.value || '');
      showFormPlaceholder();
    });
  });

  // 綁定表單提交
  form.addEventListener('submit', handlePatientFormSubmit);

  // 綁定編輯牙齒按鈕
  editTeethBtn.addEventListener('click', () => {
    if (patientState.currentPatient) {
      switchToTeethMode(patientState.currentPatient);
    }
  });

  // 綁定自動儲存草稿（僅新增病患時）
  if (!patient) {
    const inputFields = form.querySelectorAll('input, select, textarea');
    inputFields.forEach(field => {
      field.addEventListener('input', autoSaveDraft);
      field.addEventListener('change', autoSaveDraft);
    });
  }
}

// 顯示表單佔位符
function showFormPlaceholder() {
  patientFormContainer.innerHTML = `
    <div class="form-placeholder">
      <div class="placeholder-icon">👈</div>
      <p>請從左側選擇病患或新增病患</p>
    </div>
  `;
}

// 處理病患表單提交
function handlePatientFormSubmit(e) {
  e.preventDefault();
  const form = e.target;
  
  const patientData = {
    id: form.querySelector('#patientIdField').value || generateId(),
    patientNo: form.querySelector('#patientNo').value.trim(),
    patientName: form.querySelector('#patientName').value.trim(),
    patientGender: form.querySelector('#patientGender').value,
    patientBirth: form.querySelector('#patientBirth').value,
    patientPhone: form.querySelector('#patientPhone').value.trim(),
    patientEmail: form.querySelector('#patientEmail').value.trim(),
    patientAddress: form.querySelector('#patientAddress').value.trim(),
    doctorName: form.querySelector('#doctorName').value.trim(),
    doctorDept: form.querySelector('#doctorDept').value.trim(),
    doctorNote: form.querySelector('#doctorNote').value.trim(),
    treatmentType: form.querySelector('#treatmentType').value,
    treatmentDate: form.querySelector('#treatmentDate').value,
    treatmentNote: form.querySelector('#treatmentNote').value.trim(),
    updatedAt: new Date().toISOString(),
  };

  // 驗證必填欄位
  if (!patientData.patientNo || !patientData.patientName || !patientData.doctorName) {
    alert('請填寫必填欄位（病歷號碼、病患姓名、醫師姓名）');
    return;
  }

  // 檢查病歷號是否重複
  const existingIndex = patientState.patients.findIndex(p => p.id === patientData.id);
  const duplicateNo = patientState.patients.find(p => 
    p.patientNo === patientData.patientNo && p.id !== patientData.id
  );

  if (duplicateNo) {
    alert('此病歷號碼已存在，請使用其他號碼');
    return;
  }

  if (existingIndex >= 0) {
    // 更新現有病患，保留牙齒資料
    patientData.teethData = patientState.patients[existingIndex].teethData;
    patientData.createdAt = patientState.patients[existingIndex].createdAt;
    patientState.patients[existingIndex] = patientData;
  } else {
    // 新增病患
    patientData.createdAt = new Date().toISOString();
    patientData.teethData = {};
    patientState.patients.unshift(patientData);
  }

  savePatients();
  clearDraft(); // 儲存成功後清除草稿
  patientState.currentPatient = patientData;
  renderPatientList(patientSearch?.value || '');
  showPatientForm(patientData);

  // 顯示成功訊息
  alert('儲存成功！');
}

// 切換到牙齒顏色建構模式
async function switchToTeethMode(patient) {
  if (!patient) return;

  patientState.currentPatient = patient;
  
  // 更新標題顯示
  if (currentPatientNameEl) currentPatientNameEl.textContent = patient.patientName;
  if (currentPatientIdEl) currentPatientIdEl.textContent = patient.patientNo;

  // 載入該病患的牙齒資料（包含圖片）
  await loadPatientTeethData(patient);

  // 切換顯示
  patientMode.classList.add('hidden');
  teethMode.classList.remove('hidden');

  // 重新初始化 canvas 大小和圖片顯示
  setTimeout(() => {
    initCanvasSize();
    
    // 確保圖片和 offscreen canvas 正確初始化
    if (state.currentImageId && state.images.length > 0) {
      const currentImg = state.images.find(i => i.id === state.currentImageId);
      if (currentImg) {
        const displayImg = currentImg.cropped || currentImg.original;
        if (displayImg && displayImg.naturalWidth && displayImg.naturalHeight) {
          // 重新初始化 offscreen canvas
          offscreen.width = displayImg.naturalWidth;
          offscreen.height = displayImg.naturalHeight;
          offCtx.clearRect(0, 0, offscreen.width, offscreen.height);
          offCtx.drawImage(displayImg, 0, 0, offscreen.width, offscreen.height);
          
          // 計算縮放比例並設定 canvas
          fitCanvasToImage();
          console.log('switchToTeethMode: 圖片和 offscreen 已初始化');
        }
      }
    }
    
    redrawCanvas();
  }, 100);
}

// 切換回病患管理模式
function switchToPatientMode() {
  // 儲存當前病患的牙齒資料
  if (patientState.currentPatient) {
    saveCurrentPatientTeethData();
  }

  // 切換顯示
  teethMode.classList.add('hidden');
  patientMode.classList.remove('hidden');

  // 重新渲染病患列表
  renderPatientList(patientSearch?.value || '');
  
  // 如果有當前病患，顯示其表單
  if (patientState.currentPatient) {
    const updated = patientState.patients.find(p => p.id === patientState.currentPatient.id);
    if (updated) {
      patientState.currentPatient = updated;
      showPatientForm(updated);
    }
  }
}

// 載入病患的牙齒資料
async function loadPatientTeethData(patient) {
  // 清除現有狀態
  state.images = [];
  state.currentImageId = null;
  state.currentTooth = null;
  state.currentRoi = null;

  // 如果病患有圖片資料，載入它
  if (patient.imagesData && patient.imagesData.length > 0) {
    for (const imgData of patient.imagesData) {
      try {
        // 取得圖片 data URL
        const originalDataUrl = imgData.dataUrl;
        const croppedDataUrl = imgData.croppedDataUrl;
        const dataUrl = originalDataUrl || croppedDataUrl;
        
        if (!dataUrl || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:')) {
          console.warn('圖片資料缺少有效的 dataUrl:', imgData.id);
          continue;
        }
        
        // 重新建立原始 Image 物件
        const originalImg = new Image();
        await new Promise((resolve, reject) => {
          originalImg.onload = resolve;
          originalImg.onerror = () => reject(new Error('原始圖片載入失敗'));
          originalImg.src = originalDataUrl || dataUrl;
        });
        
        // 如果有裁切版本且不同，另外建立
        let croppedImg = null;
        if (croppedDataUrl && typeof croppedDataUrl === 'string' && croppedDataUrl.startsWith('data:')) {
          if (croppedDataUrl !== originalDataUrl) {
            croppedImg = new Image();
            await new Promise((resolve, reject) => {
              croppedImg.onload = resolve;
              croppedImg.onerror = () => {
                console.warn('載入病患裁切圖片失敗，使用原始圖片');
                croppedImg = originalImg;
                resolve();
              };
              croppedImg.src = croppedDataUrl;
            });
          } else {
            croppedImg = originalImg;
          }
        } else {
          // 沒有有效的裁切圖片
          croppedImg = null;
        }
        
        state.images.push({
          id: imgData.id,
          name: imgData.name || '未命名圖片',
          original: originalImg,
          cropped: croppedImg,
          dataUrl: originalDataUrl || dataUrl,
          croppedDataUrl: croppedDataUrl || originalDataUrl || dataUrl,
          records: imgData.records || {}
        });
      } catch (imgError) {
        console.error('載入病患圖片失敗:', imgData.id, imgError);
      }
    }
    
    // 如果成功載入圖片，選擇第一張並初始化 offscreen canvas
    if (state.images.length > 0) {
      const firstImg = state.images[0];
      state.currentImageId = firstImg.id;
      
      // 重要：初始化 offscreen canvas，這是顏色取樣的關鍵
      const displayImg = firstImg.cropped || firstImg.original;
      if (displayImg && displayImg.naturalWidth && displayImg.naturalHeight) {
        offscreen.width = displayImg.naturalWidth;
        offscreen.height = displayImg.naturalHeight;
        offCtx.clearRect(0, 0, offscreen.width, offscreen.height);
        offCtx.drawImage(displayImg, 0, 0, offscreen.width, offscreen.height);
        console.log('loadPatientTeethData: offscreen canvas 已初始化', offscreen.width, 'x', offscreen.height);
      } else {
        console.warn('loadPatientTeethData: 第一張圖片無效，等待圖片載入');
      }
    }
  }

  // 更新 UI
  renderImageList();
  renderToothButtons();
  redrawCanvas();
  refreshButtons();
  renderDetail();
}

// 儲存當前病患的牙齒資料
function saveCurrentPatientTeethData() {
  if (!patientState.currentPatient) return;

  // 收集所有圖片的牙齒記錄
  const teethData = {};
  state.images.forEach(img => {
    if (img && img.records) {
      Object.entries(img.records).forEach(([toothId, record]) => {
        teethData[toothId] = {
          ...record,
          imageName: img.name || '未命名圖片',
          savedAt: new Date().toISOString()
        };
      });
    }
  });

  // 收集圖片資料（包含圖片本身），加入安全檢查
  const imagesData = state.images.filter(img => img && (img.dataUrl || img.croppedDataUrl)).map(img => ({
    id: img.id,
    name: img.name || '未命名圖片',
    dataUrl: img.dataUrl || '',
    croppedDataUrl: img.croppedDataUrl || img.dataUrl || '',
    records: img.records || {}
  }));

  // 更新病患資料
  const patientIndex = patientState.patients.findIndex(p => p.id === patientState.currentPatient.id);
  if (patientIndex >= 0) {
    patientState.patients[patientIndex].teethData = teethData;
    patientState.patients[patientIndex].imagesData = imagesData; // 儲存圖片資料
    patientState.patients[patientIndex].updatedAt = new Date().toISOString();
    savePatients();
  }
}

// 初始化病患管理系統
async function initPatientSystem() {
  // 先初始化 IndexedDB
  try {
    await initIndexedDB();
    console.log('IndexedDB 初始化完成');
    
    // 自動載入本機儲存的資料
    const localData = await loadAllFromLocal(true);
    if (localData.patientsCount > 0 || localData.imagesCount > 0) {
      console.log(`已自動載入本機資料：${localData.patientsCount} 位病患，${localData.imagesCount} 張圖片`);
      // 如果有圖片，更新圖片列表
      if (localData.imagesCount > 0 && typeof renderImageList === 'function') {
        renderImageList();
      }
    }
  } catch (e) {
    console.error('IndexedDB 初始化或載入失敗:', e);
  }
  
  loadPatients();
  renderPatientList();

  // 綁定新增病患按鈕
  if (addPatientBtn) {
    addPatientBtn.addEventListener('click', () => {
      patientState.currentPatient = null;
      patientState.isEditing = false;
      renderPatientList();
      showPatientForm(null);
    });
  }

  // 綁定搜尋
  if (patientSearch) {
    patientSearch.addEventListener('input', (e) => {
      renderPatientList(e.target.value);
    });
  }

  // 綁定返回按鈕
  if (backToPatientBtn) {
    backToPatientBtn.addEventListener('click', switchToPatientMode);
  }

  // 綁定匯入匯出按鈕
  if (importDataBtn) {
    importDataBtn.addEventListener('click', openImportModal);
  }
  if (exportDataBtn) {
    exportDataBtn.addEventListener('click', openExportModal);
  }
  if (closeModalBtn) {
    closeModalBtn.addEventListener('click', closeModal);
  }
  
  // 綁定本機儲存按鈕
  if (localStorageBtn) {
    localStorageBtn.addEventListener('click', openLocalStorageModal);
  }

  // 綁定草稿按鈕
  if (restoreDraftBtn) {
    restoreDraftBtn.addEventListener('click', () => {
      if (patientState.draft) {
        showPatientForm(null);
        // 填入草稿資料
        setTimeout(() => {
          fillFormWithData(patientState.draft);
        }, 100);
      }
    });
  }
  if (clearDraftBtn) {
    clearDraftBtn.addEventListener('click', () => {
      if (confirm('確定要清除草稿嗎？')) {
        clearDraft();
      }
    });
  }
}

// 使用資料填充表單
function fillFormWithData(data) {
  const form = document.getElementById('patientForm');
  if (!form || !data) return;
  
  const fields = [
    'patientIdField', 'patientNo', 'patientName', 'patientGender',
    'patientBirth', 'patientPhone', 'patientEmail', 'patientAddress',
    'doctorName', 'doctorDept', 'doctorNote',
    'treatmentType', 'treatmentDate', 'treatmentNote'
  ];
  
  fields.forEach(field => {
    const el = form.querySelector(`#${field}`);
    const key = field === 'patientIdField' ? 'id' : field;
    if (el && data[key] !== undefined) {
      el.value = data[key];
    }
  });
}

// ===== 牙齒顏色建構系統（原有程式碼）=====
const teethUpper = [18,17,16,15,14,13,12,11,21,22,23,24,25,26,27,28];
const teethLower = [48,47,46,45,44,43,42,41,31,32,33,34,35,36,37,38];

const state = {
  images: [], // 多圖片陣列 { id, name, original, cropped, dataUrl, records: {} }
  currentImageId: null,
  imageScale: 1,
  currentTooth: null,
  currentRoi: null,
  isCropping: false,
  cropRect: null,
  pendingCropImage: null, // 待裁切的原始圖片
  roiMode: 'rect', // 'rect', 'polygon'
  polygonPoints: [], // 多邊形點陣列
  isPolygonComplete: false,
  polygonMousePos: null, // 滑鼠位置（用於預覽）
  roiAnimationOffset: 0, // ROI 動畫偏移量
  roiAnimationFrame: null, // ROI 動畫 frame ID
};

// 取得當前圖片
function getCurrentImage() {
  if (!state.currentImageId) return null;
  const img = state.images.find(i => i.id === state.currentImageId);
  if (!img) return null;
  
  // 優先返回裁切後的圖片，否則返回原始圖片
  // 並確保圖片物件有效（已載入）
  const croppedImg = img.cropped;
  const originalImg = img.original;
  
  if (croppedImg && croppedImg.naturalWidth && croppedImg.naturalHeight) {
    return croppedImg;
  }
  if (originalImg && originalImg.naturalWidth && originalImg.naturalHeight) {
    return originalImg;
  }
  
  // 如果都無效，返回任何可用的
  return croppedImg || originalImg || null;
}

// 取得當前圖片的 records
function getCurrentRecords() {
  if (!state.currentImageId) return {};
  const img = state.images.find(i => i.id === state.currentImageId);
  return img ? (img.records || {}) : {};
}

// 設定當前圖片的 record
async function setCurrentRecord(toothId, record) {
  if (!state.currentImageId) return;
  const img = state.images.find(i => i.id === state.currentImageId);
  if (img) {
    if (!img.records) img.records = {};
    img.records[toothId] = record;
    
    // 自動同步到 IndexedDB
    if (db) {
      try {
        await saveToIndexedDB('images', {
          id: img.id,
          name: img.name,
          dataUrl: img.dataUrl,
          croppedDataUrl: img.croppedDataUrl,
          records: img.records
        });
      } catch (e) {
        console.warn('同步牙齒記錄失敗:', e);
      }
    }
  }
}

// 刪除當前圖片的 record
async function deleteCurrentRecord(toothId) {
  if (!state.currentImageId) return;
  const img = state.images.find(i => i.id === state.currentImageId);
  if (img && img.records) {
    delete img.records[toothId];
    
    // 自動同步到 IndexedDB
    if (db) {
      try {
        await saveToIndexedDB('images', {
          id: img.id,
          name: img.name,
          dataUrl: img.dataUrl,
          croppedDataUrl: img.croppedDataUrl,
          records: img.records
        });
      } catch (e) {
        console.warn('同步刪除記錄失敗:', e);
      }
    }
  }
}

const fileInput = document.getElementById('fileInput');
const gridRange = document.getElementById('gridRange');
const gridNumber = document.getElementById('gridNumber');
const gridNumber2 = document.getElementById('gridNumber2');
const saveBtn = document.getElementById('saveBtn');
const clearSelectionBtn = document.getElementById('clearSelectionBtn');
const clearAllBtn = document.getElementById('clearAllBtn');
const cropCloseBtn = document.getElementById('cropCloseBtn');
const cropModal = document.getElementById('cropModal');
const cropCanvas = document.getElementById('cropCanvas');
const cropHint = document.getElementById('cropHint');
const cropCtx = cropCanvas ? cropCanvas.getContext('2d') : null;
const cropPrevBtn = document.getElementById('cropPrevBtn');
const cropNextBtn = document.getElementById('cropNextBtn');
const cropPageInfo = document.getElementById('cropPageInfo');
const cropImageName = document.getElementById('cropImageName');
const cropStatus = document.getElementById('cropStatus');
const deleteBtn = document.getElementById('deleteBtn');
const detailBody = document.getElementById('detailBody');
const colorPreview = document.getElementById('colorPreview');
const upperRow = document.getElementById('upperRow');
const lowerRow = document.getElementById('lowerRow');
const canvas = document.getElementById('imageCanvas');
const canvasHint = document.getElementById('canvasHint');
const canvasStatus = document.getElementById('canvasStatus');
const canvasColorTip = document.getElementById('canvasColorTip');
const selectedToothHint = document.getElementById('selectedToothHint');
const imageList = document.getElementById('imageList');
const imageCount = document.getElementById('imageCount');
const ctx = canvas.getContext('2d');
const offscreen = document.createElement('canvas');
const offCtx = offscreen.getContext('2d');
const rectModeBtn = document.getElementById('rectModeBtn');
const polyModeBtn = document.getElementById('polyModeBtn');
const toggleShadeGuide = document.getElementById('toggleShadeGuide');
const shadeGuidePanel = document.getElementById('shadeGuidePanel');

let isDragging = false;
let dragStart = null;
let cropDragging = false;
let cropStart = null;
let cropScale = 1;

function init() {
  // 初始化病患管理系統
  initPatientSystem();
  
  buildToothButtons();
  bindInputs();
  initCanvasSize();
  redrawCanvas();
  refreshButtons();
  renderDetail();
  updateSteps(1);
  initShadeGuidePanel();
}

// 初始化 VITA 色卡對照面板
function initShadeGuidePanel() {
  if (!shadeGuidePanel || !toggleShadeGuide) return;
  
  const gridEl = shadeGuidePanel.querySelector('.shade-guide-grid');
  if (!gridEl) return;
  
  // 按系列分組顯示色卡
  const series = {
    'A': VITA_SHADE_GUIDE.filter(s => s.code.startsWith('A')),
    'B': VITA_SHADE_GUIDE.filter(s => s.code.startsWith('B')),
    'C': VITA_SHADE_GUIDE.filter(s => s.code.startsWith('C')),
    'D': VITA_SHADE_GUIDE.filter(s => s.code.startsWith('D'))
  };
  
  let html = '';
  Object.entries(series).forEach(([seriesName, shades]) => {
    html += `<div class="shade-series">
      <div class="series-label">${seriesName}系列</div>
      <div class="series-items">
        ${shades.map(s => `
          <div class="shade-item" data-code="${s.code}" title="${s.description}\nL:${s.lch.L.toFixed(1)} C:${s.lch.C.toFixed(1)} h:${s.lch.h.toFixed(1)}°">
            <div class="shade-swatch" style="background: ${s.hex}"></div>
            <span class="shade-name">${s.code}</span>
          </div>
        `).join('')}
      </div>
    </div>`;
  });
  
  gridEl.innerHTML = html;
  
  // 切換展開/收合
  toggleShadeGuide.addEventListener('click', () => {
    const isCollapsed = shadeGuidePanel.classList.contains('collapsed');
    shadeGuidePanel.classList.toggle('collapsed');
    toggleShadeGuide.textContent = isCollapsed ? '收合' : '展開';
  });
  
  // 點擊色卡項目時顯示詳情
  gridEl.querySelectorAll('.shade-item').forEach(item => {
    item.addEventListener('click', () => {
      const code = item.dataset.code;
      const shade = VITA_SHADE_GUIDE.find(s => s.code === code);
      if (shade) {
        showShadeDetail(shade);
      }
    });
  });
}

// 顯示色卡詳細資訊
function showShadeDetail(shade) {
  const msg = `
VITA ${shade.code}
━━━━━━━━━━━━━━━
${shade.description}

🎨 顏色值
HEX: ${shade.hex}
RGB: R${shade.rgb.r} G${shade.rgb.g} B${shade.rgb.b}

📊 LCh 色彩模型
L (明度): ${shade.lch.L.toFixed(1)}
C (彩度): ${shade.lch.C.toFixed(1)}
h (色相): ${shade.lch.h.toFixed(1)}°
  `.trim();
  
  alert(msg);
}

function initCanvasSize() {
  const wrap = canvas.parentElement;
  if (wrap) {
    const w = wrap.clientWidth || 800;
    const h = Math.round(w * 9 / 16);
    canvas.width = w;
    canvas.height = h;
  }
}

function updateSteps(current) {
  document.querySelectorAll('.step').forEach(el => {
    const step = parseInt(el.dataset.step);
    el.classList.remove('active', 'done');
    if (step < current) el.classList.add('done');
    else if (step === current) el.classList.add('active');
  });
}

function updateStatus(text) {
  if (canvasStatus) canvasStatus.textContent = text;
}

function buildToothButtons() {
  upperRow.innerHTML = '';
  lowerRow.innerHTML = '';

  teethUpper.forEach((id, idx) => {
    if (idx === 8) upperRow.appendChild(createSpacer());
    upperRow.appendChild(createToothButton(id));
  });
  teethLower.forEach((id, idx) => {
    if (idx === 8) lowerRow.appendChild(createSpacer());
    lowerRow.appendChild(createToothButton(id));
  });
}

function createSpacer() {
  const div = document.createElement('div');
  div.className = 'tooth-spacer';
  return div;
}

function createToothButton(id) {
  const btn = document.createElement('button');
  btn.className = 'tooth-btn no-data';
  btn.dataset.tooth = id;
  btn.innerHTML = `
    <div class="tooth-id">${id}</div>
    <div class="color-chip"></div>
    <div class="lch-chips">
      <span class="lch-chip l-chip" title="L 明度">L</span>
      <span class="lch-chip c-chip" title="C 彩度">C</span>
      <span class="lch-chip h-chip" title="h 色相">h</span>
    </div>
    <div class="no-data-text">未建檔</div>
  `;
  btn.title = `牙位 ${id}`;
  btn.addEventListener('click', () => selectTooth(id));
  // 雙擊取消選擇
  btn.addEventListener('dblclick', (e) => {
    e.stopPropagation();
    deselectTooth(id);
  });
  return btn;
}

function bindInputs() {
  fileInput.addEventListener('change', onFileChange);
  gridRange.addEventListener('input', syncGridInputs);
  saveBtn.addEventListener('click', handleSave);
  clearSelectionBtn.addEventListener('click', () => {
    if (state.isCropping) {
      state.cropRect = null;
    } else {
      state.currentRoi = null;
      state.polygonPoints = [];
      state.isPolygonComplete = false;
      state.polygonMousePos = null;
      updateStatus('已清除框選');
    }
    redrawCanvas();
    refreshButtons();
  });
  clearAllBtn.addEventListener('click', handleClearAll);
  if (cropCloseBtn) cropCloseBtn.addEventListener('click', handleCropCancel);
  if (cropPrevBtn) cropPrevBtn.addEventListener('click', handleCropPrev);
  if (cropNextBtn) cropNextBtn.addEventListener('click', handleCropNext);
  deleteBtn.addEventListener('click', handleDelete);

  // ROI 模式按鈕
  if (rectModeBtn) rectModeBtn.addEventListener('click', () => setRoiMode('rect'));
  if (polyModeBtn) polyModeBtn.addEventListener('click', () => setRoiMode('polygon'));

  canvas.addEventListener('mousedown', onCanvasDown);
  canvas.addEventListener('mousemove', onCanvasMove);
  canvas.addEventListener('mouseup', onCanvasUp);
  canvas.addEventListener('mouseleave', onCanvasLeave);
  canvas.addEventListener('click', handleCanvasClick);
  canvas.addEventListener('dblclick', handleCanvasDblClick);

  if (cropCanvas) {
    cropCanvas.addEventListener('mousedown', onCropDown);
    cropCanvas.addEventListener('mousemove', onCropMove);
    cropCanvas.addEventListener('mouseup', onCropUp);
    cropCanvas.addEventListener('mouseleave', onCropUp);
  }
}

function onFileChange(e) {
  const files = Array.from(e.target.files);
  if (!files.length) return;
  
  let loadedCount = 0;
  const toLoad = files.filter(f => f.size <= 50 * 1024 * 1024);
  
  if (toLoad.length < files.length) {
    alert(`${files.length - toLoad.length} 個檔案超過 50MB，已略過`);
  }
  
  if (!toLoad.length) {
    fileInput.value = '';
    return;
  }
  
  updateStatus(`正在載入 ${toLoad.length} 張圖片...`);
  
  toLoad.forEach(file => {
    const reader = new FileReader();
    reader.onload = (readerEvent) => {
      const dataUrl = readerEvent.target.result;
      const img = new Image();
      img.onload = async () => {
        const id = Date.now() + '_' + Math.random().toString(36).slice(2, 8);
        const newImageData = {
          id,
          name: file.name,
          original: img,
          cropped: null,
          dataUrl: dataUrl,
          croppedDataUrl: null,
          records: {}
        };
        state.images.push(newImageData);
        
        // 自動儲存到 IndexedDB
        if (db) {
          try {
            await saveToIndexedDB('images', {
              id: newImageData.id,
              name: newImageData.name,
              dataUrl: newImageData.dataUrl,
              croppedDataUrl: null,
              records: {}
            });
          } catch (saveErr) {
            console.warn('自動儲存圖片失敗:', saveErr);
          }
        }
        
        loadedCount++;
        
        if (loadedCount === toLoad.length) {
          fileInput.value = '';
          renderImageList();
          // 選擇最新上傳的圖片，但不自動裁切
          const lastImg = state.images[state.images.length - 1];
          if (!state.currentImageId) {
            // 如果沒有選中的圖片，選擇新上傳的
            selectImage(lastImg.id);
          } else {
            // 已有選中的圖片，只更新狀態
            updateStatus(`已上傳 ${toLoad.length} 張圖片，點擊左側縮圖進行裁切`);
          }
        }
      };
      img.onerror = () => {
        loadedCount++;
        if (loadedCount === toLoad.length) {
          fileInput.value = '';
          renderImageList();
          if (state.images.length > 0 && !state.currentImageId) {
            selectImage(state.images[0].id);
          }
        }
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  });
}

function selectImageForCrop(id) {
  const imgData = state.images.find(i => i.id === id);
  if (!imgData) return;
  
  state.pendingCropImage = imgData;
  state.isCropping = true;
  state.cropRect = null;
  updateStatus('請框選要保留的牙齒區域');
  openCropModal();
}

function selectImage(id) {
  const imgData = state.images.find(i => i.id === id);
  if (!imgData) return;
  
  state.currentImageId = id;
  state.currentRoi = null;
  state.polygonPoints = [];
  state.isPolygonComplete = false;
  state.polygonMousePos = null;
  
  // 取得要顯示的圖片（優先使用裁切後的）
  const img = imgData.cropped || imgData.original;
  
  // 內部函數：初始化 offscreen canvas
  const initOffscreenCanvas = (sourceImg) => {
    if (!sourceImg || !sourceImg.naturalWidth || !sourceImg.naturalHeight) {
      console.error('selectImage: 圖片無效，無法初始化 offscreen canvas');
      return false;
    }
    
    offscreen.width = sourceImg.naturalWidth;
    offscreen.height = sourceImg.naturalHeight;
    offCtx.clearRect(0, 0, offscreen.width, offscreen.height);
    offCtx.drawImage(sourceImg, 0, 0, offscreen.width, offscreen.height);
    console.log('selectImage: offscreen canvas 已初始化', offscreen.width, 'x', offscreen.height);
    return true;
  };
  
  // 安全檢查：確保圖片有效且已載入
  if (!img || !img.naturalWidth || !img.naturalHeight) {
    console.warn('selectImage: 主圖片尚未載入完成或無效，嘗試替代方案');
    
    // 嘗試使用原始圖片
    if (imgData.original && imgData.original.naturalWidth) {
      if (!initOffscreenCanvas(imgData.original)) return;
    } 
    // 嘗試從 dataUrl 重新載入
    else if (imgData.croppedDataUrl || imgData.dataUrl) {
      const dataUrl = imgData.croppedDataUrl || imgData.dataUrl;
      console.log('selectImage: 從 dataUrl 重新載入圖片');
      
      const tempImg = new Image();
      tempImg.onload = () => {
        // 更新 imgData
        if (imgData.croppedDataUrl && imgData.croppedDataUrl === dataUrl) {
          imgData.cropped = tempImg;
        } else {
          imgData.original = tempImg;
        }
        
        // 初始化 offscreen
        initOffscreenCanvas(tempImg);
        fitCanvasToImage();
        redrawCanvas();
        renderImageList();
        refreshButtons();
        
        updateSteps(2);
        updateStatus(`已選擇: ${imgData.name}`);
        if (selectedToothHint) {
          selectedToothHint.innerHTML = '請選擇要分析的牙位';
        }
      };
      tempImg.onerror = () => {
        console.error('selectImage: 從 dataUrl 載入圖片失敗');
      };
      tempImg.src = dataUrl;
      return; // 異步處理，先返回
    } else {
      console.error('selectImage: 無法載入圖片，沒有可用的資源');
      return;
    }
  } else {
    if (!initOffscreenCanvas(img)) return;
  }
  
  fitCanvasToImage();
  redrawCanvas();
  renderImageList();
  refreshButtons();
  
  if (imgData.cropped) {
    updateSteps(2);
    updateStatus(`已選擇: ${imgData.name}`);
    if (selectedToothHint) {
      selectedToothHint.innerHTML = '請選擇要分析的牙位';
    }
  } else {
    selectImageForCrop(id);
  }
}

async function deleteImage(id) {
  const idx = state.images.findIndex(i => i.id === id);
  if (idx === -1) return;
  
  state.images.splice(idx, 1);
  
  // 從 IndexedDB 刪除
  if (db) {
    try {
      await deleteFromIndexedDB('images', id);
    } catch (e) {
      console.warn('從 IndexedDB 刪除圖片失敗:', e);
    }
  }
  
  if (state.currentImageId === id) {
    state.currentImageId = null;
    if (state.images.length > 0) {
      selectImage(state.images[0].id);
    } else {
      redrawCanvas();
    }
  }
  
  renderImageList();
  refreshButtons();
}

function renderImageList() {
  if (!imageList) return;
  
  imageCount.textContent = state.images.length;
  
  if (state.images.length === 0) {
    imageList.innerHTML = '<div class="image-list-empty">尚無圖片<br>請上傳</div>';
    return;
  }
  
  imageList.innerHTML = state.images.map(img => {
    // 取得顯示用的圖片 URL - 改進優先順序和安全檢查
    let displayUrl = null;
    
    // 優先使用裁切後的 dataUrl
    if (img.croppedDataUrl && typeof img.croppedDataUrl === 'string' && img.croppedDataUrl.startsWith('data:')) {
      displayUrl = img.croppedDataUrl;
    }
    // 其次使用原始 dataUrl
    else if (img.dataUrl && typeof img.dataUrl === 'string' && img.dataUrl.startsWith('data:')) {
      displayUrl = img.dataUrl;
    }
    // 如果沒有 dataUrl，嘗試從 Image 物件取得
    else if (img.cropped && img.cropped.src && typeof img.cropped.src === 'string' && img.cropped.src.startsWith('data:')) {
      displayUrl = img.cropped.src;
    }
    else if (img.original && img.original.src && typeof img.original.src === 'string' && img.original.src.startsWith('data:')) {
      displayUrl = img.original.src;
    }
    
    // 如果還是沒有，使用佔位圖
    if (!displayUrl) {
      displayUrl = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" width="100" height="100"%3E%3Crect fill="%23ddd" width="100" height="100"/%3E%3Ctext x="50" y="50" text-anchor="middle" dy=".3em" fill="%23999"%3E無圖片%3C/text%3E%3C/svg%3E';
    }
    
    return `
      <div class="image-thumb ${img.id === state.currentImageId ? 'active' : ''}${img.cropped ? '' : ' uncropped'}" data-id="${img.id}">
        <img src="${displayUrl}" alt="${img.name || '圖片'}">
        <button class="thumb-delete" data-id="${img.id}">✕</button>
        ${!img.cropped ? '<span class="crop-badge">✂️</span>' : ''}
      </div>
    `;
  }).join('');
  
  // 綁定事件
  imageList.querySelectorAll('.image-thumb').forEach(thumb => {
    thumb.addEventListener('click', (e) => {
      if (e.target.classList.contains('thumb-delete')) return;
      selectImage(thumb.dataset.id);
    });
  });
  
  imageList.querySelectorAll('.thumb-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (confirm('確定刪除此圖片？')) {
        deleteImage(btn.dataset.id);
      }
    });
  });
}

function fitCanvasToImage() {
  const img = getCurrentImage();
  if (!img) return;
  
  // 安全檢查：確保圖片尺寸有效
  const imgWidth = img.naturalWidth || img.width || 0;
  const imgHeight = img.naturalHeight || img.height || 0;
  
  if (imgWidth <= 0 || imgHeight <= 0) {
    console.warn('fitCanvasToImage: 圖片尺寸無效');
    return;
  }
  
  const wrap = canvas.parentElement;
  const wrapWidth = wrap.clientWidth || 900;
  const wrapHeight = wrap.clientHeight || 600;
  // 計算縮放比例，讓圖片適應容器
  const scaleW = wrapWidth / imgWidth;
  const scaleH = wrapHeight / imgHeight;
  const scale = Math.min(scaleW, scaleH, 1);
  state.imageScale = scale;
  canvas.width = Math.round(imgWidth * scale);
  canvas.height = Math.round(imgHeight * scale);
  canvasHint.style.display = 'none';
}

function syncGridInputs(e) {
  const val = clamp(parseInt(e.target.value || '8', 10), 2, 32);
  gridRange.value = val;
  if (gridNumber) gridNumber.textContent = val;
  if (gridNumber2) gridNumber2.textContent = val;
}

// ROI 模式切換
function setRoiMode(mode) {
  state.roiMode = mode;
  state.currentRoi = null;
  state.polygonPoints = [];
  state.isPolygonComplete = false;
  state.polygonMousePos = null;
  
  // 更新按鈕樣式
  if (rectModeBtn) rectModeBtn.classList.toggle('active', mode === 'rect');
  if (polyModeBtn) polyModeBtn.classList.toggle('active', mode === 'polygon');
  
  // 更新提示
  const modeText = mode === 'rect' ? '矩形框選' : '多邊形圈選（點擊定點，雙擊完成）';
  updateStatus(`已切換至：${modeText}`);
  
  redrawCanvas();
  refreshButtons();
}

function selectTooth(id) {
  if (state.isCropping) {
    alert('請先完成裁切再選擇牙位');
    return;
  }
  
  // 檢查該牙位是否在某張圖片中有記錄，如果有則自動切換
  const imageWithRecord = state.images.find(img => img.records && img.records[id]);
  if (imageWithRecord && imageWithRecord.id !== state.currentImageId) {
    // 切換到有該牙位記錄的圖片
    selectImage(imageWithRecord.id);
  }
  
  state.currentTooth = id;
  
  // 根據是否有記錄顯示不同提示
  const records = getCurrentRecords();
  if (records[id]) {
    if (selectedToothHint) {
      selectedToothHint.innerHTML = `已選擇：<strong>牙位 ${id}</strong> (已建檔) <span class="hint-tip">雙擊取消</span>`;
    }
    updateStatus(`已選擇牙位 ${id}，可查看詳情或重新框選`);
  } else {
    if (selectedToothHint) {
      const modeHint = state.roiMode === 'rect' ? '拖曳框選' : 
                       state.roiMode === 'polygon' ? '點擊定點' : 
                       '點擊牙齒區域';
      selectedToothHint.innerHTML = `已選擇：<strong>牙位 ${id}</strong> → ${modeHint} <span class="hint-tip">雙擊取消</span>`;
    }
    updateStatus(`已選擇牙位 ${id}，請在圖片上框選牙齒區域`);
  }
  
  updateSteps(3);
  refreshButtons();
  redrawCanvas();
  renderDetail();
}

// 雙擊取消選擇牙位
function deselectTooth(id) {
  // 只有當前選中的牙位才能取消
  if (state.currentTooth !== id) return;
  
  state.currentTooth = null;
  state.currentRoi = null;
  state.polygonPoints = [];
  state.isPolygonComplete = false;
  state.polygonMousePos = null;
  
  if (selectedToothHint) {
    selectedToothHint.innerHTML = '請選擇要分析的牙位';
  }
  updateStatus('已取消選擇牙位');
  updateSteps(2);
  refreshButtons();
  redrawCanvas();
  renderDetail();
}

function onCanvasDown(e) {
  const img = getCurrentImage();
  if (!img) return;
  if (state.isCropping) return;
  
  // 必須先選取牙位才能框選
  if (!state.currentTooth) {
    updateStatus('請先在下方選擇牙位後，才能框選區域');
    return;
  }
  
  // 多邊形模式不使用拖曳
  if (state.roiMode === 'polygon') return;
  
  const pos = getCanvasPos(e);
  
  // 矩形模式
  if (state.roiMode === 'rect') {
    isDragging = true;
    dragStart = pos;
    state.currentRoi = { type: 'rect', x: pos.x, y: pos.y, w: 0, h: 0 };
  }
}

function onCanvasMove(e) {
  const img = getCurrentImage();
  // 顯示滑鼠位置的顏色
  if (img && !isDragging) {
    showCanvasColorTip(e);
  }
  
  // 多邊形模式：更新預覽線條
  if (state.roiMode === 'polygon' && state.polygonPoints.length > 0 && !state.isPolygonComplete) {
    state.polygonMousePos = getCanvasPos(e);
    redrawCanvas();
    drawPolygonInProgress();
  }
  
  if (!isDragging || !img) return;
  if (state.isCropping) return;
  hideCanvasColorTip(); // 拖曳時隱藏顏色提示
  
  // 只有矩形模式才拖曳
  if (state.roiMode === 'rect') {
    const pos = getCanvasPos(e);
    const x = Math.min(pos.x, dragStart.x);
    const y = Math.min(pos.y, dragStart.y);
    const w = Math.abs(pos.x - dragStart.x);
    const h = Math.abs(pos.y - dragStart.y);
    state.currentRoi = { type: 'rect', x, y, w, h };
    redrawCanvas();
    if (state.currentRoi) drawLiveRoi(state.currentRoi);
  }
}

function onCanvasLeave() {
  hideCanvasColorTip();
  onCanvasUp();
}

function showCanvasColorTip(e) {
  const img = getCurrentImage();
  if (!canvasColorTip || !img) return;
  
  // 安全檢查 canvas 尺寸
  if (canvas.width <= 0 || canvas.height <= 0) return;
  
  const pos = getCanvasPos(e);
  const px = Math.floor(pos.x);
  const py = Math.floor(pos.y);
  if (px < 0 || py < 0 || px >= canvas.width || py >= canvas.height) {
    hideCanvasColorTip();
    return;
  }
  
  // 從 canvas 讀取顏色，加入錯誤處理
  try {
    const pixel = ctx.getImageData(px, py, 1, 1).data;
    const hex = rgbToHex(pixel[0], pixel[1], pixel[2]);
    
    // 計算 LCh 值
    const lch = rgbToLch(pixel[0], pixel[1], pixel[2]);
    
    // 更新提示內容（包含 LCh）
    canvasColorTip.innerHTML = `
      <div class="cct-color" style="background:${hex}"></div>
      <div class="cct-info">
        <span class="cct-hex">${hex.toUpperCase()}</span>
        <span class="cct-lch">L:${lch.L.toFixed(0)} C:${lch.C.toFixed(0)} h:${lch.h.toFixed(0)}°</span>
      </div>
    `;
    canvasColorTip.classList.add('visible');
    
    // 位置跟隨滑鼠
    const rect = canvas.getBoundingClientRect();
    const wrapRect = canvas.parentElement.getBoundingClientRect();
    const tipX = e.clientX - wrapRect.left + 15;
    const tipY = e.clientY - wrapRect.top - 30;
    canvasColorTip.style.left = tipX + 'px';
    canvasColorTip.style.top = Math.max(5, tipY) + 'px';
  } catch (err) {
    console.warn('讀取像素顏色失敗:', err);
    hideCanvasColorTip();
  }
}

function hideCanvasColorTip() {
  if (canvasColorTip) {
    canvasColorTip.classList.remove('visible');
  }
}

function onCanvasUp() {
  if (!isDragging) return;
  isDragging = false;
  if (state.isCropping) {
    if (state.cropRect && (state.cropRect.w < 10 || state.cropRect.h < 10)) {
      state.cropRect = null;
    }
  } else {
    // 只有矩形模式才在這裡處理
    if (state.roiMode === 'rect' && state.currentRoi) {
      if (state.currentRoi.w < 4 || state.currentRoi.h < 4) {
        state.currentRoi = null;
      } else if (state.currentTooth) {
        updateSteps(4);
        updateStatus(`已框選 ROI，點擊「儲存 ROI」或重新框選`);
      }
    }
  }
  redrawCanvas();
  refreshButtons();
}

function getCanvasPos(e) {
  const rect = canvas.getBoundingClientRect();
  // 使用精確的座標轉換，考慮可能的 CSS 縮放
  const cssWidth = rect.width;
  const cssHeight = rect.height;
  const scaleX = canvas.width / cssWidth;
  const scaleY = canvas.height / cssHeight;
  const x = (e.clientX - rect.left) * scaleX;
  const y = (e.clientY - rect.top) * scaleY;
  return {
    x: Math.max(0, Math.min(canvas.width, x)),
    y: Math.max(0, Math.min(canvas.height, y)),
  };
}

function redrawCanvas() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const img = getCurrentImage();
  if (!img) {
    canvasHint.style.display = 'flex';
    stopRoiAnimation();
    return;
  }
  
  // 安全檢查：確保圖片已載入且有效
  const imgWidth = img.naturalWidth || img.width || 0;
  const imgHeight = img.naturalHeight || img.height || 0;
  
  if (imgWidth <= 0 || imgHeight <= 0) {
    console.warn('redrawCanvas: 圖片尺寸無效');
    canvasHint.style.display = 'flex';
    return;
  }
  
  canvasHint.style.display = 'none';
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  if (!state.isCropping) {
    drawStoredRois();
    if (state.currentRoi) drawLiveRoi(state.currentRoi);
    if (state.roiMode === 'polygon' && state.polygonPoints.length > 0 && !state.isPolygonComplete) {
      drawPolygonInProgress();
    }
    
    // 如果有 ROI 需要顯示動畫，啟動動畫循環
    const records = getCurrentRecords();
    const hasActiveRoi = state.currentRoi || state.currentTooth || Object.keys(records).length > 0;
    if (hasActiveRoi) {
      startRoiAnimation();
    } else {
      stopRoiAnimation();
    }
  }
}

// ROI 動畫控制
function startRoiAnimation() {
  if (state.roiAnimationFrame) return; // 已在運行
  
  function animate() {
    state.roiAnimationOffset = (state.roiAnimationOffset + 0.5) % 28;
    
    // 重繪 Canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const img = getCurrentImage();
    if (img) {
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      if (!state.isCropping) {
        drawStoredRois();
        if (state.currentRoi) drawLiveRoi(state.currentRoi);
        if (state.roiMode === 'polygon' && state.polygonPoints.length > 0 && !state.isPolygonComplete) {
          drawPolygonInProgress();
        }
      }
    }
    
    state.roiAnimationFrame = requestAnimationFrame(animate);
  }
  
  state.roiAnimationFrame = requestAnimationFrame(animate);
}

function stopRoiAnimation() {
  if (state.roiAnimationFrame) {
    cancelAnimationFrame(state.roiAnimationFrame);
    state.roiAnimationFrame = null;
  }
}

function drawPolygonInProgress() {
  if (state.polygonPoints.length === 0) return;
  
  const dashOffset = state.roiAnimationOffset || 0;
  
  ctx.save();
  ctx.strokeStyle = 'rgba(59,130,246,0.9)';
  ctx.fillStyle = 'rgba(59,130,246,0.15)';
  ctx.lineWidth = 2.5;
  ctx.setLineDash([8, 6]);
  ctx.lineDashOffset = -dashOffset;
  
  // 繪製已確定的線段和填充區域
  ctx.beginPath();
  ctx.moveTo(state.polygonPoints[0].x, state.polygonPoints[0].y);
  for (let i = 1; i < state.polygonPoints.length; i++) {
    ctx.lineTo(state.polygonPoints[i].x, state.polygonPoints[i].y);
  }
  
  // 如果有滑鼠位置，連接到滑鼠位置再回到起始點
  if (state.polygonMousePos && state.polygonPoints.length >= 1) {
    ctx.lineTo(state.polygonMousePos.x, state.polygonMousePos.y);
  }
  
  // 自動連接回起始點，形成封閉圖形
  ctx.lineTo(state.polygonPoints[0].x, state.polygonPoints[0].y);
  ctx.fill();
  ctx.stroke();
  
  // 繪製發光外框
  ctx.strokeStyle = 'rgba(59,130,246,0.3)';
  ctx.lineWidth = 6;
  ctx.setLineDash([]);
  ctx.stroke();
  
  // 繪製預覽線（從最後一點到滑鼠位置）- 用虛線
  if (state.polygonMousePos && state.polygonPoints.length >= 1) {
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.lineDashOffset = -dashOffset;
    ctx.strokeStyle = 'rgba(59,130,246,0.6)';
    ctx.lineWidth = 2;
    const lastPt = state.polygonPoints[state.polygonPoints.length - 1];
    ctx.moveTo(lastPt.x, lastPt.y);
    ctx.lineTo(state.polygonMousePos.x, state.polygonMousePos.y);
    ctx.stroke();
  }
  
  // 繪製已定義的點
  state.polygonPoints.forEach((pt, idx) => {
    ctx.fillStyle = idx === 0 ? 'rgba(34,197,94,0.9)' : 'rgba(59,130,246,0.9)';
    ctx.shadowColor = idx === 0 ? 'rgba(34,197,94,0.5)' : 'rgba(59,130,246,0.5)';
    ctx.shadowBlur = 6;
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, idx === 0 ? 6 : 4, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
    // 起始點加白色邊框
    if (idx === 0) {
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2;
      ctx.setLineDash([]);
      ctx.stroke();
    }
  });
  
  ctx.restore();
}

function drawLiveRoi(roi) {
  ctx.save();
  
  // 動態虛線偏移
  const dashOffset = state.roiAnimationOffset || 0;
  
  if (roi.type === 'polygon' && roi.points && roi.points.length >= 3) {
    // 繪製多邊形
    ctx.strokeStyle = 'rgba(59,130,246,0.9)';
    ctx.fillStyle = 'rgba(59,130,246,0.15)';
    ctx.lineWidth = 2.5;
    ctx.setLineDash([8, 6]);
    ctx.lineDashOffset = -dashOffset;
    
    ctx.beginPath();
    ctx.moveTo(roi.points[0].x, roi.points[0].y);
    for (let i = 1; i < roi.points.length; i++) {
      ctx.lineTo(roi.points[i].x, roi.points[i].y);
    }
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
    
    // 繪製發光外框
    ctx.strokeStyle = 'rgba(59,130,246,0.3)';
    ctx.lineWidth = 6;
    ctx.setLineDash([]);
    ctx.stroke();
    
    // 繪製點
    roi.points.forEach((pt, idx) => {
      ctx.fillStyle = idx === 0 ? 'rgba(34,197,94,0.9)' : 'rgba(59,130,246,0.9)';
      ctx.shadowColor = 'rgba(59,130,246,0.5)';
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  } else {
    // 繪製矩形
    ctx.strokeStyle = 'rgba(59,130,246,0.9)';
    ctx.lineWidth = 2.5;
    ctx.setLineDash([8, 6]);
    ctx.lineDashOffset = -dashOffset;
    ctx.strokeRect(roi.x, roi.y, roi.w, roi.h);
    
    // 繪製發光外框
    ctx.strokeStyle = 'rgba(59,130,246,0.3)';
    ctx.lineWidth = 6;
    ctx.setLineDash([]);
    ctx.strokeRect(roi.x, roi.y, roi.w, roi.h);
    
    // 繪製填充
    ctx.fillStyle = 'rgba(59,130,246,0.1)';
    ctx.fillRect(roi.x, roi.y, roi.w, roi.h);
  }
  
  ctx.restore();
}

function drawCropRect(roi) {
  ctx.save();
  ctx.strokeStyle = 'rgba(234,179,8,0.9)';
  ctx.lineWidth = 2.5;
  ctx.setLineDash([8, 5]);
  ctx.strokeRect(roi.x, roi.y, roi.w, roi.h);
  ctx.restore();
}

function drawStoredRois() {
  const records = getCurrentRecords();
  const dashOffset = state.roiAnimationOffset || 0;
  
  Object.values(records).forEach(rec => {
    const isActive = rec.toothId === state.currentTooth;
    const r = rec.roiCanvas;
    
    ctx.save();
    ctx.lineWidth = isActive ? 3 : 2;
    ctx.strokeStyle = isActive ? 'rgba(16,185,129,0.95)' : 'rgba(255,255,255,0.7)';
    if (!isActive) ctx.globalAlpha = 0.7;
    
    if (isActive) {
      // 活動狀態：動態虛線
      ctx.setLineDash([8, 6]);
      ctx.lineDashOffset = -dashOffset;
    } else {
      ctx.setLineDash([4, 3]);
    }
    
    if (r.type === 'polygon' && r.points) {
      // 繪製多邊形
      ctx.beginPath();
      ctx.moveTo(r.points[0].x, r.points[0].y);
      for (let i = 1; i < r.points.length; i++) {
        ctx.lineTo(r.points[i].x, r.points[i].y);
      }
      ctx.closePath();
      ctx.stroke();
      
      // 活動狀態：繪製發光外框
      if (isActive) {
        ctx.strokeStyle = 'rgba(16,185,129,0.3)';
        ctx.lineWidth = 6;
        ctx.setLineDash([]);
        ctx.stroke();
      }
      
      // 使用第一個點作為標籤位置
      const labelX = r.points[0].x;
      const labelY = r.points[0].y;
      drawRoiLabel(rec, labelX, labelY, isActive);
    } else {
      // 繪製矩形
      ctx.strokeRect(r.x, r.y, r.w, r.h);
      
      // 活動狀態：繪製發光外框
      if (isActive) {
        ctx.strokeStyle = 'rgba(16,185,129,0.3)';
        ctx.lineWidth = 6;
        ctx.setLineDash([]);
        ctx.strokeRect(r.x, r.y, r.w, r.h);
      }
      
      drawRoiLabel(rec, r.x, r.y, isActive);
    }
    
    ctx.restore();
  });
}

function drawRoiLabel(rec, x, y, isActive) {
  const labelW = 32;
  const labelH = 18;
  
  // 繪製標籤背景
  ctx.fillStyle = isActive ? 'rgba(16,185,129,0.9)' : 'rgba(0,0,0,0.7)';
  ctx.fillRect(x, y - labelH, labelW, labelH);
  
  // 繪製牙位編號
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 11px Segoe UI';
  ctx.fillText(rec.toothId, x + 5, y - 5);
  
  // 繪製小色塊預覽
  if (rec.result && rec.result.avgColor) {
    const r = rec.roiCanvas;
    const colorX = r.type === 'polygon' ? x + labelW - 12 : x + r.w - 12;
    ctx.fillStyle = rec.result.avgColor.hex;
    ctx.fillRect(colorX, y - labelH + 3, 9, 12);
    ctx.strokeStyle = 'rgba(255,255,255,0.5)';
    ctx.lineWidth = 1;
    ctx.strokeRect(colorX, y - labelH + 3, 9, 12);
  }
}

// 點擊 Canvas 處理：標籤切換、多邊形
function handleCanvasClick(e) {
  const img = getCurrentImage();
  if (state.isCropping || !img) return;
  const pos = getCanvasPos(e);
  const records = getCurrentRecords();
  
  // 多邊形模式 - 優先處理
  if (state.roiMode === 'polygon') {
    // 必須先選取牙位才能框選
    if (!state.currentTooth) {
      updateStatus('請先在下方選擇牙位後，才能框選區域');
      return;
    }
    
    // 如果已經完成多邊形，忽略點擊
    if (state.isPolygonComplete) return;
    
    // 單擊添加點
    const newPoint = {x: pos.x, y: pos.y};
    state.polygonPoints.push(newPoint);
    updateStatus(`已添加第 ${state.polygonPoints.length} 個點，雙擊完成`);
    redrawCanvas();
    drawPolygonInProgress();
    return;
  }
  
  // 檢查是否點擊到已建檔的 ROI 標籤（僅在矩形模式或沒有選牙位時）
  if (state.roiMode === 'rect' || !state.currentTooth) {
    for (const rec of Object.values(records)) {
      const r = rec.roiCanvas;
      if (r.type === 'rect' || !r.type) {
        const labelW = 32;
        const labelH = 18;
        // 檢查標籤區域
        if (pos.x >= r.x && pos.x <= r.x + labelW &&
            pos.y >= r.y - labelH && pos.y <= r.y) {
          selectTooth(rec.toothId);
          return;
        }
        // 檢查 ROI 區域
        if (pos.x >= r.x && pos.x <= r.x + r.w &&
            pos.y >= r.y && pos.y <= r.y + r.h) {
          selectTooth(rec.toothId);
          return;
        }
      }
    }
  }
}

// 雙擊完成多邊形
function handleCanvasDblClick(e) {
  const img = getCurrentImage();
  if (state.isCropping || !img) return;
  
  // 多邊形模式雙擊完成
  if (state.roiMode === 'polygon' && state.currentTooth && state.polygonPoints.length >= 3) {
    // 移除雙擊時多添加的點（因為雙擊會觸發兩次 click，所以會多兩個重複的點）
    // 檢查最後兩個點是否位置相近（在同一位置的重複點）
    while (state.polygonPoints.length > 3) {
      const lastPt = state.polygonPoints[state.polygonPoints.length - 1];
      const prevPt = state.polygonPoints[state.polygonPoints.length - 2];
      const distance = Math.sqrt(Math.pow(lastPt.x - prevPt.x, 2) + Math.pow(lastPt.y - prevPt.y, 2));
      // 如果兩點距離小於 5 像素，視為重複點並移除
      if (distance < 5) {
        state.polygonPoints.pop();
      } else {
        break;
      }
    }
    
    state.isPolygonComplete = true;
    state.currentRoi = { type: 'polygon', points: [...state.polygonPoints] };
    updateSteps(4);
    updateStatus(`已完成多邊形圈選（${state.polygonPoints.length} 個點），點擊「儲存」`);
    redrawCanvas();
    refreshButtons();
  }
}

function handleSave() {
  if (!state.currentTooth) {
    updateStatus('請先選擇牙位', 'warn');
    alert('請先選擇牙位');
    return;
  }
  if (state.isCropping) {
    updateStatus('請先完成裁切', 'warn');
    alert('請先完成裁切');
    return;
  }
  if (!state.currentRoi) {
    updateStatus('請先框選 ROI 區域', 'warn');
    alert('請先框選 ROI');
    return;
  }
  const img = getCurrentImage();
  if (!img) {
    updateStatus('請先上傳圖片', 'warn');
    alert('請先上傳圖片');
    return;
  }
  
  const gridN = parseInt(gridRange.value, 10) || 8;
  const roiCanvas = clampRoiToCanvas(state.currentRoi);
  
  // 驗證 ROI 大小
  if (roiCanvas.type === 'polygon') {
    if (!roiCanvas.points || roiCanvas.points.length < 3) {
      updateStatus('多邊形至少需要 3 個點', 'warn');
      alert('多邊形至少需要 3 個點');
      return;
    }
  } else {
    if (roiCanvas.w < 4 || roiCanvas.h < 4) {
      updateStatus('ROI 太小，請重新框選', 'warn');
      alert('ROI 太小，請重新框選');
      return;
    }
  }
  
  const roiImagePx = toImagePixels(roiCanvas);
  
  // 驗證 offscreen canvas 是否有效（這是顏色取樣的來源）
  if (!offscreen || offscreen.width <= 0 || offscreen.height <= 0) {
    console.error('handleSave: offscreen canvas 無效，嘗試重新初始化');
    
    // 嘗試從當前圖片重新初始化 offscreen
    const currentImgData = state.images.find(i => i.id === state.currentImageId);
    if (currentImgData) {
      const sourceImg = currentImgData.cropped || currentImgData.original;
      if (sourceImg && sourceImg.naturalWidth && sourceImg.naturalHeight) {
        offscreen.width = sourceImg.naturalWidth;
        offscreen.height = sourceImg.naturalHeight;
        offCtx.clearRect(0, 0, offscreen.width, offscreen.height);
        offCtx.drawImage(sourceImg, 0, 0, offscreen.width, offscreen.height);
        console.log('handleSave: offscreen canvas 已重新初始化');
      } else {
        updateStatus('圖片資料異常，請重新選擇圖片', 'warn');
        alert('圖片資料異常，請重新選擇圖片');
        return;
      }
    } else {
      updateStatus('找不到圖片資料，請重新選擇圖片', 'warn');
      alert('找不到圖片資料，請重新選擇圖片');
      return;
    }
  }
  
  const result = analyzeRoi(roiImagePx, gridN);
  
  if (result.samplesCount === 0) {
    updateStatus('取樣失敗，請重新框選', 'warn');
    alert('取樣失敗，請重新框選');
    return;
  }
  
  const record = {
    toothId: state.currentTooth,
    roiCanvas,
    roiImagePx,
    gridN,
    result,
    createdAt: new Date().toISOString(),
  };
  setCurrentRecord(state.currentTooth, record);
  state.currentRoi = null;
  state.polygonPoints = [];
  state.isPolygonComplete = false;
  updateSteps(5);
  updateStatus(`牙位 ${state.currentTooth} 已儲存完成！`, 'success');
  if (selectedToothHint) {
    selectedToothHint.innerHTML = `<strong>牙位 ${state.currentTooth}</strong> 已儲存 ✓ 可選擇下一個牙位`;
  }
  redrawCanvas();
  refreshButtons();
  renderDetail();
}
function handleCropCancel() {
  if (!state.isCropping) return;
  state.isCropping = false;
  state.cropRect = null;
  state.pendingCropImage = null;
  closeCropModal();
  
  // 如果有其他已裁切的圖片，選擇第一張
  const croppedImg = state.images.find(i => i.cropped);
  if (croppedImg) {
    selectImage(croppedImg.id);
  } else {
    redrawCanvas();
  }
  refreshButtons();
}

// 取得未裁切圖片列表
function getUncroppedImages() {
  return state.images.filter(img => !img.cropped);
}

// 取得當前裁切圖片在未裁切列表中的索引
function getCurrentCropIndex() {
  const uncropped = getUncroppedImages();
  if (!state.pendingCropImage) return -1;
  return uncropped.findIndex(img => img.id === state.pendingCropImage.id);
}

// 更新裁切導航 UI
function updateCropNavigation() {
  const uncropped = getUncroppedImages();
  const total = state.images.length;
  const croppedCount = state.images.filter(img => img.cropped).length;
  const currentIdx = getCurrentCropIndex();
  
  if (cropPageInfo) {
    if (uncropped.length > 0 && currentIdx >= 0) {
      cropPageInfo.textContent = `${currentIdx + 1} / ${uncropped.length} (未裁切)`;
    } else {
      cropPageInfo.textContent = `${croppedCount} / ${total} 已裁切`;
    }
  }
  
  if (cropPrevBtn) {
    cropPrevBtn.disabled = currentIdx <= 0;
  }
  if (cropNextBtn) {
    cropNextBtn.disabled = currentIdx >= uncropped.length - 1 || uncropped.length <= 1;
  }
  
  if (cropImageName && state.pendingCropImage) {
    cropImageName.textContent = state.pendingCropImage.name;
  }
  
  if (cropStatus) {
    const status = state.pendingCropImage?.cropped ? '✓ 已裁切' : '待裁切';
    cropStatus.textContent = status;
  }
}

// 切換到上一張未裁切圖片
function handleCropPrev() {
  const uncropped = getUncroppedImages();
  const currentIdx = getCurrentCropIndex();
  
  if (currentIdx > 0) {
    const prevImg = uncropped[currentIdx - 1];
    state.pendingCropImage = prevImg;
    state.cropRect = null;
    updateCropNavigation();
    renderCropCanvas();
  }
}

// 切換到下一張未裁切圖片
function handleCropNext() {
  const uncropped = getUncroppedImages();
  const currentIdx = getCurrentCropIndex();
  
  if (currentIdx < uncropped.length - 1) {
    const nextImg = uncropped[currentIdx + 1];
    state.pendingCropImage = nextImg;
    state.cropRect = null;
    updateCropNavigation();
    renderCropCanvas();
  }
}

function applyCrop() {
  if (!state.pendingCropImage || !state.cropRect) return;
  
  const srcImg = state.pendingCropImage.original;
  const currentImgData = state.pendingCropImage;
  
  // 安全檢查
  if (!srcImg || !srcImg.naturalWidth || !srcImg.naturalHeight) {
    console.error('applyCrop: 原始圖片無效');
    return;
  }
  
  if (cropScale <= 0) {
    console.error('applyCrop: cropScale 無效');
    return;
  }
  
  const px = {
    x: state.cropRect.x / cropScale,
    y: state.cropRect.y / cropScale,
    w: state.cropRect.w / cropScale,
    h: state.cropRect.h / cropScale,
  };
  
  // 驗證裁切區域
  if (px.w <= 0 || px.h <= 0) {
    console.error('applyCrop: 裁切區域無效');
    return;
  }
  
  const temp = document.createElement('canvas');
  temp.width = Math.round(px.w);
  temp.height = Math.round(px.h);
  const tctx = temp.getContext('2d');
  tctx.drawImage(srcImg, px.x, px.y, px.w, px.h, 0, 0, temp.width, temp.height);
  const dataUrl = temp.toDataURL('image/png');
  const newImg = new Image();
  newImg.onload = async () => {
    // 更新圖片的 cropped 屬性
    currentImgData.cropped = newImg;
    currentImgData.croppedDataUrl = dataUrl; // 保存裁切後的 dataUrl
    
    // 自動同步到 IndexedDB
    if (db) {
      try {
        await saveToIndexedDB('images', {
          id: currentImgData.id,
          name: currentImgData.name,
          dataUrl: currentImgData.dataUrl,
          croppedDataUrl: currentImgData.croppedDataUrl,
          records: currentImgData.records || {}
        });
      } catch (saveErr) {
        console.warn('自動儲存裁切圖片失敗:', saveErr);
      }
    }
    
    state.cropRect = null;
    renderImageList();
    
    // 檢查是否還有未裁切的圖片
    const uncropped = getUncroppedImages();
    
    if (uncropped.length > 0) {
      // 還有未裁切的圖片，自動跳到下一張
      state.pendingCropImage = uncropped[0];
      updateCropNavigation();
      renderCropCanvas();
      updateStatus(`已裁切 ${currentImgData.name}，請繼續裁切下一張`);
    } else {
      // 所有圖片都已裁切完成
      state.currentImageId = currentImgData.id;
      state.currentTooth = null;
      state.currentRoi = null;
      state.isCropping = false;
      state.pendingCropImage = null;
      
      offscreen.width = newImg.naturalWidth;
      offscreen.height = newImg.naturalHeight;
      offCtx.clearRect(0, 0, offscreen.width, offscreen.height);
      offCtx.drawImage(newImg, 0, 0, offscreen.width, offscreen.height);
      
      fitCanvasToImage();
      redrawCanvas();
      refreshButtons();
      renderDetail();
      closeCropModal();
      updateSteps(2);
      updateStatus('所有圖片裁切完成！請選擇牙位', 'success');
      if (selectedToothHint) {
        selectedToothHint.innerHTML = '請在下方選擇要分析的牙位';
      }
    }
  };
  newImg.src = dataUrl;
}

function clampRoiToCanvas(roi) {
  if (roi.type === 'polygon') {
    // 多邊形只需確保有效
    return roi;
  } else {
    // 矩形模式
    const x = clamp(roi.x || 0, 0, canvas.width);
    const y = clamp(roi.y || 0, 0, canvas.height);
    const w = clamp(roi.w || 0, 0, canvas.width - x);
    const h = clamp(roi.h || 0, 0, canvas.height - y);
    return { ...roi, type: roi.type || 'rect', x, y, w, h };
  }
}

function toImagePixels(roiCanvas) {
  const scale = state.imageScale || 1;
  
  if (roiCanvas.type === 'polygon') {
    // 轉換多邊形點座標
    return {
      type: 'polygon',
      points: roiCanvas.points.map(pt => ({
        x: pt.x / scale,
        y: pt.y / scale
      }))
    };
  } else {
    // 矩形模式
    return {
      type: 'rect',
      x: roiCanvas.x / scale,
      y: roiCanvas.y / scale,
      w: roiCanvas.w / scale,
      h: roiCanvas.h / scale,
    };
  }
}

function analyzeRoi(roiPx, gridN) {
  const samples = [];
  const bandAccumV = { top: [], mid: [], bottom: [] };
  const bandAccumH = { left: [], center: [], right: [] };
  const zoneAccum = {
    topLeft: [], topCenter: [], topRight: [],
    midLeft: [], midCenter: [], midRight: [],
    bottomLeft: [], bottomCenter: [], bottomRight: []
  };
  
  if (roiPx.type === 'polygon') {
    // 多邊形取樣
    const points = roiPx.points;
    const bounds = getPolygonBounds(points);
    const cellW = bounds.w / gridN;
    const cellH = bounds.h / gridN;
    
    for (let r = 0; r < gridN; r++) {
      for (let c = 0; c < gridN; c++) {
        const sx = bounds.x + (c + 0.5) * cellW;
        const sy = bounds.y + (r + 0.5) * cellH;
        
        // 檢查點是否在多邊形內
        if (isPointInPolygon(sx, sy, points)) {
          const rgb = samplePixel(Math.round(sx), Math.round(sy));
          samples.push(rgb);
          
          const bandV = getBandV(sy, bounds.y, bounds.h);
          const bandH = getBandH(sx, bounds.x, bounds.w);
          bandAccumV[bandV].push(rgb);
          bandAccumH[bandH].push(rgb);
          
          const zoneKey = bandV + bandH.charAt(0).toUpperCase() + bandH.slice(1);
          if (zoneAccum[zoneKey]) zoneAccum[zoneKey].push(rgb);
        }
      }
    }
  } else {
    // 矩形取樣（原有邏輯）
    const cellW = roiPx.w / gridN;
    const cellH = roiPx.h / gridN;
    
    for (let r = 0; r < gridN; r++) {
      for (let c = 0; c < gridN; c++) {
        const sx = roiPx.x + (c + 0.5) * cellW;
        const sy = roiPx.y + (r + 0.5) * cellH;
        const rgb = samplePixel(Math.round(sx), Math.round(sy));
        samples.push(rgb);
        
        const bandV = getBandV(sy, roiPx.y, roiPx.h);
        const bandH = getBandH(sx, roiPx.x, roiPx.w);
        bandAccumV[bandV].push(rgb);
        bandAccumH[bandH].push(rgb);
        
        const zoneKey = bandV + bandH.charAt(0).toUpperCase() + bandH.slice(1);
        if (zoneAccum[zoneKey]) zoneAccum[zoneKey].push(rgb);
      }
    }
  }
  
  const avgColor = meanColor(samples);
  const bandColors = {
    top: meanColor(bandAccumV.top),
    mid: meanColor(bandAccumV.mid),
    bottom: meanColor(bandAccumV.bottom),
  };
  const bandColorsH = {
    left: meanColor(bandAccumH.left),
    center: meanColor(bandAccumH.center),
    right: meanColor(bandAccumH.right),
  };
  const zoneColors = {
    topLeft: meanColor(zoneAccum.topLeft),
    topCenter: meanColor(zoneAccum.topCenter),
    topRight: meanColor(zoneAccum.topRight),
    midLeft: meanColor(zoneAccum.midLeft),
    midCenter: meanColor(zoneAccum.midCenter),
    midRight: meanColor(zoneAccum.midRight),
    bottomLeft: meanColor(zoneAccum.bottomLeft),
    bottomCenter: meanColor(zoneAccum.bottomCenter),
    bottomRight: meanColor(zoneAccum.bottomRight),
  };
  return { avgColor, bandColors, bandColorsH, zoneColors, samplesCount: samples.length };
}

// 獲取多邊形邊界
function getPolygonBounds(points) {
  let minX = Infinity, maxX = -Infinity;
  let minY = Infinity, maxY = -Infinity;
  
  points.forEach(pt => {
    minX = Math.min(minX, pt.x);
    maxX = Math.max(maxX, pt.x);
    minY = Math.min(minY, pt.y);
    maxY = Math.max(maxY, pt.y);
  });
  
  return {
    x: minX,
    y: minY,
    w: maxX - minX,
    h: maxY - minY
  };
}

// 判斷點是否在多邊形內（Ray casting algorithm）
function isPointInPolygon(x, y, points) {
  let inside = false;
  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const xi = points[i].x, yi = points[i].y;
    const xj = points[j].x, yj = points[j].y;
    
    const intersect = ((yi > y) !== (yj > y)) &&
      (x < (xj - xi) * (y - yi) / (yj - yi) + xi);
    if (intersect) inside = !inside;
  }
  return inside;
}

function samplePixel(x, y) {
  // 安全檢查 offscreen canvas 是否有效
  if (!offscreen || offscreen.width <= 0 || offscreen.height <= 0) {
    console.warn('samplePixel: offscreen canvas 無效');
    return { r: 0, g: 0, b: 0 };
  }
  
  const clampedX = clamp(Math.floor(x), 0, offscreen.width - 1);
  const clampedY = clamp(Math.floor(y), 0, offscreen.height - 1);
  
  try {
    const data = offCtx.getImageData(clampedX, clampedY, 1, 1).data;
    return { r: data[0], g: data[1], b: data[2] };
  } catch (err) {
    console.warn('samplePixel: 讀取像素失敗:', err);
    return { r: 0, g: 0, b: 0 };
  }
}

function getBandV(y, roiY, roiH) {
  const rel = (y - roiY) / roiH;
  if (rel < 1 / 3) return 'top';
  if (rel < 2 / 3) return 'mid';
  return 'bottom';
}

function getBandH(x, roiX, roiW) {
  const rel = (x - roiX) / roiW;
  if (rel < 1 / 3) return 'left';
  if (rel < 2 / 3) return 'center';
  return 'right';
}

function meanColor(list) {
  if (!list.length) return { r: 0, g: 0, b: 0, hex: '#000000' };
  const sum = list.reduce((acc, c) => {
    acc.r += c.r; acc.g += c.g; acc.b += c.b; return acc;
  }, { r: 0, g: 0, b: 0 });
  const r = Math.round(sum.r / list.length);
  const g = Math.round(sum.g / list.length);
  const b = Math.round(sum.b / list.length);
  return { r, g, b, hex: rgbToHex(r, g, b) };
}

function rgbToHex(r, g, b) {
  return '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');
}

// ===== LCh 色條指標顏色計算 =====
// 根據 L、C、h 數值計算對應色條位置的顏色

function getLBarColor(L) {
  // L: 0-100，色條從黑到白
  const t = Math.min(100, Math.max(0, L)) / 100;
  const gray = Math.round(t * 255);
  return rgbToHex(gray, gray, gray);
}

function getCBarColor(C) {
  // C: 0-100+，色條從灰(#9ca3af)到橙(#f59e0b)到紅(#ef4444)
  const t = Math.min(100, Math.max(0, C)) / 100;
  let r, g, b;
  if (t < 0.5) {
    // 灰到橙
    const t2 = t * 2;
    r = Math.round(156 + (245 - 156) * t2); // #9c -> #f5
    g = Math.round(163 + (158 - 163) * t2); // #a3 -> #9e
    b = Math.round(175 + (11 - 175) * t2);  // #af -> #0b
  } else {
    // 橙到紅
    const t2 = (t - 0.5) * 2;
    r = Math.round(245 + (239 - 245) * t2); // #f5 -> #ef
    g = Math.round(158 + (68 - 158) * t2);  // #9e -> #44
    b = Math.round(11 + (68 - 11) * t2);    // #0b -> #44
  }
  return rgbToHex(r, g, b);
}

function getHBarColor(h) {
  // h: 0-360，彩虹色條
  // 色條顏色: 紅(0) -> 橙(60) -> 黃(120) -> 綠(180) -> 青(240) -> 藍(300) -> 紅(360)
  const hue = ((h % 360) + 360) % 360;
  const colors = [
    { pos: 0, r: 239, g: 68, b: 68 },     // #ef4444 紅
    { pos: 60, r: 245, g: 158, b: 11 },   // #f59e0b 橙
    { pos: 120, r: 234, g: 179, b: 8 },   // #eab308 黃
    { pos: 180, r: 34, g: 197, b: 94 },   // #22c55e 綠
    { pos: 240, r: 6, g: 182, b: 212 },   // #06b6d4 青
    { pos: 300, r: 59, g: 130, b: 246 },  // #3b82f6 藍
    { pos: 360, r: 239, g: 68, b: 68 }    // #ef4444 紅
  ];
  
  for (let i = 0; i < colors.length - 1; i++) {
    if (hue >= colors[i].pos && hue <= colors[i + 1].pos) {
      const t = (hue - colors[i].pos) / (colors[i + 1].pos - colors[i].pos);
      const r = Math.round(colors[i].r + (colors[i + 1].r - colors[i].r) * t);
      const g = Math.round(colors[i].g + (colors[i + 1].g - colors[i].g) * t);
      const b = Math.round(colors[i].b + (colors[i + 1].b - colors[i].b) * t);
      return rgbToHex(r, g, b);
    }
  }
  return '#ef4444';
}

// ===== LCh 色彩模型轉換 =====
// RGB → XYZ → Lab → LCh

function rgbToXyz(r, g, b) {
  // sRGB to linear RGB
  let rL = r / 255;
  let gL = g / 255;
  let bL = b / 255;
  
  rL = rL > 0.04045 ? Math.pow((rL + 0.055) / 1.055, 2.4) : rL / 12.92;
  gL = gL > 0.04045 ? Math.pow((gL + 0.055) / 1.055, 2.4) : gL / 12.92;
  bL = bL > 0.04045 ? Math.pow((bL + 0.055) / 1.055, 2.4) : bL / 12.92;
  
  rL *= 100;
  gL *= 100;
  bL *= 100;
  
  // RGB to XYZ (D65 illuminant)
  const x = rL * 0.4124564 + gL * 0.3575761 + bL * 0.1804375;
  const y = rL * 0.2126729 + gL * 0.7151522 + bL * 0.0721750;
  const z = rL * 0.0193339 + gL * 0.1191920 + bL * 0.9503041;
  
  return { x, y, z };
}

function xyzToLab(x, y, z) {
  // D65 reference white
  const refX = 95.047;
  const refY = 100.000;
  const refZ = 108.883;
  
  let xR = x / refX;
  let yR = y / refY;
  let zR = z / refZ;
  
  const epsilon = 0.008856;
  const kappa = 903.3;
  
  xR = xR > epsilon ? Math.pow(xR, 1/3) : (kappa * xR + 16) / 116;
  yR = yR > epsilon ? Math.pow(yR, 1/3) : (kappa * yR + 16) / 116;
  zR = zR > epsilon ? Math.pow(zR, 1/3) : (kappa * zR + 16) / 116;
  
  const L = 116 * yR - 16;
  const a = 500 * (xR - yR);
  const b = 200 * (yR - zR);
  
  return { L, a, b };
}

function labToLch(L, a, b) {
  const C = Math.sqrt(a * a + b * b);
  let h = Math.atan2(b, a) * (180 / Math.PI);
  if (h < 0) h += 360;
  
  return { L, C, h };
}

function rgbToLch(r, g, b) {
  const xyz = rgbToXyz(r, g, b);
  const lab = xyzToLab(xyz.x, xyz.y, xyz.z);
  const lch = labToLch(lab.L, lab.a, lab.b);
  return {
    L: Math.round(lch.L * 100) / 100,
    C: Math.round(lch.C * 100) / 100,
    h: Math.round(lch.h * 100) / 100
  };
}

// 計算兩個顏色之間的 Delta E (CIE76)
function deltaE(lab1, lab2) {
  const dL = lab1.L - lab2.L;
  const da = lab1.a - lab2.a;
  const db = lab1.b - lab2.b;
  return Math.sqrt(dL * dL + da * da + db * db);
}

// ===== 牙齒色卡資料庫 (VITA Classical) =====
const VITA_SHADE_GUIDE = [
  // A系列 (紅棕色調)
  { code: 'A1', name: 'A1 (最淺)', hex: '#F5EDE0', rgb: { r: 245, g: 237, b: 224 }, description: '淺色、自然白' },
  { code: 'A2', name: 'A2', hex: '#F0E4CD', rgb: { r: 240, g: 228, b: 205 }, description: '年輕人常見' },
  { code: 'A3', name: 'A3', hex: '#E8D9BC', rgb: { r: 232, g: 217, b: 188 }, description: '亞洲人常見' },
  { code: 'A3.5', name: 'A3.5', hex: '#E0CEA8', rgb: { r: 224, g: 206, b: 168 }, description: '中等偏深' },
  { code: 'A4', name: 'A4', hex: '#D4BE8C', rgb: { r: 212, g: 190, b: 140 }, description: '較深色調' },
  
  // B系列 (黃色調)
  { code: 'B1', name: 'B1', hex: '#F7F0E0', rgb: { r: 247, g: 240, b: 224 }, description: '淺黃白色' },
  { code: 'B2', name: 'B2', hex: '#F2E8D0', rgb: { r: 242, g: 232, b: 208 }, description: '淺黃色' },
  { code: 'B3', name: 'B3', hex: '#E9DCBA', rgb: { r: 233, g: 220, b: 186 }, description: '中等黃色' },
  { code: 'B4', name: 'B4', hex: '#DCC99C', rgb: { r: 220, g: 201, b: 156 }, description: '深黃色' },
  
  // C系列 (灰色調)
  { code: 'C1', name: 'C1', hex: '#E8E4DC', rgb: { r: 232, g: 228, b: 220 }, description: '淺灰白色' },
  { code: 'C2', name: 'C2', hex: '#E0DAD0', rgb: { r: 224, g: 218, b: 208 }, description: '淺灰色' },
  { code: 'C3', name: 'C3', hex: '#D5CEC0', rgb: { r: 213, g: 206, b: 192 }, description: '中灰色' },
  { code: 'C4', name: 'C4', hex: '#C5BAA4', rgb: { r: 197, g: 186, b: 164 }, description: '深灰色' },
  
  // D系列 (紅灰色調)
  { code: 'D2', name: 'D2', hex: '#EEE6D8', rgb: { r: 238, g: 230, b: 216 }, description: '淺紅灰色' },
  { code: 'D3', name: 'D3', hex: '#E4D8C4', rgb: { r: 228, g: 216, b: 196 }, description: '中紅灰色' },
  { code: 'D4', name: 'D4', hex: '#D6C4A4', rgb: { r: 214, g: 196, b: 164 }, description: '深紅灰色' },
];

// 為每個色卡計算 Lab 值
VITA_SHADE_GUIDE.forEach(shade => {
  const xyz = rgbToXyz(shade.rgb.r, shade.rgb.g, shade.rgb.b);
  shade.lab = xyzToLab(xyz.x, xyz.y, xyz.z);
  const lch = labToLch(shade.lab.L, shade.lab.a, shade.lab.b);
  shade.lch = {
    L: Math.round(lch.L * 100) / 100,
    C: Math.round(lch.C * 100) / 100,
    h: Math.round(lch.h * 100) / 100
  };
});

// 比對顏色找出最接近的色卡
function findClosestShade(r, g, b, topN = 3) {
  const xyz = rgbToXyz(r, g, b);
  const lab = xyzToLab(xyz.x, xyz.y, xyz.z);
  
  const results = VITA_SHADE_GUIDE.map(shade => {
    const dE = deltaE(lab, shade.lab);
    return {
      ...shade,
      deltaE: Math.round(dE * 100) / 100,
      matchPercent: Math.max(0, Math.round((100 - dE * 2) * 10) / 10)
    };
  });
  
  // 按 Delta E 排序
  results.sort((a, b) => a.deltaE - b.deltaE);
  
  return results.slice(0, topN);
}

// 取得 LCh 評估說明
function getLchEvaluation(lch) {
  const evaluation = {
    L: { value: lch.L, label: '', status: '' },
    C: { value: lch.C, label: '', status: '' },
    h: { value: lch.h, label: '', status: '' }
  };
  
  // L 明度評估 (牙齒通常 60-80)
  if (lch.L >= 80) {
    evaluation.L.label = '非常亮白';
    evaluation.L.status = 'bright';
  } else if (lch.L >= 70) {
    evaluation.L.label = '明亮';
    evaluation.L.status = 'normal';
  } else if (lch.L >= 60) {
    evaluation.L.label = '正常';
    evaluation.L.status = 'normal';
  } else if (lch.L >= 50) {
    evaluation.L.label = '偏暗';
    evaluation.L.status = 'dim';
  } else {
    evaluation.L.label = '較暗';
    evaluation.L.status = 'dark';
  }
  
  // C 彩度評估 (牙齒通常 10-40)
  if (lch.C >= 40) {
    evaluation.C.label = '高飽和';
    evaluation.C.status = 'high';
  } else if (lch.C >= 25) {
    evaluation.C.label = '中等飽和';
    evaluation.C.status = 'normal';
  } else if (lch.C >= 10) {
    evaluation.C.label = '低飽和';
    evaluation.C.status = 'low';
  } else {
    evaluation.C.label = '接近灰階';
    evaluation.C.status = 'gray';
  }
  
  // h 色相評估
  if (lch.h >= 0 && lch.h < 30) {
    evaluation.h.label = '紅色調';
    evaluation.h.status = 'red';
  } else if (lch.h >= 30 && lch.h < 60) {
    evaluation.h.label = '橙色調';
    evaluation.h.status = 'orange';
  } else if (lch.h >= 60 && lch.h < 90) {
    evaluation.h.label = '黃色調';
    evaluation.h.status = 'yellow';
  } else if (lch.h >= 90 && lch.h < 150) {
    evaluation.h.label = '黃綠調';
    evaluation.h.status = 'yellow-green';
  } else if (lch.h >= 150 && lch.h < 210) {
    evaluation.h.label = '綠色調';
    evaluation.h.status = 'green';
  } else if (lch.h >= 210 && lch.h < 270) {
    evaluation.h.label = '藍色調';
    evaluation.h.status = 'blue';
  } else if (lch.h >= 270 && lch.h < 330) {
    evaluation.h.label = '紫色調';
    evaluation.h.status = 'purple';
  } else {
    evaluation.h.label = '紅色調';
    evaluation.h.status = 'red';
  }
  
  return evaluation;
}

function refreshButtons() {
  const img = getCurrentImage();
  const records = getCurrentRecords();
  saveBtn.disabled = state.isCropping || !state.currentTooth || !state.currentRoi || !img;
  deleteBtn.disabled = !state.currentTooth || !records[state.currentTooth];
  renderToothButtons();
}

function renderToothButtons() {
  const currentRecords = getCurrentRecords();
  const buttons = document.querySelectorAll('.tooth-btn');
  
  // 收集所有圖片中的牙位記錄
  const allRecords = {};
  state.images.forEach(img => {
    if (img.records) {
      Object.entries(img.records).forEach(([toothId, rec]) => {
        if (!allRecords[toothId]) {
          allRecords[toothId] = { record: rec, imageId: img.id, imageName: img.name };
        }
      });
    }
  });
  
  buttons.forEach(btn => {
    const id = btn.dataset.tooth;
    const currentRecord = currentRecords[id]; // 當前圖片的記錄
    const anyRecord = allRecords[id]; // 任何圖片的記錄
    const isCurrentImage = anyRecord && anyRecord.imageId === state.currentImageId;
    
    btn.classList.toggle('active', state.currentTooth && Number(id) === Number(state.currentTooth));
    btn.classList.remove('has-data', 'has-data-other', 'no-data');
    
    const lchChips = btn.querySelector('.lch-chips');
    const lChip = btn.querySelector('.l-chip');
    const cChip = btn.querySelector('.c-chip');
    const hChip = btn.querySelector('.h-chip');
    
    if (currentRecord) {
      // 當前圖片有記錄 - 綠色
      btn.classList.add('has-data');
      const chip = btn.querySelector('.color-chip');
      if (chip) chip.style.background = currentRecord.result.avgColor.hex;
      const avgColor = currentRecord.result.avgColor;
      const lch = rgbToLch(avgColor.r, avgColor.g, avgColor.b);
      const lchEval = getLchEvaluation(lch);
      
      // 更新 LCh 色彩方塊 - 使用與色條指標相同的顏色，並顯示數值
      if (lchChips) lchChips.classList.add('visible');
      if (lChip) {
        lChip.className = 'lch-chip l-chip';
        lChip.style.background = getLBarColor(lch.L);
        lChip.textContent = Math.round(lch.L);
        lChip.title = `L 明度: ${lch.L.toFixed(1)} (${lchEval.L.label})`;
      }
      if (cChip) {
        cChip.className = 'lch-chip c-chip';
        cChip.style.background = getCBarColor(lch.C);
        cChip.textContent = Math.round(lch.C);
        cChip.title = `C 彩度: ${lch.C.toFixed(1)} (${lchEval.C.label})`;
      }
      if (hChip) {
        hChip.className = 'lch-chip h-chip';
        hChip.style.background = getHBarColor(lch.h);
        hChip.textContent = Math.round(lch.h);
        hChip.title = `h 色相: ${lch.h.toFixed(1)}° (${lchEval.h.label})`;
      }
      
      btn.title = `${id} (此圖) avg ${avgColor.hex}\nL:${lch.L.toFixed(1)} C:${lch.C.toFixed(1)} h:${lch.h.toFixed(1)}°`;
    } else if (anyRecord) {
      // 其他圖片有記錄 - 藍色
      btn.classList.add('has-data-other');
      const chip = btn.querySelector('.color-chip');
      if (chip) chip.style.background = anyRecord.record.result.avgColor.hex;
      const avgColor = anyRecord.record.result.avgColor;
      const lch = rgbToLch(avgColor.r, avgColor.g, avgColor.b);
      const lchEval = getLchEvaluation(lch);
      
      // 更新 LCh 色彩方塊 - 使用與色條指標相同的顏色，並顯示數值
      if (lchChips) lchChips.classList.add('visible');
      if (lChip) {
        lChip.className = 'lch-chip l-chip';
        lChip.style.background = getLBarColor(lch.L);
        lChip.textContent = Math.round(lch.L);
        lChip.title = `L 明度: ${lch.L.toFixed(1)} (${lchEval.L.label})`;
      }
      if (cChip) {
        cChip.className = 'lch-chip c-chip';
        cChip.style.background = getCBarColor(lch.C);
        cChip.textContent = Math.round(lch.C);
        cChip.title = `C 彩度: ${lch.C.toFixed(1)} (${lchEval.C.label})`;
      }
      if (hChip) {
        hChip.className = 'lch-chip h-chip';
        hChip.style.background = getHBarColor(lch.h);
        hChip.textContent = Math.round(lch.h);
        hChip.title = `h 色相: ${lch.h.toFixed(1)}° (${lchEval.h.label})`;
      }
      
      btn.title = `${id} (在 ${anyRecord.imageName}) avg ${avgColor.hex}\nL:${lch.L.toFixed(1)} C:${lch.C.toFixed(1)} h:${lch.h.toFixed(1)}°`;
    } else {
      // 沒有記錄
      btn.classList.add('no-data');
      const chip = btn.querySelector('.color-chip');
      if (chip) chip.style.background = '#e5e7eb';
      
      // 隱藏 LCh 色彩方塊
      if (lchChips) lchChips.classList.remove('visible');
      if (lChip) {
        lChip.className = 'lch-chip l-chip';
        lChip.style.background = '';
        lChip.textContent = 'L';
      }
      if (cChip) {
        cChip.className = 'lch-chip c-chip';
        cChip.style.background = '';
        cChip.textContent = 'C';
      }
      if (hChip) {
        hChip.className = 'lch-chip h-chip';
        hChip.style.background = '';
        hChip.textContent = 'h';
      }
      
      btn.title = `牙位 ${id}`;
    }
  });
}

function renderDetail() {
  const records = getCurrentRecords();
  if (!state.currentTooth) {
    detailBody.innerHTML = '<span class="detail-empty">尚未選擇</span>';
    deleteBtn.disabled = true;
    renderColorPreview(null);
    return;
  }
  const rec = records[state.currentTooth];
  if (!rec) {
    detailBody.innerHTML = `<span class="detail-empty">#${state.currentTooth} 未建檔</span>`;
    deleteBtn.disabled = true;
    renderColorPreview(null);
    return;
  }
  deleteBtn.disabled = false;
  const { roiImagePx, gridN, result, createdAt } = rec;
  const time = new Date(createdAt).toLocaleTimeString('zh-TW', {hour:'2-digit', minute:'2-digit'});
  const { bandColorsH, avgColor } = result;
  const hasH = bandColorsH && bandColorsH.left;
  
  // 計算 LCh 數值
  const lch = rgbToLch(avgColor.r, avgColor.g, avgColor.b);
  const lchEval = getLchEvaluation(lch);
  
  // 找出最接近的色卡
  const closestShades = findClosestShade(avgColor.r, avgColor.g, avgColor.b, 3);
  const bestMatch = closestShades[0];
  
  // ROI 尺寸顯示（處理多邊形情況）
  let roiSize = '';
  if (roiImagePx.type === 'polygon') {
    const bounds = getPolygonBounds(roiImagePx.points);
    roiSize = `${Math.round(bounds.w)}×${Math.round(bounds.h)}px (多邊形)`;
  } else {
    roiSize = `${Math.round(roiImagePx.w)}×${Math.round(roiImagePx.h)}px`;
  }
  
  detailBody.innerHTML = `
    <div class="detail-row"><strong>#${rec.toothId}</strong><span>${time}</span></div>
    <div class="detail-row"><strong>ROI</strong><span>${roiSize}</span></div>
    <div class="detail-row"><strong>取樣</strong><span>${gridN}×${gridN} (${result.samplesCount}點)</span></div>
    <div class="detail-row"><strong>平均</strong><span class="badge"><span class="color-dot" style="background:${result.avgColor.hex}"></span>${result.avgColor.hex}</span><span class="detail-lch">L:${lch.L.toFixed(1)} C:${lch.C.toFixed(1)} h:${lch.h.toFixed(1)}°</span></div>
    
    <div class="detail-section">🎨 LCh 色彩分析</div>
    <div class="detail-row lch-row">
      <strong>L 明度</strong>
      <span class="lch-value">
        <span class="lch-num">${lch.L.toFixed(1)}</span>
        <span class="lch-label ${lchEval.L.status}">${lchEval.L.label}</span>
      </span>
    </div>
    <div class="lch-bar-wrap">
      <div class="lch-bar l-bar">
        <div class="lch-indicator" style="left: ${Math.min(100, lch.L)}%"></div>
      </div>
      <span class="lch-range">0 (黑) → 100 (白)</span>
    </div>
    <div class="detail-row lch-row">
      <strong>C 彩度</strong>
      <span class="lch-value">
        <span class="lch-num">${lch.C.toFixed(1)}</span>
        <span class="lch-label ${lchEval.C.status}">${lchEval.C.label}</span>
      </span>
    </div>
    <div class="lch-bar-wrap">
      <div class="lch-bar c-bar">
        <div class="lch-indicator" style="left: ${Math.min(100, lch.C)}%"></div>
      </div>
      <span class="lch-range">0 (灰) → 100+ (鮮豔)</span>
    </div>
    <div class="detail-row lch-row">
      <strong>h 色相</strong>
      <span class="lch-value">
        <span class="lch-num">${lch.h.toFixed(1)}°</span>
        <span class="lch-label ${lchEval.h.status}">${lchEval.h.label}</span>
      </span>
    </div>
    <div class="lch-bar-wrap">
      <div class="lch-bar h-bar">
        <div class="lch-indicator" style="left: ${(lch.h / 360) * 100}%"></div>
      </div>
      <span class="lch-range">0° 紅 → 90° 黃 → 180° 綠 → 270° 藍</span>
    </div>
    
    <div class="detail-section">🦷 VITA 色卡比對</div>
    <div class="shade-match-best">
      <div class="shade-color" style="background: ${bestMatch.hex}"></div>
      <div class="shade-info">
        <span class="shade-code">${bestMatch.code}</span>
        <span class="shade-desc">${bestMatch.description}</span>
        <span class="shade-delta">ΔE: ${bestMatch.deltaE} | 匹配: ${bestMatch.matchPercent}%</span>
      </div>
    </div>
    <div class="shade-alternatives">
      ${closestShades.slice(1).map(s => `
        <div class="shade-alt">
          <div class="shade-color-sm" style="background: ${s.hex}"></div>
          <span class="shade-code-sm">${s.code}</span>
          <span class="shade-delta-sm">ΔE: ${s.deltaE}</span>
        </div>
      `).join('')}
    </div>
    
    <div class="detail-section">上中下</div>
    <div class="detail-row"><strong>Top</strong><span class="badge"><span class="color-dot" style="background:${result.bandColors.top.hex}"></span>${result.bandColors.top.hex}</span><span class="detail-lch">${(() => { const l = rgbToLch(result.bandColors.top.r, result.bandColors.top.g, result.bandColors.top.b); return `L:${l.L.toFixed(1)} C:${l.C.toFixed(1)} h:${l.h.toFixed(1)}°`; })()}</span></div>
    <div class="detail-row"><strong>Mid</strong><span class="badge"><span class="color-dot" style="background:${result.bandColors.mid.hex}"></span>${result.bandColors.mid.hex}</span><span class="detail-lch">${(() => { const l = rgbToLch(result.bandColors.mid.r, result.bandColors.mid.g, result.bandColors.mid.b); return `L:${l.L.toFixed(1)} C:${l.C.toFixed(1)} h:${l.h.toFixed(1)}°`; })()}</span></div>
    <div class="detail-row"><strong>Bot</strong><span class="badge"><span class="color-dot" style="background:${result.bandColors.bottom.hex}"></span>${result.bandColors.bottom.hex}</span><span class="detail-lch">${(() => { const l = rgbToLch(result.bandColors.bottom.r, result.bandColors.bottom.g, result.bandColors.bottom.b); return `L:${l.L.toFixed(1)} C:${l.C.toFixed(1)} h:${l.h.toFixed(1)}°`; })()}</span></div>
    ${hasH ? `
    <div class="detail-section">左中右</div>
    <div class="detail-row"><strong>Left</strong><span class="badge"><span class="color-dot" style="background:${bandColorsH.left.hex}"></span>${bandColorsH.left.hex}</span><span class="detail-lch">${(() => { const l = rgbToLch(bandColorsH.left.r, bandColorsH.left.g, bandColorsH.left.b); return `L:${l.L.toFixed(1)} C:${l.C.toFixed(1)} h:${l.h.toFixed(1)}°`; })()}</span></div>
    <div class="detail-row"><strong>Ctr</strong><span class="badge"><span class="color-dot" style="background:${bandColorsH.center.hex}"></span>${bandColorsH.center.hex}</span><span class="detail-lch">${(() => { const l = rgbToLch(bandColorsH.center.r, bandColorsH.center.g, bandColorsH.center.b); return `L:${l.L.toFixed(1)} C:${l.C.toFixed(1)} h:${l.h.toFixed(1)}°`; })()}</span></div>
    <div class="detail-row"><strong>Right</strong><span class="badge"><span class="color-dot" style="background:${bandColorsH.right.hex}"></span>${bandColorsH.right.hex}</span><span class="detail-lch">${(() => { const l = rgbToLch(bandColorsH.right.r, bandColorsH.right.g, bandColorsH.right.b); return `L:${l.L.toFixed(1)} C:${l.C.toFixed(1)} h:${l.h.toFixed(1)}°`; })()}</span></div>
    ` : ''}
  `;
  renderColorPreview(rec);
}

// 全域 tooltip 元素
let toothTooltip = null;
function ensureTooltip() {
  if (!toothTooltip) {
    toothTooltip = document.createElement('div');
    toothTooltip.className = 'tooth-tooltip';
    toothTooltip.innerHTML = '<div class="tt-color"></div><span class="tt-hex"></span><span class="tt-lch"></span>';
    document.body.appendChild(toothTooltip);
  }
  return toothTooltip;
}

function renderColorPreview(rec) {
  if (!colorPreview) return;
  if (!rec) {
    colorPreview.innerHTML = '<span class="preview-empty">選擇已建檔牙位</span>';
    return;
  }
  const { avgColor, bandColors, bandColorsH, zoneColors } = rec.result;
  const { top, mid, bottom } = bandColors;
  const { left, center, right } = bandColorsH || { left: mid, center: mid, right: mid };
  const zones = zoneColors || {};

  // 9宮格顏色
  const tl = zones.topLeft || adjustColorObj(top, -5);
  const tc = zones.topCenter || top;
  const tr = zones.topRight || adjustColorObj(top, -5);
  const ml = zones.midLeft || adjustColorObj(mid, -3);
  const mc = zones.midCenter || mid;
  const mr = zones.midRight || adjustColorObj(mid, -3);
  const bl = zones.bottomLeft || adjustColorObj(bottom, -5);
  const bc = zones.bottomCenter || bottom;
  const br = zones.bottomRight || adjustColorObj(bottom, -5);

  // Build tooth shape with Canvas-based 9-zone smooth gradient
  const tooth = document.createElement('div');
  tooth.className = 'tooth-shape';

  const cvs = document.createElement('canvas');
  const W = 110, H = 170; // 高解析度
  cvs.width = W;
  cvs.height = H;
  const tctx = cvs.getContext('2d');

  // 建立9宮格顏色陣列 (3x3)
  const grid = [
    [tl, tc, tr],
    [ml, mc, mr],
    [bl, bc, br]
  ];

  // 繪製平滑漸層
  for (let py = 0; py < H; py++) {
    for (let px = 0; px < W; px++) {
      // 正規化座標 [0,1]
      const nx = px / (W - 1);
      const ny = py / (H - 1);
      // 雙線性插值
      const color = bilinearInterpolate(grid, nx, ny);
      tctx.fillStyle = color;
      tctx.fillRect(px, py, 1, 1);
    }
  }

  // 添加真實牙齒質感
  addToothTexture(tctx, W, H);

  tooth.appendChild(cvs);

  // 高光和陰影覆蓋層
  const overlay = document.createElement('div');
  overlay.className = 'tooth-overlay';
  tooth.appendChild(overlay);

  // 滑鼠移動顯示色碼
  tooth.addEventListener('mousemove', (e) => {
    const rect = cvs.getBoundingClientRect();
    const scaleX = W / rect.width;
    const scaleY = H / rect.height;
    const cx = Math.floor((e.clientX - rect.left) * scaleX);
    const cy = Math.floor((e.clientY - rect.top) * scaleY);
    if (cx >= 0 && cx < W && cy >= 0 && cy < H) {
      const pixel = tctx.getImageData(cx, cy, 1, 1).data;
      const hex = rgbToHex(pixel[0], pixel[1], pixel[2]);
      const lch = rgbToLch(pixel[0], pixel[1], pixel[2]);
      const tooltip = ensureTooltip();
      tooltip.querySelector('.tt-color').style.background = hex;
      tooltip.querySelector('.tt-hex').textContent = hex.toUpperCase();
      tooltip.querySelector('.tt-lch').textContent = `L:${lch.L.toFixed(1)} C:${lch.C.toFixed(1)} h:${lch.h.toFixed(1)}°`;
      tooltip.classList.add('visible');
      tooltip.style.left = (e.clientX + 15) + 'px';
      tooltip.style.top = (e.clientY + 10) + 'px';
    }
  });

  tooth.addEventListener('mouseleave', () => {
    const tooltip = ensureTooltip();
    tooltip.classList.remove('visible');
  });

  // Color swatches - 9宮格色票
  // 計算各區域 LCh 值
  const tlLch = rgbToLch(tl.r, tl.g, tl.b);
  const tcLch = rgbToLch(tc.r, tc.g, tc.b);
  const trLch = rgbToLch(tr.r, tr.g, tr.b);
  const mlLch = rgbToLch(ml.r, ml.g, ml.b);
  const mcLch = rgbToLch(mc.r, mc.g, mc.b);
  const mrLch = rgbToLch(mr.r, mr.g, mr.b);
  const blLch = rgbToLch(bl.r, bl.g, bl.b);
  const bcLch = rgbToLch(bc.r, bc.g, bc.b);
  const brLch = rgbToLch(br.r, br.g, br.b);
  const avgLch = rgbToLch(avgColor.r, avgColor.g, avgColor.b);

  const swatches = document.createElement('div');
  swatches.className = 'preview-colors';
  swatches.innerHTML = `
    <div class="swatch-grid">
      <div class="color-swatch" style="background:${tl.hex}" title="左上 ${tl.hex}\nL:${tlLch.L.toFixed(1)} C:${tlLch.C.toFixed(1)} h:${tlLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${tc.hex}" title="中上 ${tc.hex}\nL:${tcLch.L.toFixed(1)} C:${tcLch.C.toFixed(1)} h:${tcLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${tr.hex}" title="右上 ${tr.hex}\nL:${trLch.L.toFixed(1)} C:${trLch.C.toFixed(1)} h:${trLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${ml.hex}" title="左中 ${ml.hex}\nL:${mlLch.L.toFixed(1)} C:${mlLch.C.toFixed(1)} h:${mlLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${mc.hex}" title="正中 ${mc.hex}\nL:${mcLch.L.toFixed(1)} C:${mcLch.C.toFixed(1)} h:${mcLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${mr.hex}" title="右中 ${mr.hex}\nL:${mrLch.L.toFixed(1)} C:${mrLch.C.toFixed(1)} h:${mrLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${bl.hex}" title="左下 ${bl.hex}\nL:${blLch.L.toFixed(1)} C:${blLch.C.toFixed(1)} h:${blLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${bc.hex}" title="中下 ${bc.hex}\nL:${bcLch.L.toFixed(1)} C:${bcLch.C.toFixed(1)} h:${bcLch.h.toFixed(1)}°"></div>
      <div class="color-swatch" style="background:${br.hex}" title="右下 ${br.hex}\nL:${brLch.L.toFixed(1)} C:${brLch.C.toFixed(1)} h:${brLch.h.toFixed(1)}°"></div>
    </div>
    <div class="swatch-avg">
      <div class="color-swatch avg" style="background:${avgColor.hex}" title="平均 ${avgColor.hex}\nL:${avgLch.L.toFixed(1)} C:${avgLch.C.toFixed(1)} h:${avgLch.h.toFixed(1)}°"></div>
      <span class="color-label">平均 ${avgColor.hex}</span>
      <span class="color-lch">L:${avgLch.L.toFixed(1)} C:${avgLch.C.toFixed(1)} h:${avgLch.h.toFixed(1)}°</span>
    </div>
  `;

  // Legend
  const legend = document.createElement('div');
  legend.className = 'preview-legend';
  legend.textContent = `#${rec.toothId} 滑鼠移至牙齒查詢色碼`;

  // Content wrapper for tooth and swatches
  const content = document.createElement('div');
  content.className = 'color-preview-content';
  content.appendChild(tooth);
  content.appendChild(swatches);

  colorPreview.innerHTML = '';
  colorPreview.appendChild(content);
  colorPreview.appendChild(legend);
}

// 調整顏色物件亮度
function adjustColorObj(colorObj, percent) {
  const hex = adjustBrightness(colorObj.hex, percent);
  const num = parseInt(hex.slice(1), 16);
  return {
    r: (num >> 16) & 0xFF,
    g: (num >> 8) & 0xFF,
    b: num & 0xFF,
    hex
  };
}

function adjustBrightness(hex, percent) {
  const num = parseInt(hex.slice(1), 16);
  const amt = Math.round(2.55 * percent);
  const R = Math.min(255, Math.max(0, (num >> 16) + amt));
  const G = Math.min(255, Math.max(0, ((num >> 8) & 0x00FF) + amt));
  const B = Math.min(255, Math.max(0, (num & 0x0000FF) + amt));
  return '#' + (0x1000000 + R * 0x10000 + G * 0x100 + B).toString(16).slice(1);
}

// 雙線性插值 - 產生平滑漸層
function bilinearInterpolate(grid, nx, ny) {
  // grid 是 3x3 顏色矩陣
  // nx, ny 在 [0,1] 範圍
  const gx = nx * 2; // 映射到 [0,2]
  const gy = ny * 2;
  const x0 = Math.min(Math.floor(gx), 1);
  const y0 = Math.min(Math.floor(gy), 1);
  const x1 = Math.min(x0 + 1, 2);
  const y1 = Math.min(y0 + 1, 2);
  const tx = gx - x0;
  const ty = gy - y0;

  const c00 = grid[y0][x0];
  const c10 = grid[y0][x1];
  const c01 = grid[y1][x0];
  const c11 = grid[y1][x1];

  // 線性插值
  const r = blerp(c00.r, c10.r, c01.r, c11.r, tx, ty);
  const g = blerp(c00.g, c10.g, c01.g, c11.g, tx, ty);
  const b = blerp(c00.b, c10.b, c01.b, c11.b, tx, ty);

  return rgbToHex(Math.round(r), Math.round(g), Math.round(b));
}

function blerp(c00, c10, c01, c11, tx, ty) {
  return lerp(lerp(c00, c10, tx), lerp(c01, c11, tx), ty);
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

// 添加牙齒質感
function addToothTexture(ctx, W, H) {
  // 高光 - 左上區域橢圓形
  const hlGrad = ctx.createRadialGradient(W * 0.3, H * 0.15, 0, W * 0.3, H * 0.15, W * 0.35);
  hlGrad.addColorStop(0, 'rgba(255,255,255,0.25)');
  hlGrad.addColorStop(0.5, 'rgba(255,255,255,0.1)');
  hlGrad.addColorStop(1, 'transparent');
  ctx.fillStyle = hlGrad;
  ctx.fillRect(0, 0, W, H);

  // 邊緣陰影 - 左右兩側
  const leftShadow = ctx.createLinearGradient(0, 0, W * 0.25, 0);
  leftShadow.addColorStop(0, 'rgba(0,0,0,0.12)');
  leftShadow.addColorStop(1, 'transparent');
  ctx.fillStyle = leftShadow;
  ctx.fillRect(0, 0, W * 0.3, H);

  const rightShadow = ctx.createLinearGradient(W, 0, W * 0.75, 0);
  rightShadow.addColorStop(0, 'rgba(0,0,0,0.12)');
  rightShadow.addColorStop(1, 'transparent');
  ctx.fillStyle = rightShadow;
  ctx.fillRect(W * 0.7, 0, W * 0.3, H);

  // 切端半透明效果
  const edgeGrad = ctx.createLinearGradient(0, H, 0, H * 0.85);
  edgeGrad.addColorStop(0, 'rgba(255,255,255,0.15)');
  edgeGrad.addColorStop(1, 'transparent');
  ctx.fillStyle = edgeGrad;
  ctx.fillRect(0, H * 0.85, W, H * 0.15);
}

function handleDelete() {
  if (!state.currentTooth) return;
  const records = getCurrentRecords();
  if (!records[state.currentTooth]) return;
  if (state.isCropping) {
    alert('請先完成裁切');
    return;
  }
  const ok = confirm(`確定刪除牙位 ${state.currentTooth} 的資料？`);
  if (!ok) return;
  deleteCurrentRecord(state.currentTooth);
  state.currentRoi = null;
  redrawCanvas();
  refreshButtons();
  renderDetail();
}

function handleClearAll() {
  const ok = confirm('清空當前圖片的所有牙位資料與 ROI？');
  if (!ok) return;
  // 清除當前圖片的 records
  const img = state.images.find(i => i.id === state.currentImageId);
  if (img) img.records = {};
  state.currentRoi = null;
  state.isCropping = false;
  state.cropRect = null;
  redrawCanvas();
  refreshButtons();
  renderDetail();
}

function openCropModal() {
  if (!cropModal) return;
  cropModal.classList.remove('hidden');
  updateCropNavigation();
  renderCropCanvas();
}

function closeCropModal() {
  if (!cropModal) return;
  cropModal.classList.add('hidden');
}

function renderCropCanvas() {
  const srcImg = state.pendingCropImage ? state.pendingCropImage.original : null;
  if (!srcImg || !cropCanvas || !cropCtx) return;
  
  // 安全檢查：確保圖片已載入
  const srcWidth = srcImg.naturalWidth || srcImg.width || 0;
  const srcHeight = srcImg.naturalHeight || srcImg.height || 0;
  
  if (srcWidth <= 0 || srcHeight <= 0) {
    console.warn('renderCropCanvas: 圖片尺寸無效');
    return;
  }
  
  const maxW = cropCanvas.parentElement ? cropCanvas.parentElement.clientWidth : 1100;
  const maxH = 700;
  const s = Math.min(maxW / srcWidth, maxH / srcHeight, 1);
  cropScale = s;
  const drawW = Math.round(srcWidth * s);
  const drawH = Math.round(srcHeight * s);
  cropCanvas.width = drawW;
  cropCanvas.height = drawH;
  cropCtx.clearRect(0, 0, drawW, drawH);
  cropCtx.drawImage(srcImg, 0, 0, drawW, drawH);
  if (cropHint) cropHint.style.display = state.cropRect ? 'none' : 'flex';
  if (state.cropRect) drawCropRectOnCropCanvas(state.cropRect);
  updateCropNavigation();
}

function onCropDown(e) {
  if (!state.pendingCropImage || !state.isCropping) return;
  const pos = getCropPos(e);
  cropDragging = true;
  cropStart = pos;
  state.cropRect = { x: pos.x, y: pos.y, w: 0, h: 0 };
}

function onCropMove(e) {
  if (!cropDragging || !state.pendingCropImage || !state.isCropping) return;
  const pos = getCropPos(e);
  const x = Math.min(pos.x, cropStart.x);
  const y = Math.min(pos.y, cropStart.y);
  const w = Math.abs(pos.x - cropStart.x);
  const h = Math.abs(pos.y - cropStart.y);
  state.cropRect = { x, y, w, h };
  renderCropCanvas();
}

function onCropUp() {
  if (!cropDragging) return;
  cropDragging = false;
  if (state.cropRect && (state.cropRect.w < 10 || state.cropRect.h < 10)) {
    state.cropRect = null;
    if (cropHint) cropHint.style.display = 'flex';
    renderCropCanvas();
    refreshButtons();
    return;
  }
  // Auto-apply crop once a valid selection is completed
  applyCrop();
}

function getCropPos(e) {
  const rect = cropCanvas.getBoundingClientRect();
  const scaleX = cropCanvas.width / rect.width;
  const scaleY = cropCanvas.height / rect.height;
  return {
    x: (e.clientX - rect.left) * scaleX,
    y: (e.clientY - rect.top) * scaleY,
  };
}

function drawCropRectOnCropCanvas(roi) {
  cropCtx.save();
  cropCtx.strokeStyle = 'rgba(234,179,8,0.9)';
  cropCtx.lineWidth = 2.5;
  cropCtx.setLineDash([8, 5]);
  cropCtx.strokeRect(roi.x, roi.y, roi.w, roi.h);
  cropCtx.restore();
}

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

// ===== 教學引導系統 =====
const tutorialState = {
  isActive: false,
  currentMode: 'patient', // 'patient' 或 'teeth'
  currentStep: 0,
  steps: [],
};

// 病患模式教學步驟
const patientTutorialSteps = [
  {
    target: '#addPatientBtn',
    icon: '👤',
    title: '新增病患',
    description: '點擊這裡可以新增一位新的病患資料。每位病患都會有獨立的資料紀錄。',
    position: 'bottom',
  },
  {
    target: '#patientSearch',
    icon: '🔍',
    title: '搜尋病患',
    description: '在這裡輸入姓名或病歷號，可以快速找到您想要的病患資料。',
    position: 'bottom',
  },
  {
    target: '.patient-list',
    icon: '📋',
    title: '病患列表',
    description: '所有病患資料都會顯示在這裡。點擊任一病患可以查看或編輯詳細資料。',
    position: 'right',
  },
  {
    target: '#exportDataBtn',
    icon: '💾',
    title: '匯出備份',
    description: '定期備份您的資料！點擊這裡可以將所有病患資料匯出成檔案保存。',
    position: 'bottom',
  },
  {
    target: '#importDataBtn',
    icon: '📥',
    title: '匯入資料',
    description: '如果您有之前匯出的備份檔案，可以從這裡匯入還原資料。',
    position: 'bottom',
  },
];

// 牙齒色彩模式教學步驟
const teethTutorialSteps = [
  {
    target: '#backToPatientBtn',
    icon: '⬅️',
    title: '返回病患列表',
    description: '點擊這裡可以返回病患管理頁面，切換或新增其他病患。',
    position: 'bottom',
  },
  {
    target: '.tooth-grid',
    icon: '🦷',
    title: '牙位選擇',
    description: '點擊想要分析的牙位按鈕。已建檔的牙位會顯示 L、C、h 色彩數值。',
    position: 'right',
  },
  {
    target: '#addImageBtn',
    icon: '📷',
    title: '新增圖片',
    description: '點擊這裡可以上傳牙齒照片。支援拍照或從相簿選擇圖片。',
    position: 'bottom',
  },
  {
    target: '.canvas-container',
    icon: '🎯',
    title: '圈選分析區域 (ROI)',
    description: '在圖片上拖曳滑鼠，圈選您想要分析色彩的牙齒區域。',
    position: 'left',
  },
  {
    target: '.detail-panel',
    icon: '🎨',
    title: 'LCh 色彩分析',
    description: '這裡會顯示選取區域的 L（明度）、C（彩度）、h（色相）分析結果。',
    position: 'left',
  },
];

// 取得教學元素
const tutorialOverlay = document.getElementById('tutorialOverlay');
const tutorialHighlight = document.getElementById('tutorialHighlight');
const tutorialTooltip = document.getElementById('tutorialTooltip');
const tutorialStepNum = document.getElementById('tutorialStepNum');
const tutorialTotalSteps = document.getElementById('tutorialTotalSteps');
const tutorialIcon = document.getElementById('tutorialIcon');
const tutorialTitle = document.getElementById('tutorialTitle');
const tutorialDesc = document.getElementById('tutorialDesc');
const tutorialPrevBtn = document.getElementById('tutorialPrevBtn');
const tutorialNextBtn = document.getElementById('tutorialNextBtn');
const tutorialSkipBtn = document.getElementById('tutorialSkipBtn');
const tutorialDots = document.getElementById('tutorialDots');
const restartTutorialBtn = document.getElementById('restartTutorialBtn');
const helpBtnPatient = document.getElementById('helpBtnPatient');
const helpBtnTeeth = document.getElementById('helpBtnTeeth');
const welcomeModal = document.getElementById('welcomeModal');
const startTutorialBtn = document.getElementById('startTutorialBtn');
const skipWelcomeBtn = document.getElementById('skipWelcomeBtn');

// 初始化教學系統
function initTutorial() {
  // 綁定事件
  if (tutorialPrevBtn) tutorialPrevBtn.addEventListener('click', prevTutorialStep);
  if (tutorialNextBtn) tutorialNextBtn.addEventListener('click', nextTutorialStep);
  if (tutorialSkipBtn) tutorialSkipBtn.addEventListener('click', endTutorial);
  if (restartTutorialBtn) restartTutorialBtn.addEventListener('click', restartTutorial);
  if (helpBtnPatient) helpBtnPatient.addEventListener('click', restartTutorial);
  if (helpBtnTeeth) helpBtnTeeth.addEventListener('click', restartTutorial);
  if (startTutorialBtn) startTutorialBtn.addEventListener('click', startTutorialFromWelcome);
  if (skipWelcomeBtn) skipWelcomeBtn.addEventListener('click', skipWelcome);
  
  // 檢查是否第一次使用
  checkFirstTimeUser();
}

// 檢查是否第一次使用
function checkFirstTimeUser() {
  const hasVisited = localStorage.getItem('dental_tutorial_completed');
  if (!hasVisited && welcomeModal) {
    // 第一次使用，顯示歡迎彈窗
    setTimeout(() => {
      welcomeModal.classList.remove('hidden');
    }, 500);
  }
}

// 從歡迎彈窗開始教學
function startTutorialFromWelcome() {
  if (welcomeModal) welcomeModal.classList.add('hidden');
  startTutorial('patient');
}

// 跳過歡迎彈窗
function skipWelcome() {
  if (welcomeModal) welcomeModal.classList.add('hidden');
  localStorage.setItem('dental_tutorial_completed', 'true');
}

// 開始教學
function startTutorial(mode) {
  tutorialState.isActive = true;
  tutorialState.currentMode = mode;
  tutorialState.currentStep = 0;
  tutorialState.steps = mode === 'patient' ? patientTutorialSteps : teethTutorialSteps;
  
  // 建立導航點
  createTutorialDots();
  
  // 顯示教學 overlay
  if (tutorialOverlay) tutorialOverlay.classList.remove('hidden');
  
  // 更新總步驟數
  if (tutorialTotalSteps) tutorialTotalSteps.textContent = tutorialState.steps.length;
  
  // 顯示第一步
  showTutorialStep(0);
}

// 建立導航點
function createTutorialDots() {
  if (!tutorialDots) return;
  tutorialDots.innerHTML = '';
  tutorialState.steps.forEach((_, index) => {
    const dot = document.createElement('div');
    dot.className = 'tutorial-dot';
    if (index === 0) dot.classList.add('active');
    dot.addEventListener('click', () => goToTutorialStep(index));
    tutorialDots.appendChild(dot);
  });
}

// 更新導航點狀態
function updateTutorialDots() {
  if (!tutorialDots) return;
  const dots = tutorialDots.querySelectorAll('.tutorial-dot');
  dots.forEach((dot, index) => {
    dot.classList.remove('active', 'done');
    if (index < tutorialState.currentStep) {
      dot.classList.add('done');
    } else if (index === tutorialState.currentStep) {
      dot.classList.add('active');
    }
  });
}

// 顯示指定步驟
function showTutorialStep(stepIndex) {
  const step = tutorialState.steps[stepIndex];
  if (!step) return;
  
  tutorialState.currentStep = stepIndex;
  
  // 更新步驟指示
  if (tutorialStepNum) tutorialStepNum.textContent = stepIndex + 1;
  
  // 更新內容
  if (tutorialIcon) tutorialIcon.textContent = step.icon;
  if (tutorialTitle) tutorialTitle.textContent = step.title;
  if (tutorialDesc) tutorialDesc.textContent = step.description;
  
  // 更新按鈕狀態
  if (tutorialPrevBtn) {
    tutorialPrevBtn.disabled = stepIndex === 0;
    tutorialPrevBtn.style.opacity = stepIndex === 0 ? '0.5' : '1';
  }
  if (tutorialNextBtn) {
    const isLast = stepIndex === tutorialState.steps.length - 1;
    tutorialNextBtn.textContent = isLast ? '完成 ✓' : '下一步 →';
  }
  
  // 更新導航點
  updateTutorialDots();
  
  // 定位高亮和提示框
  positionTutorialElements(step);
}

// 定位教學元素
function positionTutorialElements(step) {
  const targetEl = document.querySelector(step.target);
  
  if (!targetEl || !tutorialHighlight || !tutorialTooltip) {
    // 如果找不到目標元素，使用預設位置
    if (tutorialHighlight) {
      tutorialHighlight.style.display = 'none';
    }
    if (tutorialTooltip) {
      tutorialTooltip.style.top = '50%';
      tutorialTooltip.style.left = '50%';
      tutorialTooltip.style.transform = 'translate(-50%, -50%)';
    }
    return;
  }
  
  // 取得目標元素位置
  const rect = targetEl.getBoundingClientRect();
  const padding = 8;
  
  // 定位高亮區域
  tutorialHighlight.style.display = 'block';
  tutorialHighlight.style.top = `${rect.top - padding}px`;
  tutorialHighlight.style.left = `${rect.left - padding}px`;
  tutorialHighlight.style.width = `${rect.width + padding * 2}px`;
  tutorialHighlight.style.height = `${rect.height + padding * 2}px`;
  
  // 定位提示框
  const tooltipRect = tutorialTooltip.getBoundingClientRect();
  const gap = 16;
  
  let top, left;
  
  switch (step.position) {
    case 'bottom':
      top = rect.bottom + gap;
      left = rect.left + rect.width / 2 - tooltipRect.width / 2;
      break;
    case 'top':
      top = rect.top - tooltipRect.height - gap;
      left = rect.left + rect.width / 2 - tooltipRect.width / 2;
      break;
    case 'left':
      top = rect.top + rect.height / 2 - tooltipRect.height / 2;
      left = rect.left - tooltipRect.width - gap;
      break;
    case 'right':
      top = rect.top + rect.height / 2 - tooltipRect.height / 2;
      left = rect.right + gap;
      break;
    default:
      top = rect.bottom + gap;
      left = rect.left;
  }
  
  // 確保提示框不超出視窗
  const maxLeft = window.innerWidth - tooltipRect.width - 20;
  const maxTop = window.innerHeight - tooltipRect.height - 20;
  
  left = Math.max(20, Math.min(left, maxLeft));
  top = Math.max(20, Math.min(top, maxTop));
  
  tutorialTooltip.style.top = `${top}px`;
  tutorialTooltip.style.left = `${left}px`;
  tutorialTooltip.style.transform = 'none';
}

// 上一步
function prevTutorialStep() {
  if (tutorialState.currentStep > 0) {
    showTutorialStep(tutorialState.currentStep - 1);
  }
}

// 下一步
function nextTutorialStep() {
  if (tutorialState.currentStep < tutorialState.steps.length - 1) {
    showTutorialStep(tutorialState.currentStep + 1);
  } else {
    // 最後一步，結束教學
    endTutorial();
  }
}

// 跳到指定步驟
function goToTutorialStep(index) {
  if (index >= 0 && index < tutorialState.steps.length) {
    showTutorialStep(index);
  }
}

// 結束教學
function endTutorial() {
  tutorialState.isActive = false;
  if (tutorialOverlay) tutorialOverlay.classList.add('hidden');
  
  // 標記教學已完成
  localStorage.setItem('dental_tutorial_completed', 'true');
  
  // 顯示完成提示
  showToast('🎉 教學完成！如需再次觀看，請點擊右下角的 ❓ 按鈕');
}

// 重新開始教學
function restartTutorial() {
  // 判斷當前在哪個模式
  const isPatientMode = patientMode && !patientMode.classList.contains('hidden');
  const mode = isPatientMode ? 'patient' : 'teeth';
  startTutorial(mode);
}

// 顯示提示訊息
function showToast(message) {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%);
    background: #1e293b;
    color: #fff;
    padding: 12px 24px;
    border-radius: 10px;
    font-size: 14px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    z-index: 100001;
    animation: toastSlideUp 0.3s ease-out;
  `;
  toast.textContent = message;
  
  // 加入動畫樣式
  const style = document.createElement('style');
  style.textContent = `
    @keyframes toastSlideUp {
      from { opacity: 0; transform: translateX(-50%) translateY(20px); }
      to { opacity: 1; transform: translateX(-50%) translateY(0); }
    }
  `;
  document.head.appendChild(style);
  
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// 監聽模式切換，自動切換教學
function onModeChange(newMode) {
  if (tutorialState.isActive) {
    // 如果教學正在進行中，切換到對應模式的教學
    endTutorial();
  }
}

// 初始化教學系統
initTutorial();

init();
