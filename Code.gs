/**
 * Homsa System -> Google Sheets backend (secured PR roles)
 *
 * نشر Web App:
 * Execute as: Me
 * Who has access: Anyone with the link
 *
 * مهم: هذا الإصدار لا يعتمد على SECRET موجود داخل index.html.
 * تسجيل الدخول يتم من خلال login، وبعدها يتم إصدار Session Token موقّع من Apps Script.
 */
const SECRET = 'HMS-9f2Lp7QvXeR4tWyZ1cA6bN0mF3sJ8dK';
const SESSION_SECRET = 'HMS-SESSION-CHANGE-THIS-TO-A-LONG-RANDOM-SECRET-2026';
const SESSION_TTL_SECONDS = 60 * 60 * 12;

function doGet(e) {
  try {
    const p = e && e.parameter || {};
    if (p.action === 'login') {
      return json(handleLogin(String(p.username || ''), String(p.password || '')));
    }

    const session = verifySession(String(p.session || ''));
    if (!session) return json({ok:false, error:'Unauthorized'});

    if (p.action === 'me') return json({ok:true, user:publicSessionUser(session)});

    if (p.action === 'list' && p.table) {
      const table = safeSheetName(p.table);
      const rows = getCachedRows(table);
      return json({ok:true, rows:filterRowsForSession(rows, table, session)});
    }

    // action=bulk&tables=teams,employees,indoor_leads,...
    // بيرجع كل الجداول المطلوبة في نداء واحد بس، عشان نقلل عدد الطلبات لسيرفر Apps Script
    // (كل نداء منفصل بياخد وقت بدء تشغيل خاص بيه، فتجميعهم في نداء واحد بيسرّع الواجهة كتير).
    if (p.action === 'bulk' && p.tables) {
      const tables = String(p.tables).split(',')
        .map(function(t){ return safeSheetName(String(t).trim()); })
        .filter(Boolean);
      const out = {};
      tables.forEach(function(t){
        out[t] = filterRowsForSession(getCachedRows(t), t, session);
      });
      return json({ok:true, tables:out});
    }

    return json({ok:true, service:'homsa-google-sheets-sync', user:publicSessionUser(session)});
  } catch (err) {
    return json({ok:false, error:String(err)});
  }
}

function doPost(e) {
  try {
    const body = JSON.parse(e.postData && e.postData.contents || '{}');

    if (body.action === 'login') {
      return json(handleLogin(String(body.username || ''), String(body.password || '')));
    }

    const session = verifySession(String(body.session || ''));
    if (!session) return json({ok:false, error:'Unauthorized'});

    if (!body.table || !body.action) return json({ok:false, error:'Missing action/table'}, 400);

    const table = safeSheetName(body.table);
    if (!canMutateTable(session, table, body.payload || {})) {
      return json({ok:false, error:'Forbidden'}, 403);
    }

    const ss = SpreadsheetApp.getActive();
    const sheet = getOrCreateSheet(ss, table);

    if (body.action === 'delete') {
      deleteRowById(sheet, String(body.payload && body.payload.id || ''));
      invalidateCachedRows(table);
    } else if (body.action === 'upsert') {
      const payload = enforceOwnership(session, table, body.payload || {});
      upsertRow(sheet, payload);
      invalidateCachedRows(table);
    } else if (body.action === 'batchDelete') {
      // بيمسح مجموعة صفوف بنداء واحد بدل ما الواجهة تبعت نداء منفصل لكل صف (أسرع بكتير في عمليات الحذف المتتالية زي حذف رحلة بكل فنادقها وغرفها ونزلائها)
      const ids = (body.payload && body.payload.ids) || [];
      deleteRowsBatch(sheet, ids);
      invalidateCachedRows(table);
    } else if (body.action === 'batchUpsert') {
      // بيحفظ مجموعة صفوف بنداء واحد بدل نداء منفصل لكل صف
      const rows = (body.payload && body.payload.rows) || [];
      const cleanRows = rows.map(function(r){ return enforceOwnership(session, table, r || {}); });
      upsertRowsBatch(sheet, cleanRows);
      invalidateCachedRows(table);
    } else {
      return json({ok:false, error:'Unknown action'}, 400);
    }

    return json({ok:true});
  } catch (err) {
    return json({ok:false, error:String(err)}, 500);
  }
}

/* ---------------- Authentication ---------------- */

function handleLogin(username, password) {
  if (!username || !password) return {ok:false, error:'Missing username/password'};

  const ss = SpreadsheetApp.getActive();
  const sheet = ss.getSheetByName('users');

  // أول تشغيل: إنشاء المدير الافتراضي بنفس الـ hash الموجود في النسخة القديمة.
  if (!sheet || readRows(sheet).length === 0) {
    const sh = getOrCreateSheet(ss, 'users');
    const defaultUser = {
      id:'admin-001',
      name:'مدير النظام',
      username:'admin',
      passwordHash:'240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
      role:'admin',
      status:'active',
      team:'',
      employeeId:''
    };
    upsertRow(sh, defaultUser);
  }

  const users = readRows(getOrCreateSheet(ss, 'users'));
  const u = users.find(x => String(x.username || '').toLowerCase() === username.toLowerCase());
  if (!u || String(u.status || 'active') === 'inactive') return {ok:false, error:'اسم المستخدم أو كلمة المرور غير صحيحة'};

  if (sha256(password) !== String(u.passwordHash || '')) {
    return {ok:false, error:'اسم المستخدم أو كلمة المرور غير صحيحة'};
  }

  // لو team غير موجود في users، نحاول قراءته من employees.
  let team = String(u.team || '');
  let employeeId = String(u.employeeId || '');
  if (!team || !employeeId) {
    const empSheet = ss.getSheetByName('employees');
    if (empSheet) {
      const emp = readRows(empSheet).find(x =>
        (x.username && String(x.username).toLowerCase() === String(u.username).toLowerCase()) ||
        (employeeId && String(x.id) === employeeId)
      );
      if (emp) {
        team = team || String(emp.team || '');
        employeeId = employeeId || String(emp.id || '');
      }
    }
  }

  const payload = {
    uid:String(u.id),
    username:String(u.username),
    name:String(u.name || ''),
    role:String(u.role || ''),
    team:team,
    employeeId:employeeId,
    exp:Math.floor(Date.now()/1000) + SESSION_TTL_SECONDS
  };

  return {ok:true, user:payload, session:createSession(payload)};
}

function createSession(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = hmac(body, SESSION_SECRET);
  return body + '.' + sig;
}

function verifySession(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 2) return null;
    const body = parts[0], sig = parts[1];
    if (hmac(body, SESSION_SECRET) !== sig) return null;

    const payload = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(body)).getDataAsString());
    if (!payload.exp || Number(payload.exp) < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function publicSessionUser(s) {
  return {uid:s.uid, username:s.username, name:s.name, role:s.role, team:s.team || '', employeeId:s.employeeId || ''};
}

function sha256(text) {
  const bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    String(text),
    Utilities.Charset.UTF_8
  );
  return bytes.map(function(b) {
    const v = (b < 0 ? b + 256 : b).toString(16);
    return v.length === 1 ? '0' + v : v;
  }).join('');
}

function hmac(text, secret) {
  const raw = Utilities.computeHmacSha256Signature(
    String(text),
    String(secret),
    Utilities.Charset.UTF_8
  );
  return raw.map(function(b) {
    const v = (b < 0 ? b + 256 : b).toString(16);
    return v.length === 1 ? '0' + v : v;
  }).join('');
}

function base64url(text) {
  return Utilities.base64EncodeWebSafe(Utilities.newBlob(String(text)).getBytes()).replace(/=+$/,'');
}

/* ---------------- PR visibility ---------------- */

function isPRRole(role) {
  return ['pr_manager','pr_leader','pr_member'].indexOf(role) >= 0;
}

function employeeNamesForSession(session) {
  const ss = SpreadsheetApp.getActive();
  const sh = ss.getSheetByName('employees');
  if (!sh) return [];
  const emps = readRows(sh);
  if (session.role === 'pr_manager') return emps.map(x => String(x.name || '')).filter(Boolean);
  return emps.filter(x => x.team === session.team && x.status !== 'inactive')
    .map(x => String(x.name || '')).filter(Boolean);
}

function filterRowsForSession(rows, table, session) {
  if (!isPRRole(session.role)) return rows;

  if (session.role === 'pr_manager') return rows;

  const allowed = employeeNamesForSession(session);
  const myName = session.name || '';

  if (table === 'employees') {
    return rows.filter(r => allowed.indexOf(String(r.name || '')) >= 0);
  }

  if (table === 'teams') {
    return rows.filter(r => String(r.name || '') === String(session.team || ''));
  }

  if (['indoor_leads','indoor_data','subscriptions'].indexOf(table) >= 0) {
    return rows.filter(r => {
      const owner = String(r.responsiblePerson || '');
      return session.role === 'pr_leader' ? allowed.indexOf(owner) >= 0 : owner === myName;
    });
  }

  if (table === 'pr_member_data') {
    return rows.filter(r => {
      const owner = String(r.memberId || '');
      return session.role === 'pr_leader' ? allowed.indexOf(owner) >= 0 : owner === myName;
    });
  }

  return rows;
}

function canMutateTable(session, table, payload) {
  if (table === 'users') {
    return ['admin','hr'].indexOf(session.role) >= 0 || String(payload.id || '') === String(session.uid || '');
  }
  if (!isPRRole(session.role)) return true;

  if (session.role === 'pr_manager') {
    return ['teams','employees','indoor_leads','indoor_data','pr_member_data','subscriptions'].indexOf(table) >= 0;
  }

  if (session.role === 'pr_leader') {
    return ['indoor_leads','indoor_data','pr_member_data','subscriptions'].indexOf(table) >= 0;
  }

  return ['indoor_leads','indoor_data','pr_member_data','subscriptions'].indexOf(table) >= 0;
}

function enforceOwnership(session, table, payload) {
  const p = Object.assign({}, payload);
  const allowed = employeeNamesForSession(session);
  const myName = session.name || '';

  if (session.role === 'pr_member') {
    if (['indoor_leads','indoor_data','subscriptions'].indexOf(table) >= 0) {
      p.responsiblePerson = myName;
    }
    if (table === 'pr_member_data') p.memberId = myName;
  }

  if (session.role === 'pr_leader') {
    if (['indoor_leads','indoor_data','subscriptions'].indexOf(table) >= 0 &&
        p.responsiblePerson && allowed.indexOf(String(p.responsiblePerson)) < 0) {
      throw new Error('لا يمكن ربط البيانات بعضو خارج فريقك');
    }
    if (table === 'pr_member_data' &&
        p.memberId && allowed.indexOf(String(p.memberId)) < 0) {
      throw new Error('لا يمكن ربط الداتا بعضو خارج فريقك');
    }
  }

  return p;
}

/* ---------------- Performance: caching + batch ops ---------------- */
// الهدف: تقليل عدد النداءات للـ Spreadsheet ولسيرفر Apps Script نفسه، لأن
// كل نداء (حتى لو بسيط) بياخد وقت بدء تشغيل. الكاش هنا مشترك بين كل المستخدمين
// (ScriptCache) ومدته قصيرة عشان البيانات تفضل حديثة، وبيتم إلغاؤه فورًا بعد أي كتابة.

const SHEET_CACHE_TTL_SECONDS = 20;

function getCachedRows(sheetName) {
  const cache = CacheService.getScriptCache();
  const cacheKey = 'rows_' + sheetName;
  try {
    const cached = cache.get(cacheKey);
    if (cached) return JSON.parse(cached);
  } catch (_) { /* تجاهل أي خطأ كاش وارجع لقراءة الشيت مباشرة */ }

  const ss = SpreadsheetApp.getActive();
  const sheet = ss.getSheetByName(sheetName);
  const rows = sheet ? readRows(sheet) : [];

  try {
    const serialized = JSON.stringify(rows);
    // CacheService بيرفض القيم اللي أكبر من ~100KB، فبنتجاهل الكاش في الحالة دي بس من غير ما نكسر الطلب
    if (serialized.length < 95000) cache.put(cacheKey, serialized, SHEET_CACHE_TTL_SECONDS);
  } catch (_) { /* تجاهل */ }

  return rows;
}

function invalidateCachedRows(sheetName) {
  try { CacheService.getScriptCache().remove('rows_' + sheetName); } catch (_) {}
}

function upsertRowsBatch(sheet, rows) {
  if (!rows || !rows.length) return;

  const allKeys = [];
  const seenKey = {};
  rows.forEach(function(r) {
    Object.keys(r || {}).forEach(function(k) {
      if (!seenKey[k]) { seenKey[k] = true; allKeys.push(k); }
    });
  });

  const h = ensureHeaders(sheet, allKeys);
  const idCol = h.indexOf('id');
  const lastRow = sheet.getLastRow();

  // نبني index مرة واحدة بدل ما نقرا عمود الـid من جديد لكل صف (زي ما كان بيحصل قبل كده)
  const idIndex = {};
  if (idCol >= 0 && lastRow > 1) {
    const idValues = sheet.getRange(2, idCol + 1, lastRow - 1, 1).getValues().flat().map(String);
    idValues.forEach(function(id, i) { if (id) idIndex[id] = i + 2; });
  }

  let nextRow = lastRow + 1;
  rows.forEach(function(obj) {
    const id = String(obj.id || '');
    let row = (id && idIndex[id]) ? idIndex[id] : nextRow++;
    const values = h.map(function(k) {
      const v = obj[k];
      return v === null || v === undefined ? '' : (typeof v === 'object' ? JSON.stringify(v) : v);
    });
    sheet.getRange(row, 1, 1, h.length).setValues([values]);
    if (id) idIndex[id] = row;
  });
}

function deleteRowsBatch(sheet, ids) {
  if (!ids || !ids.length || sheet.getLastRow() < 2) return;
  const h = headers(sheet), idCol = h.indexOf('id') + 1;
  if (!idCol) return;

  const idSet = {};
  ids.forEach(function(id) { idSet[String(id)] = true; });

  const values = sheet.getRange(2, idCol, sheet.getLastRow() - 1, 1).getValues().flat().map(String);
  const rowsToDelete = [];
  values.forEach(function(v, i) { if (idSet[v]) rowsToDelete.push(i + 2); });

  // لازم نمسح من الصف الأخير للأول عشان الأرقام متتغيرش تحتنا ونحن بنمسح
  rowsToDelete.sort(function(a, b) { return b - a; });
  rowsToDelete.forEach(function(r) { sheet.deleteRow(r); });
}

/* ---------------- Sheets CRUD ---------------- */

function readRows(sheet) {
  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();
  if (lastRow < 2 || lastCol < 1) return [];
  const h = sheet.getRange(1,1,1,lastCol).getValues()[0].map(String);
  const values = sheet.getRange(2,1,lastRow-1,lastCol).getValues();
  return values.filter(row => row.some(v => v !== '')).map(row => {
    const obj = {};
    h.forEach((key,i) => {
      let v = row[i];
      if (v instanceof Date) v = v.toISOString();
      if (typeof v === 'string') {
        const t=v.trim();
        if ((t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))) {
          try { v=JSON.parse(t); } catch(_) {}
        }
      }
      obj[key]=v;
    });
    return obj;
  });
}

function safeSheetName(name) {
  return String(name).replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 90);
}

function getOrCreateSheet(ss, name) {
  let sh = ss.getSheetByName(name);
  if (!sh) {
    sh = ss.insertSheet(name);
    sh.getRange(1,1,1,1).setValue('id');
    sh.setFrozenRows(1);
  }
  return sh;
}

function headers(sheet) {
  const last = Math.max(sheet.getLastColumn(), 1);
  return sheet.getRange(1,1,1,last).getValues()[0].map(String).filter(Boolean);
}

function ensureHeaders(sheet, keys) {
  let h = headers(sheet);
  const missing = keys.filter(k => !h.includes(k));
  if (missing.length) {
    sheet.getRange(1,h.length+1,1,missing.length).setValues([missing]);
    h = h.concat(missing);
  }
  return h;
}

function upsertRow(sheet, obj) {
  const keys = Object.keys(obj || {});
  if (!keys.length) return;
  const h = ensureHeaders(sheet, keys);
  const idCol = h.indexOf('id') + 1;
  const id = String(obj.id || '');
  let row = sheet.getLastRow() + 1;
  if (id && idCol) {
    const values = sheet.getLastRow() > 1
      ? sheet.getRange(2,idCol,sheet.getLastRow()-1,1).getValues().flat().map(String)
      : [];
    const found = values.indexOf(id);
    if (found >= 0) row = found + 2;
  }
  const values = h.map(k => {
    const v=obj[k];
    return v === null || v === undefined ? '' : (typeof v==='object' ? JSON.stringify(v) : v);
  });
  sheet.getRange(row,1,1,h.length).setValues([values]);
}

function deleteRowById(sheet, id) {
  if (!id || sheet.getLastRow() < 2) return;
  const h = headers(sheet), idCol=h.indexOf('id')+1;
  if (!idCol) return;
  const values=sheet.getRange(2,idCol,sheet.getLastRow()-1,1).getValues().flat().map(String);
  const found=values.indexOf(id);
  if(found>=0) sheet.deleteRow(found+2);
}

function json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
