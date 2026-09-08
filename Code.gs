/**
 * Homsa System -> Google Sheets backend (secured PR roles)
 *
 * نشر Web App:
 * Execute as: Me
 * Who has access: Anyone with the link
 *
 * الأمان: الـ session secret محفوظ في Script Properties وليس داخل الكود.
 *
 * مهم: هذا الإصدار لا يعتمد على SECRET موجود داخل index.html.
 * تسجيل الدخول يتم من خلال login، وبعدها يتم إصدار Session Token موقّع من Apps Script.
 *
 * ملاحظة عن التعديلات الجديدة (الرحلات/التسكين المنفصلين):
 * لم يتم تغيير أي شيء في منطق هذا الملف من أجل ميزة فصل "الرحلات" عن "التسكين"،
 * التخزين هنا عام (generic key-value sheets)، لكن واجهة الويب لا تسمح إلا بالجداول
 * الموجودة في whitelist داخل TABLE_READ_ROLES / TABLE_WRITE_ROLES. الجدول
 * "trip_hotels" مدعوم ضمن القائمة بدون فتح إمكانية إنشاء جداول عشوائية.
 */
function doGet(e) {
  return json({
    ok:true,
    service:'homsa-google-sheets-sync',
    message:'Use POST for authentication and data operations.'
  });
}

function doPost(e) {
  try {
    const body = JSON.parse(e.postData && e.postData.contents || '{}');
    const action = String(body.action || '');

    if (action === 'login') {
      return json(handleLogin(String(body.username || ''), String(body.password || '')));
    }

    const session = verifySession(String(body.session || ''));
    if (!session) return json({ok:false, error:'Unauthorized'});

    if (action === 'me') {
      return json({ok:true, user:publicSessionUser(session)});
    }

    if (action === 'list') {
      const table = safeSheetName(body.table);
      if (!isAllowedTable(table) || !isTableReadAllowed(session, table)) {
        return json({ok:false, error:'Forbidden'});
      }
      const filtered = filterRowsForSession(getCachedRows(table), table, session);
      return json({ok:true, rows:sanitizeRowsForClient(table, filtered, session)});
    }

    if (action === 'bulk') {
      const requested = Array.isArray(body.tables) ? body.tables : String(body.tables || '').split(',');
      const tables = [];
      requested.map(function(t){ return safeSheetName(t); }).filter(Boolean).forEach(function(t){
        if (tables.indexOf(t) < 0) tables.push(t);
      });
      if (tables.length > 50) return json({ok:false, error:'Too many tables'}, 400);

      const out = {};
      for (let i=0;i<tables.length;i++) {
        const t = tables[i];
        if (!isAllowedTable(t) || !isTableReadAllowed(session, t)) {
          return json({ok:false, error:'Forbidden'});
        }
        const filtered = filterRowsForSession(getCachedRows(t), t, session);
        out[t] = sanitizeRowsForClient(t, filtered, session);
      }
      return json({ok:true, tables:out});
    }

    if (action === 'logout') {
      return json(handleLogout(session));
    }

    if (action === 'changePassword') {
      return json(handleChangePassword(session, body.payload || {}));
    }

    if (action === 'createEmployeeAccount') {
      return json(handleCreateEmployeeAccount(session, body.payload || {}));
    }

    if (!body.table || !action) return json({ok:false, error:'Missing action/table'}, 400);

    const table = safeSheetName(body.table);
    if (!isAllowedTable(table)) return json({ok:false, error:'Forbidden'}, 403);

    const payload = body.payload || {};
    if (!canMutateTable(session, table, payload, action)) {
      return json({ok:false, error:'Forbidden'}, 403);
    }

    if (action === 'batchDelete') {
      const ids = Array.isArray(payload.ids) ? payload.ids.filter(Boolean) : [];
      if (ids.length > MAX_BATCH_DELETE_IDS) return json({ok:false, error:'Too many rows'}, 400);
    }

    if (action === 'batchUpsert') {
      const rows = Array.isArray(payload.rows) ? payload.rows : [];
      if (rows.length > MAX_BATCH_ROWS) return json({ok:false, error:'Too many rows'}, 400);
    }

    const ss = SpreadsheetApp.getActive();
    const sheet = getOrCreateSheet(ss, table);

    if (action === 'delete') {
      const id = String(payload.id || '');
      const existing = getRowById(sheet, id);
      if (!rowBelongsToSession(session, table, existing)) return json({ok:false, error:'Forbidden'}, 403);
      deleteRowById(sheet, id);
      invalidateCachedRows(table);

    } else if (action === 'upsert') {
      const existing = getRowById(sheet, String(payload.id || ''));
      if (existing && !rowBelongsToSession(session, table, existing)) return json({ok:false, error:'Forbidden'}, 403);
      const cleanPayload = enforceOwnership(session, table, payload);
      upsertRow(sheet, cleanPayload);
      invalidateCachedRows(table);
      if (table === 'employees') syncUserTeamFromEmployee(cleanPayload);

    } else if (action === 'batchDelete') {
      const ids = (payload.ids || []).map(String).filter(Boolean);
      const existingRows = readRows(sheet);
      for (let i=0;i<ids.length;i++) {
        const existing = existingRows.find(function(r){ return String(r.id || '') === ids[i]; });
        if (existing && !rowBelongsToSession(session, table, existing)) {
          return json({ok:false, error:'Forbidden'}, 403);
        }
      }
      deleteRowsBatch(sheet, ids);
      invalidateCachedRows(table);

    } else if (action === 'batchUpsert') {
      const rows = payload.rows || [];
      const existingRows = readRows(sheet);
      const cleanRows = rows.map(function(r) {
        const existing = existingRows.find(function(x){ return String(x.id || '') === String((r || {}).id || ''); });
        if (existing && !rowBelongsToSession(session, table, existing)) throw new Error('Forbidden');
        return enforceOwnership(session, table, r || {});
      });
      upsertRowsBatch(sheet, cleanRows);
      invalidateCachedRows(table);
      if (table === 'employees') cleanRows.forEach(syncUserTeamFromEmployee);

    } else {
      return json({ok:false, error:'Unknown action'}, 400);
    }

    return json({ok:true});
  } catch (err) {
    return json({ok:false, error:String(err)});
  }
}

/* ---------------- Authentication & Security ---------------- */

/*
 * Security notes:
 * - No credentials or session secret are hard-coded in the client.
 * - Session secret is stored in Script Properties and generated automatically once.
 * - Sessions are short-lived and include a per-user sessionVersion.
 * - Every authenticated request re-validates the user on the server.
 * - Passwords use per-user salt + repeated SHA-256 for backward-compatible migration.
 * - The users table is never returned with password hashes.
 */

const SESSION_TTL_SECONDS = 60 * 60 * 4;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_LOCK_SECONDS = 10 * 60;
const PASSWORD_MIN_LENGTH = 12;
const MAX_BATCH_ROWS = 500;
const MAX_BATCH_DELETE_IDS = 500;

const ALL_TABLES = [
  'users','teams','employees','companies','visits','indoor_leads','indoor_data',
  'callcenter_feedback','callcenter_payments','accommodation','pr_member_data',
  'subscriptions','trips','trip_hotels','accom_hotels','accom_rooms','accom_guests',
  'dashboards','widgets','accounting','app_settings'
];

const TABLE_READ_ROLES = {
  users: ['admin','hr'],
  teams: ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out'],
  employees: ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out','callcenter','accommodation','system','analyst'],
  companies: ['admin','pr_out','pr_in','analyst'],
  visits: ['admin','pr_out','analyst'],
  indoor_leads: ['admin','pr_manager','pr_leader','pr_member','pr_in','analyst'],
  indoor_data: ['admin','pr_manager','pr_leader','pr_member','pr_in','analyst'],
  callcenter_feedback: ['admin','callcenter','analyst'],
  callcenter_payments: ['admin','callcenter','analyst'],
  accommodation: ['admin','accommodation','system','analyst'],
  pr_member_data: ['admin','pr_manager','pr_leader','pr_member','analyst'],
  // اتضافلهم accommodation و accounting هنا بس (قراءة فقط) عشان يقدروا يشوفوا
  // صفحتي "الاشتراكات" و"الفائزون" - صلاحية الكتابة (TABLE_WRITE_ROLES) تحت
  // ما اتغيرتش، يعني لسه مايقدروش يضيفوا/يعدلوا/يحذفوا فيها.
  subscriptions: ['admin','pr_manager','pr_leader','pr_member','analyst','accommodation','accounting'],
  trips: ['admin','accommodation','system','pr_manager','pr_leader','pr_member','analyst','accounting'],
  trip_hotels: ['admin','accommodation','system'],
  accom_hotels: ['admin','accommodation','system','pr_manager','pr_leader','pr_member','analyst','accounting'],
  accom_rooms: ['admin','accommodation','system','pr_manager','pr_leader','pr_member','analyst','accounting'],
  accom_guests: ['admin','accommodation','system'],
  dashboards: ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out','callcenter','accommodation','system','analyst'],
  widgets: ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out','callcenter','accommodation','system','analyst'],
  accounting: ['admin'],
  app_settings: ['admin','pr_in','accommodation','system']
};

const TABLE_WRITE_ROLES = {
  teams: ['admin','hr','pr_manager'],
  employees: ['admin','hr','pr_manager'],
  companies: ['admin','pr_out'],
  visits: ['admin','pr_out','analyst'],
  indoor_leads: ['admin','pr_manager','pr_leader','pr_member','pr_in'],
  indoor_data: ['admin','pr_manager','pr_leader','pr_member','pr_in'],
  callcenter_feedback: ['admin','callcenter'],
  callcenter_payments: ['admin','callcenter'],
  accommodation: ['admin','accommodation','system'],
  pr_member_data: ['admin','pr_manager','pr_leader','pr_member'],
  subscriptions: ['admin','pr_manager','pr_leader','pr_member'],
  trips: ['admin','accommodation','system'],
  trip_hotels: ['admin','accommodation','system'],
  accom_hotels: ['admin','accommodation','system'],
  accom_rooms: ['admin','accommodation','system'],
  accom_guests: ['admin','accommodation','system'],
  dashboards: ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out','callcenter','accommodation','system','analyst'],
  widgets: ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out','callcenter','accommodation','system','analyst'],
  accounting: ['admin'],
  app_settings: ['admin','pr_in','accommodation','system']
};

const ANALYTICS_ROLES = ['admin','hr','pr_manager','pr_leader','pr_member','pr_in','pr_out','callcenter','accommodation','system','analyst'];

function getSessionSecret() {
  const props = PropertiesService.getScriptProperties();
  let secret = props.getProperty('HOMSA_SESSION_SECRET');
  if (!secret) {
    secret = Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid();
    props.setProperty('HOMSA_SESSION_SECRET', secret);
  }
  return secret;
}

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

function isAllowedTable(table) {
  return ALL_TABLES.indexOf(table) >= 0;
}

function roleAllows(map, session, table) {
  const allowed = map[table];
  return !!allowed && allowed.indexOf(String(session.role || '')) >= 0;
}

function isTableReadAllowed(session, table) {
  return roleAllows(TABLE_READ_ROLES, session, table);
}

function isTableWriteAllowed(session, table) {
  return String(session.role || '') === 'admin' || roleAllows(TABLE_WRITE_ROLES, session, table);
}

function loginRateKey(username) {
  return 'loginfail:' + normalizeUsername(username).slice(0, 80);
}

function checkLoginRateLimit(username) {
  const cache = CacheService.getScriptCache();
  const count = Number(cache.get(loginRateKey(username)) || 0);
  if (count >= LOGIN_MAX_FAILURES) {
    throw new Error('محاولات دخول كثيرة. حاول مرة أخرى بعد 10 دقائق.');
  }
}

function recordLoginFailure(username) {
  const cache = CacheService.getScriptCache();
  const key = loginRateKey(username);
  const count = Number(cache.get(key) || 0) + 1;
  cache.put(key, String(count), LOGIN_LOCK_SECONDS);
}

function clearLoginFailures(username) {
  try { CacheService.getScriptCache().remove(loginRateKey(username)); } catch (_) {}
}

function randomSalt() {
  return Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
}

function hashPassword(password, salt) {
  let value = String(salt || '') + ':' + String(password || '');
  for (let i = 0; i < 5000; i++) value = sha256(value);
  return value;
}

function verifyPassword(user, password) {
  const salt = String(user.passwordSalt || '');
  const algo = String(user.passwordAlgo || '');
  if (salt && algo === 'sha256-iterated-v1') {
    return hashPassword(password, salt) === String(user.passwordHash || '');
  }
  // Backward-compatible check for the old unsalted SHA-256 format.
  return sha256(password) === String(user.passwordHash || '');
}

function migratePasswordIfLegacy(user, password) {
  if (user.passwordSalt && user.passwordAlgo === 'sha256-iterated-v1') return false;
  user.passwordSalt = randomSalt();
  user.passwordAlgo = 'sha256-iterated-v1';
  user.passwordHash = hashPassword(password, user.passwordSalt);
  user.sessionVersion = Number(user.sessionVersion || 1);
  return true;
}

function publicUser(user) {
  return {
    uid: String(user.id || ''),
    username: String(user.username || ''),
    name: String(user.name || ''),
    role: String(user.role || ''),
    team: String(user.team || ''),
    employeeId: String(user.employeeId || '')
  };
}

function currentUserForSession(session) {
  const rows = getCachedRows('users');
  return rows.find(function(u) { return String(u.id || '') === String(session.uid || ''); }) || null;
}

function handleLogin(username, password) {
  username = normalizeUsername(username);
  password = String(password || '');
  if (!username || !password) return {ok:false, error:'Missing username/password'};

  checkLoginRateLimit(username);

  const sheet = SpreadsheetApp.getActive().getSheetByName('users');
  if (!sheet) return {ok:false, error:'لا يوجد جدول users. أنشئ حساب المدير الأول من محرر Apps Script.'};

  const users = readRows(sheet);
  const user = users.find(function(x) {
    return normalizeUsername(x.username) === username;
  });

  if (!user || String(user.status || 'active') === 'inactive') {
    recordLoginFailure(username);
    return {ok:false, error:'اسم المستخدم أو كلمة المرور غير صحيحة'};
  }

  if (!verifyPassword(user, password)) {
    recordLoginFailure(username);
    return {ok:false, error:'اسم المستخدم أو كلمة المرور غير صحيحة'};
  }

  clearLoginFailures(username);

  let changed = false;
  if (!user.sessionVersion) {
    user.sessionVersion = 1;
    changed = true;
  }
  if (migratePasswordIfLegacy(user, password)) changed = true;
  if (changed) {
    upsertRow(sheet, user);
    invalidateCachedRows('users');
  }

  const payload = {
    uid: String(user.id),
    username: String(user.username || ''),
    name: String(user.name || ''),
    role: String(user.role || ''),
    team: String(user.team || ''),
    employeeId: String(user.employeeId || ''),
    sv: Number(user.sessionVersion || 1),
    exp: Math.floor(Date.now()/1000) + SESSION_TTL_SECONDS
  };

  return {ok:true, user:publicSessionUser(payload), session:createSession(payload)};
}

function createSession(payload) {
  const body = base64url(JSON.stringify(payload));
  const sig = hmac(body, getSessionSecret());
  return body + '.' + sig;
}

function verifySession(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 2) return null;
    const body = parts[0], sig = parts[1];
    if (hmac(body, getSessionSecret()) !== sig) return null;

    const payload = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(body)).getDataAsString());
    if (!payload.uid || !payload.exp || Number(payload.exp) < Math.floor(Date.now()/1000)) return null;

    const user = currentUserForSession(payload);
    if (!user || String(user.status || 'active') === 'inactive') return null;

    const currentVersion = Number(user.sessionVersion || 1);
    if (Number(payload.sv || 1) !== currentVersion) return null;

    // Refresh authorization data from the server so role/team changes are not trusted from the browser.
    payload.username = String(user.username || '');
    payload.name = String(user.name || '');
    payload.role = String(user.role || '');
    payload.team = String(user.team || '');
    payload.employeeId = String(user.employeeId || '');
    payload.sv = currentVersion;
    return payload;
  } catch (_) {
    return null;
  }
}

function handleLogout(session) {
  const ss = SpreadsheetApp.getActive();
  const sheet = ss.getSheetByName('users');
  if (!sheet) return {ok:true};

  const users = readRows(sheet);
  const user = users.find(function(u){ return String(u.id || '') === String(session.uid || ''); });
  if (!user) return {ok:true};

  user.sessionVersion = Number(user.sessionVersion || 1) + 1;
  upsertRow(sheet, user);
  invalidateCachedRows('users');
  return {ok:true};
}

function handleChangePassword(session, payload) {
  const currentPassword = String(payload.currentPassword || '');
  const newUsername = normalizeUsername(payload.newUsername || '');
  const newPassword = String(payload.newPassword || '');

  if (!currentPassword) return {ok:false, error:'كلمة المرور الحالية مطلوبة'};
  if (!newUsername && !newPassword) return {ok:false, error:'لا يوجد تغيير مطلوب'};
  if (newUsername && !/^[a-zA-Z0-9._-]{3,40}$/.test(newUsername)) {
    return {ok:false, error:'اسم المستخدم غير صالح'};
  }
  if (newPassword && newPassword.length < PASSWORD_MIN_LENGTH) {
    return {ok:false, error:'كلمة المرور الجديدة يجب أن تكون 12 حرفًا على الأقل'};
  }

  const ss = SpreadsheetApp.getActive();
  const sheet = ss.getSheetByName('users');
  if (!sheet) return {ok:false, error:'الحسابات غير متاحة'};

  const users = readRows(sheet);
  const user = users.find(function(u){ return String(u.id || '') === String(session.uid || ''); });
  if (!user) return {ok:false, error:'الحساب غير موجود'};
  if (!verifyPassword(user, currentPassword)) return {ok:false, error:'كلمة المرور الحالية غير صحيحة'};

  if (newUsername) {
    const taken = users.some(function(u){
      return String(u.id || '') !== String(user.id || '') &&
        normalizeUsername(u.username) === newUsername;
    });
    if (taken) return {ok:false, error:'اسم المستخدم مستخدم بالفعل'};
    user.username = newUsername;
  }

  if (newPassword) {
    user.passwordSalt = randomSalt();
    user.passwordAlgo = 'sha256-iterated-v1';
    user.passwordHash = hashPassword(newPassword, user.passwordSalt);
  }

  user.sessionVersion = Number(user.sessionVersion || 1) + 1;
  upsertRow(sheet, user);
  invalidateCachedRows('users');

  const nextPayload = {
    uid: String(user.id),
    username: String(user.username || ''),
    name: String(user.name || ''),
    role: String(user.role || ''),
    team: String(user.team || ''),
    employeeId: String(user.employeeId || ''),
    sv: Number(user.sessionVersion),
    exp: Math.floor(Date.now()/1000) + SESSION_TTL_SECONDS
  };

  return {
    ok:true,
    user:publicSessionUser(nextPayload),
    session:createSession(nextPayload)
  };
}

function setupFirstAdmin(username, password, name) {
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    username = normalizeUsername(username);
    password = String(password || '');
    name = String(name || 'مدير النظام').trim();

    if (!username || !/^[a-zA-Z0-9._-]{3,40}$/.test(username)) {
      throw new Error('اسم المستخدم غير صالح');
    }
    if (password.length < PASSWORD_MIN_LENGTH) {
      throw new Error('كلمة المرور يجب أن تكون 12 حرفًا على الأقل');
    }

    const ss = SpreadsheetApp.getActive();
    const sheet = ss.getSheetByName('users');
    if (sheet && readRows(sheet).length) throw new Error('يوجد حسابات بالفعل — لا تستخدم setupFirstAdmin');

    const sh = getOrCreateSheet(ss, 'users');
    const salt = randomSalt();
    const user = {
      id:'usr_' + Utilities.getUuid().replace(/-/g,''),
      name:name,
      username:username,
      passwordHash:hashPassword(password, salt),
      passwordSalt:salt,
      passwordAlgo:'sha256-iterated-v1',
      role:'admin',
      status:'active',
      team:'',
      employeeId:'',
      sessionVersion:1
    };
    upsertRow(sh, user);
    invalidateCachedRows('users');
    return publicUser(user);
  } finally {
    lock.releaseLock();
  }
}

function handleCreateEmployeeAccount(session, payload) {
  if (['admin','hr'].indexOf(String(session.role || '')) < 0) {
    return {ok:false, error:'Forbidden'};
  }

  payload = payload || {};
  const name = String(payload.name || '').trim();
  const username = normalizeUsername(payload.username || '');
  const password = String(payload.password || '');
  const role = String(payload.role || '').trim();

  if (!name || !username || !password || !role) return {ok:false, error:'أكمل البيانات المطلوبة'};
  if (!/^[a-zA-Z0-9._-]{3,40}$/.test(username)) return {ok:false, error:'اسم المستخدم غير صالح'};
  if (password.length < PASSWORD_MIN_LENGTH) return {ok:false, error:'كلمة المرور يجب أن تكون 12 حرفًا على الأقل'};

  const validRoles = ['admin','hr','pr_manager','pr_leader','pr_member','pr_out','pr_in','reception','accounting','callcenter','accommodation','system','analyst'];
  if (validRoles.indexOf(role) < 0) return {ok:false, error:'الصلاحية غير صالحة'};

  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const ss = SpreadsheetApp.getActive();
    const userSheet = getOrCreateSheet(ss, 'users');
    const users = readRows(userSheet);

    if (users.some(function(u){ return normalizeUsername(u.username) === username; })) {
      return {ok:false, error:'اسم المستخدم مستخدم بالفعل'};
    }

    const employeeId = 'emp_' + Utilities.getUuid().replace(/-/g,'');
    const userId = 'usr_' + Utilities.getUuid().replace(/-/g,'');
    const salt = randomSalt();

    const employeeData = payload.employeeData || {};
    const user = {
      id:userId,
      name:name,
      username:username,
      passwordHash:hashPassword(password, salt),
      passwordSalt:salt,
      passwordAlgo:'sha256-iterated-v1',
      role:role,
      status:'active',
      team:String(employeeData.team || ''),
      employeeId:employeeId,
      sessionVersion:1
    };

    const employee = {
      id:employeeId,
      name:name,
      username:username,
      department:String(employeeData.department || ''),
      status:'active',
      specialNumber:String(employeeData.specialNumber || ''),
      companyNumber:String(employeeData.companyNumber || ''),
      team:String(employeeData.team || ''),
      phone:String(employeeData.phone || ''),
      address:String(employeeData.address || ''),
      hireDate:employeeData.hireDate || '',
      salary:employeeData.salary === '' || employeeData.salary == null ? '' : Number(employeeData.salary)
    };

    upsertRow(userSheet, user);
    try {
      upsertRow(getOrCreateSheet(ss, 'employees'), employee);
    } catch (err) {
      deleteRowById(userSheet, userId);
      invalidateCachedRows('users');
      throw err;
    }

    invalidateCachedRows('users');
    invalidateCachedRows('employees');
    return {ok:true, user:publicUser(user), employee:employee};
  } finally {
    lock.releaseLock();
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

/* ---------------- Server-side visibility / ownership ---------------- */

function isPRRole(role) {
  return ['pr_manager','pr_leader','pr_member'].indexOf(role) >= 0;
}

// طبّع اسم الفريق: بيشيل مسافات البداية/النهاية عشان أي مسافة زيادة اتكتبت غلط
// في شيت الموظفين (حاجة شائعة جدًا مع الكتابة اليدوية) ما تكسرش مقارنة الفريق.
function normTeam(v) {
  return String(v || '').trim();
}

// فريق المستخدم الحالي "الحقيقي": بنجيبه من صف الموظف نفسه (employees.team) بدل
// ما نعتمد بس على session.team (اللي مصدرها users.team). السبب: لو حد عدّل فريق
// موظف من صفحة "الموظفون" بعد ما اتعمله حساب، كان بيتحدث employees.team بس، من
// غير ما يتحدث users.team بتاع نفس الشخص، فيفضل session.team قديم وغير متزامن.
// الدالة دي بترجع القيمة الحقيقية الحالية من جدول الموظفين، وترجع لـ session.team
// بس لو الموظف مش موجود في الجدول أصلاً.
function sessionOwnTeam(session) {
  const emps = getCachedRows('employees');
  const own = emps.find(function(e){ return String(e.id || '') === String(session.employeeId || ''); });
  return own ? normTeam(own.team) : normTeam(session.team);
}

function employeeNamesForSession(session) {
  // كان بيقرأ شيت employees بالكامل مباشرة (readRows) في كل مرة، من غير كاش، حتى
  // لو نفس الطلب بيلف على أكتر من جدول (bulk) أو نفس الجلسة بتعمل أكتر من عملية
  // ورا بعض. الدالة دي بتتنادى من filterRowsForSession/rowBelongsToSession/
  // enforceOwnership لكل جدول PR-filtered، فكانت بتسبب قراءة كاملة إضافية للشيت
  // (Sheets API round-trip) لكل جدول في كل bulk request. دلوقتي بتستخدم نفس كاش
  // getCachedRows('employees') المستخدم في باقي النظام (30 ثانية) بدل قراءة مباشرة.
  const emps = getCachedRows('employees');
  if (session.role === 'pr_manager') return emps.map(x => String(x.name || '')).filter(Boolean);
  const myTeam = sessionOwnTeam(session);
  return emps.filter(x => normTeam(x.team) === myTeam && x.status !== 'inactive')
    .map(x => String(x.name || '')).filter(Boolean);
}

// لو اتعدل فريق موظف من صفحة "الموظفون"، بنزامن نفس القيمة على حساب تسجيل
// الدخول بتاعه (users.team) على طول. من غير المزامنة دي، أي فحص صلاحيات بيعتمد
// على session.team (بما فيه الفحص اللي بيرفض إضافة عضو "برة الفريق") كان ممكن
// يفضل شغال بقيمة فريق قديمة لحد ما الموظف يعمل logout/login تاني.
function syncUserTeamFromEmployee(employeeRecord) {
  if (!employeeRecord || !employeeRecord.id) return;
  try {
    const ss = SpreadsheetApp.getActive();
    const userSheet = ss.getSheetByName('users');
    if (!userSheet) return;
    const users = readRows(userSheet);
    const user = users.find(function(u){ return String(u.employeeId || '') === String(employeeRecord.id); });
    if (!user) return;
    const newTeam = normTeam(employeeRecord.team);
    if (normTeam(user.team) === newTeam) return; // متزامنين بالفعل، مفيش داعي لكتابة زيادة
    user.team = newTeam;
    upsertRow(userSheet, user);
    invalidateCachedRows('users');
  } catch (e) {
    // مانوقفش العملية الأساسية (حفظ الموظف) لو المزامنة فشلت لأي سبب
  }
}

function serverAnalyticsModulesForRole(role) {
  const map = {
    admin:['teams','employees','indoor_leads','indoor_data','pr_member_data','subscriptions','callcenter_feedback','accommodation','trips_hub'],
    hr:['teams','employees'],
    pr_manager:['teams','employees','indoor_leads','indoor_data','pr_member_data','subscriptions','winners'],
    pr_leader:['employees','indoor_leads','indoor_data','pr_member_data','subscriptions','winners'],
    pr_member:['employees','indoor_leads','indoor_data','pr_member_data','subscriptions','winners'],
    pr_out:['employees','companies','visits'],
    pr_in:['employees','indoor_leads','indoor_data'],
    callcenter:['callcenter_feedback'],
    accommodation:['accommodation'],
    system:['accommodation'],
    analyst:['teams','employees','indoor_leads','pr_member_data','subscriptions','callcenter_feedback','accommodation']
  };
  return map[role] || [];
}

function filterRowsForSession(rows, table, session) {
  if (table === 'users') {
    return rows.filter(function(r){ return String(r.id || '') === String(session.uid || '') || session.role === 'admin' || session.role === 'hr'; });
  }

  if (table === 'dashboards') {
    const allowedModules = serverAnalyticsModulesForRole(session.role);
    if (session.role === 'admin' || session.role === 'analyst') {
      return rows.filter(function(r){ return allowedModules.indexOf(String(r.sourceModule || '')) >= 0; });
    }
    return rows.filter(function(r){ return allowedModules.indexOf(String(r.sourceModule || '')) >= 0; });
  }

  if (table === 'widgets') {
    const dashboards = filterRowsForSession(getCachedRows('dashboards'), 'dashboards', session);
    const ids = {};
    dashboards.forEach(function(d){ ids[String(d.id || '')] = true; });
    return rows.filter(function(r){ return ids[String(r.dashboardId || '')]; });
  }

  if (!isPRRole(session.role)) return rows;

  if (session.role === 'pr_manager') return rows;

  const allowed = employeeNamesForSession(session);
  const myName = session.name || '';

  if (table === 'employees') {
    return rows.filter(r => allowed.indexOf(String(r.name || '')) >= 0);
  }

  if (table === 'teams') {
    return rows.filter(r => normTeam(r.name) === sessionOwnTeam(session));
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

function sanitizeRowsForClient(table, rows, session) {
  return rows.map(function(r) {
    const c = Object.assign({}, r);

    if (table === 'users') {
      delete c.passwordHash;
      delete c.passwordSalt;
      delete c.passwordAlgo;
      delete c.sessionVersion;
    }

    if (table === 'employees' && ['admin','hr'].indexOf(String(session.role || '')) < 0) {
      delete c.salary;
      delete c.specialNumber;
      delete c.companyNumber;
      delete c.address;
    }

    return c;
  });
}

function rowBelongsToSession(session, table, row) {
  if (!row) return false;
  if (session.role === 'admin') return true;

  if (['indoor_leads','indoor_data','subscriptions'].indexOf(table) >= 0) {
    if (session.role === 'pr_manager') return true;
    const allowed = employeeNamesForSession(session);
    const owner = String(row.responsiblePerson || '');
    return session.role === 'pr_leader' ? allowed.indexOf(owner) >= 0 : owner === String(session.name || '');
  }

  if (table === 'pr_member_data') {
    if (session.role === 'pr_manager') return true;
    const allowed = employeeNamesForSession(session);
    const owner = String(row.memberId || '');
    return session.role === 'pr_leader' ? allowed.indexOf(owner) >= 0 : owner === String(session.name || '');
  }

  if (table === 'employees' && session.role === 'pr_member') {
    return String(row.id || '') === String(session.employeeId || '');
  }

  if (table === 'dashboards' || table === 'widgets') {
    return true;
  }

  return true;
}

function canMutateTable(session, table, payload, action) {
  // Generic users mutations are deliberately disabled. Use the dedicated
  // createEmployeeAccount / changePassword actions instead.
  if (table === 'users') return false;

  if (!isTableWriteAllowed(session, table)) return false;

  if (['dashboards','widgets'].indexOf(table) >= 0) {
    if (!ANALYTICS_ROLES.includes(String(session.role || ''))) return false;
    if (session.role === 'admin') return true;

    const allowedModules = serverAnalyticsModulesForRole(session.role);

    if (table === 'dashboards') {
      if (action === 'batchUpsert') {
        const rows = Array.isArray((payload || {}).rows) ? payload.rows : [];
        if (!rows.length) return true;
        // كانت getCachedRows('dashboards') بتتنادى جوه every() يعني لكل صف في الباتش
        // (لحد 500 صف)، وكل نداء ده معناه قراءة من ScriptCache + JSON.parse لكل
        // الجدول من الأول — بنجيبها مرة واحدة بره اللوب.
        const existingDashboards = getCachedRows('dashboards');
        return rows.every(function(p) {
          if (!p.sourceModule || allowedModules.indexOf(String(p.sourceModule)) < 0) return false;
          if (!p.id) return true;
          const existing = existingDashboards.find(function(d){ return String(d.id) === String(p.id); });
          return !!existing && String(existing.createdBy || '') === String(session.name || '');
        });
      }

      const p = payload || {};
      if (p.sourceModule && allowedModules.indexOf(String(p.sourceModule)) < 0) return false;
      if (action === 'delete' || p.id) {
        const existing = getCachedRows('dashboards').find(function(d){ return String(d.id) === String(p.id); });
        return !!existing && String(existing.createdBy || '') === String(session.name || '');
      }
      return true;
    }

    if (action === 'batchUpsert') {
      const rows = Array.isArray((payload || {}).rows) ? payload.rows : [];
      if (!rows.length) return true;
      const dashboards = getCachedRows('dashboards');
      // نفس المشكلة اللي فوق: getCachedRows('widgets') كانت بتتنادى لكل صف جوه
      // every() بدل ما تتجاب مرة واحدة.
      const existingWidgets = getCachedRows('widgets');
      return rows.every(function(p) {
        const dashboard = dashboards.find(function(d){ return String(d.id) === String(p.dashboardId || ''); });
        if (!dashboard || String(dashboard.createdBy || '') !== String(session.name || '')) return false;
        if (!p.id) return true;
        const existing = existingWidgets.find(function(w){ return String(w.id) === String(p.id); });
        return !existing || String(existing.dashboardId || '') === String(p.dashboardId || '');
      });
    }

    if (action === 'batchDelete') {
      const ids = Array.isArray((payload || {}).ids) ? payload.ids.map(String) : [];
      const widgets = getCachedRows('widgets');
      const dashboards = getCachedRows('dashboards');
      return ids.every(function(id) {
        const widget = widgets.find(function(w){ return String(w.id) === id; });
        if (!widget) return true;
        const dashboard = dashboards.find(function(d){ return String(d.id) === String(widget.dashboardId || ''); });
        return !!dashboard && String(dashboard.createdBy || '') === String(session.name || '');
      });
    }

    const p = payload || {};
    let dashboardId = String(p.dashboardId || '');
    if (action === 'delete' && p.id) {
      const existingWidget = getCachedRows('widgets').find(function(w){ return String(w.id) === String(p.id); });
      if (existingWidget) dashboardId = String(existingWidget.dashboardId || '');
    }
    const dashboard = getCachedRows('dashboards').find(function(d){ return String(d.id) === dashboardId; });
    return !!dashboard && String(dashboard.createdBy || '') === String(session.name || '');
  }

  if (table === 'app_settings' && session.role !== 'admin') {
    const key = String((payload || {}).key || '');
    if (session.role === 'pr_in') return key === 'indoor_data_sheet_link';
    if (['accommodation','system'].indexOf(session.role) >= 0) return key === 'accom_migration_v2_done';
    return false;
  }

  if (session.role === 'pr_member' && table === 'employees') {
    return String(payload && payload.id || '') === String(session.employeeId || '');
  }

  if (isPRRole(session.role)) {
    if (['pr_manager','pr_leader','pr_member'].indexOf(session.role) >= 0 &&
        ['indoor_leads','indoor_data','subscriptions','pr_member_data'].indexOf(table) >= 0) {
      return true;
    }
  }

  return true;
}

function enforceOwnership(session, table, payload) {
  const p = Object.assign({}, payload || {});
  const allowed = employeeNamesForSession(session);
  const myName = session.name || '';

  if (session.role === 'pr_member') {
    if (['indoor_leads','indoor_data','subscriptions'].indexOf(table) >= 0) {
      p.responsiblePerson = myName;
    }
    if (table === 'pr_member_data') p.memberId = myName;
    if (table === 'employees') {
      p.id = String(session.employeeId || '');
      p.name = myName;
    }
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

  if (['dashboards','widgets'].indexOf(table) >= 0 && session.role !== 'admin') {
    if (table === 'dashboards') {
      p.createdBy = myName;
    }
  }

  return p;
}

/* ---------------- Auto backfill (id / lead code) ---------------- */
// الهدف: أي صف يتضاف في أي جدول (سواء من النظام أو يدويًا في الشيت) يتاخد له
// id تلقائي لو ناقص، وأي صف في indoor_leads يتاخد له code تلقائي لو ناقص.
// بيتنفذوا من جوه getCachedRows نفسها قبل أي قراءة، عشان يشتغلوا في كل الحالات.

function backfillMissingIds(sheet) {
  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();
  if (lastRow < 2 || lastCol < 1) return false;
  const headersRow = sheet.getRange(1,1,1,lastCol).getValues()[0].map(String);
  let idCol = headersRow.indexOf('id') + 1;
  if (!idCol) { sheet.getRange(1, lastCol+1).setValue('id'); idCol = lastCol+1; }

  const numRows = lastRow - 1;
  const idValues = sheet.getRange(2, idCol, numRows, 1).getValues();
  let changed = false;
  for (let i=0;i<numRows;i++){
    if(!idValues[i][0]){
      idValues[i][0] = 'id' + Utilities.getUuid().replace(/-/g,'').slice(0,10);
      changed = true;
    }
  }
  if(changed) sheet.getRange(2, idCol, numRows, 1).setValues(idValues);
  return changed;
}

function backfillLeadCodes(sheet) {
  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();
  if (lastRow < 2) return false;
  const headersRow = sheet.getRange(1,1,1,lastCol).getValues()[0].map(String);
  let codeCol = headersRow.indexOf('code') + 1;
  const phoneCol = headersRow.indexOf('phone') + 1;
  const regDateCol = headersRow.indexOf('registrationDate') + 1;
  if (!codeCol) { sheet.getRange(1, lastCol+1).setValue('code'); codeCol = lastCol+1; }

  const numRows = lastRow - 1;
  const codeValues = sheet.getRange(2, codeCol, numRows, 1).getValues();
  const phoneValues = phoneCol ? sheet.getRange(2, phoneCol, numRows, 1).getValues() : [];
  const regValues = regDateCol ? sheet.getRange(2, regDateCol, numRows, 1).getValues() : [];

  let changed = false;
  for (let i=0;i<numRows;i++){
    if(!codeValues[i][0]){
      const phone = phoneValues[i] ? phoneValues[i][0] : '';
      const regRaw = regValues[i] ? regValues[i][0] : '';
      const d = regRaw ? new Date(regRaw) : new Date();
      codeValues[i][0] = generateLeadCode(phone, isNaN(d) ? new Date() : d);
      changed = true;
    }
  }
  if(changed) sheet.getRange(2, codeCol, numRows, 1).setValues(codeValues);
  return changed;
}

function generateLeadCode(phone, dateObj) {
  const digits = String(phone||'').replace(/\D/g,'');
  const last4 = (digits.slice(-4) || '0000').padStart(4,'0');
  const dd = String(dateObj.getDate()).padStart(2,'0');
  const mm = String(dateObj.getMonth()+1).padStart(2,'0');
  return 'ID' + last4 + dd + mm;
}

// بيربط كل صف في subscriptions بالمهتم (lead) بتاعه في indoor_leads (بمطابقة
// التليفون أو الاسم) وياخد منه code و id (كـ leadId) ويحطهم في صف الاشتراك.
// من غير ده، الكود مبيظهرش إلا لو حد فتح شاشة الاشتراكات في النظام نفسه
// (لأن الحساب كان بيتم في الواجهة بس)، فلو الصف اتضاف يدوي في الشيت، الكود بيفضل فاضي.
function backfillSubscriptionCodes(sheet) {
  const ss = SpreadsheetApp.getActive();
  const leadsSheet = ss.getSheetByName('indoor_leads');
  if (!leadsSheet) return false;
  const leads = readRows(leadsSheet);
  if (!leads.length) return false;

  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return false;
  let lastCol = sheet.getLastColumn();
  let headersRow = sheet.getRange(1,1,1,lastCol).getValues()[0].map(String);

  let codeCol = headersRow.indexOf('code') + 1;
  if (!codeCol) { sheet.getRange(1, lastCol+1).setValue('code'); codeCol = lastCol+1; lastCol++; headersRow.push('code'); }

  let leadIdCol = headersRow.indexOf('leadId') + 1;
  if (!leadIdCol) { sheet.getRange(1, lastCol+1).setValue('leadId'); leadIdCol = lastCol+1; lastCol++; headersRow.push('leadId'); }

  const phoneCol = headersRow.indexOf('phone') + 1;
  const nameCol = headersRow.indexOf('customerName') + 1;

  const numRows = lastRow - 1;
  const codeValues = sheet.getRange(2, codeCol, numRows, 1).getValues();
  const leadIdValues = sheet.getRange(2, leadIdCol, numRows, 1).getValues();
  const phoneValues = phoneCol ? sheet.getRange(2, phoneCol, numRows, 1).getValues() : [];
  const nameValues = nameCol ? sheet.getRange(2, nameCol, numRows, 1).getValues() : [];

  let changed = false;
  for (let i=0;i<numRows;i++){
    if (codeValues[i][0]) continue; // عنده code خلاص، مش هنلمسه
    const rowPhoneDigits = String(phoneValues[i] ? phoneValues[i][0] : '').replace(/\D/g,'');
    const rowName = String(nameValues[i] ? nameValues[i][0] : '').trim();
    const lead = leads.find(function(l){
      const leadPhoneDigits = String(l.phone||'').replace(/\D/g,'');
      const leadName = String(l.name||'').trim();
      const phoneMatch = rowPhoneDigits && leadPhoneDigits && (
        rowPhoneDigits === leadPhoneDigits ||
        rowPhoneDigits.slice(-10) === leadPhoneDigits.slice(-10)
      );
      const nameMatch = rowName && leadName && rowName === leadName;
      return phoneMatch || nameMatch;
    });
    if (lead) {
      codeValues[i][0] = lead.code || '';
      leadIdValues[i][0] = lead.id || '';
      changed = true;
    }
  }
  if (changed) {
    sheet.getRange(2, codeCol, numRows, 1).setValues(codeValues);
    sheet.getRange(2, leadIdCol, numRows, 1).setValues(leadIdValues);
  }
  return changed;
}

/* ---------------- Auto backfill بدون فتح النظام (Trigger مستقل) ---------------- */
function runAutoBackfillAllSheets() {
  const ss = SpreadsheetApp.getActive();
  const tablesToCheck = ['indoor_leads', 'indoor_data', 'subscriptions', 'pr_member_data', 'employees', 'teams'];
  tablesToCheck.forEach(function(name){
    const sheet = ss.getSheetByName(name);
    if (!sheet) return;
    let changedIds = false, changedCodes = false;
    try { changedIds = backfillMissingIds(sheet); } catch(_) {}
    if (name === 'indoor_leads') {
      try { changedCodes = backfillLeadCodes(sheet); } catch(_) {}
    }
    if (name === 'subscriptions') {
      try { changedCodes = backfillSubscriptionCodes(sheet) || changedCodes; } catch(_) {}
    }
    if (changedIds || changedCodes) invalidateCachedRows(name);
  });
}

/* ---------------- Performance: caching + batch ops ---------------- */
const SHEET_CACHE_TTL_SECONDS = 30;

function getCachedRows(sheetName) {
  const cache = CacheService.getScriptCache();
  const cacheKey = 'rows_' + sheetName;
  try {
    const cached = cache.get(cacheKey);
    if (cached) return JSON.parse(cached);
  } catch (_) { /* تجاهل أي خطأ كاش وارجع لقراءة الشيت مباشرة */ }

  const ss = SpreadsheetApp.getActive();
  const sheet = ss.getSheetByName(sheetName);

  if (sheet) {
    try { backfillMissingIds(sheet); } catch(_) {}
    if (sheetName === 'indoor_leads') {
      try { backfillLeadCodes(sheet); } catch(_) {}
    }
    if (sheetName === 'subscriptions') {
      try { backfillSubscriptionCodes(sheet); } catch(_) {}
    }
  }

  const rows = sheet ? readRows(sheet) : [];

  try {
    const serialized = JSON.stringify(rows);
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
      return serializeCellValue(v);
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

  rowsToDelete.sort(function(a, b) { return b - a; });
  rowsToDelete.forEach(function(r) { sheet.deleteRow(r); });
}

/* ---------------- Sheets CRUD ---------------- */

function rowValuesToObject(h, row) {
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
}

function readRows(sheet) {
  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();
  if (lastRow < 2 || lastCol < 1) return [];
  const h = sheet.getRange(1,1,1,lastCol).getValues()[0].map(String);
  const values = sheet.getRange(2,1,lastRow-1,lastCol).getValues();
  return values.filter(row => row.some(v => v !== '')).map(row => rowValuesToObject(h, row));
}

function safeSheetName(name) {
  return String(name || '').trim();
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
  const missing = keys
    .map(String)
    .filter(function(k){ return /^[A-Za-z][A-Za-z0-9_]{0,59}$/.test(k) && !h.includes(k); });
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
    return serializeCellValue(v);
  });
  sheet.getRange(row,1,1,h.length).setValues([values]);
}

function getRowById(sheet, id) {
  if (!id || sheet.getLastRow() < 2) return null;
  const h = headers(sheet);
  const idCol = h.indexOf('id') + 1;
  if (!idCol) return null;
  const lastRow = sheet.getLastRow();
  const idValues = sheet.getRange(2, idCol, lastRow - 1, 1).getValues().flat().map(String);
  const found = idValues.indexOf(String(id));
  if (found < 0) return null;
  const rowIndex = found + 2;
  const lastCol = sheet.getLastColumn();
  const rowValues = sheet.getRange(rowIndex, 1, 1, lastCol).getValues()[0];
  return rowValuesToObject(h, rowValues);
}

function sanitizeCellValue(v) {
  if (typeof v === 'string' && /^[=+\-@]/.test(v)) return "'" + v;
  return v;
}

function serializeCellValue(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return sanitizeCellValue(v);
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
