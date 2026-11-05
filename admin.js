/* 컨택싱어 관리자
   - 로그인: Supabase Auth (이메일 · 비밀번호)
   - 권한: 데이터베이스의 is_admin() 이 참인 계정만 정보를 보고 고칠 수 있다 (화면이 아니라 데이터베이스가 막는다)
   - 사용자가 입력한 값은 모두 글자로만 넣는다 (HTML로 해석하지 않음) */
(function () {
  'use strict';
  var CFG = window.CS_CONFIG || {};
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function won(n) { return Number(n || 0).toLocaleString('ko-KR'); }

  /* ---------- 날짜 (한국 시간) ---------- */
  function kstDate(d) { return new Date((d ? new Date(d) : new Date()).getTime() + 9 * 36e5).toISOString().slice(0, 10); }
  function fmt(ts, withYear) {
    if (!ts) return '';
    var k = new Date(new Date(ts).getTime() + 9 * 36e5).toISOString();
    return (withYear ? k.slice(0, 4) + '.' : '') + k.slice(5, 7) + '.' + k.slice(8, 10) + ' ' + k.slice(11, 16);
  }

  /* ---------- 알림 · 확인 ---------- */
  var toastT;
  function toast(m) { var t = $('#toast'); t.textContent = m; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(function () { t.hidden = true; }, 2600); }
  function confirmBox(title, msg, yes) {
    return new Promise(function (resolve) {
      var bg = $('#confirm'); $('#cf-t').textContent = title; $('#cf-m').textContent = msg; $('#cf-yes').textContent = yes || '확인';
      bg.hidden = false; $('#cf-no').focus();
      function done(v) { bg.hidden = true; $('#cf-yes').onclick = null; $('#cf-no').onclick = null; document.removeEventListener('keydown', key); resolve(v); }
      function key(e) { if (e.key === 'Escape') done(false); }
      $('#cf-yes').onclick = function () { done(true); }; $('#cf-no').onclick = function () { done(false); };
      document.addEventListener('keydown', key);
    });
  }

  /* ---------- 로그인 세션 ---------- */
  var SKEY = 'contactsinger-admin-session', session = null;
  try { session = JSON.parse(localStorage.getItem(SKEY) || 'null'); } catch (e) { session = null; }
  function saveSession() { try { if (session) localStorage.setItem(SKEY, JSON.stringify(session)); else localStorage.removeItem(SKEY); } catch (e) { /* 저장 불가 */ } }
  function authReq(grant, body) {
    return fetch(CFG.url + '/auth/v1/token?grant_type=' + grant, { method: 'POST', headers: { apikey: CFG.key, 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) { var e = new Error(j.error_description || j.msg || j.message || '로그인하지 못했어요'); e.status = r.status; e.code = j.error_code || j.error; throw e; }
        return j;
      }); });
  }
  function setSession(j) {
    session = { access: j.access_token, refresh: j.refresh_token, exp: Date.now() + (j.expires_in || 3600) * 1000,
                email: (j.user && j.user.email) || (session && session.email) || '', uid: (j.user && j.user.id) || (session && session.uid) || '' };
    saveSession();
  }
  function ensureToken(force) {
    if (!session) return Promise.reject(authErr());
    if (!force && session.exp - 60000 > Date.now()) return Promise.resolve();
    return authReq('refresh_token', { refresh_token: session.refresh }).then(setSession, function () { session = null; saveSession(); throw authErr(); });
  }
  function authErr() { var e = new Error('로그인이 필요해요'); e.auth = true; return e; }

  /* ---------- 데이터베이스 요청 ---------- */
  function api(path, opt, retried) {
    opt = opt || {};
    return ensureToken().then(function () {
      var h = { apikey: CFG.key, Authorization: 'Bearer ' + session.access }, k, body = opt.body;
      for (k in (opt.headers || {})) h[k] = opt.headers[k];
      if (body != null && !(body instanceof Blob)) { body = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
      return fetch(CFG.url + path, { method: opt.method || 'GET', headers: h, body: body }).then(function (r) {
        if (r.status === 401 && !retried) return ensureToken(true).then(function () { return api(path, opt, true); });
        return r.text().then(function (t) {
          var data = null; try { data = t ? JSON.parse(t) : null; } catch (x) { data = t; }
          if (!r.ok) { var e = new Error((data && (data.message || data.error)) || ('HTTP ' + r.status)); e.status = r.status; e.data = data; throw e; }
          return opt.raw ? { data: data, res: r } : data;
        });
      });
    });
  }
  function fail(e) {
    if (e && e.auth) { showLogin('다시 로그인해 주세요'); return; }
    if (window.console) console.warn('[관리자]', e);
    toast(e && e.status === 403 ? '권한이 없어요. 관리자 명단에 등록됐는지 확인해 주세요' : '처리하지 못했어요. 잠시 후 다시 시도해 주세요');
  }
  function countOf(res) { var cr = res.headers.get('content-range') || ''; var n = +(cr.split('/')[1] || 0); return isNaN(n) ? 0 : n; }
  function count(table, q) {
    return api('/rest/v1/' + table + '?select=id' + (q ? '&' + q : '') + '&limit=1', { raw: true, headers: { Prefer: 'count=exact' } }).then(function (x) { return countOf(x.res); });
  }
  function signedUrl(path) {
    return api('/storage/v1/object/sign/uploads/' + path.split('/').map(encodeURIComponent).join('/'), { method: 'POST', body: { expiresIn: 3600 } })
      .then(function (j) { var u = j && (j.signedURL || j.signedUrl); return u ? (/^https?:/.test(u) ? u : CFG.url + '/storage/v1' + u) : ''; });
  }
  function safeUrl(u) { u = String(u || '').trim(); return /^https?:\/\//i.test(u) ? u : ''; }

  /* ---------- 표 설정 ---------- */
  var STATUS = { pending: '대기', approved: '승인', rejected: '반려', active: '정상', blocked: '차단' };
  var SOURCE = { quick: '간단 등록', detail: '상세 등록' };
  var TARGET = { all: '모두', fan: '손님', venue: '사장님', artist: '가수' };
  var PLACE = { all: '시작 화면 + 홈', start: '시작 화면', home: '홈' };
  function list(a) { return (a || []).join(', '); }
  function pill(s) { return '<span class="pill ' + esc(s) + '">' + esc(STATUS[s] || s) + '</span>'; }
  var T = {
    venues: {
      title: '라이브바 사장님', one: '사장님', nameOf: function (r) { return r.venue_name; }, search: ['venue_name', 'owner_name', 'phone', 'area'],
      statuses: ['pending', 'approved', 'rejected'], cols: '1.3fr 0.9fr 1fr 1.3fr 0.8fr 90px 70px',
      head: ['매장', '사장님', '연락처', '위치', '등록', '등록일', '상태'],
      cells: function (r) { return [r.venue_name, r.owner_name, r.phone, r.area, SOURCE[r.source], fmt(r.created_at)]; },
      fields: [['매장 이름', 'venue_name'], ['사장님 성함', 'owner_name'], ['연락처', 'phone'], ['위치 · 주소', 'area'], ['원하는 공연', 'styles', list], ['공연 가능 요일', 'open_days', list]],
      details: { category: '업종', biz_no: '사업자등록번호', capacity: '수용 인원', hours: '공연 가능 시간', pay: '공연비 방식', mood: '매장 분위기', equipment: '보유 장비' }
    },
    artists: {
      title: '가수', one: '가수', nameOf: function (r) { return r.name; }, search: ['name', 'phone', 'lineup'],
      statuses: ['pending', 'approved', 'rejected'], cols: '1.3fr 0.7fr 1.3fr 1fr 0.8fr 90px 70px',
      head: ['활동명', '편성', '장르', '연락처', '등록', '등록일', '상태'],
      cells: function (r) { return [r.name, r.lineup, list(r.genres), r.phone, SOURCE[r.source], fmt(r.created_at)]; },
      fields: [['활동명 · 팀명', 'name'], ['연락처', 'phone'], ['편성', 'lineup'], ['장르', 'genres', list], ['대표 링크', 'link', 'url']],
      details: { age: '나이', region: '활동 지역', bio: '소개 · 이력', careers: '공연 경력', audio_link: '음원 링크', video_link: '공연 영상 링크', audio_file: '음원 파일 (이름만)', video_file: '영상 파일 (이름만)' }
    },
    fans: {
      title: '손님', one: '손님', nameOf: function (r) { return r.name; }, search: ['name', 'phone', 'area'],
      statuses: ['active', 'blocked'], cols: '1.2fr 1fr 1.5fr 0.9fr 90px 70px',
      head: ['닉네임', '연락처', '좋아하는 장르', '자주 가는 동네', '등록일', '상태'],
      cells: function (r) { return [r.name, r.phone, list(r.genres), r.area, fmt(r.created_at)]; },
      fields: [['닉네임', 'name'], ['연락처', 'phone'], ['좋아하는 장르', 'genres', list], ['자주 가는 동네', 'area']],
      details: {}
    }
  };

  /* ---------- 화면 전환 ---------- */
  var view = $('#view');
  function showLogin(msg) {
    $('#shell').hidden = true; $('#login').hidden = false; closeDrawer();
    var er = $('#lg-err'); er.hidden = !msg; er.textContent = msg || '';
    setTimeout(function () { $('#lg-email').focus(); }, 0);
  }
  function showShell() {
    $('#login').hidden = true; $('#shell').hidden = false;
    $('#who').textContent = session.email || '';
    $('#open-app').href = CFG.appUrl || '#';
    route();
  }
  function route() {
    if (!session) return;
    var h = (location.hash || '#dashboard').slice(1);
    if (!VIEWS[h]) h = 'dashboard';
    $$('[data-nav]').forEach(function (a) { if (a.getAttribute('data-nav') === h) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    closeDrawer();
    view.innerHTML = '<p class="loading">불러오는 중…</p>';
    VIEWS[h]();
  }
  window.addEventListener('hashchange', route);

  /* ---------- 로그인 처리 ---------- */
  $('#login-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var em = $('#lg-email').value.trim(), pw = $('#lg-pw').value, er = $('#lg-err'), btn = $('#lg-btn');
    if (!em || !pw) { er.hidden = false; er.textContent = '이메일과 비밀번호를 입력해 주세요'; return; }
    btn.disabled = true; btn.textContent = '확인 중…'; er.hidden = true;
    authReq('password', { email: em, password: pw }).then(function (j) {
      setSession(j);
      return api('/rest/v1/rpc/is_admin', { method: 'POST', body: {} });
    }).then(function (ok) {
      if (ok !== true) { logout(true); throw new Error('관리자로 등록되지 않은 계정이에요. 관리자 등록 SQL을 실행했는지 확인해 주세요'); }
      $('#lg-pw').value = ''; showShell();
    }).catch(function (err) {
      var m = err && err.message || '';
      if (/invalid login credentials/i.test(m)) m = '이메일 또는 비밀번호가 맞지 않아요';
      else if (/not confirmed/i.test(m)) m = '이메일 인증이 안 된 계정이에요. Supabase에서 Auto Confirm으로 만들어 주세요';
      else if (err && err.status >= 500 || /fetch/i.test(m)) m = '서버에 연결하지 못했어요. 잠시 후 다시 시도해 주세요';
      if (!/관리자로 등록/.test(m)) { session = null; saveSession(); }
      er.hidden = false; er.textContent = m || '로그인하지 못했어요';
    }).then(function () { btn.disabled = false; btn.textContent = '로그인'; });
  });
  function logout(silent) {
    var s = session; session = null; saveSession();
    if (s) fetch(CFG.url + '/auth/v1/logout', { method: 'POST', headers: { apikey: CFG.key, Authorization: 'Bearer ' + s.access } }).catch(function () {});
    if (!silent) showLogin('');
  }
  $('#logout').addEventListener('click', function () { logout(false); });

  /* ---------- 상세 패널 ---------- */
  var lastFocus = null;
  function openDrawer(title, html) {
    lastFocus = document.activeElement;
    $('#dr-title').textContent = title; $('#dr-body').innerHTML = html;
    $('#drawer-bg').hidden = false; $('#dr-close').focus();
  }
  function closeDrawer() { var bg = $('#drawer-bg'); if (bg.hidden) return; bg.hidden = true; $('#dr-body').innerHTML = ''; if (lastFocus && lastFocus.focus) lastFocus.focus(); }
  $('#dr-close').addEventListener('click', closeDrawer);
  $('#drawer-bg').addEventListener('click', function (e) { if (e.target.id === 'drawer-bg') closeDrawer(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && $('#confirm').hidden) closeDrawer(); });

  /* ---------- 대시보드 ---------- */
  var VIEWS = {};
  VIEWS.dashboard = function () {
    var today = 'created_at=gte.' + encodeURIComponent(kstDate() + 'T00:00:00+09:00');
    Promise.all([
      count('venues'), count('venues', 'status=eq.pending'), count('artists'), count('artists', 'status=eq.pending'),
      count('fans'), count('fans', today), count('venues', today), count('artists', today),
      api('/rest/v1/popups?select=id,active'),
      api('/rest/v1/venues?select=id,created_at,venue_name,owner_name,status,source&order=created_at.desc&limit=6'),
      api('/rest/v1/artists?select=id,created_at,name,lineup,status,source&order=created_at.desc&limit=6'),
      api('/rest/v1/fans?select=id,created_at,name,area,status&order=created_at.desc&limit=6')
    ]).then(function (r) {
      var pops = r[8] || [], on = pops.filter(function (p) { return p.active; }).length;
      var recent = [].concat(
        (r[9] || []).map(function (x) { return { t: 'venues', id: x.id, at: x.created_at, kind: '사장님', name: x.venue_name, sub: x.owner_name || '', st: x.status }; }),
        (r[10] || []).map(function (x) { return { t: 'artists', id: x.id, at: x.created_at, kind: '가수', name: x.name, sub: x.lineup || '', st: x.status }; }),
        (r[11] || []).map(function (x) { return { t: 'fans', id: x.id, at: x.created_at, kind: '손님', name: x.name, sub: x.area || '', st: x.status }; })
      ).sort(function (a, b) { return a.at < b.at ? 1 : -1; }).slice(0, 10);
      function stat(href, label, n, small, zero) { return '<a class="stat" href="' + href + '"><span>' + label + '</span><b>' + won(n) + '</b><small class="' + (zero ? 'zero' : '') + '">' + small + '</small></a>'; }
      view.innerHTML = '<div class="vh"><div><h1>대시보드</h1><p>오늘 ' + esc(kstDate().replace(/-/g, '.')) + ' · 오늘 새로 등록 ' + won(r[5] + r[6] + r[7]) + '건</p></div></div>' +
        '<div class="stats">' +
        stat('#venues', '라이브바 사장님', r[0], r[1] ? '승인 대기 ' + won(r[1]) + '건' : '대기 없음', !r[1]) +
        stat('#artists', '가수', r[2], r[3] ? '승인 대기 ' + won(r[3]) + '건' : '대기 없음', !r[3]) +
        stat('#fans', '손님', r[4], r[5] ? '오늘 +' + won(r[5]) : '오늘 신규 없음', !r[5]) +
        stat('#popups', '켜진 팝업', on, '전체 ' + won(pops.length) + '개', !on) + '</div>' +
        '<div class="card"><h2>최근 등록</h2><div class="tbl" style="--cols:70px 1.4fr 1fr 100px 70px;border:0">' +
        (recent.length ? '<div class="tr th"><span class="td">구분</span><span class="td">이름</span><span class="td">정보</span><span class="td">등록일</span><span class="td">상태</span></div>' +
          recent.map(function (x) {
            return '<button type="button" class="tr" data-open="' + x.t + ':' + esc(x.id) + '"><span class="td dim" data-l="구분">' + x.kind + '</span><span class="td main">' + esc(x.name) + '</span>' +
              '<span class="td" data-l="정보">' + esc(x.sub) + '</span><span class="td dim" data-l="등록일">' + fmt(x.at) + '</span><span class="td st">' + pill(x.st) + '</span></button>';
          }).join('') : '<p class="empty">아직 등록된 정보가 없어요. 컨택싱어 시작 화면에서 정보를 입력하면 여기에 바로 보여요.</p>') + '</div></div>';
      $$('[data-open]', view).forEach(function (b) { b.addEventListener('click', function () { var p = b.getAttribute('data-open').split(':'); openRecord(p[0], p[1]); }); });
    }).catch(fail);
  };

  /* ---------- 사장님 · 가수 · 손님 목록 ---------- */
  var PAGE = 30, LS = {};
  function cleanQ(q) { return String(q || '').replace(/[,()*:"\\%]/g, ' ').trim().slice(0, 40); }
  function listView(t) {
    var cfg = T[t], st = LS[t] || (LS[t] = { status: '', q: '', page: 0 });
    view.innerHTML = '<div class="vh"><div><h1>' + cfg.title + '</h1><p id="ls-sum">불러오는 중…</p></div><span class="grow"></span><button type="button" class="btn ghost sm" id="ls-csv">엑셀(CSV) 내려받기</button></div>' +
      '<div class="tools"><input type="search" class="search" id="ls-q" placeholder="이름 · 연락처로 찾기" aria-label="' + cfg.title + ' 검색" value="' + esc(st.q) + '">' +
      '<div class="seg" role="group" aria-label="상태"><button type="button" data-st="">전체</button>' + cfg.statuses.map(function (s) { return '<button type="button" data-st="' + s + '">' + STATUS[s] + '</button>'; }).join('') + '</div></div>' +
      '<div class="tbl" id="ls-tbl" style="--cols:' + cfg.cols + '"></div><div class="pager"><span id="ls-range"></span><span class="row"><button type="button" class="btn ghost sm" id="ls-prev">이전</button><button type="button" class="btn ghost sm" id="ls-next">다음</button></span></div>';
    function drawSeg() { $$('[data-st]', view).forEach(function (b) { b.setAttribute('aria-pressed', b.getAttribute('data-st') === st.status ? 'true' : 'false'); }); }
    function filters() {
      var f = [];
      if (st.status) f.push('status=eq.' + st.status);
      var q = cleanQ(st.q);
      if (q) f.push('or=' + encodeURIComponent('(' + cfg.search.map(function (c) { return c + '.ilike.*' + q + '*'; }).join(',') + ')'));
      return f.join('&');
    }
    function load() {
      var tbl = $('#ls-tbl'); if (!tbl) return;
      tbl.innerHTML = '<p class="loading">불러오는 중…</p>';
      var f = filters();
      api('/rest/v1/' + t + '?select=*' + (f ? '&' + f : '') + '&order=created_at.desc&limit=' + PAGE + '&offset=' + st.page * PAGE, { raw: true, headers: { Prefer: 'count=exact' } }).then(function (x) {
        var rows = x.data || [], total = countOf(x.res);
        $('#ls-sum').textContent = '전체 ' + won(total) + '건' + (st.status ? ' · ' + STATUS[st.status] : '') + (cleanQ(st.q) ? ' · “' + cleanQ(st.q) + '” 검색' : '');
        $('#ls-range').textContent = total ? (st.page * PAGE + 1) + '–' + (st.page * PAGE + rows.length) + ' / ' + won(total) : '';
        $('#ls-prev').disabled = st.page === 0; $('#ls-next').disabled = (st.page + 1) * PAGE >= total;
        if (!rows.length) { tbl.innerHTML = '<p class="empty">' + (f ? '조건에 맞는 정보가 없어요' : '아직 등록된 ' + cfg.one + ' 정보가 없어요') + '</p>'; return; }
        tbl.innerHTML = '<div class="tr th">' + cfg.head.map(function (h) { return '<span class="td">' + h + '</span>'; }).join('') + '</div>' +
          rows.map(function (r) {
            var c = cfg.cells(r);
            return '<button type="button" class="tr" data-id="' + esc(r.id) + '">' + c.map(function (v, i) {
              return '<span class="td' + (i === 0 ? ' main' : '') + '" data-l="' + esc(cfg.head[i]) + '">' + esc(v || (i === 0 ? '(이름 없음)' : '-')) + '</span>';
            }).join('') + '<span class="td st">' + pill(r.status) + '</span></button>';
          }).join('');
        var byId = {}; rows.forEach(function (r) { byId[r.id] = r; });
        $$('.tr[data-id]', tbl).forEach(function (b) { b.addEventListener('click', function () { showRecord(t, byId[b.getAttribute('data-id')], load); }); });
      }).catch(fail);
    }
    var qt;
    $('#ls-q').addEventListener('input', function (e) { clearTimeout(qt); qt = setTimeout(function () { st.q = e.target.value; st.page = 0; load(); }, 300); });
    $$('[data-st]', view).forEach(function (b) { b.addEventListener('click', function () { st.status = b.getAttribute('data-st'); st.page = 0; drawSeg(); load(); }); });
    $('#ls-prev').addEventListener('click', function () { if (st.page > 0) { st.page--; load(); } });
    $('#ls-next').addEventListener('click', function () { st.page++; load(); });
    $('#ls-csv').addEventListener('click', function () { exportCsv(t, filters()); });
    drawSeg(); load();
  }
  VIEWS.venues = function () { listView('venues'); };
  VIEWS.artists = function () { listView('artists'); };
  VIEWS.fans = function () { listView('fans'); };

  function openRecord(t, id) {
    api('/rest/v1/' + t + '?select=*&id=eq.' + encodeURIComponent(id)).then(function (rows) {
      if (rows && rows[0]) showRecord(t, rows[0], function () { if ((location.hash || '#dashboard') === '#dashboard') VIEWS.dashboard(); });
    }).catch(fail);
  }

  function val2html(v, kind) {
    if (v == null || v === '' || (Array.isArray(v) && !v.length)) return '<span style="color:var(--muted)">-</span>';
    if (typeof kind === 'function') return esc(kind(v));
    if (kind === 'url' || (typeof v === 'string' && /^https?:\/\//i.test(v))) { var u = safeUrl(v); return u ? '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(v) + '</a>' : esc(v); }
    if (Array.isArray(v)) return esc(v.map(function (x) { return Array.isArray(x) ? x.filter(Boolean).join(' · ') : (typeof x === 'object' ? JSON.stringify(x) : x); }).join('\n'));
    if (typeof v === 'object') return esc(JSON.stringify(v));
    return esc(v);
  }
  function showRecord(t, r, reload) {
    var cfg = T[t], d = r.details || {}, dl = '';
    cfg.fields.forEach(function (f) { dl += '<dt>' + f[0] + '</dt><dd>' + val2html(r[f[1]], f[2]) + '</dd>'; });
    Object.keys(cfg.details).forEach(function (k) { if (d[k] != null && d[k] !== '' && !(Array.isArray(d[k]) && !d[k].length)) dl += '<dt>' + cfg.details[k] + '</dt><dd>' + val2html(d[k]) + '</dd>'; });
    Object.keys(d).forEach(function (k) { if (!(k in cfg.details) && d[k] != null && d[k] !== '') dl += '<dt>' + esc(k) + '</dt><dd>' + val2html(d[k]) + '</dd>'; });
    dl += '<dt>등록 방법</dt><dd>' + esc(SOURCE[r.source] || '시작 화면') + '</dd><dt>등록일</dt><dd>' + fmt(r.created_at, true) + '</dd>' + (r.updated_at ? '<dt>마지막 수정</dt><dd>' + fmt(r.updated_at, true) + '</dd>' : '');
    var phone = String(r.phone || '').replace(/[^0-9+]/g, '');
    var files = (r.photo_path || r.cert_path || (r.photo_paths && r.photo_paths.length)) ? '<section class="stack" id="dr-files"><h3 class="sec-t">첨부 파일</h3><p class="hint">불러오는 중…</p></section>' : '';
    var html = '<div class="row">' + pill(r.status) + (r.source ? '<span class="pill src">' + esc(SOURCE[r.source]) + '</span>' : '') + '<span class="grow"></span>' +
      (phone ? '<a class="btn ghost sm" href="tel:' + esc(phone) + '">전화</a><a class="btn ghost sm" href="sms:' + esc(phone) + '">문자</a>' : '') + '</div>' +
      '<dl class="dl">' + dl + '</dl>' + files +
      '<section class="stack"><h3 class="sec-t">상태 바꾸기</h3><div class="row">' + cfg.statuses.map(function (s) {
        return '<button type="button" class="btn sm ' + (s === 'approved' || s === 'active' ? 'ok' : s === 'rejected' || s === 'blocked' ? 'danger' : 'ghost') + '" data-set="' + s + '"' + (r.status === s ? ' disabled' : '') + '>' + STATUS[s] + (r.status === s ? ' (현재)' : '') + '</button>';
      }).join('') + '</div></section>' +
      '<section class="stack"><label class="fld"><span>관리자 메모 (운영팀만 보여요)</span><textarea id="dr-memo" maxlength="2000">' + esc(r.admin_memo || '') + '</textarea></label><div class="row end"><button type="button" class="btn sm" id="dr-memo-save">메모 저장</button></div></section>' +
      '<section class="stack" style="border-top:1px solid var(--line);padding-top:16px"><div class="row"><span class="hint grow">삭제하면 되돌릴 수 없어요. 첨부 파일도 함께 지워져요.</span><button type="button" class="btn danger sm" id="dr-del">삭제</button></div></section>';
    openDrawer(cfg.nameOf(r) || '(이름 없음)', html);
    var body = $('#dr-body');
    function patch(ch, msg) {
      return api('/rest/v1/' + t + '?id=eq.' + encodeURIComponent(r.id), { method: 'PATCH', body: ch, headers: { Prefer: 'return=representation' } }).then(function (rows) {
        if (!rows || !rows.length) throw Object.assign(new Error('no row'), { status: 403 });
        toast(msg); Object.assign(r, rows[0]); if (reload) reload(); showRecord(t, r, reload);
      }).catch(fail);
    }
    $$('[data-set]', body).forEach(function (b) { b.addEventListener('click', function () { var s = b.getAttribute('data-set'); patch({ status: s }, STATUS[s] + ' 상태로 바꿨어요'); }); });
    $('#dr-memo-save', body).addEventListener('click', function () { patch({ admin_memo: $('#dr-memo', body).value.trim() || null }, '메모를 저장했어요'); });
    $('#dr-del', body).addEventListener('click', function () {
      confirmBox(cfg.one + ' 정보를 삭제할까요?', '“' + (cfg.nameOf(r) || '') + '” 정보와 첨부 파일이 모두 지워지고 되돌릴 수 없어요.', '삭제').then(function (yes) {
        if (!yes) return;
        var paths = [].concat(r.photo_path || [], r.cert_path || [], r.photo_paths || []);
        (paths.length ? api('/storage/v1/object/uploads', { method: 'DELETE', body: { prefixes: paths } }).catch(function () { /* 파일이 없어도 계속 */ }) : Promise.resolve())
          .then(function () { return api('/rest/v1/' + t + '?id=eq.' + encodeURIComponent(r.id), { method: 'DELETE', headers: { Prefer: 'return=representation' } }); })
          .then(function (rows) { if (!rows || !rows.length) throw Object.assign(new Error('no row'), { status: 403 }); toast('삭제했어요'); closeDrawer(); if (reload) reload(); })
          .catch(fail);
      });
    });
    // 첨부 파일: 1시간짜리 임시 주소로 보여 준다 (비공개 저장소)
    var fbox = $('#dr-files', body);
    if (fbox) {
      var items = [];
      if (r.photo_path) items.push(['프로필 사진', r.photo_path]);
      if (r.cert_path) items.push(['사업자등록증', r.cert_path]);
      (r.photo_paths || []).forEach(function (p, i) { items.push(['매장 사진 ' + (i + 1), p]); });
      Promise.all(items.map(function (it) { return signedUrl(it[1]).catch(function () { return ''; }); })).then(function (urls) {
        if (!fbox.isConnected) return;
        var thumbs = '', links = '';
        items.forEach(function (it, i) {
          var u = urls[i]; if (!u) { links += '<span class="hint">' + esc(it[0]) + ': 불러오지 못했어요</span>'; return; }
          if (/\.pdf$/i.test(it[1])) links += '<a class="file-link" href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + esc(it[0]) + ' (PDF) 열기</a>';
          else thumbs += '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer" title="' + esc(it[0]) + '"><img src="' + esc(u) + '" alt="' + esc(it[0]) + '" loading="lazy"></a>';
        });
        fbox.innerHTML = '<h3 class="sec-t">첨부 파일</h3>' + (thumbs ? '<div class="thumbs">' + thumbs + '</div>' : '') + (links ? '<div class="row">' + links + '</div>' : '') + '<p class="hint">누르면 크게 열려요 · 주소는 1시간 동안만 열려요</p>';
      });
    }
  }

  function exportCsv(t, f) {
    var cfg = T[t];
    api('/rest/v1/' + t + '?select=*' + (f ? '&' + f : '') + '&order=created_at.desc&limit=5000').then(function (rows) {
      if (!rows || !rows.length) { toast('내려받을 정보가 없어요'); return; }
      var keys = Object.keys(rows[0]).filter(function (k) { return k !== 'details'; }), dk = Object.keys(cfg.details);
      var head = keys.concat(dk.map(function (k) { return cfg.details[k]; }));
      function cell(v) {
        if (v == null) v = ''; else if (Array.isArray(v)) v = v.map(function (x) { return Array.isArray(x) ? x.join(' ') : x; }).join(', '); else if (typeof v === 'object') v = JSON.stringify(v);
        v = String(v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;   // 엑셀 수식 실행 막기
        return '"' + v.replace(/"/g, '""') + '"';
      }
      var lines = [head.map(cell).join(',')].concat(rows.map(function (r) {
        return keys.map(function (k) { return cell(k === 'status' ? STATUS[r[k]] || r[k] : k === 'source' ? SOURCE[r[k]] || r[k] : k === 'created_at' || k === 'updated_at' ? fmt(r[k], true) : r[k]); })
          .concat(dk.map(function (k) { return cell((r.details || {})[k]); })).join(',');
      }));
      var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }), a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'contactsinger_' + t + '_' + kstDate().replace(/-/g, '') + '.csv';   // 한글 파일 이름은 일부 브라우저에서 'download'로 바뀌어 영문으로
      document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
      toast(won(rows.length) + '건을 내려받았어요');
    }).catch(fail);
  }

  /* ---------- 팝업 ---------- */
  VIEWS.popups = function () {
    api('/rest/v1/popups?select=*&order=sort.asc,created_at.desc').then(function (rows) {
      rows = rows || [];
      view.innerHTML = '<div class="vh"><div><h1>팝업</h1><p>켜진 팝업은 컨택싱어 앱의 시작 화면 · 홈에 바로 떠요. 한 번에 하나씩, 순서가 빠른 것부터 보여요.</p></div><span class="grow"></span><button type="button" class="btn primary sm" id="pp-new">새 팝업 만들기</button></div>' +
        '<div class="plist">' + (rows.length ? rows.map(function (p) {
          var period = (p.starts_on || p.ends_on) ? (p.starts_on || '처음부터') + ' ~ ' + (p.ends_on || '계속') : '기간 제한 없음';
          var bu = safeUrl(p.image_url).replace(/[\s'"()\\]/g, function (c) { return encodeURIComponent(c); });
          return '<div class="pitem"><span class="pi-img" ' + (bu ? 'style="background-image:url(\'' + esc(bu) + '\')"' : '') + '></span>' +
            '<span class="pi-t"><b>' + esc(p.title) + '</b><span>' + esc(TARGET[p.target]) + ' · ' + esc(PLACE[p.place]) + ' · ' + esc(period) + ' · 순서 ' + esc(p.sort) + '</span></span>' +
            '<label class="switch"><input type="checkbox" data-tg="' + esc(p.id) + '"' + (p.active ? ' checked' : '') + ' aria-label="' + esc(p.title) + ' 켜기"><span>' + (p.active ? '켜짐' : '꺼짐') + '</span></label>' +
            '<button type="button" class="btn ghost sm" data-ed="' + esc(p.id) + '">편집</button></div>';
        }).join('') : '<div class="card"><p class="empty">아직 만든 팝업이 없어요. ‘새 팝업 만들기’로 첫 팝업을 만들어 보세요.</p></div>') + '</div>';
      var byId = {}; rows.forEach(function (p) { byId[p.id] = p; });
      $('#pp-new').addEventListener('click', function () { popupEditor(null); });
      $$('[data-ed]', view).forEach(function (b) { b.addEventListener('click', function () { popupEditor(byId[b.getAttribute('data-ed')]); }); });
      $$('[data-tg]', view).forEach(function (c) {
        c.addEventListener('change', function () {
          var on = c.checked;
          api('/rest/v1/popups?id=eq.' + encodeURIComponent(c.getAttribute('data-tg')), { method: 'PATCH', body: { active: on }, headers: { Prefer: 'return=minimal' } })
            .then(function () { c.nextElementSibling.textContent = on ? '켜짐' : '꺼짐'; toast(on ? '팝업을 켰어요 · 앱에 바로 떠요' : '팝업을 껐어요'); })
            .catch(function (e) { c.checked = !on; fail(e); });
        });
      });
    }).catch(fail);
  };
  function popupEditor(p) {
    var isNew = !p; p = p || { title: '', body: '', image_url: '', link_url: '', link_label: '', target: 'all', place: 'all', starts_on: '', ends_on: '', active: true, sort: 0 };
    function opts(map, cur) { return Object.keys(map).map(function (k) { return '<option value="' + k + '"' + (k === cur ? ' selected' : '') + '>' + map[k] + '</option>'; }).join(''); }
    view.innerHTML = '<div class="vh"><div><h1>' + (isNew ? '새 팝업' : '팝업 편집') + '</h1><p>오른쪽 미리보기처럼 앱에 떠요.</p></div><span class="grow"></span><a class="btn ghost sm" href="#popups" id="pe-back">목록으로</a></div>' +
      '<div class="editor"><form class="card stack" id="pe-form" novalidate>' +
      '<label class="fld"><span>제목 *</span><input type="text" id="pe-title" maxlength="80" required value="' + esc(p.title) + '"></label>' +
      '<label class="fld"><span>내용</span><textarea id="pe-body" maxlength="1000">' + esc(p.body || '') + '</textarea><small>줄바꿈이 그대로 보여요</small></label>' +
      '<div class="fld"><span>이미지</span><div class="row"><input type="url" id="pe-img" placeholder="https:// 로 시작하는 이미지 주소" value="' + esc(p.image_url || '') + '" style="flex:1;min-width:200px">' +
      '<label class="btn ghost sm" style="cursor:pointer">파일 올리기<input type="file" id="pe-file" accept="image/jpeg,image/png,image/webp,image/gif" class="sr"></label></div><small>5MB 이하 JPG · PNG · WEBP · GIF</small></div>' +
      '<div class="grid2"><label class="fld"><span>버튼 문구</span><input type="text" id="pe-ll" maxlength="30" placeholder="예: 자세히 보기" value="' + esc(p.link_label || '') + '"></label>' +
      '<label class="fld"><span>버튼 링크</span><input type="text" id="pe-lu" maxlength="500" placeholder="https://… 또는 booking.html" value="' + esc(p.link_url || '') + '"></label></div>' +
      '<div class="grid2"><label class="fld"><span>보여줄 대상</span><select id="pe-target">' + opts(TARGET, p.target) + '</select></label>' +
      '<label class="fld"><span>보여줄 화면</span><select id="pe-place">' + opts(PLACE, p.place) + '</select></label></div>' +
      '<div class="grid2"><label class="fld"><span>시작일 (비우면 바로)</span><input type="date" id="pe-start" value="' + esc(p.starts_on || '') + '"></label>' +
      '<label class="fld"><span>종료일 (비우면 계속)</span><input type="date" id="pe-end" value="' + esc(p.ends_on || '') + '"></label></div>' +
      '<div class="grid2"><label class="fld"><span>순서 (작을수록 먼저)</span><input type="number" id="pe-sort" value="' + esc(p.sort || 0) + '"></label>' +
      '<label class="check" style="align-self:end"><input type="checkbox" id="pe-active"' + (p.active ? ' checked' : '') + '>저장하면 바로 켜기</label></div>' +
      '<p class="err" id="pe-err" role="alert" hidden></p>' +
      '<div class="row">' + (isNew ? '' : '<button type="button" class="btn danger sm" id="pe-del">삭제</button>') + '<span class="grow"></span><a class="btn ghost" href="#popups">취소</a><button type="submit" class="btn primary" id="pe-save">저장</button></div>' +
      '</form><div class="preview"><span class="sec-t">미리보기</span><div class="phone"><div class="pv-pop" id="pv"></div></div></div></div>';
    function v(id) { return $('#' + id).value.trim(); }
    function linkOk(u) { return !u || /^https?:\/\//i.test(u) || /^[a-z0-9-]+\.html([?#].*)?$/i.test(u); }
    function drawPv() {
      var img = safeUrl(v('pe-img')), pv = $('#pv');
      pv.innerHTML = (img ? '<img alt="">' : '') + '<div class="pb"><h3></h3><p></p>' + (v('pe-lu') ? '<span class="btn primary sm block"></span>' : '') + '</div><div class="pf"><span>오늘 하루 보지 않기</span><span>닫기</span></div>';
      if (img) $('img', pv).src = img;
      $('h3', pv).textContent = v('pe-title') || '제목을 입력하세요';
      $('p', pv).textContent = $('#pe-body').value; $('p', pv).hidden = !$('#pe-body').value.trim();
      var b = $('.btn', pv); if (b) b.textContent = v('pe-ll') || '자세히 보기';
    }
    $$('#pe-form input, #pe-form textarea, #pe-form select').forEach(function (el) { el.addEventListener('input', drawPv); });
    drawPv();
    $('#pe-file').addEventListener('change', function (e) {
      var f = e.target.files[0]; if (!f) return;
      if (f.size > 5 * 1024 * 1024) { toast('5MB 이하 이미지만 올릴 수 있어요'); return; }
      var m = (f.name || '').match(/\.([a-z0-9]{2,5})$/i), path = 'popup/' + kstDate() + '-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8) + '.' + (m ? m[1].toLowerCase() : 'jpg');
      toast('이미지를 올리는 중…');
      api('/storage/v1/object/public-assets/' + path, { method: 'POST', body: f, headers: { 'Content-Type': f.type || 'image/jpeg', 'x-upsert': 'false' } }).then(function () {
        $('#pe-img').value = CFG.url + '/storage/v1/object/public/public-assets/' + path; drawPv(); toast('이미지를 올렸어요');
      }).catch(fail);
    });
    $('#pe-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var er = $('#pe-err'), body = {
        title: v('pe-title'), body: $('#pe-body').value.trim() || null, image_url: v('pe-img') || null, link_url: v('pe-lu') || null, link_label: v('pe-ll') || null,
        target: $('#pe-target').value, place: $('#pe-place').value, starts_on: v('pe-start') || null, ends_on: v('pe-end') || null,
        sort: parseInt(v('pe-sort'), 10) || 0, active: $('#pe-active').checked
      };
      var msg = !body.title ? '제목을 입력해 주세요' : (body.image_url && !safeUrl(body.image_url)) ? '이미지 주소는 https:// 로 시작해야 해요'
        : !linkOk(body.link_url) ? '버튼 링크는 https:// 주소나 앱 화면 이름(예: booking.html)만 쓸 수 있어요'
        : (body.starts_on && body.ends_on && body.starts_on > body.ends_on) ? '종료일이 시작일보다 빨라요' : '';
      if (msg) { er.hidden = false; er.textContent = msg; return; }
      er.hidden = true; $('#pe-save').disabled = true;
      (isNew ? api('/rest/v1/popups', { method: 'POST', body: body, headers: { Prefer: 'return=minimal' } })
             : api('/rest/v1/popups?id=eq.' + encodeURIComponent(p.id), { method: 'PATCH', body: body, headers: { Prefer: 'return=minimal' } }))
        .then(function () { toast(body.active ? '저장했어요 · 앱에 바로 떠요' : '저장했어요'); location.hash = '#popups'; if (location.hash === '#popups') VIEWS.popups(); })
        .catch(function (err) { $('#pe-save').disabled = false; fail(err); });
    });
    var del = $('#pe-del');
    if (del) del.addEventListener('click', function () {
      confirmBox('팝업을 삭제할까요?', '“' + p.title + '” 팝업이 지워지고 되돌릴 수 없어요.', '삭제').then(function (yes) {
        if (!yes) return;
        api('/rest/v1/popups?id=eq.' + encodeURIComponent(p.id), { method: 'DELETE', headers: { Prefer: 'return=minimal' } }).then(function () { toast('삭제했어요'); location.hash = '#popups'; }).catch(fail);
      });
    });
    $('#pe-title').focus();
  }

  /* ---------- 앱 설정 ---------- */
  var FEATS = [['signup', '신규 등록 받기', '끄면 시작 화면 · 상세 등록에서 정보 보내기가 막혀요 (둘러보기는 가능)'], ['booking', '예약', '예약 화면'], ['tip', '현장 팁', '현장 팁 화면'],
               ['feed', '피드', '피드 화면'], ['clip', '공연 영상', '전체 화면 공연 영상'], ['match', '컨택 · 매칭', '가수의 무대 컨택 · 사장님의 가수 컨택 화면']];
  VIEWS.settings = function () {
    api('/rest/v1/app_settings?select=key,value,updated_at').then(function (rows) {
      var s = {}; (rows || []).forEach(function (r) { s[r.key] = r; });
      var n = (s.notice || {}).value || {}, m = (s.maintenance || {}).value || {}, f = (s.features || {}).value || {};
      function upd(k) { return s[k] && s[k].updated_at ? '<small class="hint">마지막 저장 ' + fmt(s[k].updated_at, true) + '</small>' : ''; }
      view.innerHTML = '<div class="vh"><div><h1>앱 설정</h1><p>저장하면 컨택싱어 앱에 바로 반영돼요. (앱을 새로 열 때 적용)</p></div></div><div class="stack">' +
        '<form class="card stack" id="st-notice"><h2>공지 배너</h2><p class="hint" style="margin-top:-6px">앱 화면 맨 위에 한 줄로 보여요. 손님이 닫으면 문구가 바뀔 때까지 안 보여요.</p>' +
        '<label class="switch"><input type="checkbox" id="nt-on"' + (n.on ? ' checked' : '') + '><span>공지 켜기</span></label>' +
        '<label class="fld"><span>공지 문구</span><input type="text" id="nt-text" maxlength="80" value="' + esc(n.text || '') + '" placeholder="예: 이번 주 금요일은 대관으로 공연이 없어요"></label>' +
        '<label class="fld"><span>누르면 이동할 주소 (선택)</span><input type="text" id="nt-link" maxlength="300" value="' + esc(n.link || '') + '" placeholder="https://… 또는 schedule.html"></label>' +
        '<div class="notice-pv" id="nt-pv"><i>공지</i><span></span></div><div class="row">' + upd('notice') + '<span class="grow"></span><button type="submit" class="btn sm">공지 저장</button></div></form>' +
        '<form class="card stack" id="st-maint"><h2>점검 모드</h2><div class="warn-box">켜면 컨택싱어 앱의 모든 화면이 점검 안내로 바뀌어요. 관리자 사이트는 그대로 쓸 수 있어요.</div>' +
        '<label class="switch"><input type="checkbox" id="mt-on"' + (m.on ? ' checked' : '') + '><span>점검 모드 켜기</span></label>' +
        '<label class="fld"><span>안내 문구</span><textarea id="mt-msg" maxlength="300">' + esc(m.message || '') + '</textarea></label><div class="row">' + upd('maintenance') + '<span class="grow"></span><button type="submit" class="btn sm">점검 모드 저장</button></div></form>' +
        '<form class="card stack" id="st-feat"><h2>기능 켜기 · 끄기</h2><p class="hint" style="margin-top:-6px">끈 기능은 앱의 메뉴에서 사라지고, 주소로 들어오면 ‘잠시 쉬고 있어요’ 안내가 떠요.</p>' +
        FEATS.map(function (x) { return '<label class="check"><input type="checkbox" data-f="' + x[0] + '"' + (f[x[0]] !== false ? ' checked' : '') + '><span><b>' + x[1] + '</b> <span class="hint">' + x[2] + '</span></span></label>'; }).join('') +
        '<div class="row">' + upd('features') + '<span class="grow"></span><button type="submit" class="btn sm">기능 설정 저장</button></div></form></div>';
      function pv() { $('#nt-pv span').textContent = $('#nt-text').value || '공지 문구가 여기에 보여요'; $('#nt-pv').style.opacity = $('#nt-on').checked ? 1 : 0.45; }
      $('#nt-text').addEventListener('input', pv); $('#nt-on').addEventListener('change', pv); pv();
      function save(key, value, msg) {
        return api('/rest/v1/app_settings?on_conflict=key', { method: 'POST', body: { key: key, value: value }, headers: { Prefer: 'resolution=merge-duplicates,return=minimal' } })
          .then(function () { toast(msg); VIEWS.settings(); }).catch(fail);
      }
      $('#st-notice').addEventListener('submit', function (e) {
        e.preventDefault();
        var on = $('#nt-on').checked, text = $('#nt-text').value.trim(), link = $('#nt-link').value.trim();
        if (on && !text) { toast('공지 문구를 입력해 주세요'); return; }
        if (link && !(/^https?:\/\//i.test(link) || /^[a-z0-9-]+\.html([?#].*)?$/i.test(link))) { toast('주소는 https:// 또는 앱 화면 이름(예: schedule.html)만 쓸 수 있어요'); return; }
        save('notice', { on: on, text: text, link: link }, on ? '공지를 켰어요' : '공지를 저장했어요');
      });
      $('#st-maint').addEventListener('submit', function (e) {
        e.preventDefault();
        var on = $('#mt-on').checked, msg = $('#mt-msg').value.trim();
        (on ? confirmBox('점검 모드를 켤까요?', '앱을 여는 모든 사람에게 점검 안내만 보여요.', '켜기') : Promise.resolve(true)).then(function (yes) {
          if (yes) save('maintenance', { on: on, message: msg }, on ? '점검 모드를 켰어요' : '점검 모드를 저장했어요');
        });
      });
      $('#st-feat').addEventListener('submit', function (e) {
        e.preventDefault();
        var val = {}; $$('[data-f]', view).forEach(function (c) { val[c.getAttribute('data-f')] = c.checked; });
        save('features', val, '기능 설정을 저장했어요');
      });
    }).catch(fail);
  };

  /* ---------- 시작 ---------- */
  if (!CFG.url || !CFG.key) { showLogin('config.js 에 서버 주소와 키를 넣어 주세요'); return; }
  if (!session) { showLogin(''); return; }
  ensureToken().then(function () { return api('/rest/v1/rpc/is_admin', { method: 'POST', body: {} }); })
    .then(function (ok) { if (ok === true) showShell(); else { logout(true); showLogin('관리자로 등록되지 않은 계정이에요'); } })
    .catch(function (e) { if (e && e.auth) showLogin('다시 로그인해 주세요'); else showLogin('서버에 연결하지 못했어요. 잠시 후 새로고침해 주세요'); });
})();
