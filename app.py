from flask import Flask, request, jsonify, session, render_template
from functools import wraps
import sqlite3, hashlib, os, datetime, urllib.request, urllib.error, json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'nonghyup-secret-change-me')

# Railway는 /app 디렉토리에서 실행됨
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nonghyup.db')

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        uid TEXT PRIMARY KEY, name TEXT NOT NULL, id TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL, role TEXT DEFAULT '견습',
        status TEXT DEFAULT 'pending', is_admin INTEGER DEFAULT 0, joined TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notices (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, cat TEXT,
        body TEXT, author TEXT, pinned INTEGER DEFAULT 0, created TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT, seller TEXT, buyer TEXT, item TEXT,
        amount INTEGER DEFAULT 0, qty INTEGER DEFAULT 1, date TEXT, created TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, uid TEXT, reason TEXT,
        period TEXT, days INTEGER DEFAULT -1, start_date TEXT, date TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        price INTEGER NOT NULL, daily_limit INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_uid TEXT,
        user_name TEXT, date TEXT, time TEXT, type TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS ranks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)''')
    for rn in ['고위직','간부','조직원','견습']:
        try: c.execute("INSERT OR IGNORE INTO ranks (name) VALUES (?)", (rn,))
        except: pass
    if not c.execute('SELECT id FROM users WHERE id=?', ('admin',)).fetchone():
        c.execute('INSERT INTO users (uid,name,id,pw_hash,role,status,is_admin,joined) VALUES (?,?,?,?,?,?,?,?)',
                  ('#0001','관리자','admin',hash_pw('wowls4348'),'고위직','active',1,str(datetime.date.today())))
    else:
        c.execute("UPDATE users SET pw_hash=? WHERE id='admin' AND pw_hash=?",
                  (hash_pw('wowls4348'), hash_pw('admin123')))
    for alter in [
        "ALTER TABLE items ADD COLUMN daily_limit INTEGER DEFAULT 0",
        "ALTER TABLE blacklist ADD COLUMN days INTEGER DEFAULT -1",
        "ALTER TABLE blacklist ADD COLUMN start_date TEXT",
    ]:
        try: c.execute(alter)
        except: pass
    conn.commit(); conn.close()

def expire_blacklist():
    today = datetime.date.today()
    conn = get_db()
    rows = conn.execute("SELECT id,start_date,days FROM blacklist WHERE days>0 AND start_date IS NOT NULL").fetchall()
    for row in rows:
        try:
            start = datetime.date.fromisoformat(row['start_date'])
            if today > start + datetime.timedelta(days=row['days']):
                conn.execute("DELETE FROM blacklist WHERE id=?", (row['id'],))
        except: pass
    conn.commit(); conn.close()

def bl_remain(start_str, days):
    if days <= 0: return -1
    try:
        start = datetime.date.fromisoformat(start_str)
        return max(0, (start + datetime.timedelta(days=days) - datetime.date.today()).days)
    except: return -1

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if 'user_uid' not in session: return jsonify({'ok':False,'msg':'로그인이 필요합니다.'}), 401
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if 'user_uid' not in session: return jsonify({'ok':False,'msg':'로그인이 필요합니다.'}), 401
        if not session.get('is_admin'): return jsonify({'ok':False,'msg':'관리자 권한이 필요합니다.'}), 403
        return f(*a, **kw)
    return d

def highrank_required(f):
    @wraps(f)
    def d(*a, **kw):
        if 'user_uid' not in session: return jsonify({'ok':False,'msg':'로그인이 필요합니다.'}), 401
        if session.get('is_admin'): return f(*a, **kw)
        conn = get_db()
        u = conn.execute('SELECT role FROM users WHERE uid=?', (session['user_uid'],)).fetchone()
        conn.close()
        if not u or u['role'] not in ('고위직','가장'): return jsonify({'ok':False,'msg':'고위직 이상만 접근 가능합니다.'}), 403
        return f(*a, **kw)
    return d

@app.route('/')
def index():
    expire_blacklist()
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.json; lid = d.get('id',''); pw = d.get('pw','')
    conn = get_db()
    by_id = conn.execute('SELECT * FROM users WHERE id=?', (lid,)).fetchone()
    if not by_id: conn.close(); return jsonify({'ok':False,'msg':'존재하지 않는 계정입니다. 회원가입을 해주세요!'})
    u = conn.execute('SELECT * FROM users WHERE id=? AND pw_hash=?', (lid,hash_pw(pw))).fetchone()
    conn.close()
    if not u: return jsonify({'ok':False,'msg':'비밀번호가 틀렸습니다.'})
    if u['status']=='pending': return jsonify({'ok':False,'msg':'관리자 승인 대기 중입니다.'})
    if u['status']=='banned':  return jsonify({'ok':False,'msg':'회원가입을 해주세요!'})
    session.update({'user_uid':u['uid'],'user_name':u['name'],'user_role':u['role'],'is_admin':bool(u['is_admin'])})
    return jsonify({'ok':True,'user':{'uid':u['uid'],'name':u['name'],'role':u['role'],'isAdmin':bool(u['is_admin'])}})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear(); return jsonify({'ok':True})

@app.route('/api/register', methods=['POST'])
def api_register():
    d = request.json; nick=d.get('name','').strip(); uid=d.get('uid','').strip()
    lid=d.get('id','').strip(); pw=d.get('pw','').strip()
    if not nick or not lid or not pw: return jsonify({'ok':False,'msg':'필수 항목을 입력해 주세요.'})
    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE id=?',(lid,)).fetchone(): conn.close(); return jsonify({'ok':False,'msg':'이미 사용 중인 아이디입니다.'})
    if not uid: uid = '#'+str(conn.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']+1).zfill(4)
    conn.execute('INSERT INTO users (uid,name,id,pw_hash,role,status,is_admin,joined) VALUES (?,?,?,?,?,?,?,?)',
                 (uid,nick,lid,hash_pw(pw),'견습','pending',0,str(datetime.date.today())))
    conn.commit(); conn.close()
    return jsonify({'ok':True,'msg':'가입 신청이 완료되었습니다.'})

@app.route('/api/me')
def api_me():
    if 'user_uid' not in session: return jsonify({'ok':False})
    return jsonify({'ok':True,'user':{'uid':session['user_uid'],'name':session['user_name'],'role':session['user_role'],'isAdmin':session.get('is_admin',False)}})

@app.route('/api/users/count')
@login_required
def api_users_count():
    conn=get_db()
    total=conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    active=conn.execute("SELECT COUNT(*) as c FROM users WHERE status='active'").fetchone()['c']
    pending=conn.execute("SELECT COUNT(*) as c FROM users WHERE status='pending'").fetchone()['c']
    conn.close(); return jsonify({'total':total,'active':active,'pending':pending})

@app.route('/api/users')
@admin_required
def api_users():
    conn=get_db()
    rows=conn.execute('SELECT uid,name,id,role,status,is_admin,joined FROM users ORDER BY joined').fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/users/<uid>', methods=['PUT'])
@admin_required
def api_user_update(uid):
    d=request.json; conn=get_db()
    cur=conn.execute('SELECT name FROM users WHERE uid=?',(uid,)).fetchone()
    old_name=cur['name'] if cur else ''
    fields,vals=[],[]
    for k,col in [('name','name=?'),('role','role=?'),('status','status=?'),('is_admin','is_admin=?'),('uid','uid=?')]:
        if k in d:
            fields.append(col)
            vals.append(1 if k=='is_admin' and d[k] else (0 if k=='is_admin' else d[k]))
    if 'pw' in d: fields.append('pw_hash=?'); vals.append(hash_pw(d['pw']))
    if fields: vals.append(uid); conn.execute('UPDATE users SET '+','.join(fields)+' WHERE uid=?',vals)
    new_name=d.get('name','')
    if new_name and new_name!=old_name:
        conn.execute('UPDATE ledger SET seller=? WHERE seller=?',(new_name,old_name))
        conn.execute('UPDATE attendance SET user_name=? WHERE user_name=?',(new_name,old_name))
    if uid==session.get('user_uid'):
        if 'name' in d: session['user_name']=d['name']
        if 'role' in d: session['user_role']=d['role']
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/users/<uid>/kick', methods=['POST'])
@admin_required
def api_user_kick(uid):
    conn=get_db(); conn.execute("DELETE FROM users WHERE uid=?",(uid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/users/<uid>/approve', methods=['POST'])
@admin_required
def api_user_approve(uid):
    conn=get_db(); conn.execute("UPDATE users SET status='active' WHERE uid=?",(uid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/ranks')
@login_required
def api_ranks_get():
    conn=get_db(); rows=conn.execute('SELECT name FROM ranks ORDER BY id').fetchall(); conn.close(); return jsonify([r['name'] for r in rows])

@app.route('/api/ranks', methods=['POST'])
@admin_required
def api_ranks_create():
    name=request.json.get('name','').strip()
    if not name: return jsonify({'ok':False,'msg':'직급명을 입력해 주세요.'})
    conn=get_db()
    try: conn.execute('INSERT INTO ranks (name) VALUES (?)',(name,)); conn.commit(); conn.close(); return jsonify({'ok':True})
    except: conn.close(); return jsonify({'ok':False,'msg':'이미 존재하는 직급입니다.'})

@app.route('/api/ranks/<name>', methods=['DELETE'])
@admin_required
def api_ranks_delete(name):
    conn=get_db(); conn.execute('DELETE FROM ranks WHERE name=?',(name,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/notices')
@login_required
def api_notices():
    conn=get_db(); rows=conn.execute('SELECT * FROM notices ORDER BY pinned DESC,id DESC').fetchall(); conn.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/notices', methods=['POST'])
@admin_required
def api_notice_create():
    d=request.json; conn=get_db()
    conn.execute('INSERT INTO notices (title,cat,body,author,pinned,created) VALUES (?,?,?,?,?,?)',
                 (d['title'],d.get('cat','일반 공지'),d['body'],session['user_name'],1 if d.get('pinned') else 0,str(datetime.date.today())))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/notices/<int:nid>', methods=['DELETE'])
@admin_required
def api_notice_delete(nid):
    conn=get_db(); conn.execute('DELETE FROM notices WHERE id=?',(nid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/ledger')
@login_required
def api_ledger():
    conn=get_db(); rows=conn.execute('SELECT * FROM ledger ORDER BY id DESC').fetchall(); conn.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/ledger', methods=['POST'])
@login_required
def api_ledger_create():
    d=request.json; today=str(datetime.date.today()); conn=get_db()
    item_str=d.get('item','')
    items_db=conn.execute('SELECT * FROM items').fetchall()
    item_map={it['name']:it for it in items_db}
    today_rows=conn.execute("SELECT item,qty FROM ledger WHERE date=?",(today,)).fetchall()
    sold_today={}
    for row in today_rows:
        for part in row['item'].split(','):
            part=part.strip()
            if ' x' in part:
                name,qs=part.rsplit(' x',1)
                name=name.strip()
                try: sold_today[name]=sold_today.get(name,0)+int(qs)
                except: pass
    for part in item_str.split(','):
        part=part.strip()
        if ' x' in part:
            name,qs=part.rsplit(' x',1); name=name.strip()
            try: rq=int(qs)
            except: rq=1
            if name in item_map:
                lim=item_map[name]['daily_limit'] or 0
                if lim>0:
                    already=sold_today.get(name,0)
                    if already+rq>lim:
                        conn.close()
                        return jsonify({'ok':False,'msg':f'"{name}" 일일 한도 초과! 오늘 {already}개 판매됨. 잔여: {max(0,lim-already)}개'})
    conn.execute('INSERT INTO ledger (seller,buyer,item,amount,qty,date,created) VALUES (?,?,?,?,?,?,?)',
                 (d['seller'],d.get('buyer',''),item_str,int(d.get('amount',0)),int(d.get('qty',1)),today,str(datetime.datetime.now())))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/ledger/today_sold')
@login_required
def api_ledger_today_sold():
    today=str(datetime.date.today()); conn=get_db()
    rows=conn.execute("SELECT item,qty FROM ledger WHERE date=?",(today,)).fetchall(); conn.close()
    sold={}
    for row in rows:
        for part in row['item'].split(','):
            part=part.strip()
            if ' x' in part:
                name,qs=part.rsplit(' x',1); name=name.strip()
                try: sold[name]=sold.get(name,0)+int(qs)
                except: pass
    return jsonify(sold)

@app.route('/api/ledger/rename_seller', methods=['POST'])
@admin_required
def api_ledger_rename_seller():
    d=request.json; old=d.get('old_name','').strip(); new=d.get('new_name','').strip()
    if not old or not new: return jsonify({'ok':False,'msg':'이름을 입력해 주세요.'})
    conn=get_db()
    conn.execute('UPDATE ledger SET seller=? WHERE seller=?',(new,old))
    conn.execute('UPDATE attendance SET user_name=? WHERE user_name=?',(new,old))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/ledger/<int:lid>', methods=['PUT'])
@admin_required
def api_ledger_update(lid):
    d=request.json; conn=get_db()
    conn.execute('UPDATE ledger SET seller=?,buyer=?,item=?,amount=?,date=? WHERE id=?',
                 (d['seller'],d.get('buyer',''),d['item'],int(d.get('amount',0)),d.get('date',''),lid))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/ledger/<int:lid>', methods=['DELETE'])
@admin_required
def api_ledger_delete(lid):
    conn=get_db(); conn.execute('DELETE FROM ledger WHERE id=?',(lid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/blacklist')
@login_required
def api_blacklist():
    expire_blacklist(); conn=get_db()
    rows=conn.execute('SELECT * FROM blacklist ORDER BY id DESC').fetchall(); conn.close()
    result=[]
    for r in rows:
        row=dict(r); row['remain']=bl_remain(row.get('start_date',''),row.get('days',-1)); result.append(row)
    return jsonify(result)

@app.route('/api/blacklist', methods=['POST'])
@highrank_required
def api_blacklist_create():
    d=request.json; raw=d.get('period','영구').strip(); today=str(datetime.date.today())
    if raw.isdigit(): days=int(raw); ps=raw+'일'
    elif raw in ('영구',''): days=-1; ps='영구'
    else:
        num=''.join(filter(str.isdigit,raw))
        if num: days=int(num); ps=num+'일'
        else: days=-1; ps=raw
    conn=get_db()
    conn.execute('INSERT INTO blacklist (name,uid,reason,period,days,start_date,date) VALUES (?,?,?,?,?,?,?)',
                 (d['name'],d.get('uid','-'),d['reason'],ps,days,today,today))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/blacklist/<int:bid>', methods=['DELETE'])
@highrank_required
def api_blacklist_delete(bid):
    conn=get_db(); conn.execute('DELETE FROM blacklist WHERE id=?',(bid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/items')
@login_required
def api_items():
    conn=get_db(); rows=conn.execute('SELECT * FROM items ORDER BY id').fetchall(); conn.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/items', methods=['POST'])
@admin_required
def api_items_create():
    d=request.json; conn=get_db()
    conn.execute('INSERT INTO items (name,price,daily_limit) VALUES (?,?,?)',(d['name'],int(d['price']),int(d.get('daily_limit',0))))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/items/<int:iid>', methods=['PUT'])
@admin_required
def api_items_update(iid):
    d=request.json; conn=get_db(); fields,vals=[],[]
    if 'name' in d: fields.append('name=?'); vals.append(d['name'])
    if 'price' in d: fields.append('price=?'); vals.append(int(d['price']))
    if 'daily_limit' in d: fields.append('daily_limit=?'); vals.append(int(d['daily_limit']))
    if fields: vals.append(iid); conn.execute('UPDATE items SET '+','.join(fields)+' WHERE id=?',vals); conn.commit()
    conn.close(); return jsonify({'ok':True})

@app.route('/api/items/<int:iid>', methods=['DELETE'])
@admin_required
def api_items_delete(iid):
    conn=get_db(); conn.execute('DELETE FROM items WHERE id=?',(iid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/config', methods=['GET'])
@login_required
def api_config_get():
    conn=get_db(); rows=conn.execute('SELECT key,value FROM config').fetchall(); conn.close(); return jsonify({r['key']:r['value'] for r in rows})

@app.route('/api/config', methods=['POST'])
@admin_required
def api_config_set():
    conn=get_db()
    for k,v in request.json.items(): conn.execute('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)',(k,v))
    conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/webhook/send', methods=['POST'])
@login_required
def api_webhook_send():
    conn=get_db(); row=conn.execute("SELECT value FROM config WHERE key='webhook'").fetchone(); conn.close()
    if not row or not row['value']: return jsonify({'ok':False,'msg':'웹훅 URL이 설정되지 않았습니다.'})
    d=request.json; seller=d.get('seller','알 수 없음'); buyer=d.get('buyer','알 수 없음')
    total=d.get('total',0); lines=d.get('lines',[]); ts=d.get('time','')
    payload={"embeds":[{"title":"📝 장부 작성 로그","color":0x4CAF50,
        "fields":[{"name":"담당자","value":seller,"inline":False},{"name":"구매자","value":buyer,"inline":False},
                  {"name":"총 금액","value":f"**{int(total):,}원**","inline":False},
                  {"name":"품목","value":'\n'.join(lines) if lines else '-',"inline":False}],
        "footer":{"text":f"오늘 {ts}"},"timestamp":datetime.datetime.utcnow().isoformat()+'Z'}]}
    body=json.dumps(payload,ensure_ascii=False).encode('utf-8')
    req=urllib.request.Request(row['value'].strip(),data=body,
        headers={'Content-Type':'application/json; charset=utf-8','User-Agent':'Mozilla/5.0 (compatible; NHIntranet/1.0)'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=10): return jsonify({'ok':True})
    except urllib.error.HTTPError as e:
        return jsonify({'ok':False,'msg':f'HTTP {e.code}: {e.read().decode("utf-8",errors="ignore")[:200]}'})
    except Exception as e:
        return jsonify({'ok':False,'msg':str(e)})

@app.route('/api/attendance', methods=['GET'])
@login_required
def api_att_get():
    uid=session['user_uid']; month=request.args.get('month',str(datetime.date.today())[:7])
    conn=get_db(); rows=conn.execute('SELECT * FROM attendance WHERE user_uid=? AND date LIKE ? ORDER BY date,time',(uid,month+'%')).fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/attendance/today')
@login_required
def api_att_today():
    uid=session['user_uid']; today=str(datetime.date.today())
    conn=get_db(); rows=conn.execute('SELECT * FROM attendance WHERE user_uid=? AND date=? ORDER BY time',(uid,today)).fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/attendance/all')
@login_required
def api_att_all():
    today=str(datetime.date.today())
    conn=get_db(); rows=conn.execute('SELECT * FROM attendance WHERE date=? ORDER BY time ASC',(today,)).fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/attendance/all_mine')
@login_required
def api_att_all_mine():
    uid=session['user_uid']
    conn=get_db(); rows=conn.execute('SELECT * FROM attendance WHERE user_uid=? ORDER BY date,time',(uid,)).fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/attendance', methods=['POST'])
@login_required
def api_att_post():
    d=request.json; atype=d.get('type'); now=datetime.datetime.now()
    today=str(now.date()); t=now.strftime('%H:%M:%S')
    uid=session['user_uid']; name=session['user_name']
    conn=get_db()
    recs=conn.execute('SELECT * FROM attendance WHERE user_uid=? AND date=? ORDER BY time',(uid,today)).fetchall()
    last=recs[-1] if recs else None
    if atype=='in' and last and last['type']=='in': conn.close(); return jsonify({'ok':False,'msg':'이미 출근 기록이 있습니다. 퇴근 후 다시 출근해 주세요.'})
    if atype=='out' and (not last or last['type']=='out'): conn.close(); return jsonify({'ok':False,'msg':'먼저 출근을 기록해 주세요.'})
    conn.execute('INSERT INTO attendance (user_uid,user_name,date,time,type) VALUES (?,?,?,?,?)',(uid,name,today,t,atype))
    conn.commit(); conn.close(); return jsonify({'ok':True,'time':t})

@app.route('/api/attendance/clear_mine', methods=['DELETE'])
@login_required
def api_att_clear_mine():
    uid=session['user_uid']; conn=get_db(); conn.execute('DELETE FROM attendance WHERE user_uid=?',(uid,)); conn.commit(); conn.close(); return jsonify({'ok':True})

@app.route('/api/attendance/clear_all', methods=['DELETE'])
@admin_required
def api_att_clear_all():
    conn=get_db(); conn.execute('DELETE FROM attendance'); conn.commit(); conn.close(); return jsonify({'ok':True})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', debug=False, port=port)
