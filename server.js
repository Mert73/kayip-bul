const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3200);
const HOST = process.env.HOST || "0.0.0.0";
const ROOT = __dirname, PUBLIC = path.join(ROOT, "public");
const DATA_FILE = path.join(ROOT, "listings.json");
const USERS_FILE = path.join(ROOT, "users.json");
const MESSAGES_FILE = path.join(ROOT, "messages.json");
const MAX_BODY = 2_000_000;
const sessions = new Map();

function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; } }
function saveJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2), "utf8"); }
function loadListings() { return readJson(DATA_FILE, []); }
function saveListings(items) { saveJson(DATA_FILE, items); }
function send(res, status, body, type = "application/json; charset=utf-8", extra = {}) {
  res.writeHead(status, { "Content-Type": type, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'", ...extra });
  res.end(type.startsWith("application/json") ? JSON.stringify(body) : body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => { data += chunk; if (data.length > MAX_BODY) { reject(new Error("İstek çok büyük.")); req.destroy(); } });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { reject(new Error("Geçersiz JSON.")); } });
    req.on("error", reject);
  });
}
function cookie(req, key) {
  const row = (req.headers.cookie || "").split(";").map(x => x.trim()).find(x => x.startsWith(key + "="));
  return row ? decodeURIComponent(row.slice(key.length + 1)) : "";
}
function currentUser(req) { const id = sessions.get(cookie(req, "kb_session")); return id ? readJson(USERS_FILE, []).find(u => u.id === id) || null : null; }
function publicUser(u) { return u ? { id: u.id, username: u.username, createdAt: u.createdAt, role: u.role || "user" } : null; }
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString("hex") };
}
function verifyPassword(password, u) {
  const hash = crypto.scryptSync(password, u.salt, 64);
  return crypto.timingSafeEqual(hash, Buffer.from(u.passwordHash, "hex"));
}
const provinces = new Set(["Adana","Adıyaman","Afyonkarahisar","Ağrı","Aksaray","Amasya","Ankara","Antalya","Ardahan","Artvin","Aydın","Balıkesir","Bartın","Batman","Bayburt","Bilecik","Bingöl","Bitlis","Bolu","Burdur","Bursa","Çanakkale","Çankırı","Çorum","Denizli","Diyarbakır","Düzce","Edirne","Elazığ","Erzincan","Erzurum","Eskişehir","Gaziantep","Giresun","Gümüşhane","Hakkâri","Hatay","Iğdır","Isparta","İstanbul","İzmir","Kahramanmaraş","Karabük","Karaman","Kars","Kastamonu","Kayseri","Kırıkkale","Kırklareli","Kırşehir","Kilis","Kocaeli","Konya","Kütahya","Malatya","Manisa","Mardin","Mersin","Muğla","Muş","Nevşehir","Niğde","Ordu","Osmaniye","Rize","Sakarya","Samsun","Siirt","Sinop","Sivas","Şanlıurfa","Şırnak","Tekirdağ","Tokat","Trabzon","Tunceli","Uşak","Van","Yalova","Yozgat","Zonguldak"]);
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  try {
    if (req.method === "GET" && url.pathname === "/api/status") return send(res, 200, { ok:true, app:"KAYIP BUL", version:"0.2.0", count:loadListings().length });
    if (req.method === "GET" && url.pathname === "/api/me") return send(res, 200, { user: publicUser(currentUser(req)) });
    if (req.method === "POST" && url.pathname === "/api/register") {
      const b = await readBody(req), username = String(b.username || "").trim(), password = String(b.password || "");
      if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username)) return send(res, 400, { error:"Kullanıcı adı 3-24 karakter olmalı; harf, sayı, _ veya - kullan." });
      if (password.length < 8) return send(res, 400, { error:"Şifre en az 8 karakter olmalı." });
      const users = readJson(USERS_FILE, []);
      if (users.some(u => u.username.toLocaleLowerCase("tr-TR") === username.toLocaleLowerCase("tr-TR"))) return send(res, 409, { error:"Bu kullanıcı adı kullanılıyor." });
      const hp = hashPassword(password);
      const user = { id:crypto.randomUUID(), username, salt:hp.salt, passwordHash:hp.hash, createdAt:new Date().toISOString(), role:"user" };
      users.push(user); saveJson(USERS_FILE, users);
      const token = crypto.randomBytes(32).toString("hex"); sessions.set(token, user.id);
      return send(res, 201, { user:publicUser(user) }, "application/json; charset=utf-8", { "Set-Cookie":`kb_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/` });
    }
    if (req.method === "POST" && url.pathname === "/api/login") {
      const b = await readBody(req), username = String(b.username || "").trim();
      const user = readJson(USERS_FILE, []).find(u => u.username.toLocaleLowerCase("tr-TR") === username.toLocaleLowerCase("tr-TR"));
      if (!user || !verifyPassword(String(b.password || ""), user)) return send(res, 401, { error:"Kullanıcı adı veya şifre hatalı." });
      const token = crypto.randomBytes(32).toString("hex"); sessions.set(token, user.id);
      return send(res, 200, { user:publicUser(user) }, "application/json; charset=utf-8", { "Set-Cookie":`kb_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/` });
    }
    if (req.method === "POST" && url.pathname === "/api/logout") {
      sessions.delete(cookie(req, "kb_session"));
      return send(res, 200, { ok:true }, "application/json; charset=utf-8", { "Set-Cookie":"kb_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
    }
    if (req.method === "GET" && url.pathname === "/api/matches") {
      const user = currentUser(req); if (!user) return send(res, 401, {error:"Eşleşmeleri görmek için giriş yap."});
      const all = loadListings().filter(x => !x.hidden && x.ownerId === user.id);
      const visible = loadListings().filter(x => !x.hidden && x.ownerId !== user.id);
      const norm = v => String(v || "").toLocaleLowerCase("tr-TR").normalize("NFD").replace(/[\\u0300-\\u036f]/g, "");
      const matches = [];
      for (const mine of all) {
        for (const other of visible) {
          if (mine.type === other.type || norm(mine.city) !== norm(other.city) || norm(mine.category) !== norm(other.category)) continue;
          const words = norm((mine.title || "") + " " + (mine.description || "")).split(/[^\\p{L}\\p{N}]+/u).filter(w => w.length >= 4);
          const otherText = norm((other.title || "") + " " + (other.description || ""));
          const common = [...new Set(words)].filter(w => otherText.includes(w));
          matches.push({mine:{id:mine.id,title:mine.title,type:mine.type,city:mine.city,category:mine.category},other:{id:other.id,title:other.title,type:other.type,city:other.city,category:other.category,description:other.description,createdAt:other.createdAt},score:Math.min(100,60+common.length*10),common});
        }
      }
      matches.sort((a,b)=>b.score-a.score);
      return send(res,200,{matches:matches.slice(0,50)});
    }
    if (req.method === "GET" && url.pathname === "/api/my-listings") {
      const user = currentUser(req); if (!user) return send(res, 401, {error:"Önce giriş yap."});
      return send(res, 200, { listings:loadListings().filter(x => x.ownerId === user.id) });
    }
    if (req.method === "GET" && url.pathname === "/api/messages") {
      const user = currentUser(req); if (!user) return send(res, 401, {error:"Önce giriş yap."});
      const msgs = readJson(MESSAGES_FILE, []).filter(m => m.fromId === user.id || m.toId === user.id);
      return send(res, 200, { messages:msgs.map(m => ({id:m.id, listingId:m.listingId, from:m.fromName, to:m.toName, text:m.text, createdAt:m.createdAt, mine:m.fromId===user.id})) });
    }
    if (req.method === "POST" && url.pathname === "/api/messages") {
      const user = currentUser(req); if (!user) return send(res, 401, {error:"Mesaj göndermek için giriş yap."});
      const b = await readBody(req), listing = loadListings().find(x => x.id === b.listingId && !x.hidden);
      const text = String(b.text || "").trim().slice(0, 1000);
      if (!listing) return send(res, 404, {error:"İlan bulunamadı."});
      if (!text || text.length < 2) return send(res, 400, {error:"Mesaj en az 2 karakter olmalı."});
      if (!listing.ownerId || listing.ownerId === user.id) return send(res, 400, {error:"Bu ilana mesaj gönderilemiyor."});
      const owner = readJson(USERS_FILE, []).find(u => u.id === listing.ownerId);
      if (!owner) return send(res, 400, {error:"İlan sahibinin hesabı bulunamadı."});
      const msgs = readJson(MESSAGES_FILE, []);
      const msg = {id:crypto.randomUUID(), listingId:listing.id, fromId:user.id, fromName:user.username, toId:owner.id, toName:owner.username, text, createdAt:new Date().toISOString()};
      msgs.push(msg); saveJson(MESSAGES_FILE, msgs);
      return send(res, 201, {ok:true, message:"Mesaj güvenli gelen kutusuna gönderildi."});
    }
    if (req.method === "GET" && url.pathname === "/api/listings") {
      const all = loadListings().filter(x => !x.hidden);
      const type=url.searchParams.get("type"), category=url.searchParams.get("category"), city=url.searchParams.get("city");
      const q=(url.searchParams.get("q")||"").trim().toLocaleLowerCase("tr-TR");
      return send(res,200,{listings:all.filter(x=>(!type||x.type===type)&&(!category||x.category===category)&&(!city||x.city===city)&&(!q||`${x.title} ${x.description} ${x.city} ${x.district} ${x.category}`.toLocaleLowerCase("tr-TR").includes(q))).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))});
    }
    if (req.method === "POST" && url.pathname === "/api/listings") {
      const user = currentUser(req); if (!user) return send(res,401,{error:"İlan yayınlamak için önce giriş yap veya hesap oluştur."});
      const body=await readBody(req), type=["lost","found"].includes(body.type)?body.type:null;
      const title=String(body.title||"").trim().slice(0,80), category=String(body.category||"").trim().slice(0,40), city=String(body.city||"").trim(), district=String(body.district||"").trim().slice(0,60), description=String(body.description||"").trim().slice(0,800);
      const image=typeof body.image==="string"&&/^data:image\/(jpeg|png|webp);base64,/.test(body.image)&&body.image.length<=900000?body.image:"";
      if(body.image&&!image)return send(res,400,{error:"Fotoğraf geçersiz veya çok büyük. Daha küçük bir JPG, PNG ya da WebP fotoğrafı seç."});
      if(!type||!title||!category||!provinces.has(city)||!description)return send(res,400,{error:"Lütfen ilan türü, başlık, kategori, geçerli şehir ve açıklamayı doldur."});
      if(title.length<4||description.length<10)return send(res,400,{error:"Başlık en az 4, açıklama en az 10 karakter olmalı."});
      const items=loadListings(), item={id:crypto.randomUUID(),type,title,category,city,district,description,image,ownerId:user.id,ownerName:user.username,createdAt:new Date().toISOString(),status:"active",hidden:false};
      items.push(item);saveListings(items);return send(res,201,{listing:item});
    }
    if (req.method === "POST" && url.pathname.startsWith("/api/listings/") && url.pathname.endsWith("/report")) {
      const id=url.pathname.split("/")[3], items=loadListings(), item=items.find(x=>x.id===id);
      if(!item)return send(res,404,{error:"İlan bulunamadı."});item.reports=(item.reports||0)+1;if(item.reports>=3)item.hidden=true;saveListings(items);
      return send(res,200,{ok:true,message:"Bildirimin alındı."});
    }
    if (req.method === "DELETE" && url.pathname.startsWith("/api/listings/")) {
      const user=currentUser(req);if(!user)return send(res,401,{error:"Giriş yap."});
      const id=url.pathname.split("/")[3],items=loadListings(),item=items.find(x=>x.id===id);
      if(!item)return send(res,404,{error:"İlan bulunamadı."});
      if(item.ownerId!==user.id && user.role!=="admin")return send(res,403,{error:"Bu ilanı kaldırma yetkin yok."});
      item.hidden=true;item.status="removed";saveListings(items);return send(res,200,{ok:true});
    }
    if (req.method === "GET" && url.pathname === "/api/admin/listings") {
      const user=currentUser(req);if(!user||user.role!=="admin")return send(res,403,{error:"Yönetici hesabıyla giriş yapmalısın."});
      return send(res,200,{listings:loadListings()});
    }
    if (req.method === "POST" && url.pathname === "/api/admin/promote") {
      const b=await readBody(req), expected=process.env.ADMIN_KEY;
      if(!expected||String(b.adminKey||"")!==expected)return send(res,403,{error:"Yönetici anahtarı hatalı veya ADMIN_KEY tanımlı değil."});
      const user=currentUser(req);if(!user)return send(res,401,{error:"Önce normal hesabınla giriş yap."});
      const users=readJson(USERS_FILE,[]), target=users.find(u=>u.id===user.id);target.role="admin";saveJson(USERS_FILE,users);
      return send(res,200,{ok:true,message:"Bu hesap yönetici oldu. Çıkış yapıp tekrar giriş yap."});
    }
    if (req.method === "POST" && url.pathname === "/api/admin/hide") {
      const user=currentUser(req);if(!user||user.role!=="admin")return send(res,403,{error:"Yönetici girişi gerekli."});
      const b=await readBody(req),items=loadListings(),item=items.find(x=>x.id===b.id);if(!item)return send(res,404,{error:"İlan yok."});
      item.hidden=true;item.status="moderated";saveListings(items);return send(res,200,{ok:true});
    }
  } catch (e) { return send(res,400,{error:e.message||"İstek işlenemedi."}); }
  if (req.method === "GET") {
    let pathname=decodeURIComponent(url.pathname);if(pathname==="/")pathname="/index.html";
    const filePath=path.normalize(path.join(PUBLIC,pathname));
    if(!filePath.startsWith(PUBLIC+path.sep))return send(res,403,{error:"Erişim reddedildi."});
    fs.readFile(filePath,(err,data)=>{if(err)return send(res,404,{error:"Dosya bulunamadı."});const ext=path.extname(filePath).toLowerCase();const types={".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".svg":"image/svg+xml"};send(res,200,data,types[ext]||"application/octet-stream");});
    return;
  }
  send(res,404,{error:"Bulunamadı."});
});
server.listen(PORT,HOST,()=>console.log(`KAYIP BUL çalışıyor: http://127.0.0.1:${PORT}\nAğ arayüzü: ${HOST}:${PORT}`));
