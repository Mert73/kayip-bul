# KAYIP BUL v0.2 — profil, mesaj ve moderasyon prototipi

## Güncelleme
1. Termux sunucusunda `CTRL+C`.
2. Yedek al: `cd ~/kayip-bul && cp listings.json listings-yedek.json`
3. Yeni ZIP'i indir.
4. ZIP içinden `kayip-bul/server.js`, `kayip-bul/public/index.html`, `kayip-bul/users.json`, `kayip-bul/messages.json` dosyalarını çıkarıp `~/` altına yaz.
5. Başlat: `cd ~/kayip-bul && PORT=3200 npm start`

## Özellikler
- Kullanıcı kayıt/giriş, parola scrypt ile hashlenir
- Hesaba bağlı yeni ilanlar ve “İlanlarım” ekranı
- İlan sahibiyle uygulama içi mesajlaşma ve gelen kutusu
- Kullanıcının kendi ilanını kaldırması
- Yönetici anahtarıyla admin rolü alma; admin ilanları gizleyebilir
- Önceki ilanlar listelenmeye devam eder ancak eski ilanların ownerId'si yoksa mesaj hedefi olmaz.

## Yönetici kurulumu
Termux'ta sunucuyu durdurup `export ADMIN_KEY='uzun-rastgele-bir-anahtar'` komutunu çalıştır; ardından `PORT=3200 npm start`. Giriş yaptıktan sonra Yönetici düğmesine basıp aynı anahtarı gir. İlk admin olduktan sonra çıkış yapıp tekrar giriş yap. Anahtarı kimseyle paylaşma.

## Güvenlik notu
Bu bir prototiptir, internete doğrudan açılmaya hazır değildir. Oturumlar sunucu belleğinde tutulur; sunucu yeniden başlayınca kullanıcıların tekrar giriş yapması gerekir. Rate limiting, e-posta doğrulaması, CSRF koruması, dosya yedekleme ve daha güçlü moderasyon eklenmeden gerçek genel kullanıma açmayın. Gerçek kişisel bilgileri ilanlarda paylaşmayın.
