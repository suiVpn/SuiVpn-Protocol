/// SuiVPN Multi-Path Dynamic Routing (MPDR) Module
/// 
/// Bu modül, SuiVPN'in temel farklılaştırıcı özelliği olan Multi-Path Dynamic Routing
/// algoritmasını uygular. MPDR, kullanıcı verilerini güvenli ve anonim bir şekilde iletmek için
/// dinamik olarak çoklu rota seçen ve optimum yol konfigürasyonunu belirleyen gelişmiş bir algoritmadır.
module suivpn::mpdr {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::vec_map::{Self, VecMap};
    use sui::vec_set::{Self, VecSet};
    use std::vector;
    use std::string::{Self, String};
    use std::option::{Self, Option};
    use suivpn::registry::{Self, NodeInfo};
    use suivpn::governance::{Self, GovernanceCapability};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidPathCount: u64 = 1;
    const EInvalidNode: u64 = 2;
    const EInvalidConfig: u64 = 3;
    const EPathNotFound: u64 = 4;
    const ESessionNotFound: u64 = 5;
    const EInsufficientNodes: u64 = 6;
    const EInvalidWeight: u64 = 7;
    const EInvalidMetric: u64 = 8;
    const EInvalidFragment: u64 = 9;
    const ESessionExpired: u64 = 10;
    
    // Patika kriteri türleri
    const CRITERIA_LATENCY: u8 = 0;
    const CRITERIA_SECURITY: u8 = 1;
    const CRITERIA_CAPACITY: u8 = 2;
    const CRITERIA_GEO_DIVERSITY: u8 = 3;
    
    // Şifreleme metotları
    const ENCRYPTION_AES_256_GCM: u8 = 0;
    const ENCRYPTION_CHACHA20_POLY1305: u8 = 1;
    const ENCRYPTION_SALSA20: u8 = 2;
    
    // Sabitler
    const DEFAULT_MIN_PATH_COUNT: u64 = 3;
    const DEFAULT_MAX_PATH_COUNT: u64 = 7;
    const DEFAULT_FRAGMENT_SIZE: u64 = 8192; // 8KB
    const DEFAULT_SESSION_TIMEOUT: u64 = 3600; // 1 saat (saniye)
    const DEFAULT_PATH_REEVALUATION_INTERVAL: u64 = 300; // 5 dakika (saniye)
    
    /// MPDR Konfigürasyonu
    /// MPDR algoritmasının çalışma parametrelerini içerir
    struct MPDRConfig has key, store {
        id: UID,
        // Minimum patika sayısı
        min_path_count: u64,
        // Maksimum patika sayısı
        max_path_count: u64,
        // Patika seçimi için kriter ağırlıkları (binde)
        criteria_weights: VecMap<u8, u64>,
        // Varsayılan patika hesaplama frekansı (saniye)
        path_calculation_frequency: u64,
        // Varsayılan parça boyutu (bayt)
        default_fragment_size: u64,
        // Varsayılan şifreleme metodu
        default_encryption_method: u8,
        // Varsayılan oturum zaman aşımı (saniye)
        default_session_timeout: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// MPDR Oturumu
    /// Kullanıcı ve VPN oturumuna ait patika ve yönlendirme bilgilerini içerir
    struct MPDRSession has key {
        id: UID,
        // Oturum sahibi
        owner: address,
        // Patikalar listesi
        paths: vector<RoutingPath>,
        // Mevcut aktif patikalar seti
        active_paths: VecSet<ID>,
        // Oturum oluşturma zamanı
        created_at: u64,
        // Son aktif zamanı
        last_active: u64,
        // Oturum sona erme zamanı
        expiry_time: u64,
        // Oturum şifreleme anahtarı (hash'lenmiş)
        session_key_hash: vector<u8>,
        // Toplam aktarılan veri miktarı (bayt)
        total_data_transferred: u64,
        // Parça boyutu
        fragment_size: u64,
        // Şifreleme metodu
        encryption_method: u8,
        // Kullanıcı konfigürasyonu
        user_config: Option<MPDRUserConfig>,
        // Protokol versiyon numarası
        protocol_version: u64,
    }
    
    /// MPDR Kullanıcı Konfigürasyonu
    /// Kullanıcı spesifik MPDR parametrelerini içerir
    struct MPDRUserConfig has store, drop {
        // Kullanıcı tarafından belirlenen minimum patika sayısı
        min_path_count: u64,
        // Kullanıcı tarafından belirlenen maksimum patika sayısı
        max_path_count: u64,
        // Kullanıcı kriter ağırlıkları (binde)
        criteria_weights: VecMap<u8, u64>,
        // Kullanıcının tercih ettiği bölgeler
        preferred_regions: VecSet<u8>,
        // Kullanıcının kaçındığı bölgeler
        avoided_regions: VecSet<u8>,
        // Kullanıcının tercih ettiği şifreleme metodu
        preferred_encryption: u8,
        // Değerlendirme için özelleştirilmiş metrikler
        custom_metrics: Option<VecMap<String, u64>>,
    }
    
    /// Yönlendirme Patikası
    /// Veri transferi için kullanılan spesifik bir patikayı temsil eder
    struct RoutingPath has store, drop {
        // Patika ID'si
        path_id: ID,
        // Patikadaki düğümler
        nodes: vector<ID>,
        // Bu patika için şifreleme anahtarları (hash'lenmiş)
        encryption_keys: vector<vector<u8>>,
        // Patika puanı
        score: u64,
        // Patika gecikmesi (ms)
        latency: u64,
        // Patika kapasitesi (Mbps)
        capacity: u64,
        // Patika güvenlik skoru
        security_score: u64,
        // Patika coğrafi çeşitlilik skoru
        geo_diversity_score: u64,
        // Patika oluşturma zamanı
        created_at: u64,
        // Son değerlendirme zamanı
        last_evaluated: u64,
        // Patika üzerinden aktarılan toplam veri
        total_data_transferred: u64,
        // Patika aktif mi?
        is_active: bool,
    }
    
    /// Veri Fragmenti
    /// Parçalanmış ve şifrelenmiş veri parçasını temsil eder
    struct DataFragment has store, drop {
        // Fragment ID'si
        fragment_id: ID,
        // Kaynak oturum ID'si
        session_id: ID,
        // Fragment sıra numarası
        sequence_number: u64,
        // Yönlendirme patikası ID'si
        path_id: ID,
        // Şifrelenmiş veri
        encrypted_data: vector<u8>,
        // Doğrulama hash'i
        verification_hash: vector<u8>,
        // Oluşturma zamanı
        created_at: u64,
        // Fragment zaman aşımı
        expiry_time: u64,
        // Başarıyla iletildi mi?
        is_delivered: bool,
    }
    
    /// Patika Değerlendirme Metriği
    /// Patika değerlendirmesi için kullanılan metrikleri içerir
    struct PathMetrics has store, drop {
        // Gecikme (ms)
        latency: u64,
        // Güvenlik skoru
        security_score: u64,
        // Kapasite (Mbps)
        capacity: u64,
        // Coğrafi çeşitlilik skoru
        geo_diversity_score: u64,
        // Kullanım oranı
        usage_rate: u64,
        // Başarı oranı
        success_rate: u64,
        // Özelleştirilmiş metrikler
        custom_metrics: Option<VecMap<String, u64>>,
    }
    
    // Eventler
    
    /// Oturum oluşturma eventi
    struct SessionCreated has copy, drop {
        session_id: ID,
        owner: address,
        path_count: u64,
        created_at: u64,
        expiry_time: u64,
    }
    
    /// Patika oluşturma eventi
    struct PathCreated has copy, drop {
        path_id: ID,
        session_id: ID,
        node_count: u64,
        score: u64,
        created_at: u64,
    }
    
    /// Veri aktarım eventi
    struct DataTransferred has copy, drop {
        session_id: ID,
        fragment_count: u64,
        total_size: u64,
        timestamp: u64,
    }
    
    /// Patika güncelleme eventi
    struct PathUpdated has copy, drop {
        path_id: ID,
        session_id: ID,
        old_score: u64,
        new_score: u64,
        timestamp: u64,
    }
    
    /// Oturum sona erme eventi
    struct SessionEnded has copy, drop {
        session_id: ID,
        owner: address,
        duration: u64,
        total_data: u64,
        timestamp: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let mpdr_config = MPDRConfig {
            id: object::new(ctx),
            min_path_count: DEFAULT_MIN_PATH_COUNT,
            max_path_count: DEFAULT_MAX_PATH_COUNT,
            criteria_weights: vec_map::empty(),
            path_calculation_frequency: DEFAULT_PATH_REEVALUATION_INTERVAL,
            default_fragment_size: DEFAULT_FRAGMENT_SIZE,
            default_encryption_method: ENCRYPTION_AES_256_GCM,
            default_session_timeout: DEFAULT_SESSION_TIMEOUT,
            last_updated: 0,
        };
        
        // Kriter ağırlıklarını ayarla
        // Ağırlıkların toplamı 1000 olmalı (binde)
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_LATENCY, 350); // %35 ağırlık
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_SECURITY, 300); // %30 ağırlık
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_CAPACITY, 200); // %20 ağırlık
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_GEO_DIVERSITY, 150); // %15 ağırlık
        
        transfer::share_object(mpdr_config);
    }
    
    /// Yeni bir MPDR oturumu oluştur
    public entry fun create_session(
        mpdr_config: &MPDRConfig,
        node_ids: vector<ID>,
        session_key_hash: vector<u8>,
        preferred_path_count: Option<u64>,
        user_config: Option<vector<u8>>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm sayısını kontrol et
        let node_count = vector::length(&node_ids);
        assert!(node_count >= mpdr_config.min_path_count, EInsufficientNodes);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        let expiry_time = now + mpdr_config.default_session_timeout;
        
        // Patika sayısını belirle
        let path_count = if (option::is_some(&preferred_path_count)) {
            let count = *option::borrow(&preferred_path_count);
            if (count < mpdr_config.min_path_count) {
                mpdr_config.min_path_count
            } else if (count > mpdr_config.max_path_count) {
                mpdr_config.max_path_count
            } else {
                count
            }
        } else {
            mpdr_config.min_path_count
        };
        
        // Oturum oluştur
        let session = MPDRSession {
            id: object::new(ctx),
            owner: sender,
            paths: vector::empty(),
            active_paths: vec_set::empty(),
            created_at: now,
            last_active: now,
            expiry_time,
            session_key_hash,
            total_data_transferred: 0,
            fragment_size: mpdr_config.default_fragment_size,
            encryption_method: mpdr_config.default_encryption_method,
            user_config: parse_user_config(user_config, mpdr_config),
            protocol_version: 1, // Protokol versiyon 1
        };
        
        let session_id = object::id(&session);
        
        // Patikalar oluştur
        create_initial_paths(&mut session, node_ids, path_count, now, ctx);
        
        // Oturum oluşturma eventini yayınla
        event::emit(SessionCreated {
            session_id,
            owner: sender,
            path_count,
            created_at: now,
            expiry_time,
        });
        
        // Oturumu kullanıcıya aktar
        transfer::transfer(session, sender);
    }
    
    /// Bir oturum için başlangıç patikalarını oluştur
    fun create_initial_paths(
        session: &mut MPDRSession,
        node_ids: vector<ID>,
        path_count: u64,
        now: u64,
        ctx: &mut TxContext
    ) {
        // Node ID'lerini karıştır (basit bir Fisher-Yates algoritması)
        let length = vector::length(&node_ids);
        let i = 0;
        
        while (i < length) {
            let j = (((now + i) % length) as u64);
            if (i != j) {
                let temp = *vector::borrow(&node_ids, i);
                let temp_j = *vector::borrow(&node_ids, j);
                *vector::borrow_mut(&mut node_ids, i) = temp_j;
                *vector::borrow_mut(&mut node_ids, j) = temp;
            };
            i = i + 1;
        };
        
        // Patika sayısı kadar patika oluştur
        let i = 0;
        while (i < path_count && i < length) {
            let path_nodes = vector::empty<ID>();
            
            // Her patikaya uygun sayıda düğüm ekle
            // Basitleştirilmiş bir şekilde, her patikaya bir düğüm ekliyoruz
            // Gerçek bir implementasyonda, daha karmaşık patika oluşturma algoritmaları kullanılabilir
            let node_id = *vector::borrow(&node_ids, i);
            vector::push_back(&mut path_nodes, node_id);
            
            // Patika ID'si oluştur
            let path_id_obj = object::new(ctx);
            let path_id = object::uid_to_inner(&path_id_obj);
            object::delete(path_id_obj);
            
            // Patika metriklerini başlat
            // Gerçek bir implementasyonda, bu metrikler düğüm özellikleri ve ağ durumuna göre hesaplanır
            let latency = 100; // 100 ms
            let capacity = 100; // 100 Mbps
            let security_score = 800; // 0-1000 arası
            let geo_diversity_score = 500; // 0-1000 arası
            
            // Patika puanını hesapla
            let score = calculate_path_score(
                latency,
                security_score,
                capacity,
                geo_diversity_score,
                if (option::is_some(&session.user_config)) {
                    option::borrow(&session.user_config)
                } else {
                    &get_default_user_config()
                }
            );
            
            // Şifreleme anahtarlarını oluştur (boş)
            let encryption_keys = vector::empty<vector<u8>>();
            
            // Patikayı oluştur
            let path = RoutingPath {
                path_id,
                nodes: path_nodes,
                encryption_keys,
                score,
                latency,
                capacity,
                security_score,
                geo_diversity_score,
                created_at: now,
                last_evaluated: now,
                total_data_transferred: 0,
                is_active: true,
            };
            
            // Patikayı oturuma ekle
            vector::push_back(&mut session.paths, path);
            vec_set::insert(&mut session.active_paths, path_id);
            
            // Patika oluşturma eventini yayınla
            event::emit(PathCreated {
                path_id,
                session_id: object::id(session),
                node_count: vector::length(&path_nodes),
                score,
                created_at: now,
            });
            
            i = i + 1;
        };
    }
    
    /// Kullanıcı konfigürasyonunu ayrıştır
    fun parse_user_config(
        user_config_bytes: Option<vector<u8>>,
        mpdr_config: &MPDRConfig
    ): Option<MPDRUserConfig> {
        if (option::is_none(&user_config_bytes)) {
            return option::none()
        };
        
        // Bu fonksiyon gerçek bir implementasyonda daha karmaşık olacaktır
        // Şu anda basit bir default konfigürasyon döndürüyoruz
        
        option::some(get_default_user_config())
    }
    
    /// Varsayılan kullanıcı konfigürasyonu oluştur
    fun get_default_user_config(): MPDRUserConfig {
        let criteria_weights = vec_map::empty<u8, u64>();
        vec_map::insert(&mut criteria_weights, CRITERIA_LATENCY, 350);
        vec_map::insert(&mut criteria_weights, CRITERIA_SECURITY, 300);
        vec_map::insert(&mut criteria_weights, CRITERIA_CAPACITY, 200);
        vec_map::insert(&mut criteria_weights, CRITERIA_GEO_DIVERSITY, 150);
        
        MPDRUserConfig {
            min_path_count: DEFAULT_MIN_PATH_COUNT,
            max_path_count: DEFAULT_MAX_PATH_COUNT,
            criteria_weights,
            preferred_regions: vec_set::empty(),
            avoided_regions: vec_set::empty(),
            preferred_encryption: ENCRYPTION_AES_256_GCM,
            custom_metrics: option::none(),
        }
    }
    
    /// Patika puanını hesapla
    /// S(p) = α·L(p) + β·SEC(p) + γ·C(p) + δ·G(p)
    /// Burada:
    /// - L(p): Gecikme metriği
    /// - SEC(p): Güvenlik metriği
    /// - C(p): Kapasite metriği
    /// - G(p): Coğrafi çeşitlilik metriği
    /// - α, β, γ, δ: Ağırlık katsayıları
    fun calculate_path_score(
        latency: u64,
        security_score: u64,
        capacity: u64,
        geo_diversity_score: u64,
        user_config: &MPDRUserConfig
    ): u64 {
        // Latency: Düşük değer daha iyidir, bu nedenle 1000'den çıkarıyoruz
        // Max latency'i 500ms kabul ediyoruz
        let latency_score = if (latency >= 500) { 0 } else { 1000 - (latency * 2) };
        
        // Kapasite: Yüksek değer daha iyidir
        // Max kapasite'yi 1000 Mbps kabul ediyoruz
        let capacity_score = if (capacity >= 1000) { 1000 } else { capacity };
        
        // Güvenlik ve coğrafi çeşitlilik zaten 0-1000 arasında
        
        // Ağırlıklı skoru hesapla
        let latency_weight = *vec_map::get(&user_config.criteria_weights, &CRITERIA_LATENCY);
        let security_weight = *vec_map::get(&user_config.criteria_weights, &CRITERIA_SECURITY);
        let capacity_weight = *vec_map::get(&user_config.criteria_weights, &CRITERIA_CAPACITY);
        let geo_weight = *vec_map::get(&user_config.criteria_weights, &CRITERIA_GEO_DIVERSITY);
        
        // Ağırlıklı skor
        let weighted_score = 
            (latency_score * latency_weight +
             security_score * security_weight +
             capacity_score * capacity_weight +
             geo_diversity_score * geo_weight) / 1000;
        
        weighted_score
    }
    
    /// Ağ üzerinden veri aktarımını simüle et
    public entry fun transmit_data(
        session: &mut MPDRSession,
        data_size: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Sahibi kontrol et
        assert!(sender == session.owner, ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Oturumun süresi dolmuş mu kontrol et
        assert!(now < session.expiry_time, ESessionExpired);
        
        // Aktif yollar var mı kontrol et
        assert!(!vec_set::is_empty(&session.active_paths), EInsufficientNodes);
        
        // Veriyi fragmanlar halinde böl
        let fragment_size = session.fragment_size;
        let fragment_count = (data_size + fragment_size - 1) / fragment_size; // Yukarı yuvarlama
        
        // Tüm aktif patikalar arasında veriyi dağıt
        let active_paths = vec_set::into_keys(session.active_paths);
        let active_path_count = vector::length(&active_paths);
        
        // Patika başına düşen fragment sayısı
        let fragments_per_path = (fragment_count + active_path_count - 1) / active_path_count; // Yuvarla
        
        // Her patika için, veri aktarımını update et
        let i = 0;
        let mut_paths = &mut session.paths;
        
        while (i < vector::length(mut_paths)) {
            let path = vector::borrow_mut(mut_paths, i);
            
            if (path.is_active) {
                // Bu patika üzerinden aktarılan veri miktarı
                let path_data_size = fragments_per_path * fragment_size;
                if (path_data_size > data_size) {
                    path_data_size = data_size;
                };
                
                path.total_data_transferred = path.total_data_transferred + path_data_size;
                path.last_evaluated = now;
                
                // Kalan veri miktarını güncelle
                if (data_size > path_data_size) {
                    data_size = data_size - path_data_size;
                } else {
                    data_size = 0;
                };
                
                // Tüm veri aktarıldıysa döngüden çık
                if (data_size == 0) {
                    break
                };
            };
            
            i = i + 1;
        };
        
        // Oturum bilgilerini güncelle
        session.last_active = now;
        session.total_data_transferred = session.total_data_transferred + data_size;
        
        // Veri aktarım eventini yayınla
        event::emit(DataTransferred {
            session_id: object::id(session),
            fragment_count,
            total_size: data_size,
            timestamp: now,
        });
    }
    
    /// Patika değerlendirmesi yap ve patikalarını optimum olarak güncelle
    public entry fun reevaluate_paths(
        session: &mut MPDRSession,
        node_ids: vector<ID>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Sahibi kontrol et
        assert!(sender == session.owner, ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Oturumun süresi dolmuş mu kontrol et
        assert!(now < session.expiry_time, ESessionExpired);
        
        // Mevcut patikaları güncelle
        // Gerçek bir implementasyonda, bu kısım mevcut patika performansına göre
        // daha karmaşık optimizasyonlar içerecektir
        
        let i = 0;
        let paths = &mut session.paths;
        
        while (i < vector::length(paths)) {
            let path = vector::borrow_mut(paths, i);
            
            // Basit metrik güncellemesi
            let old_score = path.score;
            
            // Gerçek implementasyonda bu değerler ağ durumundan ölçülecektir
            path.latency = path.latency + 10; // Gecikme artışı simüle ediliyor
            if (path.latency > 500) { path.latency = 500; }; // Maksimum değeri sınırla
            
            path.capacity = if (path.capacity > 50) { path.capacity - 10 } else { path.capacity }; // Kapasite azalması simüle ediliyor
            
            // Yeni skoru hesapla
            path.score = calculate_path_score(
                path.latency,
                path.security_score,
                path.capacity,
                path.geo_diversity_score,
                if (option::is_some(&session.user_config)) {
                    option::borrow(&session.user_config)
                } else {
                    &get_default_user_config()
                }
            );
            
            path.last_evaluated = now;
            
            // Skoru düşük olan patikaları devre dışı bırak
            if (path.score < 300) { // Skor eşiği
                path.is_active = false;
                vec_set::remove(&mut session.active_paths, &path.path_id);
            };
            
            // Patika güncelleme eventini yayınla
            event::emit(PathUpdated {
                path_id: path.path_id,
                session_id: object::id(session),
                old_score,
                new_score: path.score,
                timestamp: now,
            });
            
            i = i + 1;
        };
        
        // Aktif patika sayısı minimum değerin altına düştüyse yeni patikalar ekle
        let active_count = vec_set::size(&session.active_paths);
        let min_paths = if (option::is_some(&session.user_config)) {
            option::borrow(&session.user_config).min_path_count
        } else {
            DEFAULT_MIN_PATH_COUNT
        };
        
        if (active_count < min_paths) {
            // Yeni patikalar oluştur
            let new_paths_needed = min_paths - active_count;
            create_initial_paths(session, node_ids, new_paths_needed, now, ctx);
        };
    }
    
    /// Oturumu sonlandır
    public entry fun end_session(
        session: &mut MPDRSession,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Sahibi kontrol et
        assert!(sender == session.owner, ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Oturum süresini hesapla
        let duration = now - session.created_at;
        
        // Oturum sona erme eventini yayınla
        event::emit(SessionEnded {
            session_id: object::id(session),
            owner: sender,
            duration,
            total_data: session.total_data_transferred,
            timestamp: now,
        });
        
        // Oturumu sona erdir
        session.expiry_time = now;
    }
    
    /// MPDR konfigürasyonunu güncelle
    public entry fun update_mpdr_config(
        mpdr_config: &mut MPDRConfig,
        min_path_count: Option<u64>,
        max_path_count: Option<u64>,
        path_calculation_frequency: Option<u64>,
        default_fragment_size: Option<u64>,
        default_encryption_method: Option<u8>,
        default_session_timeout: Option<u64>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Parametreleri güncelle (varsa)
        if (option::is_some(&min_path_count)) {
            mpdr_config.min_path_count = *option::borrow(&min_path_count);
            assert!(mpdr_config.min_path_count <= mpdr_config.max_path_count, EInvalidConfig);
        };
        
        if (option::is_some(&max_path_count)) {
            mpdr_config.max_path_count = *option::borrow(&max_path_count);
            assert!(mpdr_config.min_path_count <= mpdr_config.max_path_count, EInvalidConfig);
        };
        
        if (option::is_some(&path_calculation_frequency)) {
            mpdr_config.path_calculation_frequency = *option::borrow(&path_calculation_frequency);
        };
        
        if (option::is_some(&default_fragment_size)) {
            mpdr_config.default_fragment_size = *option::borrow(&default_fragment_size);
        };
        
        if (option::is_some(&default_encryption_method)) {
            let method = *option::borrow(&default_encryption_method);
            assert!(
                method == ENCRYPTION_AES_256_GCM || 
                method == ENCRYPTION_CHACHA20_POLY1305 || 
                method == ENCRYPTION_SALSA20,
                EInvalidConfig
            );
            mpdr_config.default_encryption_method = method;
        };
        
        if (option::is_some(&default_session_timeout)) {
            mpdr_config.default_session_timeout = *option::borrow(&default_session_timeout);
        };
        
        mpdr_config.last_updated = now;
    }
    
    /// Kriter ağırlıklarını güncelle
    public entry fun update_criteria_weights(
        mpdr_config: &mut MPDRConfig,
        latency_weight: u64,
        security_weight: u64,
        capacity_weight: u64,
        geo_diversity_weight: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Ağırlıkların toplamının 1000 olmasını sağla
        let total_weight = latency_weight + security_weight + capacity_weight + geo_diversity_weight;
        assert!(total_weight == 1000, EInvalidWeight);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Ağırlıkları güncelle
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_LATENCY, latency_weight);
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_SECURITY, security_weight);
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_CAPACITY, capacity_weight);
        vec_map::insert(&mut mpdr_config.criteria_weights, CRITERIA_GEO_DIVERSITY, geo_diversity_weight);
        
        mpdr_config.last_updated = now;
    }
    
    // Getter fonksiyonları
    
    /// MPDR konfigürasyon bilgilerini al
    public fun get_mpdr_config_info(
        mpdr_config: &MPDRConfig
    ): (u64, u64, u64, u64, u8, u64, u64) {
        (
            mpdr_config.min_path_count,
            mpdr_config.max_path_count,
            mpdr_config.path_calculation_frequency,
            mpdr_config.default_fragment_size,
            mpdr_config.default_encryption_method,
            mpdr_config.default_session_timeout,
            mpdr_config.last_updated
        )
    }
    
    /// Kriter ağırlıklarını al
    public fun get_criteria_weights(
        mpdr_config: &MPDRConfig
    ): (u64, u64, u64, u64) {
        (
            *vec_map::get(&mpdr_config.criteria_weights, &CRITERIA_LATENCY),
            *vec_map::get(&mpdr_config.criteria_weights, &CRITERIA_SECURITY),
            *vec_map::get(&mpdr_config.criteria_weights, &CRITERIA_CAPACITY),
            *vec_map::get(&mpdr_config.criteria_weights, &CRITERIA_GEO_DIVERSITY)
        )
    }
    
    /// Oturum bilgilerini al
    public fun get_session_info(
        session: &MPDRSession
    ): (address, u64, u64, u64, u64, u64, u8, u64) {
        (
            session.owner,
            vector::length(&session.paths),
            vec_set::size(&session.active_paths),
            session.created_at,
            session.last_active,
            session.expiry_time,
            session.encryption_method,
            session.total_data_transferred
        )
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_mpdr_config_for_testing(ctx: &mut TxContext): MPDRConfig {
        MPDRConfig {
            id: object::new(ctx),
            min_path_count: DEFAULT_MIN_PATH_COUNT,
            max_path_count: DEFAULT_MAX_PATH_COUNT,
            criteria_weights: vec_map::empty(),
            path_calculation_frequency: DEFAULT_PATH_REEVALUATION_INTERVAL,
            default_fragment_size: DEFAULT_FRAGMENT_SIZE,
            default_encryption_method: ENCRYPTION_AES_256_GCM,
            default_session_timeout: DEFAULT_SESSION_TIMEOUT,
            last_updated: 0,
        }
    }
}
