/// SuiVPN Security Controls Module
/// 
/// Bu modül, SuiVPN protokolünün güvenlik kontrollerini, tehdit algılama, 
/// önleme ve yanıt mekanizmalarını yönetir. Ağın güvenliğini ve kullanıcı 
/// gizliliğini korumak için tasarlanmış, çok katmanlı bir güvenlik mimarisi sağlar.
module suivpn::security_controls {
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
    use suivpn::governance::{Self, GovernanceCapability};
    use suivpn::registry::{Self, NodeInfo};
    use suivpn::validator::{Self, Validator};
    use suivpn::slashing::{Self};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidThreshold: u64 = 1;
    const EInvalidSeverity: u64 = 2;
    const EInvalidNode: u64 = 3;
    const EInvalidPeriod: u64 = 4;
    const EInvalidRule: u64 = 5;
    const EInvalidAddress: u64 = 6;
    const ENotFound: u64 = 7;
    const EDuplicateEntry: u64 = 8;
    const EInvalidState: u64 = 9;
    const EInvalidAction: u64 = 10;
    
    // Güvenlik olay türleri
    const SECURITY_EVENT_ANOMALY: u8 = 0;
    const SECURITY_EVENT_ATTACK: u8 = 1;
    const SECURITY_EVENT_CENSORSHIP: u8 = 2;
    const SECURITY_EVENT_BREACH: u8 = 3;
    const SECURITY_EVENT_DOWNTIME: u8 = 4;
    const SECURITY_EVENT_MALICIOUS: u8 = 5;
    const SECURITY_EVENT_VULNERABILITY: u8 = 6;
    
    // Güvenlik olay ciddiyet seviyeleri
    const SEVERITY_LOW: u8 = 0;
    const SEVERITY_MEDIUM: u8 = 1;
    const SEVERITY_HIGH: u8 = 2;
    const SEVERITY_CRITICAL: u8 = 3;
    
    // Güvenlik durumları
    const SECURITY_STATUS_NORMAL: u8 = 0;
    const SECURITY_STATUS_ELEVATED: u8 = 1;
    const SECURITY_STATUS_HIGH_ALERT: u8 = 2;
    const SECURITY_STATUS_EMERGENCY: u8 = 3;
    
    // Eylem türleri
    const ACTION_MONITOR: u8 = 0;
    const ACTION_WARN: u8 = 1;
    const ACTION_RESTRICT: u8 = 2;
    const ACTION_QUARANTINE: u8 = 3;
    const ACTION_SUSPEND: u8 = 4;
    const ACTION_BAN: u8 = 5;
    const ACTION_SLASH: u8 = 6;
    
    // Sabitler
    const DEFAULT_BAN_PERIOD_SECONDS: u64 = 2592000; // 30 gün (saniye)
    const DEFAULT_ANOMALY_THRESHOLD: u64 = 100; // Anomali eşiği
    const DEFAULT_ALERT_THRESHOLD: u64 = 200; // Uyarı eşiği
    const DEFAULT_EMERGENCY_THRESHOLD: u64 = 500; // Acil durum eşiği
    const MAX_SECURITY_EVENTS_HISTORY: u64 = 1000; // Maksimum güvenlik olay geçmişi
    
    /// Güvenlik Konfigürasyonu
    /// Güvenlik parametrelerini ve eşiklerini içerir
    struct SecurityConfig has key, store {
        id: UID,
        // Güvenlik durumu eşikleri
        anomaly_threshold: u64,
        alert_threshold: u64,
        emergency_threshold: u64,
        // Varsayılan yasaklama süresi (saniye)
        default_ban_period: u64,
        // Olay tipi bazlı puan çarpanları
        event_type_weights: VecMap<u8, u64>,
        // Ciddiyet bazlı puan çarpanları
        severity_weights: VecMap<u8, u64>,
        // Eylem bazlı puan eşikleri
        action_thresholds: VecMap<u8, u64>,
        // Otomatik eylem kuralları aktif mi?
        auto_actions_enabled: bool,
        // Güvenlik kuralları
        security_rules: vector<SecurityRule>,
        // Onaylı güvenlik protokolleri
        approved_protocols: VecSet<String>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Güvenlik Merkezi
    /// Güvenlik olaylarını ve güvenlik durumunu yönetir
    struct SecurityCenter has key {
        id: UID,
        // Mevcut ağ genelinde güvenlik durumu
        network_security_status: u8,
        // Toplam güvenlik olayları sayısı
        total_security_events: u64,
        // Olay tipi bazlı olay sayıları
        event_type_counts: VecMap<u8, u64>,
        // Düğüm bazlı toplam güvenlik puanları
        node_security_scores: Table<ID, u64>,
        // Adres bazlı toplam güvenlik puanları
        address_security_scores: Table<address, u64>,
        // Güvenlik olayları geçmişi
        security_events_history: vector<SecurityEvent>,
        // Kara liste (yasaklı adresler -> yasak bitiş zamanı)
        blacklist: Table<address, u64>,
        // Karantina listesi (karantina altındaki düğümler -> karantina bitiş zamanı)
        quarantined_nodes: Table<ID, u64>,
        // Askıya alınmış düğümler
        suspended_nodes: VecSet<ID>,
        // Son güvenlik değerlendirmesi zamanı
        last_assessment_time: u64,
    }
    
    /// Güvenlik Olayı
    /// Bir güvenlik olayını veya ihlalini temsil eder
    struct SecurityEvent has store, drop {
        // Olay ID'si
        event_id: ID,
        // Olay zamanı
        timestamp: u64,
        // Olay tipi
        event_type: u8,
        // Ciddiyet seviyesi
        severity: u8,
        // İlgili düğüm (varsa)
        node_id: Option<ID>,
        // İlgili adres (varsa)
        address: Option<address>,
        // Olay açıklaması
        description: String,
        // Olay ayrıntıları (JSON formatında)
        details: Option<String>,
        // Alınan eylem
        action_taken: u8,
        // Etki puanı
        impact_score: u64,
        // Doğrulayan düğümler
        validating_nodes: vector<ID>,
    }
    
    /// Güvenlik Kuralı
    /// Bir güvenlik kuralını veya politikasını tanımlar
    struct SecurityRule has store, drop {
        // Kural ID'si
        rule_id: u64,
        // Kural adı
        name: String,
        // Kural açıklaması
        description: String,
        // Tetikleyici olay tipleri
        trigger_event_types: vector<u8>,
        // Minimum ciddiyet seviyesi
        min_severity: u8,
        // Eşik değeri
        threshold: u64,
        // Tetiklenecek eylem
        action: u8,
        // Eylem süresi (saniye, 0=süresiz)
        action_duration: u64,
        // Kural aktif mi?
        is_active: bool,
        // Oluşturma zamanı
        created_at: u64,
    }
    
    /// Güvenlik Denetimi
    /// Bir düğüm için güvenlik denetimi sonuçlarını içerir
    struct SecurityAudit has key, store {
        id: UID,
        // Denetlenen düğüm
        node_id: ID,
        // Denetim zamanı
        audit_time: u64,
        // Denetim skoru (0-1000)
        score: u64,
        // Başarılı kontroller
        passed_checks: VecSet<String>,
        // Başarısız kontroller
        failed_checks: VecSet<String>,
        // Uyarılar
        warnings: vector<String>,
        // Denetleyici adres
        auditor: address,
        // Denetim sonucu
        result: String,
        // Denetim imzası
        signature: vector<u8>,
    }
    
    // Eventler
    
    /// Güvenlik olayı eventi
    struct SecurityEventOccurred has copy, drop {
        event_id: ID,
        event_type: u8,
        severity: u8,
        node_id: Option<ID>,
        address: Option<address>,
        timestamp: u64,
        action_taken: u8,
        impact_score: u64,
    }
    
    /// Güvenlik durumu değişikliği eventi
    struct SecurityStatusChanged has copy, drop {
        old_status: u8,
        new_status: u8,
        reason: String,
        timestamp: u64,
    }
    
    /// Düğüm karantina eventi
    struct NodeQuarantined has copy, drop {
        node_id: ID,
        reason: String,
        end_time: u64,
        timestamp: u64,
    }
    
    /// Adres yasaklama eventi
    struct AddressBlacklisted has copy, drop {
        address: address,
        reason: String,
        end_time: u64,
        timestamp: u64,
    }
    
    /// Güvenlik denetimi eventi
    struct SecurityAuditCompleted has copy, drop {
        audit_id: ID,
        node_id: ID,
        score: u64,
        pass_count: u64,
        fail_count: u64,
        timestamp: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let security_config = SecurityConfig {
            id: object::new(ctx),
            anomaly_threshold: DEFAULT_ANOMALY_THRESHOLD,
            alert_threshold: DEFAULT_ALERT_THRESHOLD,
            emergency_threshold: DEFAULT_EMERGENCY_THRESHOLD,
            default_ban_period: DEFAULT_BAN_PERIOD_SECONDS,
            event_type_weights: vec_map::empty(),
            severity_weights: vec_map::empty(),
            action_thresholds: vec_map::empty(),
            auto_actions_enabled: true,
            security_rules: vector::empty(),
            approved_protocols: vec_set::empty(),
            last_updated: 0,
        };
        
        // Olay tipi ağırlıklarını ayarla
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_ANOMALY, 10);
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_ATTACK, 50);
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_CENSORSHIP, 40);
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_BREACH, 60);
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_DOWNTIME, 20);
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_MALICIOUS, 70);
        vec_map::insert(&mut security_config.event_type_weights, SECURITY_EVENT_VULNERABILITY, 30);
        
        // Ciddiyet ağırlıklarını ayarla
        vec_map::insert(&mut security_config.severity_weights, SEVERITY_LOW, 10);
        vec_map::insert(&mut security_config.severity_weights, SEVERITY_MEDIUM, 30);
        vec_map::insert(&mut security_config.severity_weights, SEVERITY_HIGH, 60);
        vec_map::insert(&mut security_config.severity_weights, SEVERITY_CRITICAL, 100);
        
        // Eylem eşiklerini ayarla
        vec_map::insert(&mut security_config.action_thresholds, ACTION_MONITOR, 10);
        vec_map::insert(&mut security_config.action_thresholds, ACTION_WARN, 30);
        vec_map::insert(&mut security_config.action_thresholds, ACTION_RESTRICT, 50);
        vec_map::insert(&mut security_config.action_thresholds, ACTION_QUARANTINE, 100);
        vec_map::insert(&mut security_config.action_thresholds, ACTION_SUSPEND, 200);
        vec_map::insert(&mut security_config.action_thresholds, ACTION_BAN, 300);
        vec_map::insert(&mut security_config.action_thresholds, ACTION_SLASH, 500);
        
        // Onaylı protokolleri ayarla
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(b"OpenVPN"));
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(b"WireGuard"));
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(b"IKEv2/IPSec"));
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(b"L2TP/IPSec"));
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(b"SSTP"));
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(b"ShadowSocks"));
        
        // Varsayılan güvenlik kurallarını oluştur
        let rule1 = SecurityRule {
            rule_id: 1,
            name: string::utf8(b"Downtime Detection"),
            description: string::utf8(b"Detect prolonged node downtime"),
            trigger_event_types: vector::singleton(SECURITY_EVENT_DOWNTIME),
            min_severity: SEVERITY_MEDIUM,
            threshold: 30,
            action: ACTION_WARN,
            action_duration: 0,
            is_active: true,
            created_at: 0,
        };
        
        let rule2 = SecurityRule {
            rule_id: 2,
            name: string::utf8(b"Attack Prevention"),
            description: string::utf8(b"Prevent suspected attacks"),
            trigger_event_types: vector::singleton(SECURITY_EVENT_ATTACK),
            min_severity: SEVERITY_HIGH,
            threshold: 50,
            action: ACTION_QUARANTINE,
            action_duration: 86400, // 1 gün
            is_active: true,
            created_at: 0,
        };
        
        let rule3 = SecurityRule {
            rule_id: 3,
            name: string::utf8(b"Malicious Activity"),
            description: string::utf8(b"Block malicious nodes"),
            trigger_event_types: vector::singleton(SECURITY_EVENT_MALICIOUS),
            min_severity: SEVERITY_HIGH,
            threshold: 70,
            action: ACTION_SUSPEND,
            action_duration: 604800, // 7 gün
            is_active: true,
            created_at: 0,
        };
        
        let rule4 = SecurityRule {
            rule_id: 4,
            name: string::utf8(b"Critical Breach"),
            description: string::utf8(b"Ban nodes with critical security breaches"),
            trigger_event_types: vector::singleton(SECURITY_EVENT_BREACH),
            min_severity: SEVERITY_CRITICAL,
            threshold: 100,
            action: ACTION_BAN,
            action_duration: DEFAULT_BAN_PERIOD_SECONDS,
            is_active: true,
            created_at: 0,
        };
        
        vector::push_back(&mut security_config.security_rules, rule1);
        vector::push_back(&mut security_config.security_rules, rule2);
        vector::push_back(&mut security_config.security_rules, rule3);
        vector::push_back(&mut security_config.security_rules, rule4);
        
        let security_center = SecurityCenter {
            id: object::new(ctx),
            network_security_status: SECURITY_STATUS_NORMAL,
            total_security_events: 0,
            event_type_counts: vec_map::empty(),
            node_security_scores: table::new(ctx),
            address_security_scores: table::new(ctx),
            security_events_history: vector::empty(),
            blacklist: table::new(ctx),
            quarantined_nodes: table::new(ctx),
            suspended_nodes: vec_set::empty(),
            last_assessment_time: 0,
        };
        
        // Olay sayaçlarını başlat
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_ANOMALY, 0);
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_ATTACK, 0);
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_CENSORSHIP, 0);
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_BREACH, 0);
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_DOWNTIME, 0);
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_MALICIOUS, 0);
        vec_map::insert(&mut security_center.event_type_counts, SECURITY_EVENT_VULNERABILITY, 0);
        
        transfer::share_object(security_config);
        transfer::share_object(security_center);
    }
    
    /// Güvenlik olayı bildir
    public entry fun report_security_event(
        security_center: &mut SecurityCenter,
        security_config: &SecurityConfig,
        event_type: u8,
        severity: u8,
        node_id: Option<ID>,
        address: Option<address>,
        description: vector<u8>,
        details: Option<vector<u8>>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Olay tipini ve ciddiyet seviyesini kontrol et
        assert!(
            event_type == SECURITY_EVENT_ANOMALY ||
            event_type == SECURITY_EVENT_ATTACK ||
            event_type == SECURITY_EVENT_CENSORSHIP ||
            event_type == SECURITY_EVENT_BREACH ||
            event_type == SECURITY_EVENT_DOWNTIME ||
            event_type == SECURITY_EVENT_MALICIOUS ||
            event_type == SECURITY_EVENT_VULNERABILITY,
            EInvalidSeverity
        );
        
        assert!(
            severity == SEVERITY_LOW ||
            severity == SEVERITY_MEDIUM ||
            severity == SEVERITY_HIGH ||
            severity == SEVERITY_CRITICAL,
            EInvalidSeverity
        );
        
        let reporter = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Etki puanını hesapla
        let event_weight = *vec_map::get(&security_config.event_type_weights, &event_type);
        let severity_weight = *vec_map::get(&security_config.severity_weights, &severity);
        let impact_score = event_weight * severity_weight;
        
        // Uygun eylemi belirle
        let action = determine_action(security_config, event_type, severity, impact_score);
        
        // Olay ID'si oluştur
        let event_id = object::new(ctx);
        let event_id_inner = object::uid_to_inner(&event_id);
        object::delete(event_id);
        
        // Validatör düğümlerin listesi (şimdilik boş)
        let validating_nodes = vector::empty<ID>();
        
        // Güvenlik olayı oluştur
        let security_event = SecurityEvent {
            event_id: event_id_inner,
            timestamp: now,
            event_type,
            severity,
            node_id,
            address,
            description: string::utf8(description),
            details: option::map(details, |d| string::utf8(*d)),
            action_taken: action,
            impact_score,
            validating_nodes,
        };
        
        // Güvenlik durumunu güncelle
        update_security_status(security_center, security_config, impact_score, now);
        
        // İlgili kayıtları güncelle
        
        // Düğüm güvenlik skorunu güncelle
        if (option::is_some(&node_id)) {
            let node = *option::borrow(&node_id);
            
            if (table::contains(&security_center.node_security_scores, node)) {
                let score = table::borrow_mut(&mut security_center.node_security_scores, node);
                *score = *score + impact_score;
            } else {
                table::add(&mut security_center.node_security_scores, node, impact_score);
            };
            
            // Eylemi uygula
            apply_node_action(security_center, node, action, now, security_config.default_ban_period);
        };
        
        // Adres güvenlik skorunu güncelle
        if (option::is_some(&address)) {
            let addr = *option::borrow(&address);
            
            if (table::contains(&security_center.address_security_scores, addr)) {
                let score = table::borrow_mut(&mut security_center.address_security_scores, addr);
                *score = *score + impact_score;
            } else {
                table::add(&mut security_center.address_security_scores, addr, impact_score);
            };
            
            // Eylemi uygula
            apply_address_action(security_center, addr, action, now, security_config.default_ban_period);
        };
        
        // Olay sayılarını güncelle
        let count = vec_map::get_mut(&mut security_center.event_type_counts, &event_type);
        *count = *count + 1;
        security_center.total_security_events = security_center.total_security_events + 1;
        
        // Olay geçmişini güncelle
        vector::push_back(&mut security_center.security_events_history, security_event);
        
        // Geçmiş boyutunu kontrol et
        if (vector::length(&security_center.security_events_history) > MAX_SECURITY_EVENTS_HISTORY) {
            vector::remove(&mut security_center.security_events_history, 0);
        };
        
        // Güvenlik kurallarını kontrol et
        if (security_config.auto_actions_enabled) {
            check_security_rules(security_center, security_config, event_type, severity, impact_score, node_id, address, now);
        };
        
        // Güvenlik olayı eventini yayınla
        event::emit(SecurityEventOccurred {
            event_id: event_id_inner,
            event_type,
            severity,
            node_id,
            address,
            timestamp: now,
            action_taken: action,
            impact_score,
        });
        
        security_center.last_assessment_time = now;
    }
    
    /// Düğüm karantinaya al
    public entry fun quarantine_node(
        security_center: &mut SecurityCenter,
        node_id: ID,
        reason: vector<u8>,
        duration_seconds: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Sürenin geçerli olup olmadığını kontrol et
        assert!(duration_seconds > 0, EInvalidPeriod);
        
        // Karantina bitiş zamanını hesapla
        let end_time = now + duration_seconds;
        
        // Düğümü karantinaya al
        if (table::contains(&security_center.quarantined_nodes, node_id)) {
            // Zaten karantinada, süreyi uzat
            *table::borrow_mut(&mut security_center.quarantined_nodes, node_id) = end_time;
        } else {
            // Yeni karantina ekle
            table::add(&mut security_center.quarantined_nodes, node_id, end_time);
        };
        
        // Karantina eventini yayınla
        event::emit(NodeQuarantined {
            node_id,
            reason: string::utf8(reason),
            end_time,
            timestamp: now,
        });
    }
    
    /// Adresi kara listeye al
    public entry fun blacklist_address(
        security_center: &mut SecurityCenter,
        address: address,
        reason: vector<u8>,
        duration_seconds: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Sürenin geçerli olup olmadığını kontrol et
        assert!(duration_seconds > 0, EInvalidPeriod);
        
        // Yasaklama bitiş zamanını hesapla
        let end_time = now + duration_seconds;
        
        // Adresi kara listeye al
        if (table::contains(&security_center.blacklist, address)) {
            // Zaten kara listede, süreyi uzat
            *table::borrow_mut(&mut security_center.blacklist, address) = end_time;
        } else {
            // Yeni yasaklama ekle
            table::add(&mut security_center.blacklist, address, end_time);
        };
        
        // Yasaklama eventini yayınla
        event::emit(AddressBlacklisted {
            address,
            reason: string::utf8(reason),
            end_time,
            timestamp: now,
        });
    }
    
    /// Düğümü askıya al
    public entry fun suspend_node(
        security_center: &mut SecurityCenter,
        node_id: ID,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        // Düğümü askıya al
        vec_set::insert(&mut security_center.suspended_nodes, node_id);
    }
    
    /// Düğüm askıya almayı kaldır
    public entry fun unsuspend_node(
        security_center: &mut SecurityCenter,
        node_id: ID,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        // Düğümün askıya alınmış olup olmadığını kontrol et
        assert!(vec_set::contains(&security_center.suspended_nodes, &node_id), ENotFound);
        
        // Askıya almayı kaldır
        vec_set::remove(&mut security_center.suspended_nodes, &node_id);
    }
    
    /// Adresin kara listede olup olmadığını kontrol et
    public fun is_address_blacklisted(
        security_center: &SecurityCenter,
        address: address,
        clock: &Clock
    ): bool {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        if (table::contains(&security_center.blacklist, address)) {
            let end_time = *table::borrow(&security_center.blacklist, address);
            
            // Süresiz yasak (end_time = 0) veya süre dolmamış ise
            end_time == 0 || now < end_time
        } else {
            false
        }
    }
    
    /// Düğümün karantinada olup olmadığını kontrol et
    public fun is_node_quarantined(
        security_center: &SecurityCenter,
        node_id: ID,
        clock: &Clock
    ): bool {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        if (table::contains(&security_center.quarantined_nodes, node_id)) {
            let end_time = *table::borrow(&security_center.quarantined_nodes, node_id);
            
            // Süresiz karantina (end_time = 0) veya süre dolmamış ise
            end_time == 0 || now < end_time
        } else {
            false
        }
    }
    
    /// Düğümün askıya alınmış olup olmadığını kontrol et
    public fun is_node_suspended(
        security_center: &SecurityCenter,
        node_id: ID
    ): bool {
        vec_set::contains(&security_center.suspended_nodes, &node_id)
    }
    
    /// Güvenlik denetimi oluştur
    public entry fun create_security_audit(
        node_id: ID,
        score: u64,
        passed_check_strings: vector<vector<u8>>,
        failed_check_strings: vector<vector<u8>>,
        warning_strings: vector<vector<u8>>,
        result: vector<u8>,
        signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let auditor = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Puanın geçerli olup olmadığını kontrol et
        assert!(score <= 1000, EInvalidValue);
        
        // Kontrol listelerini dönüştür
        let passed_checks = vec_set::empty<String>();
        let i = 0;
        let len = vector::length(&passed_check_strings);
        
        while (i < len) {
            let check = string::utf8(*vector::borrow(&passed_check_strings, i));
            vec_set::insert(&mut passed_checks, check);
            i = i + 1;
        };
        
        let failed_checks = vec_set::empty<String>();
        let i = 0;
        let len = vector::length(&failed_check_strings);
        
        while (i < len) {
            let check = string::utf8(*vector::borrow(&failed_check_strings, i));
            vec_set::insert(&mut failed_checks, check);
            i = i + 1;
        };
        
        let warnings = vector::empty<String>();
        let i = 0;
        let len = vector::length(&warning_strings);
        
        while (i < len) {
            let warning = string::utf8(*vector::borrow(&warning_strings, i));
            vector::push_back(&mut warnings, warning);
            i = i + 1;
        };
        
        // Denetim nesnesi oluştur
        let audit = SecurityAudit {
            id: object::new(ctx),
            node_id,
            audit_time: now,
            score,
            passed_checks,
            failed_checks,
            warnings,
            auditor,
            result: string::utf8(result),
            signature,
        };
        
        let audit_id = object::id(&audit);
        
        // Denetim tamamlandı eventini yayınla
        event::emit(SecurityAuditCompleted {
            audit_id,
            node_id,
            score,
            pass_count: vec_set::size(&passed_checks),
            fail_count: vec_set::size(&failed_checks),
            timestamp: now,
        });
        
        // Denetimi düğüm sahibine aktar
        transfer::transfer(audit, get_node_owner(node_id));
    }
    
    /// Güvenlik kuralı ekle
    public entry fun add_security_rule(
        security_config: &mut SecurityConfig,
        name: vector<u8>,
        description: vector<u8>,
        event_types: vector<u8>,
        min_severity: u8,
        threshold: u64,
        action: u8,
        action_duration: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Ciddiyet seviyesini kontrol et
        assert!(
            min_severity == SEVERITY_LOW ||
            min_severity == SEVERITY_MEDIUM ||
            min_severity == SEVERITY_HIGH ||
            min_severity == SEVERITY_CRITICAL,
            EInvalidSeverity
        );
        
        // Eylemi kontrol et
        assert!(
            action == ACTION_MONITOR ||
            action == ACTION_WARN ||
            action == ACTION_RESTRICT ||
            action == ACTION_QUARANTINE ||
            action == ACTION_SUSPEND ||
            action == ACTION_BAN ||
            action == ACTION_SLASH,
            EInvalidAction
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni kural ID'sini belirle
        let rule_id = vector::length(&security_config.security_rules) + 1;
        
        // Olay tiplerini kontrol et ve dönüştür
        let trigger_event_types = vector::empty<u8>();
        let i = 0;
        let len = vector::length(&event_types);
        
        while (i < len) {
            let event_type = *vector::borrow(&event_types, i);
            assert!(
                event_type == SECURITY_EVENT_ANOMALY ||
                event_type == SECURITY_EVENT_ATTACK ||
                event_type == SECURITY_EVENT_CENSORSHIP ||
                event_type == SECURITY_EVENT_BREACH ||
                event_type == SECURITY_EVENT_DOWNTIME ||
                event_type == SECURITY_EVENT_MALICIOUS ||
                event_type == SECURITY_EVENT_VULNERABILITY,
                EInvalidSeverity
            );
            vector::push_back(&mut trigger_event_types, event_type);
            i = i + 1;
        };
        
        // Kural oluştur
        let rule = SecurityRule {
            rule_id,
            name: string::utf8(name),
            description: string::utf8(description),
            trigger_event_types,
            min_severity,
            threshold,
            action,
            action_duration,
            is_active: true,
            created_at: now,
        };
        
        // Kuralı ekle
        vector::push_back(&mut security_config.security_rules, rule);
        
        security_config.last_updated = now;
    }
    
    /// Güvenlik kuralını değiştir
    public entry fun update_security_rule(
        security_config: &mut SecurityConfig,
        rule_id: u64,
        is_active: bool,
        threshold: Option<u64>,
        action: Option<u8>,
        action_duration: Option<u64>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Kuralın var olup olmadığını kontrol et
        assert!(rule_id > 0 && rule_id <= vector::length(&security_config.security_rules), ENotFound);
        
        // Eylem geçerli mi kontrol et (varsa)
        if (option::is_some(&action)) {
            let act = *option::borrow(&action);
            assert!(
                act == ACTION_MONITOR ||
                act == ACTION_WARN ||
                act == ACTION_RESTRICT ||
                act == ACTION_QUARANTINE ||
                act == ACTION_SUSPEND ||
                act == ACTION_BAN ||
                act == ACTION_SLASH,
                EInvalidAction
            );
        };
        
        // Kuralı bul ve güncelle
        let rule = vector::borrow_mut(&mut security_config.security_rules, (rule_id - 1 as u64));
        
        // Aktiflik durumunu güncelle
        rule.is_active = is_active;
        
        // Eşiği güncelle (varsa)
        if (option::is_some(&threshold)) {
            rule.threshold = *option::borrow(&threshold);
        };
        
        // Eylemi güncelle (varsa)
        if (option::is_some(&action)) {
            rule.action = *option::borrow(&action);
        };
        
        // Eylem süresini güncelle (varsa)
        if (option::is_some(&action_duration)) {
            rule.action_duration = *option::borrow(&action_duration);
        };
        
        security_config.last_updated = now;
    }
    
    /// Güvenlik konfigürasyonunu güncelle
    public entry fun update_security_config(
        security_config: &mut SecurityConfig,
        anomaly_threshold: Option<u64>,
        alert_threshold: Option<u64>,
        emergency_threshold: Option<u64>,
        ban_period: Option<u64>,
        auto_actions: Option<bool>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Anomali eşiğini güncelle (varsa)
        if (option::is_some(&anomaly_threshold)) {
            security_config.anomaly_threshold = *option::borrow(&anomaly_threshold);
        };
        
        // Uyarı eşiğini güncelle (varsa)
        if (option::is_some(&alert_threshold)) {
            let alert = *option::borrow(&alert_threshold);
            assert!(alert > security_config.anomaly_threshold, EInvalidThreshold);
            security_config.alert_threshold = alert;
        };
        
        // Acil durum eşiğini güncelle (varsa)
        if (option::is_some(&emergency_threshold)) {
            let emergency = *option::borrow(&emergency_threshold);
            assert!(emergency > security_config.alert_threshold, EInvalidThreshold);
            security_config.emergency_threshold = emergency;
        };
        
        // Yasaklama süresini güncelle (varsa)
        if (option::is_some(&ban_period)) {
            security_config.default_ban_period = *option::borrow(&ban_period);
        };
        
        // Otomatik eylemleri güncelle (varsa)
        if (option::is_some(&auto_actions)) {
            security_config.auto_actions_enabled = *option::borrow(&auto_actions);
        };
        
        security_config.last_updated = now;
    }
    
    /// Onaylı protokol ekle
    public entry fun add_approved_protocol(
        security_config: &mut SecurityConfig,
        protocol: vector<u8>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Protokolü ekle
        vec_set::insert(&mut security_config.approved_protocols, string::utf8(protocol));
        
        security_config.last_updated = now;
    }
    
    /// Onaylı protokol kaldır
    public entry fun remove_approved_protocol(
        security_config: &mut SecurityConfig,
        protocol: vector<u8>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Protokolün var olup olmadığını kontrol et
        let protocol_str = string::utf8(protocol);
        assert!(vec_set::contains(&security_config.approved_protocols, &protocol_str), ENotFound);
        
        // Protokolü kaldır
        vec_set::remove(&mut security_config.approved_protocols, &protocol_str);
        
        security_config.last_updated = now;
    }
    
    /// Süresi dolmuş karantinaları temizle
    public entry fun clear_expired_quarantines(
        security_center: &mut SecurityCenter,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Süresi dolmuş karantinaları bul
        let expired_nodes = vector::empty<ID>();
        
        let nodes = table::keys(&security_center.quarantined_nodes);
        let i = 0;
        let len = vector::length(&nodes);
        
        while (i < len) {
            let node_id = *vector::borrow(&nodes, i);
            let end_time = *table::borrow(&security_center.quarantined_nodes, node_id);
            
            if (end_time > 0 && now >= end_time) {
                vector::push_back(&mut expired_nodes, node_id);
            };
            
            i = i + 1;
        };
        
        // Süresi dolmuş karantinaları kaldır
        let i = 0;
        let len = vector::length(&expired_nodes);
        
        while (i < len) {
            let node_id = *vector::borrow(&expired_nodes, i);
            table::remove(&mut security_center.quarantined_nodes, node_id);
            i = i + 1;
        };
    }
    
    /// Süresi dolmuş yasaklamaları temizle
    public entry fun clear_expired_blacklists(
        security_center: &mut SecurityCenter,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Süresi dolmuş yasaklamaları bul
        let expired_addresses = vector::empty<address>();
        
        let addresses = table::keys(&security_center.blacklist);
        let i = 0;
        let len = vector::length(&addresses);
        
        while (i < len) {
            let addr = *vector::borrow(&addresses, i);
            let end_time = *table::borrow(&security_center.blacklist, addr);
            
            if (end_time > 0 && now >= end_time) {
                vector::push_back(&mut expired_addresses, addr);
            };
            
            i = i + 1;
        };
        
        // Süresi dolmuş yasaklamaları kaldır
        let i = 0;
        let len = vector::length(&expired_addresses);
        
        while (i < len) {
            let addr = *vector::borrow(&expired_addresses, i);
            table::remove(&mut security_center.blacklist, addr);
            i = i + 1;
        };
    }
    
    // Yardımcı fonksiyonlar
    
    /// Bir güvenlik olayı için uygun eylemi belirle
    fun determine_action(
        security_config: &SecurityConfig,
        event_type: u8,
        severity: u8,
        impact_score: u64
    ): u8 {
        // İlk olarak tüm eylem eşiklerini incele
        let action = ACTION_MONITOR; // Varsayılan eylem
        
        if (impact_score >= *vec_map::get(&security_config.action_thresholds, &ACTION_SLASH)) {
            action = ACTION_SLASH;
        } else if (impact_score >= *vec_map::get(&security_config.action_thresholds, &ACTION_BAN)) {
            action = ACTION_BAN;
        } else if (impact_score >= *vec_map::get(&security_config.action_thresholds, &ACTION_SUSPEND)) {
            action = ACTION_SUSPEND;
        } else if (impact_score >= *vec_map::get(&security_config.action_thresholds, &ACTION_QUARANTINE)) {
            action = ACTION_QUARANTINE;
        } else if (impact_score >= *vec_map::get(&security_config.action_thresholds, &ACTION_RESTRICT)) {
            action = ACTION_RESTRICT;
        } else if (impact_score >= *vec_map::get(&security_config.action_thresholds, &ACTION_WARN)) {
            action = ACTION_WARN;
        };
        
        // Kritik olaylar için özel durumlar
        if (severity == SEVERITY_CRITICAL) {
            if (event_type == SECURITY_EVENT_BREACH || event_type == SECURITY_EVENT_MALICIOUS) {
                action = ACTION_BAN;
            } else if (event_type == SECURITY_EVENT_ATTACK) {
                action = ACTION_SUSPEND;
            };
        };
        
        action
    }
    
    /// Güvenlik kurallarını kontrol et
    fun check_security_rules(
        security_center: &mut SecurityCenter,
        security_config: &SecurityConfig,
        event_type: u8,
        severity: u8,
        impact_score: u64,
        node_id: Option<ID>,
        address: Option<address>,
        now: u64
    ) {
        let rules = &security_config.security_rules;
        let i = 0;
        let len = vector::length(rules);
        
        while (i < len) {
            let rule = vector::borrow(rules, i);
            
            if (rule.is_active && severity >= rule.min_severity && impact_score >= rule.threshold) {
                // Olay tipini kontrol et
                let j = 0;
                let triggers_len = vector::length(&rule.trigger_event_types);
                let is_triggered = false;
                
                while (j < triggers_len && !is_triggered) {
                    if (*vector::borrow(&rule.trigger_event_types, j) == event_type) {
                        is_triggered = true;
                    };
                    j = j + 1;
                };
                
                if (is_triggered) {
                    // Eylemi uygula
                    if (option::is_some(&node_id)) {
                        apply_node_action(
                            security_center, 
                            *option::borrow(&node_id), 
                            rule.action, 
                            now, 
                            rule.action_duration
                        );
                    };
                    
                    if (option::is_some(&address)) {
                        apply_address_action(
                            security_center, 
                            *option::borrow(&address), 
                            rule.action, 
                            now, 
                            rule.action_duration
                        );
                    };
                };
            };
            
            i = i + 1;
        };
    }
    
    /// Düğüme bir eylem uygula
    fun apply_node_action(
        security_center: &mut SecurityCenter,
        node_id: ID,
        action: u8,
        now: u64,
        default_duration: u64
    ) {
        if (action == ACTION_SUSPEND) {
            vec_set::insert(&mut security_center.suspended_nodes, node_id);
        } else if (action == ACTION_QUARANTINE) {
            // Karantina süresini hesapla
            let duration = if (default_duration == 0) { 86400 } else { default_duration }; // Varsayılan 1 gün
            let end_time = now + duration;
            
            if (table::contains(&security_center.quarantined_nodes, node_id)) {
                let current_end_time = *table::borrow(&security_center.quarantined_nodes, node_id);
                if (end_time > current_end_time) {
                    *table::borrow_mut(&mut security_center.quarantined_nodes, node_id) = end_time;
                };
            } else {
                table::add(&mut security_center.quarantined_nodes, node_id, end_time);
            };
        } else if (action == ACTION_SLASH) {
            // Slash işlemi başka bir modülde gerçekleştirilecek
            // Burada sadece işaretleme yapılıyor
            vec_set::insert(&mut security_center.suspended_nodes, node_id);
            
            // Burada düğümün cezalandırılması gerektiğini işaretliyoruz
            // Gerçek implementasyonda slashing modülüne bir çağrı yapılacak
        };
    }
    
    /// Adrese bir eylem uygula
    fun apply_address_action(
        security_center: &mut SecurityCenter,
        address: address,
        action: u8,
        now: u64,
        default_duration: u64
    ) {
        if (action == ACTION_BAN) {
            // Yasaklama süresini hesapla
            let duration = if (default_duration == 0) { DEFAULT_BAN_PERIOD_SECONDS } else { default_duration };
            let end_time = now + duration;
            
            if (table::contains(&security_center.blacklist, address)) {
                let current_end_time = *table::borrow(&security_center.blacklist, address);
                if (end_time > current_end_time) {
                    *table::borrow_mut(&mut security_center.blacklist, address) = end_time;
                };
            } else {
                table::add(&mut security_center.blacklist, address, end_time);
            };
        };
    }
    
    /// Güvenlik durumunu güncelle
    fun update_security_status(
        security_center: &mut SecurityCenter,
        security_config: &SecurityConfig,
        impact_score: u64,
        now: u64
    ) {
        let old_status = security_center.network_security_status;
        let new_status = old_status;
        
        // Son 24 saat içindeki toplam etki puanını hesapla
        let total_recent_impact = calculate_recent_impact(security_center, now, 86400); // 24 saat
        
        // Yeni durumu belirle
        if (total_recent_impact >= security_config.emergency_threshold) {
            new_status = SECURITY_STATUS_EMERGENCY;
        } else if (total_recent_impact >= security_config.alert_threshold) {
            new_status = SECURITY_STATUS_HIGH_ALERT;
        } else if (total_recent_impact >= security_config.anomaly_threshold) {
            new_status = SECURITY_STATUS_ELEVATED;
        } else {
            new_status = SECURITY_STATUS_NORMAL;
        };
        
        // Durum değiştiyse güncelle ve event yayınla
        if (new_status != old_status) {
            security_center.network_security_status = new_status;
            
            let reason = if (new_status > old_status) {
                string::utf8(b"Security threat level increased due to recent events")
            } else {
                string::utf8(b"Security threat level decreased as situation stabilized")
            };
            
            event::emit(SecurityStatusChanged {
                old_status,
                new_status,
                reason,
                timestamp: now,
            });
        };
    }
    
    /// Son belirli süredeki toplam etki puanını hesapla
    fun calculate_recent_impact(
        security_center: &SecurityCenter,
        now: u64,
        time_window: u64
    ): u64 {
        let events = &security_center.security_events_history;
        let total_impact = 0;
        let i = 0;
        let len = vector::length(events);
        
        // Son olaylardan geriye doğru hesapla
        // Not: Olaylar tarih sırasına göre olduğu için, ilk eski olay bulunduğunda döngüden çıkılabilir
        let start_time = if (now > time_window) { now - time_window } else { 0 };
        
        while (i < len) {
            let event_index = len - i - 1; // Sondan başlayarak incele
            let event = vector::borrow(events, event_index);
            
            if (event.timestamp >= start_time) {
                total_impact = total_impact + event.impact_score;
            } else {
                break
            };
            
            i = i + 1;
        };
        
        total_impact
    }
    
    /// Düğüm sahibini al
    fun get_node_owner(node_id: ID): address {
        // Gerçek implementasyonda registry modülünden çağrılacak
        // Şimdilik varsayılan adres döndürelim
        @suivpn
    }
    
    // Getter fonksiyonları
    
    /// Güvenlik durumunu al
    public fun get_security_status(security_center: &SecurityCenter): u8 {
        security_center.network_security_status
    }
    
    /// Düğüm güvenlik skorunu al
    public fun get_node_security_score(security_center: &SecurityCenter, node_id: ID): u64 {
        if (table::contains(&security_center.node_security_scores, node_id)) {
            *table::borrow(&security_center.node_security_scores, node_id)
        } else {
            0
        }
    }
    
    /// Adres güvenlik skorunu al
    public fun get_address_security_score(security_center: &SecurityCenter, address: address): u64 {
        if (table::contains(&security_center.address_security_scores, address)) {
            *table::borrow(&security_center.address_security_scores, address)
        } else {
            0
        }
    }
    
    /// Protokolün onaylı olup olmadığını kontrol et
    public fun is_protocol_approved(security_config: &SecurityConfig, protocol: vector<u8>): bool {
        vec_set::contains(&security_config.approved_protocols, &string::utf8(protocol))
    }
    
    /// Güvenlik konfigürasyon bilgilerini al
    public fun get_security_config_info(security_config: &SecurityConfig): (u64, u64, u64, u64, bool, u64) {
        (
            security_config.anomaly_threshold,
            security_config.alert_threshold,
            security_config.emergency_threshold,
            security_config.default_ban_period,
            security_config.auto_actions_enabled,
            security_config.last_updated
        )
    }
    
    /// Güvenlik merkezi bilgilerini al
    public fun get_security_center_info(security_center: &SecurityCenter): (u8, u64, u64, u64, u64) {
        (
            security_center.network_security_status,
            security_center.total_security_events,
            table::length(&security_center.blacklist),
            table::length(&security_center.quarantined_nodes),
            vec_set::size(&security_center.suspended_nodes)
        )
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_security_config_for_testing(ctx: &mut TxContext): SecurityConfig {
        SecurityConfig {
            id: object::new(ctx),
            anomaly_threshold: DEFAULT_ANOMALY_THRESHOLD,
            alert_threshold: DEFAULT_ALERT_THRESHOLD,
            emergency_threshold: DEFAULT_EMERGENCY_THRESHOLD,
            default_ban_period: DEFAULT_BAN_PERIOD_SECONDS,
            event_type_weights: vec_map::empty(),
            severity_weights: vec_map::empty(),
            action_thresholds: vec_map::empty(),
            auto_actions_enabled: true,
            security_rules: vector::empty(),
            approved_protocols: vec_set::empty(),
            last_updated: 0,
        }
    }
}
