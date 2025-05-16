/// SuiVPN Node Validation Module
/// 
/// Bu modül, SuiVPN ağına katılmak isteyen düğümlerin doğrulanması ve
/// aktif düğümlerin sürekli performans değerlendirmesi için gerekli mekanizmaları sağlar.
/// Düğüm kalitesini, güvenliğini ve güvenilirliğini sağlamak için çeşitli kontroller uygular.
module suivpn::node_validation {
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
    use suivpn::validator::{Self, Validator, ValidatorRegistry};
    use suivpn::registry::{Self, NodeInfo};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidNode: u64 = 1;
    const ENodeAlreadyValidated: u64 = 2;
    const EInvalidScore: u64 = 3;
    const EValidationPeriodNotEnded: u64 = 4;
    const EChallengeNotFound: u64 = 5;
    const EChallengeExpired: u64 = 6;
    const EInvalidChallenge: u64 = 7;
    const EInvalidResponse: u64 = 8;
    const EChallengeAlreadyCompleted: u64 = 9;
    const EInvalidValidator: u64 = 10;
    const EInvalidCriteria: u64 = 11;
    const EInvalidThreshold: u64 = 12;
    
    // Doğrulama durumları
    const VALIDATION_STATUS_PENDING: u8 = 0;
    const VALIDATION_STATUS_ACTIVE: u8 = 1;
    const VALIDATION_STATUS_FAILED: u8 = 2;
    const VALIDATION_STATUS_EXPIRED: u8 = 3;
    
    // Doğrulama kriterleri tipleri
    const CRITERIA_BANDWIDTH: u8 = 0;
    const CRITERIA_LATENCY: u8 = 1;
    const CRITERIA_UPTIME: u8 = 2;
    const CRITERIA_SECURITY: u8 = 3;
    const CRITERIA_GEOGRAPHICAL: u8 = 4;
    
    // Challenge tipleri
    const CHALLENGE_BANDWIDTH_TEST: u8 = 0;
    const CHALLENGE_LATENCY_TEST: u8 = 1;
    const CHALLENGE_CRYPTO_VERIFICATION: u8 = 2;
    const CHALLENGE_PROTOCOL_COMPLIANCE: u8 = 3;
    const CHALLENGE_CONNECTIVITY_TEST: u8 = 4;
    
    // Sabitler
    const CHALLENGE_EXPIRATION: u64 = 86400; // 1 gün (saniye)
    const VALIDATION_PERIOD: u64 = 604800; // 7 gün (saniye)
    const MIN_BANDWIDTH_MBPS: u64 = 100; // Minimum 100 Mbps
    const MAX_LATENCY_MS: u64 = 150; // Maksimum 150 ms
    const MIN_UPTIME_PERCENTAGE: u64 = 980; // Minimum %98 (binde)
    
    /// Doğrulama konfigürasyonu
    /// Düğüm doğrulama kriterlerini ve parametrelerini içerir
    struct ValidationConfig has key, store {
        id: UID,
        // Doğrulama kriterleri ve ağırlıkları (binde)
        criteria_weights: VecMap<u8, u64>,
        // Minimum bant genişliği gereksinimi (Mbps)
        min_bandwidth: u64,
        // Maksimum gecikme süresi (ms)
        max_latency: u64,
        // Minimum çevrimiçi kalma yüzdesi (binde)
        min_uptime: u64,
        // Doğrulama için minimum toplam skor (binde)
        min_validation_score: u64,
        // Challenge süresi (saniye)
        challenge_expiration: u64,
        // Doğrulama periyodu (saniye)
        validation_period: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Doğrulama kaydı
    /// Tüm düğüm doğrulama sonuçlarını ve sürmekte olan doğrulamaları içerir
    struct ValidationRegistry has key {
        id: UID,
        // Düğüm doğrulama sonuçları
        validation_results: Table<ID, ValidationResult>,
        // Aktif challenge'lar
        active_challenges: Table<ID, vector<Challenge>>,
        // Challenge yanıtları
        challenge_responses: Table<ID, vector<ChallengeResponse>>,
        // Doğrulayıcı düğüm performansı
        validator_performance: Table<ID, ValidatorPerformance>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Doğrulama sonucu
    /// Bir düğümün doğrulama sonucunu içerir
    struct ValidationResult has store {
        // Düğüm ID'si
        node_id: ID,
        // Doğrulama durumu
        status: u8,
        // Toplam doğrulama skoru (binde)
        total_score: u64,
        // Kriter bazlı skorlar
        criteria_scores: VecMap<u8, u64>,
        // Doğrulama zamanı
        validation_time: u64,
        // Doğrulama sona erme zamanı
        expiration_time: u64,
        // Son doğrulayan
        last_validator: address,
    }
    
    /// Challenge
    /// Bir düğüme gönderilen doğrulama challenge'ını temsil eder
    struct Challenge has store, drop, copy {
        // Challenge ID'si
        challenge_id: ID,
        // Hedef düğüm ID'si
        node_id: ID,
        // Challenge tipi
        challenge_type: u8,
        // Challenge içeriği
        content: String,
        // Beklenen yanıt tipi
        expected_response_type: String,
        // Challenge oluşturma zamanı
        creation_time: u64,
        // Challenge sona erme zamanı
        expiration_time: u64,
        // Challenge oluşturucu
        creator: address,
        // Doğrulama kriteri
        validation_criteria: u8,
    }
    
    /// Challenge yanıtı
    /// Bir düğümün bir challenge'a verdiği yanıtı temsil eder
    struct ChallengeResponse has store, drop, copy {
        // İlişkili challenge ID'si
        challenge_id: ID,
        // Yanıt veren düğüm ID'si
        node_id: ID,
        // Yanıt içeriği
        response: String,
        // Ek yanıt verileri (örn. ölçüm sonuçları)
        measurements: Option<VecMap<String, String>>,
        // Yanıt zamanı
        response_time: u64,
        // Yanıt geçerli mi?
        is_valid: bool,
        // Değerlendirme skoru (varsa)
        score: Option<u64>,
    }
    
    /// Validator performansı
    /// Bir doğrulayıcı düğümün performans metriklerini içerir
    struct ValidatorPerformance has store {
        // Validator ID'si
        validator_id: ID,
        // Ortalama bant genişliği (Mbps)
        avg_bandwidth: u64,
        // Ortalama gecikme süresi (ms)
        avg_latency: u64,
        // Çevrimiçi kalma yüzdesi (binde)
        uptime: u64,
        // Başarılı doğrulama oranı (binde)
        success_rate: u64,
        // Tamamlanan challenge sayısı
        completed_challenges: u64,
        // Doğrulama skoru (binde)
        validation_score: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    // Eventler
    
    /// Challenge oluşturma eventi
    struct ChallengeCreated has copy, drop {
        challenge_id: ID,
        node_id: ID,
        challenge_type: u8,
        creator: address,
        creation_time: u64,
        expiration_time: u64,
    }
    
    /// Challenge yanıtı eventi
    struct ChallengeResponded has copy, drop {
        challenge_id: ID,
        node_id: ID,
        response_time: u64,
        is_valid: bool,
    }
    
    /// Doğrulama sonucu eventi
    struct NodeValidated has copy, drop {
        node_id: ID,
        status: u8,
        total_score: u64,
        validator: address,
        validation_time: u64,
    }
    
    /// Validator performans güncelleme eventi
    struct ValidatorPerformanceUpdated has copy, drop {
        validator_id: ID,
        avg_bandwidth: u64,
        avg_latency: u64,
        uptime: u64,
        validation_score: u64,
        update_time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let validation_config = ValidationConfig {
            id: object::new(ctx),
            criteria_weights: vec_map::empty(),
            min_bandwidth: MIN_BANDWIDTH_MBPS,
            max_latency: MAX_LATENCY_MS,
            min_uptime: MIN_UPTIME_PERCENTAGE,
            min_validation_score: 700, // Minimum %70 (binde)
            challenge_expiration: CHALLENGE_EXPIRATION,
            validation_period: VALIDATION_PERIOD,
            last_updated: 0,
        };
        
        // Kriter ağırlıklarını ayarla
        vec_map::insert(&mut validation_config.criteria_weights, CRITERIA_BANDWIDTH, 250); // %25 (binde)
        vec_map::insert(&mut validation_config.criteria_weights, CRITERIA_LATENCY, 250); // %25 (binde)
        vec_map::insert(&mut validation_config.criteria_weights, CRITERIA_UPTIME, 200); // %20 (binde)
        vec_map::insert(&mut validation_config.criteria_weights, CRITERIA_SECURITY, 200); // %20 (binde)
        vec_map::insert(&mut validation_config.criteria_weights, CRITERIA_GEOGRAPHICAL, 100); // %10 (binde)
        
        let validation_registry = ValidationRegistry {
            id: object::new(ctx),
            validation_results: table::new(ctx),
            active_challenges: table::new(ctx),
            challenge_responses: table::new(ctx),
            validator_performance: table::new(ctx),
            last_updated: 0,
        };
        
        transfer::share_object(validation_config);
        transfer::share_object(validation_registry);
    }
    
    /// Yeni bir düğüm doğrulaması oluştur
    public entry fun create_node_validation(
        validation_registry: &mut ValidationRegistry,
        node: &NodeInfo,
        validator: &Validator,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let node_id = object::id(node);
        let validator_id = object::id(validator);
        
        // Düğümün zaten doğrulanmış olup olmadığını kontrol et
        assert!(!table::contains(&validation_registry.validation_results, node_id), ENodeAlreadyValidated);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni doğrulama sonucu oluştur
        let validation_result = ValidationResult {
            node_id,
            status: VALIDATION_STATUS_PENDING,
            total_score: 0,
            criteria_scores: vec_map::empty(),
            validation_time: now,
            expiration_time: now + VALIDATION_PERIOD,
            last_validator: sender,
        };
        
        // Sonucu kaydet
        table::add(&mut validation_registry.validation_results, node_id, validation_result);
        
        // Validator performansı var mı kontrol et
        if (!table::contains(&validation_registry.validator_performance, validator_id)) {
            // Yeni validator performansı oluştur
            let performance = ValidatorPerformance {
                validator_id,
                avg_bandwidth: 0,
                avg_latency: 0,
                uptime: 1000, // Başlangıçta %100 (binde)
                success_rate: 1000, // Başlangıçta %100 (binde)
                completed_challenges: 0,
                validation_score: 1000, // Başlangıçta %100 (binde)
                last_updated: now,
            };
            
            table::add(&mut validation_registry.validator_performance, validator_id, performance);
        };
        
        validation_registry.last_updated = now;
    }
    
    /// Düğüme challenge gönder
    public entry fun create_challenge(
        validation_registry: &mut ValidationRegistry,
        validation_config: &ValidationConfig,
        node_id: ID,
        challenge_type: u8,
        content: vector<u8>,
        expected_response_type: vector<u8>,
        validation_criteria: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Challenge tipini kontrol et
        assert!(
            challenge_type == CHALLENGE_BANDWIDTH_TEST ||
            challenge_type == CHALLENGE_LATENCY_TEST ||
            challenge_type == CHALLENGE_CRYPTO_VERIFICATION ||
            challenge_type == CHALLENGE_PROTOCOL_COMPLIANCE ||
            challenge_type == CHALLENGE_CONNECTIVITY_TEST,
            EInvalidChallenge
        );
        
        // Doğrulama kriterini kontrol et
        assert!(
            validation_criteria == CRITERIA_BANDWIDTH ||
            validation_criteria == CRITERIA_LATENCY ||
            validation_criteria == CRITERIA_UPTIME ||
            validation_criteria == CRITERIA_SECURITY ||
            validation_criteria == CRITERIA_GEOGRAPHICAL,
            EInvalidCriteria
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Challenge nesnesi oluştur
        // Challenge ID'si için benzersiz bir değer oluştur
        let challenge_id = object::new(ctx);
        let id_copy = object::uid_to_inner(&challenge_id);
        object::delete(challenge_id);
        
        let challenge = Challenge {
            challenge_id: id_copy,
            node_id,
            challenge_type,
            content: string::utf8(content),
            expected_response_type: string::utf8(expected_response_type),
            creation_time: now,
            expiration_time: now + validation_config.challenge_expiration,
            creator: sender,
            validation_criteria,
        };
        
        // Düğüm için challenge tablosu var mı?
        if (!table::contains(&validation_registry.active_challenges, node_id)) {
            table::add(&mut validation_registry.active_challenges, node_id, vector::empty());
        };
        
        // Challenge'ı ekle
        let challenges = table::borrow_mut(&mut validation_registry.active_challenges, node_id);
        vector::push_back(challenges, challenge);
        
        // Challenge oluşturma eventini yayınla
        event::emit(ChallengeCreated {
            challenge_id: id_copy,
            node_id,
            challenge_type,
            creator: sender,
            creation_time: now,
            expiration_time: now + validation_config.challenge_expiration,
        });
        
        validation_registry.last_updated = now;
    }
    
    /// Challenge yanıtı gönder
    public entry fun submit_challenge_response(
        validation_registry: &mut ValidationRegistry,
        node_id: ID,
        challenge_id: ID,
        response: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm için challenge tablosu var mı?
        assert!(table::contains(&validation_registry.active_challenges, node_id), EChallengeNotFound);
        
        // Challenge'ı bul
        let challenges = table::borrow(&validation_registry.active_challenges, node_id);
        let challenge_opt = find_challenge(challenges, challenge_id);
        assert!(option::is_some(&challenge_opt), EChallengeNotFound);
        let challenge = *option::borrow(&challenge_opt);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Challenge'ın süresi dolmuş mu?
        assert!(now <= challenge.expiration_time, EChallengeExpired);
        
        // Yanıt nesnesi oluştur
        let challenge_response = ChallengeResponse {
            challenge_id,
            node_id,
            response: string::utf8(response),
            measurements: option::none(),
            response_time: now,
            is_valid: false, // Başlangıçta geçersiz, değerlendirme sonrası güncellenecek
            score: option::none(),
        };
        
        // Düğüm için yanıt tablosu var mı?
        if (!table::contains(&validation_registry.challenge_responses, node_id)) {
            table::add(&mut validation_registry.challenge_responses, node_id, vector::empty());
        };
        
        // Yanıtı ekle
        let responses = table::borrow_mut(&mut validation_registry.challenge_responses, node_id);
        vector::push_back(responses, challenge_response);
        
        // Challenge yanıtı eventini yayınla
        event::emit(ChallengeResponded {
            challenge_id,
            node_id,
            response_time: now,
            is_valid: false, // Başlangıçta geçersiz, değerlendirme sonrası güncellenecek
        });
        
        validation_registry.last_updated = now;
    }
    
    /// Challenge yanıtını değerlendir
    public entry fun evaluate_challenge_response(
        validation_registry: &mut ValidationRegistry,
        validation_config: &ValidationConfig,
        node_id: ID,
        challenge_id: ID,
        is_valid: bool,
        score: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm için yanıt tablosu var mı?
        assert!(table::contains(&validation_registry.challenge_responses, node_id), EChallengeNotFound);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yanıtı bul ve güncelle
        let responses = table::borrow_mut(&mut validation_registry.challenge_responses, node_id);
        let (found, i) = find_challenge_response_index(responses, challenge_id);
        assert!(found, EChallengeNotFound);
        
        let response = vector::borrow_mut(responses, i);
        response.is_valid = is_valid;
        response.score = option::some(score);
        
        // Challenge'ı aktif listeden kaldır
        if (table::contains(&validation_registry.active_challenges, node_id)) {
            let challenges = table::borrow_mut(&mut validation_registry.active_challenges, node_id);
            remove_challenge(challenges, challenge_id);
        };
        
        // Challenge yanıtı eventini güncellenen değerlerle yayınla
        event::emit(ChallengeResponded {
            challenge_id,
            node_id,
            response_time: response.response_time,
            is_valid,
        });
        
        validation_registry.last_updated = now;
    }
    
    /// Düğümü doğrula ve sonucu güncelle
    public entry fun validate_node(
        validation_registry: &mut ValidationRegistry,
        validation_config: &ValidationConfig,
        node_id: ID,
        validator_id: ID,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm doğrulama sonucu var mı?
        assert!(table::contains(&validation_registry.validation_results, node_id), EInvalidNode);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Doğrulama sonucunu al
        let result = table::borrow_mut(&mut validation_registry.validation_results, node_id);
        
        // Tüm yanıtları değerlendir ve skoru hesapla
        let total_score = calculate_validation_score(
            validation_registry,
            validation_config,
            node_id
        );
        
        // Sonucu güncelle
        result.total_score = total_score;
        result.status = if (total_score >= validation_config.min_validation_score) {
            VALIDATION_STATUS_ACTIVE
        } else {
            VALIDATION_STATUS_FAILED
        };
        result.validation_time = now;
        result.expiration_time = now + validation_config.validation_period;
        result.last_validator = sender;
        
        // Validator performansını güncelle
        if (table::contains(&validation_registry.validator_performance, validator_id)) {
            let performance = table::borrow_mut(&mut validation_registry.validator_performance, validator_id);
            performance.completed_challenges = performance.completed_challenges + 1;
            
            // Eğer bu bir başarılı doğrulama ise, performans metriklerini güncelle
            if (result.status == VALIDATION_STATUS_ACTIVE) {
                // Burada basitleştirilmiş bir güncelleme yapılıyor
                // Gerçek bir implementasyonda, daha karmaşık metrikler kullanılabilir
                performance.success_rate = (performance.success_rate * 9 + 1000) / 10; // %90 eski + %10 yeni
            } else {
                performance.success_rate = (performance.success_rate * 9 + 0) / 10; // %90 eski + %10 yeni (başarısız)
            };
            
            performance.last_updated = now;
            
            // Validator performans güncelleme eventini yayınla
            event::emit(ValidatorPerformanceUpdated {
                validator_id,
                avg_bandwidth: performance.avg_bandwidth,
                avg_latency: performance.avg_latency,
                uptime: performance.uptime,
                validation_score: performance.validation_score,
                update_time: now,
            });
        };
        
        // Doğrulama sonucu eventini yayınla
        event::emit(NodeValidated {
            node_id,
            status: result.status,
            total_score,
            validator: sender,
            validation_time: now,
        });
        
        validation_registry.last_updated = now;
    }
    
    /// Validator performans metriklerini güncelle
    public entry fun update_validator_performance(
        validation_registry: &mut ValidationRegistry,
        validator_id: ID,
        bandwidth: u64,
        latency: u64,
        uptime: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Validator performansı var mı?
        assert!(table::contains(&validation_registry.validator_performance, validator_id), EInvalidValidator);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Performans metriklerini güncelle
        let performance = table::borrow_mut(&mut validation_registry.validator_performance, validator_id);
        
        // Eğer mevcut değerler varsa, hareketli ortalama kullan
        if (performance.avg_bandwidth > 0) {
            performance.avg_bandwidth = (performance.avg_bandwidth * 9 + bandwidth) / 10; // %90 eski + %10 yeni
        } else {
            performance.avg_bandwidth = bandwidth;
        };
        
        if (performance.avg_latency > 0) {
            performance.avg_latency = (performance.avg_latency * 9 + latency) / 10; // %90 eski + %10 yeni
        } else {
            performance.avg_latency = latency;
        };
        
        if (performance.uptime > 0) {
            performance.uptime = (performance.uptime * 9 + uptime) / 10; // %90 eski + %10 yeni
        } else {
            performance.uptime = uptime;
        };
        
        // Validation skoru hesapla
        // Basitleştirilmiş bir hesaplama yapılıyor
        let bandwidth_score = if (bandwidth >= 1000) { 1000 } else { bandwidth };
        let latency_score = if (latency <= 20) { 1000 } else if (latency >= 200) { 0 } else { 1000 - ((latency - 20) * 1000) / 180 };
        let uptime_score = if (uptime >= 999) { 1000 } else { uptime };
        
        performance.validation_score = (bandwidth_score + latency_score + uptime_score) / 3;
        performance.last_updated = now;
        
        // Validator performans güncelleme eventini yayınla
        event::emit(ValidatorPerformanceUpdated {
            validator_id,
            avg_bandwidth: performance.avg_bandwidth,
            avg_latency: performance.avg_latency,
            uptime: performance.uptime,
            validation_score: performance.validation_score,
            update_time: now,
        });
        
        validation_registry.last_updated = now;
    }
    
    /// Doğrulama konfigürasyonunu güncelle
    public entry fun update_validation_config(
        validation_config: &mut ValidationConfig,
        governance_cap: &GovernanceCapability,
        min_bandwidth: u64,
        max_latency: u64,
        min_uptime: u64,
        min_validation_score: u64,
        challenge_expiration: u64,
        validation_period: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Parametreleri kontrol et
        assert!(min_validation_score <= 1000, EInvalidThreshold);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Konfigürasyonu güncelle
        validation_config.min_bandwidth = min_bandwidth;
        validation_config.max_latency = max_latency;
        validation_config.min_uptime = min_uptime;
        validation_config.min_validation_score = min_validation_score;
        validation_config.challenge_expiration = challenge_expiration;
        validation_config.validation_period = validation_period;
        validation_config.last_updated = now;
    }
    
    /// Kriter ağırlığını güncelle
    public entry fun update_criteria_weight(
        validation_config: &mut ValidationConfig,
        governance_cap: &GovernanceCapability,
        criteria: u8,
        weight: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Kriteri kontrol et
        assert!(
            criteria == CRITERIA_BANDWIDTH ||
            criteria == CRITERIA_LATENCY ||
            criteria == CRITERIA_UPTIME ||
            criteria == CRITERIA_SECURITY ||
            criteria == CRITERIA_GEOGRAPHICAL,
            EInvalidCriteria
        );
        
        // Ağırlığı kontrol et
        assert!(weight <= 1000, EInvalidThreshold);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Mevcut tüm ağırlıkların toplamını hesapla (güncellenen kriter hariç)
        let total_weight = 0;
        let keys = vec_map::keys(&validation_config.criteria_weights);
        let i = 0;
        let len = vector::length(&keys);
        
        while (i < len) {
            let key = *vector::borrow(&keys, i);
            if (key != criteria) {
                total_weight = total_weight + *vec_map::get(&validation_config.criteria_weights, &key);
            };
            i = i + 1;
        };
        
        // Toplam ağırlık 1000'i geçmemeli
        assert!(total_weight + weight <= 1000, EInvalidThreshold);
        
        // Ağırlığı güncelle
        vec_map::insert(&mut validation_config.criteria_weights, criteria, weight);
        validation_config.last_updated = now;
    }
    
    // Yardımcı fonksiyonlar
    
    /// Doğrulama skorunu hesapla
    fun calculate_validation_score(
        validation_registry: &ValidationRegistry,
        validation_config: &ValidationConfig,
        node_id: ID
    ): u64 {
        // Düğüm için yanıtlar var mı?
        if (!table::contains(&validation_registry.challenge_responses, node_id)) {
            return 0
        };
        
        let responses = table::borrow(&validation_registry.challenge_responses, node_id);
        
        // Kriter bazlı skorlar ve sayımlar
        let criteria_scores = vec_map::empty<u8, u64>();
        let criteria_counts = vec_map::empty<u8, u64>();
        
        // Tüm yanıtları işle
        let i = 0;
        let len = vector::length(responses);
        
        while (i < len) {
            let response = vector::borrow(responses, i);
            
            // Sadece geçerli yanıtları değerlendir
            if (response.is_valid && option::is_some(&response.score)) {
                // Yanıtın ilişkili olduğu challenge'ı bul
                if (table::contains(&validation_registry.active_challenges, node_id)) {
                    let challenges = table::borrow(&validation_registry.active_challenges, node_id);
                    let challenge_opt = find_challenge(challenges, response.challenge_id);
                    
                    if (option::is_some(&challenge_opt)) {
                        let challenge = *option::borrow(&challenge_opt);
                        let criteria = challenge.validation_criteria;
                        let score = *option::borrow(&response.score);
                        
                        // Skor ve sayım güncelle
                        if (vec_map::contains(&criteria_scores, &criteria)) {
                            let current_score = *vec_map::get(&criteria_scores, &criteria);
                            let current_count = *vec_map::get(&criteria_counts, &criteria);
                            
                            vec_map::insert(&mut criteria_scores, criteria, current_score + score);
                            vec_map::insert(&mut criteria_counts, criteria, current_count + 1);
                        } else {
                            vec_map::insert(&mut criteria_scores, criteria, score);
                            vec_map::insert(&mut criteria_counts, criteria, 1);
                        };
                    };
                };
            };
            
            i = i + 1;
        };
        
        // Kriter başına ortalama skorları hesapla
        let criteria_avgs = vec_map::empty<u8, u64>();
        let score_keys = vec_map::keys(&criteria_scores);
        let j = 0;
        let score_len = vector::length(&score_keys);
        
        while (j < score_len) {
            let criteria = *vector::borrow(&score_keys, j);
            let score = *vec_map::get(&criteria_scores, &criteria);
            let count = *vec_map::get(&criteria_counts, &criteria);
            
            if (count > 0) {
                vec_map::insert(&mut criteria_avgs, criteria, score / count);
            };
            
            j = j + 1;
        };
        
        // Ağırlıklı toplam skoru hesapla
        let total_weighted_score = 0;
        let total_weight = 0;
        
        let k = 0;
        let avg_keys = vec_map::keys(&criteria_avgs);
        let avg_len = vector::length(&avg_keys);
        
        while (k < avg_len) {
            let criteria = *vector::borrow(&avg_keys, k);
            let avg_score = *vec_map::get(&criteria_avgs, &criteria);
            
            if (vec_map::contains(&validation_config.criteria_weights, &criteria)) {
                let weight = *vec_map::get(&validation_config.criteria_weights, &criteria);
                total_weighted_score = total_weighted_score + (avg_score * weight);
                total_weight = total_weight + weight;
            };
            
            k = k + 1;
        };
        
        // Eğer toplam ağırlık sıfırsa, skor hesaplanamaz
        if (total_weight == 0) {
            return 0
        };
        
        // Nihai skoru hesapla ve döndür
        total_weighted_score / total_weight
    }
    
    /// Belirli bir ID'ye sahip challenge'ı bul
    fun find_challenge(challenges: &vector<Challenge>, challenge_id: ID): Option<Challenge> {
        let i = 0;
        let len = vector::length(challenges);
        
        while (i < len) {
            let challenge = vector::borrow(challenges, i);
            if (challenge.challenge_id == challenge_id) {
                return option::some(*challenge)
            };
            i = i + 1;
        };
        
        option::none()
    }
    
    /// Belirli bir ID'ye sahip challenge'ı kaldır
    fun remove_challenge(challenges: &mut vector<Challenge>, challenge_id: ID) {
        let i = 0;
        let len = vector::length(challenges);
        
        while (i < len) {
            let challenge = vector::borrow(challenges, i);
            if (challenge.challenge_id == challenge_id) {
                vector::remove(challenges, i);
                return
            };
            i = i + 1;
        };
    }
    
    /// Belirli bir challenge ID'sine sahip yanıtın indeksini bul
    fun find_challenge_response_index(responses: &vector<ChallengeResponse>, challenge_id: ID): (bool, u64) {
        let i = 0;
        let len = vector::length(responses);
        
        while (i < len) {
            let response = vector::borrow(responses, i);
            if (response.challenge_id == challenge_id) {
                return (true, i)
            };
            i = i + 1;
        };
        
        (false, 0)
    }
    
    // Getter fonksiyonları
    
    /// Doğrulama sonucunu al
    public fun get_validation_result(
        validation_registry: &ValidationRegistry,
        node_id: ID
    ): (u8, u64, u64, u64, address) {
        assert!(table::contains(&validation_registry.validation_results, node_id), EInvalidNode);
        
        let result = table::borrow(&validation_registry.validation_results, node_id);
        
        (
            result.status,
            result.total_score,
            result.validation_time,
            result.expiration_time,
            result.last_validator
        )
    }
    
    /// Validator performansını al
    public fun get_validator_performance(
        validation_registry: &ValidationRegistry,
        validator_id: ID
    ): (u64, u64, u64, u64, u64, u64) {
        assert!(table::contains(&validation_registry.validator_performance, validator_id), EInvalidValidator);
        
        let performance = table::borrow(&validation_registry.validator_performance, validator_id);
        
        (
            performance.avg_bandwidth,
            performance.avg_latency,
            performance.uptime,
            performance.success_rate,
            performance.completed_challenges,
            performance.validation_score
        )
    }
    
    /// Doğrulama konfigürasyonu bilgilerini al
    public fun get_validation_config_info(
        validation_config: &ValidationConfig
    ): (u64, u64, u64, u64, u64, u64, u64) {
        (
            validation_config.min_bandwidth,
            validation_config.max_latency,
            validation_config.min_uptime,
            validation_config.min_validation_score,
            validation_config.challenge_expiration,
            validation_config.validation_period,
            validation_config.last_updated
        )
    }
    
    /// Kriter ağırlığını al
    public fun get_criteria_weight(
        validation_config: &ValidationConfig,
        criteria: u8
    ): u64 {
        assert!(vec_map::contains(&validation_config.criteria_weights, &criteria), EInvalidCriteria);
        *vec_map::get(&validation_config.criteria_weights, &criteria)
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_validation_config_for_testing(ctx: &mut TxContext): ValidationConfig {
        ValidationConfig {
            id: object::new(ctx),
            criteria_weights: vec_map::empty(),
            min_bandwidth: MIN_BANDWIDTH_MBPS,
            max_latency: MAX_LATENCY_MS,
            min_uptime: MIN_UPTIME_PERCENTAGE,
            min_validation_score: 700, // Minimum %70 (binde)
            challenge_expiration: CHALLENGE_EXPIRATION,
            validation_period: VALIDATION_PERIOD,
            last_updated: 0,
        }
    }
    
    #[test_only]
    public fun create_validation_registry_for_testing(ctx: &mut TxContext): ValidationRegistry {
        ValidationRegistry {
            id: object::new(ctx),
            validation_results: table::new(ctx),
            active_challenges: table::new(ctx),
            challenge_responses: table::new(ctx),
            validator_performance: table::new(ctx),
            last_updated: 0,
        }
    }
}
