/// SuiVPN Slashing Module
/// 
/// Bu modül, protokol kurallarını ihlal eden düğümleri cezalandırmak için
/// kullanılan slashing (kesinti/ceza) mekanizmasını yönetir. Kötü niyetli davranışların
/// ekonomik olarak caydırıcı olmasını sağlar ve ağın güvenliğini korur.
module suivpn::slashing {
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
    use suivpn::governance::{Self, GovernanceCapability};
    use suivpn::validator::{Self, Validator, ValidatorRegistry};
    use suivpn::token::{Self, SVPN};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EValidatorNotFound: u64 = 1;
    const EInvalidEvidence: u64 = 2;
    const EEvidenceExpired: u64 = 3;
    const ESlashLimitExceeded: u64 = 4;
    const EInvalidSlashReason: u64 = 5;
    const EInvalidSlashAmount: u64 = 6;
    const EValidatorAlreadyJailed: u64 = 7;
    const EValidatorNotJailed: u64 = 8;
    const EInvalidEvidenceType: u64 = 9;
    const ECooldownPeriod: u64 = 10;
    
    // Slash nedenleri
    const SLASH_REASON_DOWNTIME: u8 = 0;
    const SLASH_REASON_DOUBLE_SIGN: u8 = 1;
    const SLASH_REASON_VALIDATOR_PROTOCOL_VIOLATION: u8 = 2;
    const SLASH_REASON_DATA_UNAVAILABILITY: u8 = 3;
    const SLASH_REASON_MALICIOUS_BEHAVIOR: u8 = 4;
    
    // Kanıt tipleri
    const EVIDENCE_TYPE_DOWNTIME_REPORT: u8 = 0;
    const EVIDENCE_TYPE_DOUBLE_SIGN_PROOF: u8 = 1;
    const EVIDENCE_TYPE_PROTOCOL_VIOLATION: u8 = 2;
    const EVIDENCE_TYPE_DATA_UNAVAILABILITY: u8 = 3;
    const EVIDENCE_TYPE_MALICIOUS_BEHAVIOR: u8 = 4;
    
    // Sabitler
    const EVIDENCE_EXPIRATION: u64 = 1209600; // 14 gün (saniye)
    const MIN_SLASH_AMOUNT: u64 = 1_000_000_000; // 1,000 SVPN
    const MAX_SLASH_PERCENTAGE: u64 = 300; // %30 (binde)
    const MAX_CONSECUTIVE_FAILURES: u64 = 10; // art arda maksimum hata sayısı
    
    /// Slashing konfigürasyonu
    /// Protokolün slashing parametrelerini içerir
    struct SlashingConfig has key, store {
        id: UID,
        // Neden bazlı slashing oranları (binde)
        // Örneğin 100 değeri, stake'in %10'unun kesileceği anlamına gelir
        reason_rates: VecMap<u8, u64>,
        // Tekrarlayan ihlaller için çarpanlar
        repeat_multipliers: VecMap<u8, u64>,
        // Minimum slashing miktarı
        min_slash_amount: u64,
        // Maksimum slashing oranı (binde)
        max_slash_percentage: u64,
        // Kanıt geçerlilik süresi (saniye)
        evidence_expiration: u64,
        // Jailing için gereken minimum ihlal sayısı
        min_jail_violations: u64,
        // Jail süresi (saniye)
        jail_duration: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Slashing Kaydı
    /// Tüm slashing olaylarının kaydını tutar
    struct SlashingRegistry has key {
        id: UID,
        // Validator ID -> ihlal sayısı
        violation_counts: Table<ID, VecMap<u8, u64>>,
        // Son slashing olayları
        slash_history: vector<SlashEvent>,
        // Aktif kanıtlar
        active_evidences: Table<ID, vector<Evidence>>,
        // Toplam kesilen miktar
        total_slashed: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Kanıt
    /// Bir slashing olayı için kanıt içerir
    struct Evidence has store, drop, copy {
        // Kanıt ID'si
        evidence_id: ID,
        // Hedef validator ID'si
        validator_id: ID,
        // Kanıt tipi
        evidence_type: u8,
        // Kanıt açıklaması
        description: String,
        // Kanıt hash'i (varsa)
        evidence_hash: Option<vector<u8>>,
        // Kanıt zamanı
        time: u64,
        // Kanıt raporlayıcısı
        reporter: address,
        // Kanıt için önerilen slash nedeni
        suggested_reason: u8,
    }
    
    /// Slash Olayı
    /// Bir slashing olayını temsil eder
    struct SlashEvent has store, drop, copy {
        // Hedef validator ID'si
        validator_id: ID,
        // Slash nedeni
        reason: u8,
        // Slash miktarı
        amount: u64,
        // Slash oranı (binde)
        percentage: u64,
        // Slash zamanı
        time: u64,
        // Slash yürütücüsü
        executor: address,
        // İlgili kanıt ID'si (varsa)
        evidence_id: Option<ID>,
        // Jailing yapıldı mı?
        jail_applied: bool,
    }
    
    // Eventler
    
    /// Kanıt gönderme eventi
    struct EvidenceSubmitted has copy, drop {
        evidence_id: ID,
        validator_id: ID,
        evidence_type: u8,
        reporter: address,
        time: u64,
    }
    
    /// Slashing eventi
    struct ValidatorSlashed has copy, drop {
        validator_id: ID,
        reason: u8,
        amount: u64,
        percentage: u64,
        executor: address,
        time: u64,
    }
    
    /// Jail eventi
    struct ValidatorJailed has copy, drop {
        validator_id: ID,
        reason: u8,
        jail_time: u64,
        jail_duration: u64,
    }
    
    /// Jail'den çıkarma eventi
    struct ValidatorUnjailed has copy, drop {
        validator_id: ID,
        unjail_time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let slashing_config = SlashingConfig {
            id: object::new(ctx),
            reason_rates: vec_map::empty(),
            repeat_multipliers: vec_map::empty(),
            min_slash_amount: MIN_SLASH_AMOUNT,
            max_slash_percentage: MAX_SLASH_PERCENTAGE,
            evidence_expiration: EVIDENCE_EXPIRATION,
            min_jail_violations: 3,
            jail_duration: 604800, // 7 gün (saniye)
            last_updated: 0,
        };
        
        // Sebeplere göre kesinti oranlarını ayarla
        vec_map::insert(&mut slashing_config.reason_rates, SLASH_REASON_DOWNTIME, 10); // %1 (binde 10)
        vec_map::insert(&mut slashing_config.reason_rates, SLASH_REASON_DOUBLE_SIGN, 100); // %10 (binde 100)
        vec_map::insert(&mut slashing_config.reason_rates, SLASH_REASON_VALIDATOR_PROTOCOL_VIOLATION, 50); // %5 (binde 50)
        vec_map::insert(&mut slashing_config.reason_rates, SLASH_REASON_DATA_UNAVAILABILITY, 30); // %3 (binde 30)
        vec_map::insert(&mut slashing_config.reason_rates, SLASH_REASON_MALICIOUS_BEHAVIOR, 200); // %20 (binde 200)
        
        // Tekrarlayan ihlaller için çarpanları ayarla
        vec_map::insert(&mut slashing_config.repeat_multipliers, 1, 100); // 1x (ilk ihlal)
        vec_map::insert(&mut slashing_config.repeat_multipliers, 2, 150); // 1.5x (ikinci ihlal)
        vec_map::insert(&mut slashing_config.repeat_multipliers, 3, 200); // 2x (üçüncü ihlal)
        vec_map::insert(&mut slashing_config.repeat_multipliers, 4, 300); // 3x (dördüncü ihlal)
        vec_map::insert(&mut slashing_config.repeat_multipliers, 5, 500); // 5x (beşinci ihlal ve sonrası)
        
        let slashing_registry = SlashingRegistry {
            id: object::new(ctx),
            violation_counts: table::new(ctx),
            slash_history: vector::empty(),
            active_evidences: table::new(ctx),
            total_slashed: 0,
            last_updated: 0,
        };
        
        transfer::share_object(slashing_config);
        transfer::share_object(slashing_registry);
    }
    
    /// Kanıt gönder
    public entry fun submit_evidence(
        slashing_registry: &mut SlashingRegistry,
        validator_id: ID,
        evidence_type: u8,
        description: vector<u8>,
        evidence_hash: vector<u8>,
        suggested_reason: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Kanıt tipini kontrol et
        assert!(
            evidence_type == EVIDENCE_TYPE_DOWNTIME_REPORT ||
            evidence_type == EVIDENCE_TYPE_DOUBLE_SIGN_PROOF ||
            evidence_type == EVIDENCE_TYPE_PROTOCOL_VIOLATION ||
            evidence_type == EVIDENCE_TYPE_DATA_UNAVAILABILITY ||
            evidence_type == EVIDENCE_TYPE_MALICIOUS_BEHAVIOR,
            EInvalidEvidenceType
        );
        
        // Neden türünü kontrol et
        assert!(
            suggested_reason == SLASH_REASON_DOWNTIME ||
            suggested_reason == SLASH_REASON_DOUBLE_SIGN ||
            suggested_reason == SLASH_REASON_VALIDATOR_PROTOCOL_VIOLATION ||
            suggested_reason == SLASH_REASON_DATA_UNAVAILABILITY ||
            suggested_reason == SLASH_REASON_MALICIOUS_BEHAVIOR,
            EInvalidSlashReason
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Kanıt ID'si için benzersiz bir değer oluştur
        let evidence_id = object::new(ctx);
        let id_copy = object::uid_to_inner(&evidence_id);
        object::delete(evidence_id);
        
        let evidence = Evidence {
            evidence_id: id_copy,
            validator_id,
            evidence_type,
            description: string::utf8(description),
            evidence_hash: if (vector::length(&evidence_hash) > 0) {
                option::some(evidence_hash)
            } else {
                option::none()
            },
            time: now,
            reporter: sender,
            suggested_reason,
        };
        
        // Validator'ın kayıtlı kanıtları var mı?
        if (!table::contains(&slashing_registry.active_evidences, validator_id)) {
            table::add(&mut slashing_registry.active_evidences, validator_id, vector::empty());
        };
        
        // Kanıtı validator'a ekle
        let evidences = table::borrow_mut(&mut slashing_registry.active_evidences, validator_id);
        vector::push_back(evidences, evidence);
        
        // Kanıt gönderme eventini yayınla
        event::emit(EvidenceSubmitted {
            evidence_id: id_copy,
            validator_id,
            evidence_type,
            reporter: sender,
            time: now,
        });
        
        slashing_registry.last_updated = now;
    }
    
    /// Validator'a kesinti uygula
    public entry fun slash_validator(
        slashing_registry: &mut SlashingRegistry,
        slashing_config: &SlashingConfig,
        validator_registry: &mut ValidatorRegistry,
        validator: &mut Validator,
        reason: u8,
        evidence_id: Option<ID>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Kesinti nedeninin geçerli olup olmadığını kontrol et
        assert!(
            reason == SLASH_REASON_DOWNTIME ||
            reason == SLASH_REASON_DOUBLE_SIGN ||
            reason == SLASH_REASON_VALIDATOR_PROTOCOL_VIOLATION ||
            reason == SLASH_REASON_DATA_UNAVAILABILITY ||
            reason == SLASH_REASON_MALICIOUS_BEHAVIOR,
            EInvalidSlashReason
        );
        
        let validator_id = object::id(validator);
        
        // İhlal sayısını al veya oluştur
        if (!table::contains(&slashing_registry.violation_counts, validator_id)) {
            table::add(&mut slashing_registry.violation_counts, validator_id, vec_map::empty());
        };
        let violation_counts = table::borrow_mut(&mut slashing_registry.violation_counts, validator_id);
        
        // İhlal sayısını artır
        let current_count = if (vec_map::contains(violation_counts, &reason)) {
            *vec_map::get(violation_counts, &reason)
        } else {
            0
        };
        vec_map::insert(violation_counts, reason, current_count + 1);
        
        // Bu neden için kesinti oranını al
        let base_percentage = *vec_map::get(&slashing_config.reason_rates, &reason);
        
        // Tekrar çarpanını hesapla
        let repeat_count = if (current_count >= 5) { 5 } else { current_count + 1 };
        let multiplier = *vec_map::get(&slashing_config.repeat_multipliers, &repeat_count);
        
        // Toplam kesinti oranını hesapla
        let slash_percentage = (base_percentage * multiplier) / 100;
        
        // Maksimum kesinti oranını aşmamasını sağla
        if (slash_percentage > slashing_config.max_slash_percentage) {
            slash_percentage = slashing_config.max_slash_percentage;
        };
        
        // Validator'ın kendi stake miktarını al
        let self_stake = validator::get_validator_self_stake(validator);
        
        // Kesinti miktarını hesapla
        let slash_amount = (self_stake * slash_percentage) / 1000;
        
        // Minimum kesinti miktarını kontrol et
        if (slash_amount < slashing_config.min_slash_amount && self_stake > slashing_config.min_slash_amount) {
            slash_amount = slashing_config.min_slash_amount;
        };
        
        // Maksimum kesinti miktarını aşmamasını sağla
        if (slash_amount > self_stake) {
            slash_amount = self_stake;
        };
        
        // Jail uygulanacak mı kontrol et
        let jail_applied = false;
        if (current_count + 1 >= slashing_config.min_jail_violations) {
            // Validator'ı jail'e gönder
            let jail_time = now;
            let jail_duration = slashing_config.jail_duration;
            
            // Jail eventi yayınla
            event::emit(ValidatorJailed {
                validator_id,
                reason,
                jail_time,
                jail_duration,
            });
            
            jail_applied = true;
            
            // Validator modülü tarafından jail işlemi gerçekleştirilmelidir
            // Burada doğrudan validator.status değiştirilmedi, bunun yerine validator modülü
            // tarafından jail fonksiyonu çağrılmalıdır (validator::jail_validator)
        };
        
        // Slash olayını kaydet
        let slash_event = SlashEvent {
            validator_id,
            reason,
            amount: slash_amount,
            percentage: slash_percentage,
            time: now,
            executor: tx_context::sender(ctx),
            evidence_id,
            jail_applied,
        };
        
        vector::push_back(&mut slashing_registry.slash_history, slash_event);
        slashing_registry.total_slashed = slashing_registry.total_slashed + slash_amount;
        slashing_registry.last_updated = now;
        
        // Slash eventini yayınla
        event::emit(ValidatorSlashed {
            validator_id,
            reason,
            amount: slash_amount,
            percentage: slash_percentage,
            executor: tx_context::sender(ctx),
            time: now,
        });
        
        // Validator modülü tarafından stake kesintisi gerçekleştirilmelidir
        // Burada doğrudan validator.self_stake değiştirilmedi, bunun yerine validator modülü
        // tarafından slash fonksiyonu çağrılmalıdır (validator::slash_validator)
    }
    
    /// Kanıtları değerlendir ve uygun cezaları uygula
    public entry fun process_evidences(
        slashing_registry: &mut SlashingRegistry,
        slashing_config: &SlashingConfig,
        validator_registry: &mut ValidatorRegistry,
        validator: &mut Validator,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        let validator_id = object::id(validator);
        
        // Validator için kanıt var mı?
        if (!table::contains(&slashing_registry.active_evidences, validator_id)) {
            return
        };
        
        let evidences = table::borrow_mut(&mut slashing_registry.active_evidences, validator_id);
        let i = 0;
        let len = vector::length(evidences);
        
        while (i < len) {
            let evidence = vector::borrow(evidences, i);
            
            // Kanıt süresi dolmuş mu?
            if (now > evidence.time + slashing_config.evidence_expiration) {
                // Süresi dolmuş kanıtları işleme alma
                i = i + 1;
                continue
            };
            
            // Kanıtın geçerliliğini kontrol et (burada basit bir kontrol yapılıyor)
            // Gerçek bir implementasyonda, kanıtın detaylı bir şekilde doğrulanması gerekir
            
            // Kesinti uygula
            slash_validator(
                slashing_registry,
                slashing_config,
                validator_registry,
                validator,
                evidence.suggested_reason,
                option::some(evidence.evidence_id),
                governance_cap,
                clock,
                ctx
            );
            
            i = i + 1;
        };
        
        // İşlenmiş kanıtları sil (basitlik için hepsini siliyoruz)
        // Gerçek bir implementasyonda, sadece işlenen veya süresi dolan kanıtlar silinmelidir
        vector::clear(evidences);
    }
    
    /// Slashing konfigürasyonunu güncelle
    public entry fun update_slashing_config(
        slashing_config: &mut SlashingConfig,
        governance_cap: &GovernanceCapability,
        min_slash_amount: u64,
        max_slash_percentage: u64,
        evidence_expiration: u64,
        min_jail_violations: u64,
        jail_duration: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Değerleri güncelle
        slashing_config.min_slash_amount = min_slash_amount;
        slashing_config.max_slash_percentage = max_slash_percentage;
        slashing_config.evidence_expiration = evidence_expiration;
        slashing_config.min_jail_violations = min_jail_violations;
        slashing_config.jail_duration = jail_duration;
        slashing_config.last_updated = now;
    }
    
    /// Kesinti oranını güncelle
    public entry fun update_slash_rate(
        slashing_config: &mut SlashingConfig,
        governance_cap: &GovernanceCapability,
        reason: u8,
        rate: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Neden türünü kontrol et
        assert!(
            reason == SLASH_REASON_DOWNTIME ||
            reason == SLASH_REASON_DOUBLE_SIGN ||
            reason == SLASH_REASON_VALIDATOR_PROTOCOL_VIOLATION ||
            reason == SLASH_REASON_DATA_UNAVAILABILITY ||
            reason == SLASH_REASON_MALICIOUS_BEHAVIOR,
            EInvalidSlashReason
        );
        
        // Oranı kontrol et
        assert!(rate <= 1000, EInvalidSlashAmount); // Maksimum %100 (binde 1000)
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Oranı güncelle
        vec_map::insert(&mut slashing_config.reason_rates, reason, rate);
        slashing_config.last_updated = now;
    }
    
    /// Tekrar çarpanını güncelle
    public entry fun update_repeat_multiplier(
        slashing_config: &mut SlashingConfig,
        governance_cap: &GovernanceCapability,
        repeat_count: u64,
        multiplier: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Tekrar sayısını kontrol et
        assert!(repeat_count >= 1 && repeat_count <= 5, EInvalidValue);
        
        // Çarpanı kontrol et
        assert!(multiplier >= 100 && multiplier <= 1000, EInvalidValue); // 1x ile 10x arası
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Çarpanı güncelle
        let repeat_count_u8 = (repeat_count as u8);
        vec_map::insert(&mut slashing_config.repeat_multipliers, repeat_count_u8, multiplier);
        slashing_config.last_updated = now;
    }
    
    // Getter fonksiyonları
    
    /// Validator'ın ihlal sayısını al
    public fun get_violation_count(
        slashing_registry: &SlashingRegistry,
        validator_id: ID,
        reason: u8
    ): u64 {
        if (!table::contains(&slashing_registry.violation_counts, validator_id)) {
            return 0
        };
        
        let violation_counts = table::borrow(&slashing_registry.violation_counts, validator_id);
        
        if (!vec_map::contains(violation_counts, &reason)) {
            return 0
        };
        
        *vec_map::get(violation_counts, &reason)
    }
    
    /// Validator'ın tüm ihlallerinin sayısını al
    public fun get_total_violations(
        slashing_registry: &SlashingRegistry,
        validator_id: ID
    ): u64 {
        if (!table::contains(&slashing_registry.violation_counts, validator_id)) {
            return 0
        };
        
        let violation_counts = table::borrow(&slashing_registry.violation_counts, validator_id);
        let total = 0;
        
        let i = 0;
        let reasons = vec_map::keys(violation_counts);
        let len = vector::length(&reasons);
        
        while (i < len) {
            let reason = *vector::borrow(&reasons, i);
            total = total + *vec_map::get(violation_counts, &reason);
            i = i + 1;
        };
        
        total
    }
    
    /// Slash olaylarının sayısını al
    public fun get_slash_history_length(slashing_registry: &SlashingRegistry): u64 {
        vector::length(&slashing_registry.slash_history)
    }
    
    /// Belirli bir indeksteki slash olayını al
    public fun get_slash_event_at(
        slashing_registry: &SlashingRegistry,
        index: u64
    ): SlashEvent {
        assert!(index < vector::length(&slashing_registry.slash_history), EInvalidValue);
        *vector::borrow(&slashing_registry.slash_history, index)
    }
    
    /// Bir sebep için kesinti oranını al
    public fun get_slash_rate(
        slashing_config: &SlashingConfig,
        reason: u8
    ): u64 {
        *vec_map::get(&slashing_config.reason_rates, &reason)
    }
    
    /// Bir tekrar sayısı için çarpanı al
    public fun get_repeat_multiplier(
        slashing_config: &SlashingConfig,
        repeat_count: u8
    ): u64 {
        let count = if (repeat_count > 5) { 5 } else { repeat_count };
        *vec_map::get(&slashing_config.repeat_multipliers, &count)
    }
    
    /// Slashing konfigürasyon bilgilerini al
    public fun get_slashing_config_info(
        slashing_config: &SlashingConfig
    ): (u64, u64, u64, u64, u64, u64) {
        (
            slashing_config.min_slash_amount,
            slashing_config.max_slash_percentage,
            slashing_config.evidence_expiration,
            slashing_config.min_jail_violations,
            slashing_config.jail_duration,
            slashing_config.last_updated
        )
    }
    
    /// Toplam kesinti miktarını al
    public fun get_total_slashed(slashing_registry: &SlashingRegistry): u64 {
        slashing_registry.total_slashed
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_slashing_config_for_testing(ctx: &mut TxContext): SlashingConfig {
        SlashingConfig {
            id: object::new(ctx),
            reason_rates: vec_map::empty(),
            repeat_multipliers: vec_map::empty(),
            min_slash_amount: MIN_SLASH_AMOUNT,
            max_slash_percentage: MAX_SLASH_PERCENTAGE,
            evidence_expiration: EVIDENCE_EXPIRATION,
            min_jail_violations: 3,
            jail_duration: 604800, // 7 gün (saniye)
            last_updated: 0,
        }
    }
    
    #[test_only]
    public fun create_slashing_registry_for_testing(ctx: &mut TxContext): SlashingRegistry {
        SlashingRegistry {
            id: object::new(ctx),
            violation_counts: table::new(ctx),
            slash_history: vector::empty(),
            active_evidences: table::new(ctx),
            total_slashed: 0,
            last_updated: 0,
        }
    }
}
