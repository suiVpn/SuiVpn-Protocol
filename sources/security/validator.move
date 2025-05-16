/// SuiVPN Validator Module
/// 
/// Bu modül, SuiVPN protokolünün doğrulayıcı düğümlerini ve seçim mekanizmasını yönetir.
/// Doğrulayıcılar, protokolün güvenliğini ve bütünlüğünü sağlar, işlemleri doğrular
/// ve konsensüs sürecine katılır.
module suivpn::validator {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::vec_map::{Self, VecMap};
    use sui::vec_set::{Self, VecSet};
    use std::vector;
    use std::option::{Self, Option};
    use suivpn::governance::{Self, GovernanceCapability};
    use suivpn::token::{Self, SVPN};
    use suivpn::registry::{Self, NodeInfo};
    use std::string::{Self, String};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidValidator: u64 = 1;
    const EInvalidStake: u64 = 2;
    const EValidatorNotActive: u64 = 3;
    const EValidatorAlreadyRegistered: u64 = 4;
    const EInsufficientStake: u64 = 5;
    const EValidatorSetFull: u64 = 6;
    const EInvalidCommissionRate: u64 = 7;
    const EValidatorCooldown: u64 = 8;
    const EInvalidMachine: u64 = 9;
    const EInvalidUnstakeAmount: u64 = 10;
    const EInvalidRegion: u64 = 11;
    
    // Validator durumları
    const VALIDATOR_STATUS_INACTIVE: u8 = 0;
    const VALIDATOR_STATUS_PENDING: u8 = 1;
    const VALIDATOR_STATUS_ACTIVE: u8 = 2;
    const VALIDATOR_STATUS_JAILED: u8 = 3;
    const VALIDATOR_STATUS_LEAVING: u8 = 4;
    
    // Sabitler
    const MIN_VALIDATOR_STAKE: u64 = 100_000_000_000; // 100,000 SVPN
    const MAX_VALIDATOR_COUNT: u64 = 100;
    const MIN_COMMISSION_RATE: u64 = 10; // %1 (binde)
    const MAX_COMMISSION_RATE: u64 = 300; // %30 (binde)
    const UNSTAKE_COOLDOWN_PERIOD: u64 = 1209600; // 14 gün (saniye)
    const JAIL_DURATION: u64 = 604800; // 7 gün (saniye)
    
    /// Validator kaydı
    /// Protokol tarafından onaylanan tüm doğrulayıcıları içerir
    struct ValidatorRegistry has key {
        id: UID,
        // Aktif doğrulayıcı sayısı
        active_validator_count: u64,
        // Toplam stake miktarı
        total_stake: u64,
        // Aktif doğrulayıcı ID'leri
        active_validators: VecSet<ID>,
        // Doğrulayıcı rotasyonu için son güncelleme zamanı
        last_rotation: u64,
        // Doğrulayıcı rotasyon periyodu (saniye)
        rotation_period: u64,
        // Son epoch
        current_epoch: u64,
        // Doğrulayıcı limit ve parametreleri
        max_validator_count: u64,
        min_validator_stake: u64,
        // Bölge bazlı doğrulayıcı limitleri - (bölge ID, maksimum sayı)
        region_limits: VecMap<u8, u64>,
        // Bölge bazlı aktif doğrulayıcı sayısı - (bölge ID, aktif sayı)
        region_counts: VecMap<u8, u64>,
    }
    
    /// Doğrulayıcı bilgileri
    /// Bir doğrulayıcı hakkında tüm bilgileri içerir
    struct Validator has key, store {
        id: UID,
        // Doğrulayıcı sahibi
        owner: address,
        // Doğrulayıcı adı
        name: String,
        // Doğrulayıcı açıklaması
        description: String,
        // Doğrulayıcı logosu (URL)
        logo_url: String,
        // Doğrulayıcı websitesi
        website: String,
        // İletişim bilgileri
        contact: String,
        // Doğrulayıcı durumu
        status: u8,
        // Toplam stake miktarı
        total_stake: u64,
        // Doğrulayıcı stake miktarı (sahibi tarafından)
        self_stake: u64,
        // Delegatör stake miktarı (diğer kullanıcılar tarafından)
        delegator_stake: u64,
        // Komisyon oranı (binde)
        commission_rate: u64,
        // Doğrulayıcı gelirleri
        rewards: u64,
        // Doğrulayıcı performans metrikleri (başarılı doğrulama oranı, binde)
        performance_score: u64,
        // Doğrulayıcı çevrimiçi zamanı (yüzde, binde)
        uptime: u64,
        // Son güncelleme zamanı
        last_updated: u64,
        // Katılım zamanı
        joined_at: u64,
        // Node bilgisi
        node_info: ID, // NodeInfo nesnesi
        // Bölge bilgisi
        region: u8,
        // Teknik bilgiler
        ip_address: Option<String>, // Yalnızca özel erişim için
        public_key: String,
        // Son stake/unstake işlemi
        last_stake_action: u64,
        // Ceza bilgileri
        jail_time: u64,
        slash_count: u64,
    }
    
    /// Stake işlemi
    /// Bir kullanıcının bir doğrulayıcıya stake etme işlemini temsil eder
    struct Stake has key, store {
        id: UID,
        // Stake sahibi
        owner: address,
        // Doğrulayıcı ID
        validator_id: ID,
        // Stake miktarı
        amount: u64,
        // Stake başlangıç zamanı
        start_time: u64,
        // Son ödül alma zamanı
        last_reward_time: u64,
        // Birikmiş ödüller
        accumulated_rewards: u64,
        // Unlock zamanı (varsa)
        unlock_time: Option<u64>,
    }
    
    /// Doğrulayıcı rotasyonu ve seçimi için kullanılan geçici yardımcı yapı
    struct ValidatorSelection has copy, drop {
        validator_id: ID,
        weight: u64,
        region: u8,
    }
    
    // Eventler
    
    /// Doğrulayıcı kayıt eventi
    struct ValidatorRegistered has copy, drop {
        validator_id: ID,
        owner: address,
        name: String,
        stake_amount: u64,
        time: u64,
    }
    
    /// Doğrulayıcı durumu değişikliği eventi
    struct ValidatorStatusChanged has copy, drop {
        validator_id: ID,
        old_status: u8,
        new_status: u8,
        time: u64,
    }
    
    /// Stake eventi
    struct StakeDeposited has copy, drop {
        stake_id: ID,
        validator_id: ID,
        owner: address,
        amount: u64,
        time: u64,
    }
    
    /// Unstake eventi
    struct StakeWithdrawn has copy, drop {
        stake_id: ID,
        validator_id: ID,
        owner: address,
        amount: u64,
        time: u64,
    }
    
    /// Ödül toplama eventi
    struct RewardsClaimed has copy, drop {
        stake_id: ID,
        validator_id: ID,
        owner: address,
        amount: u64,
        time: u64,
    }
    
    /// Doğrulayıcı cezalandırma eventi
    struct ValidatorSlashed has copy, drop {
        validator_id: ID,
        reason: String,
        slash_amount: u64,
        time: u64,
    }
    
    /// Doğrulayıcı rotasyonu eventi
    struct ValidatorRotation has copy, drop {
        epoch: u64,
        active_validators: u64,
        time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let validator_registry = ValidatorRegistry {
            id: object::new(ctx),
            active_validator_count: 0,
            total_stake: 0,
            active_validators: vec_set::empty(),
            last_rotation: 0,
            rotation_period: 86400, // 1 gün (saniye)
            current_epoch: 0,
            max_validator_count: MAX_VALIDATOR_COUNT,
            min_validator_stake: MIN_VALIDATOR_STAKE,
            region_limits: vec_map::empty(),
            region_counts: vec_map::empty(),
        };
        
        // Bölge limitlerini başlat
        // Bölge ID'leri:
        // 1: Kuzey Amerika, 2: Güney Amerika, 3: Avrupa, 4: Afrika, 5: Asya, 6: Okyanusya
        vec_map::insert(&mut validator_registry.region_limits, 1, 30); // Kuzey Amerika: max 30 doğrulayıcı
        vec_map::insert(&mut validator_registry.region_limits, 2, 15); // Güney Amerika: max 15 doğrulayıcı
        vec_map::insert(&mut validator_registry.region_limits, 3, 30); // Avrupa: max 30 doğrulayıcı
        vec_map::insert(&mut validator_registry.region_limits, 4, 15); // Afrika: max 15 doğrulayıcı
        vec_map::insert(&mut validator_registry.region_limits, 5, 30); // Asya: max 30 doğrulayıcı
        vec_map::insert(&mut validator_registry.region_limits, 6, 15); // Okyanusya: max 15 doğrulayıcı
        
        // Bölge sayaçlarını başlat
        vec_map::insert(&mut validator_registry.region_counts, 1, 0);
        vec_map::insert(&mut validator_registry.region_counts, 2, 0);
        vec_map::insert(&mut validator_registry.region_counts, 3, 0);
        vec_map::insert(&mut validator_registry.region_counts, 4, 0);
        vec_map::insert(&mut validator_registry.region_counts, 5, 0);
        vec_map::insert(&mut validator_registry.region_counts, 6, 0);
        
        transfer::share_object(validator_registry);
    }
    
    /// Yeni bir doğrulayıcı kaydı oluştur
    public entry fun register_validator(
        validator_registry: &mut ValidatorRegistry,
        node_info: &NodeInfo,
        name: vector<u8>,
        description: vector<u8>,
        logo_url: vector<u8>,
        website: vector<u8>,
        contact: vector<u8>,
        commission_rate: u64,
        stake_amount: u64,
        region: u8,
        public_key: vector<u8>,
        ip_address: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Temel doğrulamalar
        
        // Stake miktarı minimum gereksinimi karşılamalı
        assert!(stake_amount >= validator_registry.min_validator_stake, EInsufficientStake);
        
        // Komisyon oranı geçerli aralıkta olmalı
        assert!(commission_rate >= MIN_COMMISSION_RATE && commission_rate <= MAX_COMMISSION_RATE, EInvalidCommissionRate);
        
        // Bölge ID'si geçerli olmalı (1-6 arası)
        assert!(region >= 1 && region <= 6, EInvalidRegion);
        
        // Bölge limitini kontrol et
        let region_count = *vec_map::get(&validator_registry.region_counts, &region);
        let region_limit = *vec_map::get(&validator_registry.region_limits, &region);
        assert!(region_count < region_limit, EValidatorSetFull);
        
        // Node ID'sini al
        let node_id = object::id(node_info);
        
        // Doğrulayıcı oluştur
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        let validator = Validator {
            id: object::new(ctx),
            owner: sender,
            name: string::utf8(name),
            description: string::utf8(description),
            logo_url: string::utf8(logo_url),
            website: string::utf8(website),
            contact: string::utf8(contact),
            status: VALIDATOR_STATUS_PENDING,
            total_stake: stake_amount,
            self_stake: stake_amount,
            delegator_stake: 0,
            commission_rate,
            rewards: 0,
            performance_score: 1000, // Başlangıçta %100 (binde)
            uptime: 1000, // Başlangıçta %100 (binde)
            last_updated: now,
            joined_at: now,
            node_info: node_id,
            region,
            ip_address: if (vector::length(&ip_address) > 0) { option::some(string::utf8(ip_address)) } else { option::none() },
            public_key: string::utf8(public_key),
            last_stake_action: now,
            jail_time: 0,
            slash_count: 0,
        };
        
        // Stake nesnesi oluştur
        let stake = Stake {
            id: object::new(ctx),
            owner: sender,
            validator_id: object::id(&validator),
            amount: stake_amount,
            start_time: now,
            last_reward_time: now,
            accumulated_rewards: 0,
            unlock_time: option::none(),
        };
        
        // Doğrulayıcı sayısını güncelle ve bölge sayacını artır
        if (validator_registry.active_validator_count < validator_registry.max_validator_count) {
            vec_set::insert(&mut validator_registry.active_validators, object::id(&validator));
            validator_registry.active_validator_count = validator_registry.active_validator_count + 1;
            validator_registry.total_stake = validator_registry.total_stake + stake_amount;
            
            // Bölge sayacını artır
            let current_count = *vec_map::get(&validator_registry.region_counts, &region);
            vec_map::insert(&mut validator_registry.region_counts, region, current_count + 1);
        };
        
        // Doğrulayıcı kayıt eventini yayınla
        event::emit(ValidatorRegistered {
            validator_id: object::id(&validator),
            owner: sender,
            name: string::utf8(name),
            stake_amount,
            time: now,
        });
        
        // Doğrulayıcı ve stake nesnelerini paylaş
        transfer::share_object(validator);
        transfer::transfer(stake, sender);
    }
    
    /// Doğrulayıcıyı aktif et
    public entry fun activate_validator(
        validator_registry: &mut ValidatorRegistry,
        validator: &mut Validator,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        assert!(validator.status == VALIDATOR_STATUS_PENDING, EInvalidValidator);
        
        // Doğrulayıcı durumunu aktif olarak değiştir
        let old_status = validator.status;
        validator.status = VALIDATOR_STATUS_ACTIVE;
        validator.last_updated = now;
        
        // Doğrulayıcı durumu değişikliği eventini yayınla
        event::emit(ValidatorStatusChanged {
            validator_id: object::id(validator),
            old_status,
            new_status: validator.status,
            time: now,
        });
    }
    
    /// Bir doğrulayıcıya stake ekle (kendi doğrulayıcısı için)
    public entry fun add_self_stake(
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Doğrulayıcı sahibini kontrol et
        assert!(sender == validator.owner, ENotAuthorized);
        
        // Doğrulayıcının aktif veya beklemede olduğunu kontrol et
        assert!(
            validator.status == VALIDATOR_STATUS_ACTIVE || validator.status == VALIDATOR_STATUS_PENDING,
            EValidatorNotActive
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Stake miktarlarını güncelle
        validator.self_stake = validator.self_stake + amount;
        validator.total_stake = validator.total_stake + amount;
        validator.last_updated = now;
        validator.last_stake_action = now;
        
        // Registry'deki toplam stake miktarını güncelle
        validator_registry.total_stake = validator_registry.total_stake + amount;
        
        // Yeni bir stake nesnesi oluştur veya mevcut stake'i güncelle
        // Bu örnekte basitlik için, self stake için doğrudan güncelleme yapıyoruz
        // Gerçek implementasyonda, stake nesneleri üzerinden işlem yapmak gerekebilir
        
        // Stake ekleme eventini yayınla
        event::emit(StakeDeposited {
            stake_id: object::new(ctx), // Geçici ID, gerçek implementasyonda stake ID kullanılmalı
            validator_id: object::id(validator),
            owner: sender,
            amount,
            time: now,
        });
    }
    
    /// Başka bir doğrulayıcıya delegate stake ekle
    public entry fun delegate_stake(
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Doğrulayıcının aktif olduğunu kontrol et
        assert!(validator.status == VALIDATOR_STATUS_ACTIVE, EValidatorNotActive);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Stake miktarlarını güncelle
        validator.delegator_stake = validator.delegator_stake + amount;
        validator.total_stake = validator.total_stake + amount;
        validator.last_updated = now;
        
        // Registry'deki toplam stake miktarını güncelle
        validator_registry.total_stake = validator_registry.total_stake + amount;
        
        // Yeni stake nesnesi oluştur
        let stake = Stake {
            id: object::new(ctx),
            owner: sender,
            validator_id: object::id(validator),
            amount,
            start_time: now,
            last_reward_time: now,
            accumulated_rewards: 0,
            unlock_time: option::none(),
        };
        
        // Stake ekleme eventini yayınla
        event::emit(StakeDeposited {
            stake_id: object::id(&stake),
            validator_id: object::id(validator),
            owner: sender,
            amount,
            time: now,
        });
        
        // Stake nesnesini kullanıcıya gönder
        transfer::transfer(stake, sender);
    }
    
    /// Bir doğrulayıcıdan self stake çek
    public entry fun withdraw_self_stake(
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Doğrulayıcı sahibini kontrol et
        assert!(sender == validator.owner, ENotAuthorized);
        
        // Çekilecek miktar, minimum validator stake sınırını aşmamalı
        assert!(validator.self_stake - amount >= validator_registry.min_validator_stake, EInvalidStake);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Son stake işleminden beri bekleme süresini kontrol et
        assert!(now >= validator.last_stake_action + UNSTAKE_COOLDOWN_PERIOD, EValidatorCooldown);
        
        // Stake miktarlarını güncelle
        validator.self_stake = validator.self_stake - amount;
        validator.total_stake = validator.total_stake - amount;
        validator.last_updated = now;
        validator.last_stake_action = now;
        
        // Registry'deki toplam stake miktarını güncelle
        validator_registry.total_stake = validator_registry.total_stake - amount;
        
        // Stake çekme eventini yayınla
        event::emit(StakeWithdrawn {
            stake_id: object::new(ctx), // Geçici ID, gerçek implementasyonda stake ID kullanılmalı
            validator_id: object::id(validator),
            owner: sender,
            amount,
            time: now,
        });
        
        // Burada tokenları kullanıcıya transfer etme işlemi olacak 
        // Gerçek implementasyonda token modülü ile entegrasyon gerekir
    }
    
    /// Delegate stake çek
    public entry fun withdraw_delegated_stake(
        stake: &mut Stake,
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Stake sahibini kontrol et
        assert!(sender == stake.owner, ENotAuthorized);
        
        // Doğrulayıcı ID'sini kontrol et
        assert!(object::id(validator) == stake.validator_id, EInvalidValidator);
        
        // Çekilecek miktarı kontrol et
        assert!(amount > 0 && amount <= stake.amount, EInvalidUnstakeAmount);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Unlock zamanını kontrol et (eğer varsa)
        if (option::is_some(&stake.unlock_time)) {
            let unlock_time = *option::borrow(&stake.unlock_time);
            assert!(now >= unlock_time, EValidatorCooldown);
        };
        
        // Stake miktarlarını güncelle
        stake.amount = stake.amount - amount;
        validator.delegator_stake = validator.delegator_stake - amount;
        validator.total_stake = validator.total_stake - amount;
        validator.last_updated = now;
        
        // Registry'deki toplam stake miktarını güncelle
        validator_registry.total_stake = validator_registry.total_stake - amount;
        
        // Stake çekme eventini yayınla
        event::emit(StakeWithdrawn {
            stake_id: object::id(stake),
            validator_id: object::id(validator),
            owner: sender,
            amount,
            time: now,
        });
        
        // Eğer kalan miktar 0 ise stake nesnesini yok et
        if (stake.amount == 0) {
            // Gerçek implementasyonda nesne imha edilir veya farklı işlemler uygulanabilir
        };
        
        // Burada tokenları kullanıcıya transfer etme işlemi olacak 
        // Gerçek implementasyonda token modülü ile entegrasyon gerekir
    }
    
    /// Doğrulayıcı bilgilerini güncelle
    public entry fun update_validator_info(
        validator: &mut Validator,
        name: vector<u8>,
        description: vector<u8>,
        logo_url: vector<u8>,
        website: vector<u8>,
        contact: vector<u8>,
        commission_rate: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Doğrulayıcı sahibini kontrol et
        assert!(sender == validator.owner, ENotAuthorized);
        
        // Komisyon oranını kontrol et
        assert!(commission_rate >= MIN_COMMISSION_RATE && commission_rate <= MAX_COMMISSION_RATE, EInvalidCommissionRate);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Bilgileri güncelle
        validator.name = string::utf8(name);
        validator.description = string::utf8(description);
        validator.logo_url = string::utf8(logo_url);
        validator.website = string::utf8(website);
        validator.contact = string::utf8(contact);
        validator.commission_rate = commission_rate;
        validator.last_updated = now;
    }
    
    /// Doğrulayıcı performans ve çevrimiçi durumunu güncelle
    public entry fun update_validator_performance(
        validator: &mut Validator,
        performance_score: u64,
        uptime: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Performance ve uptime değerlerini kontrol et (maksimum 1000, yani %100)
        let perf = if (performance_score > 1000) { 1000 } else { performance_score };
        let up = if (uptime > 1000) { 1000 } else { uptime };
        
        // Bilgileri güncelle
        validator.performance_score = perf;
        validator.uptime = up;
        validator.last_updated = now;
    }
    
    /// Bir doğrulayıcıyı cezalandır
    public entry fun slash_validator(
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        slash_amount: u64,
        reason: vector<u8>,
        jail: bool,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Doğrulayıcının aktif olduğunu kontrol et
        assert!(validator.status == VALIDATOR_STATUS_ACTIVE, EValidatorNotActive);
        
        // Ceza miktarını kontrol et
        let slash_amt = if (slash_amount > validator.self_stake) {
            validator.self_stake
        } else {
            slash_amount
        };
        
        // Stake miktarlarını güncelle
        validator.self_stake = validator.self_stake - slash_amt;
        validator.total_stake = validator.total_stake - slash_amt;
        validator.slash_count = validator.slash_count + 1;
        validator.last_updated = now;
        
        // Registry'deki toplam stake miktarını güncelle
        validator_registry.total_stake = validator_registry.total_stake - slash_amt;
        
        // Eğer jail parametresi true ise, doğrulayıcıyı hapse at
        if (jail) {
            let old_status = validator.status;
            validator.status = VALIDATOR_STATUS_JAILED;
            validator.jail_time = now;
            
            // Aktif doğrulayıcılar kümesinden çıkar
            if (vec_set::contains(&validator_registry.active_validators, &object::id(validator))) {
                vec_set::remove(&mut validator_registry.active_validators, &object::id(validator));
                validator_registry.active_validator_count = validator_registry.active_validator_count - 1;
                
                // Bölge sayacını azalt
                let region = validator.region;
                let current_count = *vec_map::get(&validator_registry.region_counts, &region);
                vec_map::insert(&mut validator_registry.region_counts, region, current_count - 1);
            };
            
            // Doğrulayıcı durumu değişikliği eventini yayınla
            event::emit(ValidatorStatusChanged {
                validator_id: object::id(validator),
                old_status,
                new_status: validator.status,
                time: now,
            });
        };
        
        // Cezalandırma eventini yayınla
        event::emit(ValidatorSlashed {
            validator_id: object::id(validator),
            reason: string::utf8(reason),
            slash_amount: slash_amt,
            time: now,
        });
        
        // Burada penaltı tokenların hazineye veya yakma adresine gönderilmesi işlemi olacak
        // Gerçek implementasyonda token modülü ile entegrasyon gerekir
    }
    
    /// Bir doğrulayıcıyı hapisten çıkar
    public entry fun unjail_validator(
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Doğrulayıcının hapiste olduğunu kontrol et
        assert!(validator.status == VALIDATOR_STATUS_JAILED, EInvalidValidator);
        
        // Hapisten çıkma zamanını kontrol et
        assert!(now >= validator.jail_time + JAIL_DURATION, EValidatorCooldown);
        
        // Minimum stake koşulunu kontrol et
        assert!(validator.self_stake >= validator_registry.min_validator_stake, EInsufficientStake);
        
        // Doğrulayıcı durumunu güncelle
        let old_status = validator.status;
        validator.status = VALIDATOR_STATUS_ACTIVE;
        validator.last_updated = now;
        
        // Aktif doğrulayıcılar kümesine ekle
        if (!vec_set::contains(&validator_registry.active_validators, &object::id(validator))) {
            vec_set::insert(&mut validator_registry.active_validators, object::id(validator));
            validator_registry.active_validator_count = validator_registry.active_validator_count + 1;
            
            // Bölge sayacını artır
            let region = validator.region;
            let current_count = *vec_map::get(&validator_registry.region_counts, &region);
            vec_map::insert(&mut validator_registry.region_counts, region, current_count + 1);
        };
        
        // Doğrulayıcı durumu değişikliği eventini yayınla
        event::emit(ValidatorStatusChanged {
            validator_id: object::id(validator),
            old_status,
            new_status: validator.status,
            time: now,
        });
    }
    
    /// Doğrulayıcı rotasyonunu gerçekleştir
    public entry fun perform_validator_rotation(
        validator_registry: &mut ValidatorRegistry,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Rotasyon zamanını kontrol et
        assert!(now >= validator_registry.last_rotation + validator_registry.rotation_period, EValidatorCooldown);
        
        // Yeni epoch
        let new_epoch = validator_registry.current_epoch + 1;
        validator_registry.current_epoch = new_epoch;
        validator_registry.last_rotation = now;
        
        // Doğrulayıcı rotasyonu eventini yayınla
        event::emit(ValidatorRotation {
            epoch: new_epoch,
            active_validators: validator_registry.active_validator_count,
            time: now,
        });
        
        // Not: Gerçek bir implementasyonda, burada doğrulayıcı seti değişiklikleri, 
        // performans bazlı rotasyon ve diğer karmaşık işlemler gerçekleştirilir
    }
    
    /// Bir doğrulayıcıdan ayrıl (doğrulayıcı sahibi için)
    public entry fun leave_validator_set(
        validator: &mut Validator,
        validator_registry: &mut ValidatorRegistry,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Doğrulayıcı sahibini kontrol et
        assert!(sender == validator.owner, ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Doğrulayıcı durumunu güncelle
        let old_status = validator.status;
        validator.status = VALIDATOR_STATUS_LEAVING;
        validator.last_updated = now;
        
        // Aktif doğrulayıcılar kümesinden çıkar
        if (vec_set::contains(&validator_registry.active_validators, &object::id(validator))) {
            vec_set::remove(&mut validator_registry.active_validators, &object::id(validator));
            validator_registry.active_validator_count = validator_registry.active_validator_count - 1;
            
            // Bölge sayacını azalt
            let region = validator.region;
            let current_count = *vec_map::get(&validator_registry.region_counts, &region);
            vec_map::insert(&mut validator_registry.region_counts, region, current_count - 1);
        };
        
        // Doğrulayıcı durumu değişikliği eventini yayınla
        event::emit(ValidatorStatusChanged {
            validator_id: object::id(validator),
            old_status,
            new_status: validator.status,
            time: now,
        });
        
        // Not: Burada delegatörlere bildirim gönderme, stake'leri çözme süreci başlatma gibi 
        // ek işlemler gerçekleştirilebilir
    }
    
    // Getter fonksiyonları
    
    /// Doğrulayıcı bilgilerini al
    public fun get_validator_info(validator: &Validator): (
        address, String, String, u8, u64, u64, u64, u64, u64, u64, u64, u8, String
    ) {
        (
            validator.owner,
            validator.name,
            validator.description,
            validator.status,
            validator.total_stake,
            validator.self_stake,
            validator.delegator_stake,
            validator.commission_rate,
            validator.performance_score,
            validator.uptime,
            validator.joined_at,
            validator.region,
            validator.public_key
        )
    }
    
    /// Validator Registry bilgilerini al
    public fun get_validator_registry_info(registry: &ValidatorRegistry): (
        u64, u64, u64, u64, u64, u64
    ) {
        (
            registry.active_validator_count,
            registry.total_stake,
            registry.last_rotation,
            registry.rotation_period,
            registry.current_epoch,
            registry.max_validator_count
        )
    }
    
    /// Stake bilgilerini al
    public fun get_stake_info(stake: &Stake): (
        address, ID, u64, u64, u64, u64
    ) {
        (
            stake.owner,
            stake.validator_id,
            stake.amount,
            stake.start_time,
            stake.last_reward_time,
            stake.accumulated_rewards
        )
    }
    
    /// Bir bölgenin doğrulayıcı sayısını al
    public fun get_region_validator_count(registry: &ValidatorRegistry, region: u8): u64 {
        *vec_map::get(&registry.region_counts, &region)
    }
    
    /// Bir bölgenin doğrulayıcı limitini al
    public fun get_region_validator_limit(registry: &ValidatorRegistry, region: u8): u64 {
        *vec_map::get(&registry.region_limits, &region)
    }
    
    /// Aktif doğrulayıcıların sayısını al
    public fun get_active_validator_count(registry: &ValidatorRegistry): u64 {
        registry.active_validator_count
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_validator_registry_for_testing(ctx: &mut TxContext): ValidatorRegistry {
        let validator_registry = ValidatorRegistry {
            id: object::new(ctx),
            active_validator_count: 0,
            total_stake: 0,
            active_validators: vec_set::empty(),
            last_rotation: 0,
            rotation_period: 86400, // 1 gün (saniye)
            current_epoch: 0,
            max_validator_count: MAX_VALIDATOR_COUNT,
            min_validator_stake: MIN_VALIDATOR_STAKE,
            region_limits: vec_map::empty(),
            region_counts: vec_map::empty(),
        }
    }
}
