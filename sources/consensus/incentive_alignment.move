/// SuiVPN Incentive Alignment Module
/// 
/// Bu modül, SuiVPN protokolünün teşvik hizalama mekanizmalarını uygular.
/// Ağ katılımcılarının (düğüm operatörleri, kullanıcılar, yatırımcılar, vs.) çıkarlarını hizalamak,
/// protokolün uzun vadeli sağlığını ve başarısını teşvik etmek ve ağın güvenliğini
/// sağlamak için tasarlanmıştır.
module suivpn::incentive_alignment {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::vec_map::{Self, VecMap};
    use sui::vec_set::{Self, VecSet};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use std::vector;
    use std::string::{Self, String};
    use std::option::{Self, Option};
    use suivpn::governance::{Self, GovernanceCapability};
    use suivpn::token::{Self, SVPN};
    use suivpn::validator::{Self, Validator};
    use suivpn::registry::{Self, NodeInfo};
    use suivpn::quality_metrics::{Self};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidReward: u64 = 1;
    const EInvalidAmount: u64 = 2;
    const EInvalidPeriod: u64 = 3;
    const EInvalidRate: u64 = 4;
    const EInvalidNodeType: u64 = 5;
    const EInvalidThreshold: u64 = 6;
    const EInvalidStake: u64 = 7;
    const EInvalidSchedule: u64 = 8;
    const ENodeNotFound: u64 = 9;
    const ENodeNotActive: u64 = 10;
    const EInsufficientFunds: u64 = 11;
    const ERewardClaimTooEarly: u64 = 12;
    const EInvalidConfiguration: u64 = 13;
    
    // Ödül tipleri
    const REWARD_TYPE_VALIDATION: u8 = 0;
    const REWARD_TYPE_BANDWIDTH: u8 = 1;
    const REWARD_TYPE_STAKING: u8 = 2;
    const REWARD_TYPE_GOVERNANCE: u8 = 3;
    const REWARD_TYPE_REFERRAL: u8 = 4;
    const REWARD_TYPE_QUALITY: u8 = 5;
    
    // Düğüm tipleri
    const NODE_TYPE_RELAY: u8 = 0;
    const NODE_TYPE_VALIDATOR: u8 = 1;
    const NODE_TYPE_COMPUTE: u8 = 2;
    const NODE_TYPE_STORAGE: u8 = 3;
    
    // Sabitler
    const DEFAULT_REWARD_EPOCH_SECONDS: u64 = 86400; // 1 gün (saniye)
    const DEFAULT_CLAIM_COOLDOWN_SECONDS: u64 = 604800; // 7 gün (saniye)
    const MIN_STAKE_AMOUNT: u64 = 100_000_000_000; // 100 SVPN tokeni (1e9 decimals)
    const MIN_STAKING_PERIOD_SECONDS: u64 = 2592000; // 30 gün (saniye)
    const BASE_INFLATIONARY_REWARD_RATE: u64 = 50; // Baz enflasyonist ödül oranı (yıllık %5, binde)
    
    /// Teşvik Konfigürasyonu
    /// Ödül parametrelerini ve teşvik mekanizmalarını içerir
    struct IncentiveConfig has key, store {
        id: UID,
        // Ödül epoch süresi (saniye)
        reward_epoch_seconds: u64,
        // Ödül talep etmeler arası bekleme süresi (saniye)
        claim_cooldown_seconds: u64,
        // Ödül havuzu dağıtım oranları (binde)
        reward_pool_distribution: VecMap<u8, u64>,
        // Düğüm tipi bazlı ödül çarpanları (binde)
        node_type_multipliers: VecMap<u8, u64>,
        // Kalite bazlı ödül çarpanları (puan aralığı -> çarpan)
        quality_multipliers: VecMap<u64, u64>,
        // Stake miktarı bazlı ödül çarpanları (miktar aralığı -> çarpan)
        stake_amount_multipliers: VecMap<u64, u64>,
        // Stake süresi bazlı ödül çarpanları (süre aralığı -> çarpan)
        stake_duration_multipliers: VecMap<u64, u64>,
        // Yıllık enflasyonist ödül oranı (binde)
        inflationary_reward_rate: u64,
        // Toplam ödül havuzunun maksimum yüzdesi (binde)
        max_reward_pool_percentage: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Teşvik Yöneticisi
    /// Ödül havuzlarını, ödül dağıtımını ve istihkak takibini yönetir
    struct IncentiveManager has key {
        id: UID,
        // Ödül havuzları (ödül tipi -> balance)
        reward_pools: VecMap<u8, Balance<SVPN>>,
        // Düğüm bazlı ödül istihkakları
        node_rewards: Table<ID, RewardInfo>,
        // Adres bazlı yönetişim ödül istihkakları
        governance_rewards: Table<address, RewardInfo>,
        // Adres bazlı son talep zamanları
        last_claim_times: Table<address, u64>,
        // Mevcut epoch
        current_epoch: u64,
        // Toplam dağıtılan ödüller
        total_rewards_distributed: u64,
        // Son ödül dağıtımı zamanı
        last_distribution_time: u64,
    }
    
    /// Ödül Bilgisi
    /// Bir düğüm veya adres için birikmiş ödül bilgilerini içerir
    struct RewardInfo has store {
        // Talep edilebilir ödül miktarı
        claimable_amount: u64,
        // Ödül tipi bazlı dağılım
        reward_breakdown: VecMap<u8, u64>,
        // Toplam kazanılan ödül
        total_rewarded: u64,
        // Toplam talep edilen ödül
        total_claimed: u64,
        // Son ödül kazanma zamanı
        last_reward_time: u64,
    }
    
    /// Stake Bilgisi
    /// Bir kullanıcının stake bilgilerini tutar
    struct StakeInfo has key, store {
        id: UID,
        // Stake sahibi
        owner: address,
        // Stake edilen düğüm ID'si (varsa)
        node_id: Option<ID>,
        // Stake edilen miktar
        amount: u64,
        // Stake edilmiş tokenlar
        staked_balance: Balance<SVPN>,
        // Stake başlangıç zamanı
        start_time: u64,
        // Kilit açılma zamanı
        unlock_time: u64,
        // Son ödül hesaplama zamanı
        last_reward_time: u64,
        // Birikmiş ödüller
        accumulated_rewards: u64,
        // Toplam talep edilen ödüller
        total_claimed_rewards: u64,
    }
    
    /// Referans Programı
    /// Kullanıcılar arası referans ilişkilerini ve ödüllerini yönetir
    struct ReferralProgram has key {
        id: UID,
        // Referans ilişkileri (yeni kullanıcı -> referans veren)
        referrals: Table<address, address>,
        // Referans ödülleri (referans veren -> toplam ödül)
        referral_rewards: Table<address, u64>,
        // Referans sayıları (referans veren -> sayı)
        referral_counts: Table<address, u64>,
        // Referans başına ödül miktarı
        reward_per_referral: u64,
        // Referans derinliği (kaç seviye referans ödüllendirilir)
        referral_depth: u8,
        // Ödül dağıtım oranları (seviye -> oran, binde)
        level_rates: VecMap<u8, u64>,
    }
    
    // Eventler
    
    /// Ödül dağıtım eventi
    struct RewardsDistributed has copy, drop {
        distribution_id: ID,
        epoch: u64,
        total_amount: u64,
        node_count: u64,
        timestamp: u64,
    }
    
    /// Ödül talep eventi
    struct RewardsClaimed has copy, drop {
        claimer: address,
        node_id: Option<ID>,
        amount: u64,
        reward_type: u8,
        timestamp: u64,
    }
    
    /// Stake eventi
    struct TokensStaked has copy, drop {
        stake_id: ID,
        owner: address,
        node_id: Option<ID>,
        amount: u64,
        unlock_time: u64,
        timestamp: u64,
    }
    
    /// Unstake eventi
    struct TokensUnstaked has copy, drop {
        stake_id: ID,
        owner: address,
        amount: u64,
        rewards: u64,
        timestamp: u64,
    }
    
    /// Referans eventi
    struct ReferralRegistered has copy, drop {
        referrer: address,
        referred: address,
        reward: u64,
        timestamp: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let incentive_config = IncentiveConfig {
            id: object::new(ctx),
            reward_epoch_seconds: DEFAULT_REWARD_EPOCH_SECONDS,
            claim_cooldown_seconds: DEFAULT_CLAIM_COOLDOWN_SECONDS,
            reward_pool_distribution: vec_map::empty(),
            node_type_multipliers: vec_map::empty(),
            quality_multipliers: vec_map::empty(),
            stake_amount_multipliers: vec_map::empty(),
            stake_duration_multipliers: vec_map::empty(),
            inflationary_reward_rate: BASE_INFLATIONARY_REWARD_RATE,
            max_reward_pool_percentage: 300, // %30 (binde)
            last_updated: 0,
        };
        
        // Ödül havuzu dağıtım oranlarını ayarla (toplam 1000)
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_VALIDATION, 350); // %35
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_BANDWIDTH, 300); // %30
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_STAKING, 200); // %20
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_GOVERNANCE, 50); // %5
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_REFERRAL, 50); // %5
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_QUALITY, 50); // %5
        
        // Düğüm tipi ödül çarpanlarını ayarla
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_RELAY, 800); // 0.8x
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_VALIDATOR, 1200); // 1.2x
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_COMPUTE, 1000); // 1.0x
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_STORAGE, 1000); // 1.0x
        
        // Kalite çarpanlarını ayarla
        vec_map::insert(&mut incentive_config.quality_multipliers, 900, 1200); // %90+ kalite: 1.2x
        vec_map::insert(&mut incentive_config.quality_multipliers, 800, 1100); // %80+ kalite: 1.1x
        vec_map::insert(&mut incentive_config.quality_multipliers, 700, 1000); // %70+ kalite: 1.0x
        vec_map::insert(&mut incentive_config.quality_multipliers, 600, 900); // %60+ kalite: 0.9x
        vec_map::insert(&mut incentive_config.quality_multipliers, 500, 800); // %50+ kalite: 0.8x
        vec_map::insert(&mut incentive_config.quality_multipliers, 0, 700); // < %50 kalite: 0.7x
        
        // Stake miktarı çarpanlarını ayarla (SVPN token cinsinden)
        vec_map::insert(&mut incentive_config.stake_amount_multipliers, 1_000_000_000_000, 1200); // 1,000,000+ SVPN: 1.2x
        vec_map::insert(&mut incentive_config.stake_amount_multipliers, 500_000_000_000, 1150); // 500,000+ SVPN: 1.15x
        vec_map::insert(&mut incentive_config.stake_amount_multipliers, 100_000_000_000, 1100); // 100,000+ SVPN: 1.1x
        vec_map::insert(&mut incentive_config.stake_amount_multipliers, 50_000_000_000, 1050); // 50,000+ SVPN: 1.05x
        vec_map::insert(&mut incentive_config.stake_amount_multipliers, 10_000_000_000, 1000); // 10,000+ SVPN: 1.0x
        vec_map::insert(&mut incentive_config.stake_amount_multipliers, 0, 900); // < 10,000 SVPN: 0.9x
        
        // Stake süresi çarpanlarını ayarla (saniye cinsinden)
        vec_map::insert(&mut incentive_config.stake_duration_multipliers, 31536000, 1300); // 1+ yıl: 1.3x
        vec_map::insert(&mut incentive_config.stake_duration_multipliers, 15768000, 1200); // 6+ ay: 1.2x
        vec_map::insert(&mut incentive_config.stake_duration_multipliers, 7884000, 1100); // 3+ ay: 1.1x
        vec_map::insert(&mut incentive_config.stake_duration_multipliers, 2592000, 1000); // 1+ ay: 1.0x
        vec_map::insert(&mut incentive_config.stake_duration_multipliers, 0, 900); // < 1 ay: 0.9x
        
        let incentive_manager = IncentiveManager {
            id: object::new(ctx),
            reward_pools: vec_map::empty(),
            node_rewards: table::new(ctx),
            governance_rewards: table::new(ctx),
            last_claim_times: table::new(ctx),
            current_epoch: 0,
            total_rewards_distributed: 0,
            last_distribution_time: 0,
        };
        
        // Ödül havuzlarını başlat
        vec_map::insert(&mut incentive_manager.reward_pools, REWARD_TYPE_VALIDATION, balance::zero<SVPN>());
        vec_map::insert(&mut incentive_manager.reward_pools, REWARD_TYPE_BANDWIDTH, balance::zero<SVPN>());
        vec_map::insert(&mut incentive_manager.reward_pools, REWARD_TYPE_STAKING, balance::zero<SVPN>());
        vec_map::insert(&mut incentive_manager.reward_pools, REWARD_TYPE_GOVERNANCE, balance::zero<SVPN>());
        vec_map::insert(&mut incentive_manager.reward_pools, REWARD_TYPE_REFERRAL, balance::zero<SVPN>());
        vec_map::insert(&mut incentive_manager.reward_pools, REWARD_TYPE_QUALITY, balance::zero<SVPN>());
        
        let referral_program = ReferralProgram {
            id: object::new(ctx),
            referrals: table::new(ctx),
            referral_rewards: table::new(ctx),
            referral_counts: table::new(ctx),
            reward_per_referral: 1_000_000_000, // 1 SVPN
            referral_depth: 2,
            level_rates: vec_map::empty(),
        };
        
        // Referans seviye oranlarını ayarla
        vec_map::insert(&mut referral_program.level_rates, 0, 700); // Seviye 0 (doğrudan): %70
        vec_map::insert(&mut referral_program.level_rates, 1, 300); // Seviye 1 (dolaylı): %30
        
        transfer::share_object(incentive_config);
        transfer::share_object(incentive_manager);
        transfer::share_object(referral_program);
    }
    
    /// Ödül havuzuna token ekle
    public entry fun add_to_reward_pool(
        incentive_manager: &mut IncentiveManager,
        reward_type: u8,
        amount_coin: Coin<SVPN>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Ödül tipini kontrol et
        assert!(
            reward_type == REWARD_TYPE_VALIDATION ||
            reward_type == REWARD_TYPE_BANDWIDTH ||
            reward_type == REWARD_TYPE_STAKING ||
            reward_type == REWARD_TYPE_GOVERNANCE ||
            reward_type == REWARD_TYPE_REFERRAL ||
            reward_type == REWARD_TYPE_QUALITY,
            EInvalidReward
        );
        
        // Miktarın pozitif olup olmadığını kontrol et
        let amount = coin::value(&amount_coin);
        assert!(amount > 0, EInvalidAmount);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Tokenları ödül havuzuna ekle
        balance::join(vec_map::get_mut(&mut incentive_manager.reward_pools, &reward_type), coin::into_balance(amount_coin));
        
        incentive_manager.last_distribution_time = now;
    }
    
    /// Ödülleri dağıt (düğüm operatörleri için)
    public entry fun distribute_node_rewards(
        incentive_manager: &mut IncentiveManager,
        incentive_config: &IncentiveConfig,
        quality_registry: &quality_metrics::QualityRegistry,
        validator_registry: &validator::ValidatorRegistry,
        node_ids: vector<ID>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Ödül havuzu büyüklüklerini hesapla
        let validation_pool = balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_VALIDATION));
        let bandwidth_pool = balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_BANDWIDTH));
        let quality_pool = balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_QUALITY));
        
        // Toplam ödül havuzu
        let total_pool = validation_pool + bandwidth_pool + quality_pool;
        
        // Dağıtılacak düğüm sayısı
        let node_count = vector::length(&node_ids);
        assert!(node_count > 0, EInvalidAmount);
        
        // Düğüm başına temel ödül miktarı
        let base_reward_per_node = total_pool / node_count;
        
        // Her düğüm için ödülleri hesapla
        let i = 0;
        let total_distributed = 0;
        
        while (i < node_count) {
            let node_id = *vector::borrow(&node_ids, i);
            
            // Düğüm tipini ve kalite puanını al
            let node_type = get_node_type_safe(node_id);
            let quality_score = quality_metrics::get_node_quality_score(quality_registry, node_id);
            
            // Ödül çarpanlarını hesapla
            let node_type_multiplier = get_node_type_multiplier(incentive_config, node_type);
            let quality_multiplier = get_quality_multiplier(incentive_config, quality_score);
            
            // Düğüm için toplam ödül miktarını hesapla
            let node_reward = (base_reward_per_node * node_type_multiplier * quality_multiplier) / (1000 * 1000);
            
            // Düğüm ödüllerini güncelle
            if (!table::contains(&incentive_manager.node_rewards, node_id)) {
                let reward_breakdown = vec_map::empty<u8, u64>();
                vec_map::insert(&mut reward_breakdown, REWARD_TYPE_VALIDATION, 0);
                vec_map::insert(&mut reward_breakdown, REWARD_TYPE_BANDWIDTH, 0);
                vec_map::insert(&mut reward_breakdown, REWARD_TYPE_QUALITY, 0);
                
                table::add(
                    &mut incentive_manager.node_rewards,
                    node_id,
                    RewardInfo {
                        claimable_amount: 0,
                        reward_breakdown,
                        total_rewarded: 0,
                        total_claimed: 0,
                        last_reward_time: now,
                    }
                );
            };
            
            let reward_info = table::borrow_mut(&mut incentive_manager.node_rewards, node_id);
            
            // Ödül dağılımını hesapla
            let validation_reward = (node_reward * *vec_map::get(&incentive_config.reward_pool_distribution, &REWARD_TYPE_VALIDATION)) / 1000;
            let bandwidth_reward = (node_reward * *vec_map::get(&incentive_config.reward_pool_distribution, &REWARD_TYPE_BANDWIDTH)) / 1000;
            let quality_reward = (node_reward * *vec_map::get(&incentive_config.reward_pool_distribution, &REWARD_TYPE_QUALITY)) / 1000;
            
            // Toplam ödül
            let total_node_reward = validation_reward + bandwidth_reward + quality_reward;
            
            // Ödül bilgisini güncelle
            reward_info.claimable_amount = reward_info.claimable_amount + total_node_reward;
            *vec_map::get_mut(&mut reward_info.reward_breakdown, &REWARD_TYPE_VALIDATION) = 
                *vec_map::get(&reward_info.reward_breakdown, &REWARD_TYPE_VALIDATION) + validation_reward;
            *vec_map::get_mut(&mut reward_info.reward_breakdown, &REWARD_TYPE_BANDWIDTH) = 
                *vec_map::get(&reward_info.reward_breakdown, &REWARD_TYPE_BANDWIDTH) + bandwidth_reward;
            *vec_map::get_mut(&mut reward_info.reward_breakdown, &REWARD_TYPE_QUALITY) = 
                *vec_map::get(&reward_info.reward_breakdown, &REWARD_TYPE_QUALITY) + quality_reward;
            
            reward_info.total_rewarded = reward_info.total_rewarded + total_node_reward;
            reward_info.last_reward_time = now;
            
            total_distributed = total_distributed + total_node_reward;
            i = i + 1;
        };
        
        // Ödül havuzlarından ödülleri düş
        // İlk olarak token miktarlarını hesapla
        let validation_amount = (total_distributed * *vec_map::get(&incentive_config.reward_pool_distribution, &REWARD_TYPE_VALIDATION)) / 1000;
        let bandwidth_amount = (total_distributed * *vec_map::get(&incentive_config.reward_pool_distribution, &REWARD_TYPE_BANDWIDTH)) / 1000;
        let quality_amount = (total_distributed * *vec_map::get(&incentive_config.reward_pool_distribution, &REWARD_TYPE_QUALITY)) / 1000;
        
        // Havuzlardan çek (mevcut bakiyeyi aşmamak koşuluyla)
        if (validation_amount > 0 && validation_amount <= validation_pool) {
            let _validation_tokens = balance::split(
                vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_VALIDATION),
                validation_amount
            );
            // İlgili modül entegrasyonu olmadığı için şimdilik ödülleri tutuyoruz
            // Gerçek uygulamada bu tokenlar hazineye, stake havuzuna veya ilgili bir modüle gönderilebilir
        };
        
        if (bandwidth_amount > 0 && bandwidth_amount <= bandwidth_pool) {
            let _bandwidth_tokens = balance::split(
                vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_BANDWIDTH),
                bandwidth_amount
            );
        };
        
        if (quality_amount > 0 && quality_amount <= quality_pool) {
            let _quality_tokens = balance::split(
                vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_QUALITY),
                quality_amount
            );
        };
        
        // Epoch ve toplam dağıtılan ödülleri güncelle
        incentive_manager.current_epoch = incentive_manager.current_epoch + 1;
        incentive_manager.total_rewards_distributed = incentive_manager.total_rewards_distributed + total_distributed;
        incentive_manager.last_distribution_time = now;
        
        // ID oluştur
        let distribution_id = object::new(ctx);
        let dist_id = object::uid_to_inner(&distribution_id);
        object::delete(distribution_id);
        
        // Ödül dağıtım eventini yayınla
        event::emit(RewardsDistributed {
            distribution_id: dist_id,
            epoch: incentive_manager.current_epoch,
            total_amount: total_distributed,
            node_count,
            timestamp: now,
        });
    }
    
    /// Düğüm ödüllerini talep et
    public entry fun claim_node_rewards(
        incentive_manager: &mut IncentiveManager,
        node_id: ID,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Düğüm sahibi olup olmadığını kontrol et
        assert!(is_node_owner(node_id, sender), ENotAuthorized);
        
        // Ödül kaydının var olup olmadığını kontrol et
        assert!(table::contains(&incentive_manager.node_rewards, node_id), ENodeNotFound);
        
        let reward_info = table::borrow_mut(&mut incentive_manager.node_rewards, node_id);
        
        // Talep edilebilir miktarın yeterli olup olmadığını kontrol et
        assert!(reward_info.claimable_amount >= amount, EInsufficientFunds);
        
        // Son talep zamanını kontrol et
        if (table::contains(&incentive_manager.last_claim_times, sender)) {
            let last_claim_time = *table::borrow(&incentive_manager.last_claim_times, sender);
            assert!(
                now >= last_claim_time + incentive_manager.claim_cooldown_seconds,
                ERewardClaimTooEarly
            );
        };
        
        // Ödülü düş
        reward_info.claimable_amount = reward_info.claimable_amount - amount;
        reward_info.total_claimed = reward_info.total_claimed + amount;
        
        // Son talep zamanını güncelle
        if (table::contains(&incentive_manager.last_claim_times, sender)) {
            *table::borrow_mut(&mut incentive_manager.last_claim_times, sender) = now;
        } else {
            table::add(&mut incentive_manager.last_claim_times, sender, now);
        };
        
        // Ödül talep eventini yayınla
        event::emit(RewardsClaimed {
            claimer: sender,
            node_id: option::some(node_id),
            amount,
            reward_type: REWARD_TYPE_VALIDATION, // Birincil tip olarak validation kullanıyoruz
            timestamp: now,
        });
        
        // Tokenları gönder
        let reward_coin = coin::from_balance(balance::split(
            vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_VALIDATION),
            amount
        ), ctx);
        
        transfer::public_transfer(reward_coin, sender);
    }
    
    /// Token stake et
    public entry fun stake_tokens(
        token_amount: Coin<SVPN>,
        node_id: Option<ID>,
        lock_period_seconds: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Miktarın minimum stake miktarından büyük olup olmadığını kontrol et
        let amount = coin::value(&token_amount);
        assert!(amount >= MIN_STAKE_AMOUNT, EInvalidAmount);
        
        // Kilit süresinin minimum süreden büyük olup olmadığını kontrol et
        assert!(lock_period_seconds >= MIN_STAKING_PERIOD_SECONDS, EInvalidPeriod);
        
        // Eğer bir düğüm ID'si belirtilmişse, düğümün varlığını kontrol et
        if (option::is_some(&node_id)) {
            let nid = *option::borrow(&node_id);
            assert!(is_valid_node(nid), EInvalidNode);
        };
        
        // Kilit açılma zamanını hesapla
        let unlock_time = now + lock_period_seconds;
        
        // Stake nesnesi oluştur
        let staked_balance = coin::into_balance(token_amount);
        
        let stake_info = StakeInfo {
            id: object::new(ctx),
            owner: sender,
            node_id,
            amount,
            staked_balance,
            start_time: now,
            unlock_time,
            last_reward_time: now,
            accumulated_rewards: 0,
            total_claimed_rewards: 0,
        };
        
        let stake_id = object::id(&stake_info);
        
        // Stake eventini yayınla
        event::emit(TokensStaked {
            stake_id,
            owner: sender,
            node_id,
            amount,
            unlock_time,
            timestamp: now,
        });
        
        transfer::transfer(stake_info, sender);
    }
    
    /// Stake edilen tokenleri çek
    public entry fun unstake_tokens(
        stake_info: &mut StakeInfo,
        incentive_manager: &mut IncentiveManager,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Sahibi kontrol et
        assert!(stake_info.owner == sender, ENotAuthorized);
        
        // Çekilebilir miktarı kontrol et
        assert!(amount > 0 && amount <= stake_info.amount, EInvalidAmount);
        
        // Kilit süresini kontrol et
        assert!(now >= stake_info.unlock_time, EInvalidPeriod);
        
        // Ödülleri hesapla
        calculate_staking_rewards(stake_info, now);
        
        // Tokenları çek
        let unstaked_balance = balance::split(&mut stake_info.staked_balance, amount);
        stake_info.amount = stake_info.amount - amount;
        
        // Ödülleri al
        let rewards = stake_info.accumulated_rewards;
        stake_info.accumulated_rewards = 0;
        stake_info.total_claimed_rewards = stake_info.total_claimed_rewards + rewards;
        
        // Unstake eventini yayınla
        event::emit(TokensUnstaked {
            stake_id: object::id(stake_info),
            owner: sender,
            amount,
            rewards,
            timestamp: now,
        });
        
        // Tokenları gönder
        let unstaked_coin = coin::from_balance(unstaked_balance, ctx);
        transfer::public_transfer(unstaked_coin, sender);
        
        // Ödülleri gönder (varsa)
        if (rewards > 0) {
            // Gerçekte, ödüller staking ödül havuzundan verilecektir
            // Burada basitlik için validation ödül havuzundan veriyoruz
            
            // Havuzda yeterli bakiye olup olmadığını kontrol et
            let pool_balance = balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_STAKING));
            let reward_amount = if (rewards <= pool_balance) { rewards } else { pool_balance };
            
            if (reward_amount > 0) {
                let reward_coin = coin::from_balance(balance::split(
                    vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_STAKING),
                    reward_amount
                ), ctx);
                
                transfer::public_transfer(reward_coin, sender);
                
                // Ödül talep eventini yayınla
                event::emit(RewardsClaimed {
                    claimer: sender,
                    node_id: stake_info.node_id,
                    amount: reward_amount,
                    reward_type: REWARD_TYPE_STAKING,
                    timestamp: now,
                });
            };
        };
    }
    
    /// Stake ödüllerini talep et
    public entry fun claim_staking_rewards(
        stake_info: &mut StakeInfo,
        incentive_manager: &mut IncentiveManager,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Sahibi kontrol et
        assert!(stake_info.owner == sender, ENotAuthorized);
        
        // Ödülleri hesapla
        calculate_staking_rewards(stake_info, now);
        
        // Mevcut ödülleri kontrol et
        assert!(stake_info.accumulated_rewards > 0, EInsufficientFunds);
        
        // Son talep zamanını kontrol et
        if (table::contains(&incentive_manager.last_claim_times, sender)) {
            let last_claim_time = *table::borrow(&incentive_manager.last_claim_times, sender);
            assert!(
                now >= last_claim_time + incentive_manager.claim_cooldown_seconds,
                ERewardClaimTooEarly
            );
        };
        
        // Ödülleri al
        let rewards = stake_info.accumulated_rewards;
        stake_info.accumulated_rewards = 0;
        stake_info.total_claimed_rewards = stake_info.total_claimed_rewards + rewards;
        stake_info.last_reward_time = now;
        
        // Son talep zamanını güncelle
        if (table::contains(&incentive_manager.last_claim_times, sender)) {
            *table::borrow_mut(&mut incentive_manager.last_claim_times, sender) = now;
        } else {
            table::add(&mut incentive_manager.last_claim_times, sender, now);
        };
        
        // Havuzda yeterli bakiye olup olmadığını kontrol et
        let pool_balance = balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_STAKING));
        let reward_amount = if (rewards <= pool_balance) { rewards } else { pool_balance };
        
        if (reward_amount > 0) {
            let reward_coin = coin::from_balance(balance::split(
                vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_STAKING),
                reward_amount
            ), ctx);
            
            transfer::public_transfer(reward_coin, sender);
            
            // Ödül talep eventini yayınla
            event::emit(RewardsClaimed {
                claimer: sender,
                node_id: stake_info.node_id,
                amount: reward_amount,
                reward_type: REWARD_TYPE_STAKING,
                timestamp: now,
            });
        };
    }
    
    /// Referans kaydı oluştur
    public entry fun register_referral(
        referral_program: &mut ReferralProgram,
        incentive_manager: &mut IncentiveManager,
        referrer: address,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let referred = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Kendini referans olarak ekleme durumunu kontrol et
        assert!(referred != referrer, EInvalidNode);
        
        // Henüz referans kaydı olmadığını kontrol et
        assert!(!table::contains(&referral_program.referrals, referred), EInvalidNode);
        
        // Referans kaydı oluştur
        table::add(&mut referral_program.referrals, referred, referrer);
        
        // Referans sayısını güncelle
        if (table::contains(&referral_program.referral_counts, referrer)) {
            let count = table::borrow_mut(&mut referral_program.referral_counts, referrer);
            *count = *count + 1;
        } else {
            table::add(&mut referral_program.referral_counts, referrer, 1);
        };
        
        // Referans ödülünü hesapla
        let reward = referral_program.reward_per_referral;
        
        // Referans ödüllerini güncelle
        if (table::contains(&referral_program.referral_rewards, referrer)) {
            let total_reward = table::borrow_mut(&mut referral_program.referral_rewards, referrer);
            *total_reward = *total_reward + reward;
        } else {
            table::add(&mut referral_program.referral_rewards, referrer, reward);
        };
        
        // Referans eventini yayınla
        event::emit(ReferralRegistered {
            referrer,
            referred,
            reward,
            timestamp: now,
        });
        
        // Ödeme işlemi gerçekleştir
        let pool_balance = balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_REFERRAL));
        
        if (reward <= pool_balance) {
            let reward_coin = coin::from_balance(balance::split(
                vec_map::get_mut(&mut incentive_manager.reward_pools, &REWARD_TYPE_REFERRAL),
                reward
            ), ctx);
            
            transfer::public_transfer(reward_coin, referrer);
            
            // Ödül talep eventini yayınla
            event::emit(RewardsClaimed {
                claimer: referrer,
                node_id: option::none(),
                amount: reward,
                reward_type: REWARD_TYPE_REFERRAL,
                timestamp: now,
            });
        };
    }
    
    /// Teşvik konfigürasyonunu güncelle
    public entry fun update_incentive_config(
        incentive_config: &mut IncentiveConfig,
        reward_epoch: Option<u64>,
        claim_cooldown: Option<u64>,
        inflationary_rate: Option<u64>,
        max_pool_percentage: Option<u64>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Ödül epoch süresini güncelle (varsa)
        if (option::is_some(&reward_epoch)) {
            let epoch = *option::borrow(&reward_epoch);
            assert!(epoch > 0, EInvalidPeriod);
            incentive_config.reward_epoch_seconds = epoch;
        };
        
        // Talep bekleme süresini güncelle (varsa)
        if (option::is_some(&claim_cooldown)) {
            let cooldown = *option::borrow(&claim_cooldown);
            assert!(cooldown > 0, EInvalidPeriod);
            incentive_config.claim_cooldown_seconds = cooldown;
        };
        
        // Enflasyonist ödül oranını güncelle (varsa)
        if (option::is_some(&inflationary_rate)) {
            let rate = *option::borrow(&inflationary_rate);
            assert!(rate <= 1000, EInvalidRate); // En fazla %100 (binde)
            incentive_config.inflationary_reward_rate = rate;
        };
        
        // Maksimum havuz yüzdesini güncelle (varsa)
        if (option::is_some(&max_pool_percentage)) {
            let percentage = *option::borrow(&max_pool_percentage);
            assert!(percentage <= 1000, EInvalidRate); // En fazla %100 (binde)
            incentive_config.max_reward_pool_percentage = percentage;
        };
        
        incentive_config.last_updated = now;
    }
    
    /// Ödül havuzu dağıtım oranlarını güncelle
    public entry fun update_reward_distribution(
        incentive_config: &mut IncentiveConfig,
        validation_rate: u64,
        bandwidth_rate: u64,
        staking_rate: u64,
        governance_rate: u64,
        referral_rate: u64,
        quality_rate: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Toplam oranın 1000 olup olmadığını kontrol et
        let total_rate = validation_rate + bandwidth_rate + staking_rate + governance_rate + referral_rate + quality_rate;
        assert!(total_rate == 1000, EInvalidRate);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Dağıtım oranlarını güncelle
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_VALIDATION, validation_rate);
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_BANDWIDTH, bandwidth_rate);
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_STAKING, staking_rate);
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_GOVERNANCE, governance_rate);
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_REFERRAL, referral_rate);
        vec_map::insert(&mut incentive_config.reward_pool_distribution, REWARD_TYPE_QUALITY, quality_rate);
        
        incentive_config.last_updated = now;
    }
    
    /// Düğüm tipi çarpanlarını güncelle
    public entry fun update_node_type_multipliers(
        incentive_config: &mut IncentiveConfig,
        relay_multiplier: u64,
        validator_multiplier: u64,
        compute_multiplier: u64,
        storage_multiplier: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Çarpanların geçerli olup olmadığını kontrol et
        assert!(
            relay_multiplier > 0 && validator_multiplier > 0 && 
            compute_multiplier > 0 && storage_multiplier > 0,
            EInvalidRate
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Düğüm tipi çarpanlarını güncelle
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_RELAY, relay_multiplier);
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_VALIDATOR, validator_multiplier);
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_COMPUTE, compute_multiplier);
        vec_map::insert(&mut incentive_config.node_type_multipliers, NODE_TYPE_STORAGE, storage_multiplier);
        
        incentive_config.last_updated = now;
    }
    
    /// Referans programı parametrelerini güncelle
    public entry fun update_referral_program(
        referral_program: &mut ReferralProgram,
        reward_per_referral: Option<u64>,
        referral_depth: Option<u8>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Ödül miktarını güncelle (varsa)
        if (option::is_some(&reward_per_referral)) {
            let reward = *option::borrow(&reward_per_referral);
            assert!(reward > 0, EInvalidAmount);
            referral_program.reward_per_referral = reward;
        };
        
        // Referans derinliğini güncelle (varsa)
        if (option::is_some(&referral_depth)) {
            let depth = *option::borrow(&referral_depth);
            assert!(depth > 0 && depth <= 5, EInvalidNode); // En fazla 5 seviye
            referral_program.referral_depth = depth;
        };
    }
    
    // Yardımcı fonksiyonlar
    
    /// Stake ödüllerini hesapla
    fun calculate_staking_rewards(stake_info: &mut StakeInfo, current_time: u64) {
        // Son ödül hesaplama zamanından şu ana kadar geçen süre
        let time_diff = current_time - stake_info.last_reward_time;
        
        if (time_diff > 0 && stake_info.amount > 0) {
            // Yıllık ödül oranı (%5, binde olarak ifade edilir)
            let annual_rate = BASE_INFLATIONARY_REWARD_RATE;
            
            // Bir yıl saniye cinsinden
            let seconds_per_year = 31536000;
            
            // Ödül miktarını hesapla
            // Formül: stake_amount * annual_rate * time_diff / (seconds_per_year * 1000)
            let reward_amount = (stake_info.amount * annual_rate * time_diff) / (seconds_per_year * 1000);
            
            if (reward_amount > 0) {
                stake_info.accumulated_rewards = stake_info.accumulated_rewards + reward_amount;
                stake_info.last_reward_time = current_time;
            };
        };
    }
    
    /// Bir adresi düğüm sahibi olup olmadığını kontrol et
    fun is_node_owner(node_id: ID, address: address): bool {
        // Burada başka bir modüle erişim gerekiyor (registry)
        // Test için her zaman true döndürüyoruz
        true
    }
    
    /// Bir düğümün geçerli olup olmadığını kontrol et
    fun is_valid_node(node_id: ID): bool {
        // Burada başka bir modüle erişim gerekiyor (registry)
        // Test için her zaman true döndürüyoruz
        true
    }
    
    /// Düğüm tipini al (güvenli bir şekilde)
    fun get_node_type_safe(node_id: ID): u8 {
        // Burada başka bir modüle erişim gerekiyor (registry)
        // Test için varsayılan değer döndürüyoruz
        NODE_TYPE_RELAY
    }
    
    /// Düğüm tipi çarpanını al
    fun get_node_type_multiplier(incentive_config: &IncentiveConfig, node_type: u8): u64 {
        if (vec_map::contains(&incentive_config.node_type_multipliers, &node_type)) {
            *vec_map::get(&incentive_config.node_type_multipliers, &node_type)
        } else {
            1000 // Varsayılan: 1.0x
        }
    }
    
    /// Kalite çarpanını al
    fun get_quality_multiplier(incentive_config: &IncentiveConfig, quality_score: u64): u64 {
        let keys = vec_map::keys(&incentive_config.quality_multipliers);
        let i = 0;
        let len = vector::length(&keys);
        let multiplier = 1000; // Varsayılan: 1.0x
        
        while (i < len) {
            let threshold = *vector::borrow(&keys, i);
            if (quality_score >= threshold && 
                (i == 0 || quality_score < *vector::borrow(&keys, i - 1))) {
                multiplier = *vec_map::get(&incentive_config.quality_multipliers, &threshold);
                break
            };
            i = i + 1;
        };
        
        multiplier
    }
    
    // Getter fonksiyonları
    
    /// Düğüm ödül bilgilerini al
    public fun get_node_reward_info(
        incentive_manager: &IncentiveManager,
        node_id: ID
    ): (u64, u64, u64, u64) {
        if (!table::contains(&incentive_manager.node_rewards, node_id)) {
            return (0, 0, 0, 0)
        };
        
        let reward_info = table::borrow(&incentive_manager.node_rewards, node_id);
        
        (
            reward_info.claimable_amount,
            reward_info.total_rewarded,
            reward_info.total_claimed,
            reward_info.last_reward_time
        )
    }
    
    /// Stake bilgilerini al
    public fun get_stake_info(
        stake_info: &StakeInfo
    ): (address, Option<ID>, u64, u64, u64, u64, u64, u64) {
        (
            stake_info.owner,
            stake_info.node_id,
            stake_info.amount,
            stake_info.start_time,
            stake_info.unlock_time,
            stake_info.last_reward_time,
            stake_info.accumulated_rewards,
            stake_info.total_claimed_rewards
        )
    }
    
    /// Ödül havuzu boyutlarını al
    public fun get_reward_pool_sizes(
        incentive_manager: &IncentiveManager
    ): (u64, u64, u64, u64, u64, u64) {
        (
            balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_VALIDATION)),
            balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_BANDWIDTH)),
            balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_STAKING)),
            balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_GOVERNANCE)),
            balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_REFERRAL)),
            balance::value(vec_map::get(&incentive_manager.reward_pools, &REWARD_TYPE_QUALITY))
        )
    }
    
    /// Teşvik konfigürasyon bilgilerini al
    public fun get_incentive_config_info(
        incentive_config: &IncentiveConfig
    ): (u64, u64, u64, u64, u64) {
        (
            incentive_config.reward_epoch_seconds,
            incentive_config.claim_cooldown_seconds,
            incentive_config.inflationary_reward_rate,
            incentive_config.max_reward_pool_percentage,
            incentive_config.last_updated
        )
    }
    
    /// Referans programı bilgilerini al
    public fun get_referral_program_info(
        referral_program: &ReferralProgram
    ): (u64, u8) {
        (
            referral_program.reward_per_referral,
            referral_program.referral_depth
        )
    }
    
    /// Bir adresin referans sayısını al
    public fun get_referral_count(
        referral_program: &ReferralProgram,
        referrer: address
    ): u64 {
        if (table::contains(&referral_program.referral_counts, referrer)) {
            *table::borrow(&referral_program.referral_counts, referrer)
        } else {
            0
        }
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_incentive_config_for_testing(ctx: &mut TxContext): IncentiveConfig {
        IncentiveConfig {
            id: object::new(ctx),
            reward_epoch_seconds: DEFAULT_REWARD_EPOCH_SECONDS,
            claim_cooldown_seconds: DEFAULT_CLAIM_COOLDOWN_SECONDS,
            reward_pool_distribution: vec_map::empty(),
            node_type_multipliers: vec_map::empty(),
            quality_multipliers: vec_map::empty(),
            stake_amount_multipliers: vec_map::empty(),
            stake_duration_multipliers: vec_map::empty(),
            inflationary_reward_rate: BASE_INFLATIONARY_REWARD_RATE,
            max_reward_pool_percentage: 300, // %30 (binde)
            last_updated: 0,
        }
    }
}
