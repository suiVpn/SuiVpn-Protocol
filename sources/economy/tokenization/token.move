/// SuiVPN Token Module
/// 
/// Bu modül, SuiVPN protokolünün native token'ını (SVPN) uygular.
/// Token ekonomisi, arz ve talep mekanizması, ödül dağıtımı ve token
/// yönetişimi için gerekli yapıları içerir.
module suivpn::token {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID, ID};
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::vec_map::{Self, VecMap};
    use sui::balance::{Self, Balance};
    use std::vector;
    use std::string::{Self, String};
    use std::option::{Self, Option};
    use suivpn::governance::{Self, GovernanceCapability};
    
    /// SVPN token tipi
    struct SVPN has drop {}
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInsufficientFunds: u64 = 1;
    const EInvalidAmount: u64 = 2;
    const EInvalidParameter: u64 = 3;
    const EInvalidDestination: u64 = 4;
    const EInvalidMintLimit: u64 = 5;
    const EInvalidBurnRate: u64 = 6;
    const EInvalidStake: u64 = 7;
    const EMaxSupplyReached: u64 = 8;
    const EInvalidVestingSchedule: u64 = 9;
    const EInvalidUnlock: u64 = 10;
    const EDuplicateEntry: u64 = 11;
    
    // Dağıtım kategorileri
    const DISTRIBUTION_TEAM: u8 = 0;
    const DISTRIBUTION_ICO: u8 = 1;
    const DISTRIBUTION_ECOSYSTEM: u8 = 2;
    const DISTRIBUTION_LIQUIDITY: u8 = 3;
    const DISTRIBUTION_TREASURY: u8 = 4;
    const DISTRIBUTION_COMMUNITY: u8 = 5;
    const DISTRIBUTION_VALIDATOR_REWARDS: u8 = 6;
    
    // Sabitler
    const MAX_SUPPLY: u64 = 1_000_000_000_000_000_000; // 1 milyar SVPN (1e9 * 1e9)
    const INITIAL_SUPPLY: u64 = 250_000_000_000_000_000; // 250 milyon SVPN
    const DECIMALS: u8 = 9;
    
    /// Token Konfigürasyonu
    /// Token ekonomisinin parametrelerini içerir
    struct TokenConfig has key, store {
        id: UID,
        // Maksimum token arzı
        max_supply: u64,
        // Güncel tedavüldeki token arzı
        circulating_supply: u64,
        // Toplam basılmış token miktarı
        total_minted: u64,
        // Toplam yakılmış token miktarı
        total_burned: u64,
        // İşlem ücreti oranı (binde)
        transaction_fee_rate: u64,
        // İşlem ücretlerinden yakma oranı (binde)
        burn_rate: u64,
        // Hazine oranı (binde)
        treasury_rate: u64,
        // Validator ödül oranı (binde)
        validator_reward_rate: u64,
        // Güvenlik fonu oranı (binde)
        security_fund_rate: u64,
        // Hazine adresi
        treasury_address: address,
        // Güvenlik fonu adresi
        security_fund_address: address,
        // Token adı
        name: String,
        // Token sembolü
        symbol: String,
        // Ondalık hanesi
        decimals: u8,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Token Dağıtım Planı
    /// Token'ların nasıl dağıtılacağını tanımlar
    struct DistributionPlan has key, store {
        id: UID,
        // Dağıtım kategorileri ve tahsisler (kategori -> (miktar, kilitli miktar))
        allocations: VecMap<u8, AllocationInfo>,
        // Kategori bazlı kilitli tokenlar ve vesting planları
        vesting_schedules: VecMap<u8, VestingSchedule>,
        // Toplam dağıtım miktarı
        total_allocation: u64,
        // Toplam serbest bırakılan miktar
        total_released: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Tahsis Bilgisi
    /// Bir kategori için token tahsisini içerir
    struct AllocationInfo has store, copy, drop {
        // Toplam tahsis miktarı
        total_amount: u64,
        // Kilitli miktar
        locked_amount: u64,
        // Serbest bırakılan miktar
        released_amount: u64,
        // Son serbest bırakılma zamanı
        last_release_time: u64,
    }
    
    /// Vesting Takvimi
    /// Token'ların zaman içinde nasıl serbest bırakılacağını tanımlar
    struct VestingSchedule has store, copy, drop {
        // Başlangıç zamanı
        start_time: u64,
        // Toplam süre (saniye)
        duration: u64,
        // Cliff süresi (saniye)
        cliff_duration: u64,
        // Ödeme periyodu (saniye)
        release_period: u64,
        // Başlangıçta serbest olan oran (binde)
        initial_release_pct: u64,
        // Token konu edildiği düğüm staking gereksinimi
        staking_requirement: bool,
    }
    
    /// Stake Havuzu
    /// Staking için kullanılan tokenları içerir
    struct StakePool has key {
        id: UID,
        // Stake edilmiş tokenlerin toplamı
        total_staked: Balance<SVPN>,
        // Kullanıcı bazlı stake miktarları
        stakes: Table<address, StakeInfo>,
        // Ödül havuzu
        reward_pool: Balance<SVPN>,
        // Toplam staker sayısı
        total_stakers: u64,
        // Yıllık ödül oranı (yüzde, binde)
        annual_reward_rate: u64,
        // Minimum stake süresi (saniye)
        min_stake_duration: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Stake Bilgisi
    /// Bir kullanıcının stake bilgilerini içerir
    struct StakeInfo has store {
        // Stake edilen miktar
        amount: u64,
        // Stake başlangıç zamanı
        start_time: u64,
        // Unlock zamanı (varsa)
        unlock_time: Option<u64>,
        // Son ödül hesaplama zamanı
        last_reward_time: u64,
        // Birikmiş ödüller
        pending_rewards: u64,
        // Toplam alınan ödüller
        total_rewards: u64,
    }
    
    // Eventler
    
    /// Token mint eventi
    struct TokenMinted has copy, drop {
        amount: u64,
        destination: address,
        category: u8,
        time: u64,
    }
    
    /// Token yakma eventi
    struct TokenBurned has copy, drop {
        amount: u64,
        source: address,
        reason: String,
        time: u64,
    }
    
    /// Dağıtım eventi
    struct TokenDistributed has copy, drop {
        category: u8,
        amount: u64,
        destination: address,
        time: u64,
    }
    
    /// Stake eventi
    struct TokenStaked has copy, drop {
        staker: address,
        amount: u64,
        time: u64,
    }
    
    /// Unstake eventi
    struct TokenUnstaked has copy, drop {
        staker: address,
        amount: u64,
        time: u64,
    }
    
    /// Ödül talep eventi
    struct RewardsClaimed has copy, drop {
        staker: address,
        amount: u64,
        time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        // SVPN token'ı oluştur
        let (treasury_cap, metadata) = coin::create_currency(
            SVPN {},
            DECIMALS,
            b"SuiVPN Token",
            b"SVPN",
            b"Privacy-preserving decentralized VPN network token",
            option::none(),
            ctx
        );
        
        let sender = tx_context::sender(ctx);
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000; // MS to seconds
        
        // Token konfigürasyonu oluştur
        let token_config = TokenConfig {
            id: object::new(ctx),
            max_supply: MAX_SUPPLY,
            circulating_supply: 0,
            total_minted: 0,
            total_burned: 0,
            transaction_fee_rate: 20, // %2 (binde)
            burn_rate: 200, // %20 (binde)
            treasury_rate: 150, // %15 (binde)
            validator_reward_rate: 600, // %60 (binde)
            security_fund_rate: 50, // %5 (binde)
            treasury_address: sender,
            security_fund_address: sender,
            name: string::utf8(b"SuiVPN Token"),
            symbol: string::utf8(b"SVPN"),
            decimals: DECIMALS,
            last_updated: now,
        };
        
        // Dağıtım planı oluştur
        let distribution_plan = DistributionPlan {
            id: object::new(ctx),
            allocations: vec_map::empty(),
            vesting_schedules: vec_map::empty(),
            total_allocation: MAX_SUPPLY,
            total_released: 0,
            last_updated: now,
        };
        
        // Dağıtım kategorileri ve tahsislerini ayarla (1 milyar token)
        // Takım: %18
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_TEAM,
            180_000_000_000_000_000,
            now,
            ctx
        );
        // ICO: %15
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_ICO,
            150_000_000_000_000_000,
            now,
            ctx
        );
        // Ekosistem geliştirme: %20
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_ECOSYSTEM,
            200_000_000_000_000_000,
            now,
            ctx
        );
        // Likidite: %12
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_LIQUIDITY,
            120_000_000_000_000_000,
            now,
            ctx
        );
        // Hazine: %15
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_TREASURY,
            150_000_000_000_000_000,
            now,
            ctx
        );
        // Topluluk: %10
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_COMMUNITY,
            100_000_000_000_000_000,
            now,
            ctx
        );
        // Validator ödülleri: %10
        create_allocation(
            &mut distribution_plan,
            DISTRIBUTION_VALIDATOR_REWARDS,
            100_000_000_000_000_000,
            now,
            ctx
        );
        
        // Vesting takvimlerini ayarla
        // Takım: 4 yıl vesting, 1 yıl cliff
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_TEAM,
            now,
            126144000, // 4 yıl (saniye)
            31536000, // 1 yıl cliff (saniye)
            2592000, // Aylık serbest bırakma (saniye)
            0, // Başlangıçta serbest: %0
            true, // Staking gerektirir
            ctx
        );
        
        // ICO: 2 yıl vesting, 3 ay cliff
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_ICO,
            now,
            63072000, // 2 yıl (saniye)
            7776000, // 3 ay cliff (saniye)
            2592000, // Aylık serbest bırakma (saniye)
            100, // Başlangıçta serbest: %10 (binde)
            false, // Staking gerektirmez
            ctx
        );
        
        // Ekosistem: 3 yıl vesting, 6 ay cliff
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_ECOSYSTEM,
            now,
            94608000, // 3 yıl (saniye)
            15552000, // 6 ay cliff (saniye)
            2592000, // Aylık serbest bırakma (saniye)
            50, // Başlangıçta serbest: %5 (binde)
            true, // Staking gerektirir
            ctx
        );
        
        // Likidite: 1 yıl vesting, cliff yok
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_LIQUIDITY,
            now,
            31536000, // 1 yıl (saniye)
            0, // Cliff yok
            2592000, // Aylık serbest bırakma (saniye)
            200, // Başlangıçta serbest: %20 (binde)
            false, // Staking gerektirmez
            ctx
        );
        
        // Hazine: 5 yıl vesting, cliff yok
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_TREASURY,
            now,
            157680000, // 5 yıl (saniye)
            0, // Cliff yok
            2592000, // Aylık serbest bırakma (saniye)
            50, // Başlangıçta serbest: %5 (binde)
            false, // Staking gerektirmez
            ctx
        );
        
        // Topluluk: 2 yıl vesting, cliff yok
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_COMMUNITY,
            now,
            63072000, // 2 yıl (saniye)
            0, // Cliff yok
            2592000, // Aylık serbest bırakma (saniye)
            100, // Başlangıçta serbest: %10 (binde)
            false, // Staking gerektirmez
            ctx
        );
        
        // Validator ödülleri: 5 yıl vesting, cliff yok
        set_vesting_schedule(
            &mut distribution_plan,
            DISTRIBUTION_VALIDATOR_REWARDS,
            now,
            157680000, // 5 yıl (saniye)
            0, // Cliff yok
            2592000, // Aylık serbest bırakma (saniye)
            100, // Başlangıçta serbest: %10 (binde)
            true, // Staking gerektirir
            ctx
        );
        
        // StakePool oluştur
        let stake_pool = StakePool {
            id: object::new(ctx),
            total_staked: balance::zero(),
            stakes: table::new(ctx),
            reward_pool: balance::zero(),
            total_stakers: 0,
            annual_reward_rate: 100, // %10 yıllık ödül (binde)
            min_stake_duration: 2592000, // 30 gün (saniye)
            last_updated: now,
        };
        
        // Başlangıç token miktarını mint et
        let initial_supply = mint_initial_tokens(&treasury_cap, distribution_plan, ctx);
        
        // Konfigürasyonu kaydet (circulating_supply ve total_minted güncellenir)
        token_config.circulating_supply = initial_supply;
        token_config.total_minted = initial_supply;
        
        // Nesneleri paylaş
        transfer::public_transfer(treasury_cap, sender);
        transfer::public_transfer(metadata, sender);
        transfer::share_object(token_config);
        transfer::share_object(stake_pool);
    }
    
    /// Başlangıç tokenlarını mint et
    fun mint_initial_tokens(
        treasury_cap: &TreasuryCap<SVPN>,
        distribution_plan: DistributionPlan,
        ctx: &mut TxContext
    ): u64 {
        let sender = tx_context::sender(ctx);
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        let initial_supply = 0;
        
        // Dağıtım planı ve yetkileri paylaş
        transfer::share_object(distribution_plan);
        
        // Başlangıç arzını hesapla ve döndür
        initial_supply
    }
    
    /// Allocation oluştur (modül başlatma için yardımcı fonksiyon)
    fun create_allocation(
        distribution_plan: &mut DistributionPlan,
        category: u8,
        amount: u64,
        now: u64,
        ctx: &mut TxContext
    ) {
        let allocation = AllocationInfo {
            total_amount: amount,
            locked_amount: amount,
            released_amount: 0,
            last_release_time: now,
        };
        
        vec_map::insert(&mut distribution_plan.allocations, category, allocation);
    }
    
    /// Vesting takvimi ayarla (modül başlatma için yardımcı fonksiyon)
    fun set_vesting_schedule(
        distribution_plan: &mut DistributionPlan,
        category: u8,
        start_time: u64,
        duration: u64,
        cliff_duration: u64,
        release_period: u64,
        initial_release_pct: u64,
        staking_requirement: bool,
        ctx: &mut TxContext
    ) {
        let schedule = VestingSchedule {
            start_time,
            duration,
            cliff_duration,
            release_period,
            initial_release_pct,
            staking_requirement,
        };
        
        vec_map::insert(&mut distribution_plan.vesting_schedules, category, schedule);
        
        // Başlangıçta serbest bırakılacak miktar
        if (initial_release_pct > 0) {
            let allocation = vec_map::get_mut(&mut distribution_plan.allocations, &category);
            let initial_release = (allocation.total_amount * initial_release_pct) / 1000;
            
            allocation.locked_amount = allocation.locked_amount - initial_release;
            allocation.released_amount = allocation.released_amount + initial_release;
            distribution_plan.total_released = distribution_plan.total_released + initial_release;
        };
    }
    
    /// Token mint et
    public entry fun mint_tokens(
        treasury_cap: &mut TreasuryCap<SVPN>,
        token_config: &mut TokenConfig,
        amount: u64,
        destination: address,
        category: u8,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        // Mint edilecek miktarın geçerli olup olmadığını kontrol et
        assert!(amount > 0, EInvalidAmount);
        
        // Maksimum arzı aşıp aşmadığını kontrol et
        let new_total = token_config.total_minted + amount;
        assert!(new_total <= token_config.max_supply, EMaxSupplyReached);
        
        // Kategori geçerli mi?
        assert!(
            category == DISTRIBUTION_TEAM ||
            category == DISTRIBUTION_ICO ||
            category == DISTRIBUTION_ECOSYSTEM ||
            category == DISTRIBUTION_LIQUIDITY ||
            category == DISTRIBUTION_TREASURY ||
            category == DISTRIBUTION_COMMUNITY ||
            category == DISTRIBUTION_VALIDATOR_REWARDS,
            EInvalidParameter
        );
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        // Token mint et
        let minted_coin = coin::mint(treasury_cap, amount, ctx);
        
        // Token konfigürasyonunu güncelle
        token_config.total_minted = new_total;
        token_config.circulating_supply = token_config.circulating_supply + amount;
        token_config.last_updated = now;
        
        // Tokenları hedefe gönder
        transfer::public_transfer(minted_coin, destination);
        
        // Mint eventini yayınla
        event::emit(TokenMinted {
            amount,
            destination,
            category,
            time: now,
        });
    }
    
    /// Token yak
    public entry fun burn_tokens(
        token_config: &mut TokenConfig,
        burn_coin: Coin<SVPN>,
        reason: vector<u8>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let amount = coin::value(&burn_coin);
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        // Tokenları yak
        coin::burn(burn_coin);
        
        // Token konfigürasyonunu güncelle
        token_config.total_burned = token_config.total_burned + amount;
        token_config.circulating_supply = token_config.circulating_supply - amount;
        token_config.last_updated = now;
        
        // Yakma eventini yayınla
        event::emit(TokenBurned {
            amount,
            source: sender,
            reason: string::utf8(reason),
            time: now,
        });
    }
    
    /// Token stake et
    public entry fun stake_tokens(
        stake_pool: &mut StakePool,
        stake_coin: Coin<SVPN>,
        lock_duration: Option<u64>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let amount = coin::value(&stake_coin);
        
        // Stake miktarının geçerli olup olmadığını kontrol et
        assert!(amount > 0, EInvalidAmount);
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        // Eğer kullanıcı zaten stake ettiyse, mevcut stake'i güncelle
        if (table::contains(&stake_pool.stakes, sender)) {
            let stake_info = table::borrow_mut(&mut stake_pool.stakes, sender);
            
            // Önce birikmiş ödülleri hesapla
            calculate_rewards(stake_pool, stake_info, now);
            
            // Stake miktarını artır
            stake_info.amount = stake_info.amount + amount;
            stake_info.start_time = now;
            
            // Unlock zamanını ayarla (varsa)
            if (option::is_some(&lock_duration)) {
                let duration = *option::borrow(&lock_duration);
                assert!(duration >= stake_pool.min_stake_duration, EInvalidStake);
                stake_info.unlock_time = option::some(now + duration);
            } else {
                stake_info.unlock_time = option::some(now + stake_pool.min_stake_duration);
            };
        } else {
            // Yeni stake bilgisi oluştur
            let unlock_time = if (option::is_some(&lock_duration)) {
                let duration = *option::borrow(&lock_duration);
                assert!(duration >= stake_pool.min_stake_duration, EInvalidStake);
                option::some(now + duration)
            } else {
                option::some(now + stake_pool.min_stake_duration)
            };
            
            let stake_info = StakeInfo {
                amount,
                start_time: now,
                unlock_time,
                last_reward_time: now,
                pending_rewards: 0,
                total_rewards: 0,
            };
            
            table::add(&mut stake_pool.stakes, sender, stake_info);
            stake_pool.total_stakers = stake_pool.total_stakers + 1;
        };
        
        // Tokenleri stake havuzuna ekle
        balance::join(&mut stake_pool.total_staked, coin::into_balance(stake_coin));
        stake_pool.last_updated = now;
        
        // Stake eventini yayınla
        event::emit(TokenStaked {
            staker: sender,
            amount,
            time: now,
        });
    }
    
    /// Stake'i çöz
    public entry fun unstake_tokens(
        stake_pool: &mut StakePool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Kullanıcının stake bilgisi var mı?
        assert!(table::contains(&stake_pool.stakes, sender), EInvalidStake);
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        let stake_info = table::borrow_mut(&mut stake_pool.stakes, sender);
        
        // Unstake miktarının geçerli olup olmadığını kontrol et
        assert!(amount > 0 && amount <= stake_info.amount, EInvalidAmount);
        
        // Unlock zamanını kontrol et
        if (option::is_some(&stake_info.unlock_time)) {
            let unlock_time = *option::borrow(&stake_info.unlock_time);
            assert!(now >= unlock_time, EInvalidUnlock);
        };
        
        // Birikmiş ödülleri hesapla
        calculate_rewards(stake_pool, stake_info, now);
        
        // Stake miktarını güncelle
        stake_info.amount = stake_info.amount - amount;
        
        // Tokenları kullanıcıya gönder
        let unstaked_coin = coin::from_balance(balance::split(&mut stake_pool.total_staked, amount), ctx);
        transfer::public_transfer(unstaked_coin, sender);
        
        // Eğer kalan miktar sıfırsa, stake bilgisini sil
        if (stake_info.amount == 0) {
            // Kalan ödülleri aktar
            if (stake_info.pending_rewards > 0) {
                let rewards_coin = coin::from_balance(balance::split(&mut stake_pool.reward_pool, stake_info.pending_rewards), ctx);
                transfer::public_transfer(rewards_coin, sender);
                
                // Ödül talep eventini yayınla
                event::emit(RewardsClaimed {
                    staker: sender,
                    amount: stake_info.pending_rewards,
                    time: now,
                });
                
                stake_info.total_rewards = stake_info.total_rewards + stake_info.pending_rewards;
                stake_info.pending_rewards = 0;
            };
            
            // Stake bilgisini sil ve staker sayısını azalt
            table::remove(&mut stake_pool.stakes, sender);
            stake_pool.total_stakers = stake_pool.total_stakers - 1;
        };
        
        stake_pool.last_updated = now;
        
        // Unstake eventini yayınla
        event::emit(TokenUnstaked {
            staker: sender,
            amount,
            time: now,
        });
    }
    
    /// Ödülleri talep et
    public entry fun claim_rewards(
        stake_pool: &mut StakePool,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Kullanıcının stake bilgisi var mı?
        assert!(table::contains(&stake_pool.stakes, sender), EInvalidStake);
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        let stake_info = table::borrow_mut(&mut stake_pool.stakes, sender);
        
        // Birikmiş ödülleri hesapla
        calculate_rewards(stake_pool, stake_info, now);
        
        // Eğer talep edilecek ödül varsa, aktar
        assert!(stake_info.pending_rewards > 0, EInsufficientFunds);
        
        let reward_amount = stake_info.pending_rewards;
        let rewards_coin = coin::from_balance(balance::split(&mut stake_pool.reward_pool, reward_amount), ctx);
        
        stake_info.total_rewards = stake_info.total_rewards + reward_amount;
        stake_info.pending_rewards = 0;
        stake_info.last_reward_time = now;
        
        transfer::public_transfer(rewards_coin, sender);
        stake_pool.last_updated = now;
        
        // Ödül talep eventini yayınla
        event::emit(RewardsClaimed {
            staker: sender,
            amount: reward_amount,
            time: now,
        });
    }
    
    /// Ödül havuzuna token ekle
    public entry fun add_to_reward_pool(
        stake_pool: &mut StakePool,
        reward_coin: Coin<SVPN>,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(&reward_coin);
        
        // Miktar kontrolü
        assert!(amount > 0, EInvalidAmount);
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        // Tokenları ödül havuzuna ekle
        balance::join(&mut stake_pool.reward_pool, coin::into_balance(reward_coin));
        stake_pool.last_updated = now;
    }
    
    /// Yıllık ödül oranını güncelle
    public entry fun update_annual_reward_rate(
        stake_pool: &mut StakePool,
        new_rate: u64,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        // Oran kontrolü
        assert!(new_rate <= 1000, EInvalidParameter); // Max %100 (binde)
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        stake_pool.annual_reward_rate = new_rate;
        stake_pool.last_updated = now;
    }
    
    /// Minimum stake süresini güncelle
    public entry fun update_min_stake_duration(
        stake_pool: &mut StakePool,
        new_duration: u64,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        stake_pool.min_stake_duration = new_duration;
        stake_pool.last_updated = now;
    }
    
    /// İşlem ücreti oranını güncelle
    public entry fun update_transaction_fee_rate(
        token_config: &mut TokenConfig,
        new_rate: u64,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        // Oran kontrolü
        assert!(new_rate <= 100, EInvalidParameter); // Max %10 (binde)
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        token_config.transaction_fee_rate = new_rate;
        token_config.last_updated = now;
    }
    
    /// Yakma oranını güncelle
    public entry fun update_burn_rate(
        token_config: &mut TokenConfig,
        new_rate: u64,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        // Oran kontrolü
        assert!(new_rate <= 1000, EInvalidParameter); // Max %100 (binde)
        
        // Toplam oran kontrolü
        let total_rate = new_rate + token_config.treasury_rate + token_config.validator_reward_rate + token_config.security_fund_rate;
        assert!(total_rate <= 1000, EInvalidBurnRate);
        
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        token_config.burn_rate = new_rate;
        token_config.last_updated = now;
    }
    
    /// Hazine adresini güncelle
    public entry fun update_treasury_address(
        token_config: &mut TokenConfig,
        new_address: address,
        governance_cap: &GovernanceCapability,
        ctx: &mut TxContext
    ) {
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        token_config.treasury_address = new_address;
        token_config.last_updated = now;
    }
    
    // Yardımcı fonksiyonlar
    
    /// Birikmiş ödülleri hesapla
    fun calculate_rewards(
        stake_pool: &StakePool,
        stake_info: &mut StakeInfo,
        current_time: u64
    ) {
        // Ödül hesaplama süresi
        let reward_period = current_time - stake_info.last_reward_time;
        
        if (reward_period > 0 && stake_info.amount > 0) {
            // Yıllık ödül oranı bazında ödül hesapla
            // Örneğin: %10 yıllık ödül için, günlük ödül = stake_amount * 0.1 / 365
            let annual_seconds = 31536000; // 365 gün (saniye)
            let reward_amount = (stake_info.amount * stake_pool.annual_reward_rate * reward_period) / (annual_seconds * 1000);
            
            if (reward_amount > 0) {
                stake_info.pending_rewards = stake_info.pending_rewards + reward_amount;
            };
            
            stake_info.last_reward_time = current_time;
        };
    }
    
    // Getter fonksiyonları
    
    /// Token bilgilerini al
    public fun get_token_info(
        token_config: &TokenConfig
    ): (u64, u64, u64, u64, String, String, u8) {
        (
            token_config.max_supply,
            token_config.circulating_supply,
            token_config.total_minted,
            token_config.total_burned,
            token_config.name,
            token_config.symbol,
            token_config.decimals
        )
    }
    
    /// İşlem ücreti bilgilerini al
    public fun get_fee_rates(
        token_config: &TokenConfig
    ): (u64, u64, u64, u64, u64) {
        (
            token_config.transaction_fee_rate,
            token_config.burn_rate,
            token_config.treasury_rate,
            token_config.validator_reward_rate,
            token_config.security_fund_rate
        )
    }
    
    /// Stake bilgisini al
    public fun get_stake_info(
        stake_pool: &StakePool,
        staker: address
    ): (u64, u64, Option<u64>, u64, u64) {
        assert!(table::contains(&stake_pool.stakes, staker), EInvalidStake);
        
        let stake_info = table::borrow(&stake_pool.stakes, staker);
        
        (
            stake_info.amount,
            stake_info.start_time,
            stake_info.unlock_time,
            stake_info.pending_rewards,
            stake_info.total_rewards
        )
    }
    
    /// Stake havuzu bilgilerini al
    public fun get_stake_pool_info(
        stake_pool: &StakePool
    ): (u64, u64, u64, u64, u64) {
        (
            balance::value(&stake_pool.total_staked),
            balance::value(&stake_pool.reward_pool),
            stake_pool.total_stakers,
            stake_pool.annual_reward_rate,
            stake_pool.min_stake_duration
        )
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_token_for_testing(ctx: &mut TxContext): (TreasuryCap<SVPN>, TokenConfig) {
        let (treasury_cap, metadata) = coin::create_currency(
            SVPN {},
            DECIMALS,
            b"SuiVPN Token",
            b"SVPN",
            b"Privacy-preserving decentralized VPN network token",
            option::none(),
            ctx
        );
        
        let sender = tx_context::sender(ctx);
        let now = tx_context::epoch_timestamp_ms(ctx) / 1000;
        
        let token_config = TokenConfig {
            id: object::new(ctx),
            max_supply: MAX_SUPPLY,
            circulating_supply: 0,
            total_minted: 0,
            total_burned: 0,
            transaction_fee_rate: 20, // %2 (binde)
            burn_rate: 200, // %20 (binde)
            treasury_rate: 150, // %15 (binde)
            validator_reward_rate: 600, // %60 (binde)
            security_fund_rate: 50, // %5 (binde)
            treasury_address: sender,
            security_fund_address: sender,
            name: string::utf8(b"SuiVPN Token"),
            symbol: string::utf8(b"SVPN"),
            decimals: DECIMALS,
            last_updated: now,
        };
        
        transfer::public_transfer(metadata, sender);
        
        (treasury_cap, token_config)
    }
}
