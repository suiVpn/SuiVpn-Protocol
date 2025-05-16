/// SuiVPN Dynamic Pricing Module
///
/// Bu modül, SuiVPN protokolünün dinamik fiyatlandırma mekanizmasını uygular.
/// Arz-talep dengesi, ağ yoğunluğu, düğüm kalitesi ve diğer faktörlere bağlı olarak
/// gerçek zamanlı fiyatlandırma optimize edilir. Bu, ağın verimli kullanımını teşvik eder
/// ve hem kullanıcılar hem de düğüm operatörleri için adil bir pazar oluşturur.
module suivpn::dynamic_pricing {
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
    use suivpn::token::{Self, SVPN};
    use suivpn::registry::{Self, NodeInfo};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidPrice: u64 = 1;
    const EInvalidParameter: u64 = 2;
    const EInvalidModel: u64 = 3;
    const EInvalidRegion: u64 = 4;
    const EPriceRangeViolation: u64 = 5;
    const ERateChangeViolation: u64 = 6;
    const EInvalidNode: u64 = 7;
    const EInvalidOffer: u64 = 8;
    const EInvalidFactor: u64 = 9;
    
    // Fiyatlandırma modelleri
    const PRICING_MODEL_LINEAR: u8 = 0;
    const PRICING_MODEL_EXPONENTIAL: u8 = 1;
    const PRICING_MODEL_SIGMOID: u8 = 2;
    const PRICING_MODEL_CUSTOM: u8 = 3;
    
    // Talep faktörleri
    const DEMAND_FACTOR_USERS: u8 = 0;
    const DEMAND_FACTOR_BANDWIDTH: u8 = 1;
    const DEMAND_FACTOR_TIME: u8 = 2;
    const DEMAND_FACTOR_REGION: u8 = 3;
    
    // Arz faktörleri
    const SUPPLY_FACTOR_NODES: u8 = 0;
    const SUPPLY_FACTOR_CAPACITY: u8 = 1;
    const SUPPLY_FACTOR_QUALITY: u8 = 2;
    
    // Sabitler
    const DEFAULT_BASE_PRICE: u64 = 1_000_000; // 0.001 SVPN tokeni (1e9 decimals)
    const DEFAULT_MIN_PRICE: u64 = 500_000; // 0.0005 SVPN tokeni
    const DEFAULT_MAX_PRICE: u64 = 10_000_000_000; // 10 SVPN tokeni
    const DEFAULT_PRICE_UPDATE_INTERVAL: u64 = 3600; // 1 saat (saniye)
    const DEFAULT_MAX_RATE_CHANGE: u64 = 200; // %20 (binde)
    
    /// Fiyatlandırma konfigürasyonu
    /// Dinamik fiyatlandırma sistemi için temel parametreleri içerir
    struct PricingConfig has key, store {
        id: UID,
        // Temel fiyat (SVPN/GB)
        base_price: u64,
        // Minimum fiyat (SVPN/GB)
        min_price: u64,
        // Maksimum fiyat (SVPN/GB)
        max_price: u64,
        // Fiyat güncelleme aralığı (saniye)
        price_update_interval: u64,
        // Maksimum fiyat değişim oranı (binde)
        max_rate_change: u64,
        // Varsayılan fiyatlandırma modeli
        default_pricing_model: u8,
        // Fiyatlandırma faktörleri ve ağırlıkları
        demand_factors: VecMap<u8, u64>,
        supply_factors: VecMap<u8, u64>,
        // Bölge bazlı fiyat çarpanları
        region_multipliers: VecMap<u8, u64>,
        // Fiyatlandırma modeli parametreleri
        model_parameters: VecMap<String, u64>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Pazar Analitiği
    /// Arz-talep durumu ve pazar metrikleri hakkında bilgi içerir
    struct MarketAnalytics has key {
        id: UID,
        // Toplam aktif kullanıcı sayısı
        total_active_users: u64,
        // Toplam aktif düğüm sayısı
        total_active_nodes: u64,
        // Toplam bant genişliği kullanımı (GB)
        total_bandwidth_usage: u64,
        // Bölge bazlı kullanıcı dağılımı
        user_distribution: VecMap<u8, u64>,
        // Bölge bazlı düğüm dağılımı
        node_distribution: VecMap<u8, u64>,
        // Saatlik ortalama fiyatlar
        hourly_avg_prices: vector<u64>,
        // Günlük ortalama fiyatlar
        daily_avg_prices: vector<u64>,
        // Talep tahmini (gelecek 24 saat)
        demand_forecast: vector<u64>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Düğüm Fiyatlandırması
    /// Bir düğümün fiyatlandırma bilgilerini içerir
    struct NodePricing has key, store {
        id: UID,
        // Düğüm ID'si
        node_id: ID,
        // Düğüm sahibi
        owner: address,
        // Mevcut fiyat (SVPN/GB)
        current_price: u64,
        // Minimum fiyat (SVPN/GB)
        min_price: u64,
        // Maksimum fiyat (SVPN/GB)
        max_price: u64,
        // Fiyatlandırma stratejisi
        pricing_strategy: u8,
        // Özel fiyatlandırma parametreleri
        custom_parameters: Option<VecMap<String, u64>>,
        // Dinamik fiyatlandırma aktif mi?
        dynamic_pricing_enabled: bool,
        // İndirim oranları (kalabalık saatler dışı, yüksek hacim vb.)
        discount_rates: VecMap<String, u64>,
        // Son fiyat güncellemesi
        last_price_update: u64,
        // Fiyat geçmişi (son 24 saat)
        price_history: vector<u64>,
    }
    
    /// Fiyat Teklifi
    /// Bir düğümün zaman ve fiyat bazlı teklif bilgilerini içerir
    struct PriceOffer has key, store {
        id: UID,
        // Teklif sahibi düğüm
        node_id: ID,
        // Başlangıç zamanı
        start_time: u64,
        // Bitiş zamanı
        end_time: u64,
        // Teklif fiyatı (SVPN/GB)
        price: u64,
        // Maksimum bant genişliği (GB)
        max_bandwidth: u64,
        // Kalan bant genişliği (GB)
        remaining_bandwidth: u64,
        // Teklif aktif mi?
        is_active: bool,
        // Teklif şartları
        terms: Option<String>,
        // Oluşturma zamanı
        created_at: u64,
    }
    
    // Eventler
    
    /// Fiyat güncelleme eventi
    struct PriceUpdated has copy, drop {
        node_id: ID,
        old_price: u64,
        new_price: u64,
        update_time: u64,
    }
    
    /// Pazar analitiği güncelleme eventi
    struct MarketAnalyticsUpdated has copy, drop {
        total_users: u64,
        total_nodes: u64,
        avg_price: u64,
        update_time: u64,
    }
    
    /// Teklif oluşturma eventi
    struct OfferCreated has copy, drop {
        offer_id: ID,
        node_id: ID,
        price: u64,
        max_bandwidth: u64,
        start_time: u64,
        end_time: u64,
    }
    
    /// Teklif güncelleme eventi
    struct OfferUpdated has copy, drop {
        offer_id: ID,
        old_price: u64,
        new_price: u64,
        remaining_bandwidth: u64,
        update_time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let pricing_config = PricingConfig {
            id: object::new(ctx),
            base_price: DEFAULT_BASE_PRICE,
            min_price: DEFAULT_MIN_PRICE,
            max_price: DEFAULT_MAX_PRICE,
            price_update_interval: DEFAULT_PRICE_UPDATE_INTERVAL,
            max_rate_change: DEFAULT_MAX_RATE_CHANGE,
            default_pricing_model: PRICING_MODEL_LINEAR,
            demand_factors: vec_map::empty(),
            supply_factors: vec_map::empty(),
            region_multipliers: vec_map::empty(),
            model_parameters: vec_map::empty(),
            last_updated: 0,
        };
        
        // Talep faktörlerini ayarla (ağırlıkların toplamı 1000)
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_USERS, 400); // %40
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_BANDWIDTH, 300); // %30
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_TIME, 200); // %20
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_REGION, 100); // %10
        
        // Arz faktörlerini ayarla (ağırlıkların toplamı 1000)
        vec_map::insert(&mut pricing_config.supply_factors, SUPPLY_FACTOR_NODES, 500); // %50
        vec_map::insert(&mut pricing_config.supply_factors, SUPPLY_FACTOR_CAPACITY, 300); // %30
        vec_map::insert(&mut pricing_config.supply_factors, SUPPLY_FACTOR_QUALITY, 200); // %20
        
        // Bölge çarpanlarını ayarla (binde, 1000 = 1x çarpan)
        // Bölge ID'leri registry modülünden alınmıştır
        // 1: Kuzey Amerika, 2: Güney Amerika, 3: Avrupa, 4: Afrika, 5: Asya, 6: Okyanusya
        vec_map::insert(&mut pricing_config.region_multipliers, 1, 1000); // Kuzey Amerika: 1x
        vec_map::insert(&mut pricing_config.region_multipliers, 2, 800); // Güney Amerika: 0.8x
        vec_map::insert(&mut pricing_config.region_multipliers, 3, 1100); // Avrupa: 1.1x
        vec_map::insert(&mut pricing_config.region_multipliers, 4, 750); // Afrika: 0.75x
        vec_map::insert(&mut pricing_config.region_multipliers, 5, 950); // Asya: 0.95x
        vec_map::insert(&mut pricing_config.region_multipliers, 6, 900); // Okyanusya: 0.9x
        
        // Model parametrelerini ayarla
        vec_map::insert(&mut pricing_config.model_parameters, string::utf8(b"linear_slope"), 100); // 0.1
        vec_map::insert(&mut pricing_config.model_parameters, string::utf8(b"exponential_base"), 1100); // 1.1
        vec_map::insert(&mut pricing_config.model_parameters, string::utf8(b"sigmoid_steepness"), 500); // 0.5
        
        let market_analytics = MarketAnalytics {
            id: object::new(ctx),
            total_active_users: 0,
            total_active_nodes: 0,
            total_bandwidth_usage: 0,
            user_distribution: vec_map::empty(),
            node_distribution: vec_map::empty(),
            hourly_avg_prices: vector::empty(),
            daily_avg_prices: vector::empty(),
            demand_forecast: vector::empty(),
            last_updated: 0,
        };
        
        // Bölge dağılımlarını başlat
        vec_map::insert(&mut market_analytics.user_distribution, 1, 0);
        vec_map::insert(&mut market_analytics.user_distribution, 2, 0);
        vec_map::insert(&mut market_analytics.user_distribution, 3, 0);
        vec_map::insert(&mut market_analytics.user_distribution, 4, 0);
        vec_map::insert(&mut market_analytics.user_distribution, 5, 0);
        vec_map::insert(&mut market_analytics.user_distribution, 6, 0);
        
        vec_map::insert(&mut market_analytics.node_distribution, 1, 0);
        vec_map::insert(&mut market_analytics.node_distribution, 2, 0);
        vec_map::insert(&mut market_analytics.node_distribution, 3, 0);
        vec_map::insert(&mut market_analytics.node_distribution, 4, 0);
        vec_map::insert(&mut market_analytics.node_distribution, 5, 0);
        vec_map::insert(&mut market_analytics.node_distribution, 6, 0);
        
        transfer::share_object(pricing_config);
        transfer::share_object(market_analytics);
    }
    
    /// Bir düğüm için fiyatlandırma oluştur
    public entry fun create_node_pricing(
        pricing_config: &PricingConfig,
        node_info: &NodeInfo,
        min_price: Option<u64>,
        max_price: Option<u64>,
        pricing_strategy: Option<u8>,
        dynamic_pricing_enabled: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm sahibini kontrol et
        let node_id = object::id(node_info);
        let node_owner = registry::get_node_owner(node_info);
        assert!(sender == node_owner, ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Fiyat limitlerini belirle
        let min_price_val = if (option::is_some(&min_price)) {
            let price = *option::borrow(&min_price);
            assert!(price >= pricing_config.min_price, EPriceRangeViolation);
            price
        } else {
            pricing_config.min_price
        };
        
        let max_price_val = if (option::is_some(&max_price)) {
            let price = *option::borrow(&max_price);
            assert!(price <= pricing_config.max_price, EPriceRangeViolation);
            assert!(price > min_price_val, EPriceRangeViolation);
            price
        } else {
            pricing_config.max_price
        };
        
        // Fiyatlandırma stratejisini belirle
        let strategy = if (option::is_some(&pricing_strategy)) {
            let strat = *option::borrow(&pricing_strategy);
            assert!(
                strat == PRICING_MODEL_LINEAR ||
                strat == PRICING_MODEL_EXPONENTIAL ||
                strat == PRICING_MODEL_SIGMOID ||
                strat == PRICING_MODEL_CUSTOM,
                EInvalidModel
            );
            strat
        } else {
            pricing_config.default_pricing_model
        };
        
        // Başlangıç fiyatını hesapla
        let initial_price = calculate_initial_price(pricing_config, node_info, min_price_val, max_price_val);
        
        // İndirim oranlarını oluştur
        let discount_rates = vec_map::empty<String, u64>();
        vec_map::insert(&mut discount_rates, string::utf8(b"off_peak"), 200); // %20 indirim
        vec_map::insert(&mut discount_rates, string::utf8(b"high_volume"), 150); // %15 indirim
        vec_map::insert(&mut discount_rates, string::utf8(b"long_term"), 100); // %10 indirim
        
        let node_pricing = NodePricing {
            id: object::new(ctx),
            node_id,
            owner: node_owner,
            current_price: initial_price,
            min_price: min_price_val,
            max_price: max_price_val,
            pricing_strategy: strategy,
            custom_parameters: option::none(),
            dynamic_pricing_enabled,
            discount_rates,
            last_price_update: now,
            price_history: vector::empty(),
        };
        
        // Fiyat geçmişine başlangıç değeri olarak şimdiki fiyatı ekle
        vector::push_back(&mut node_pricing.price_history, initial_price);
        
        // Fiyat güncelleme eventini yayınla
        event::emit(PriceUpdated {
            node_id,
            old_price: 0,
            new_price: initial_price,
            update_time: now,
        });
        
        transfer::share_object(node_pricing);
    }
    
    /// Düğüm fiyatını güncelle
    public entry fun update_node_price(
        node_pricing: &mut NodePricing,
        pricing_config: &PricingConfig,
        market_analytics: &MarketAnalytics,
        node_info: &NodeInfo,
        new_price: Option<u64>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm sahibini kontrol et
        assert!(sender == node_pricing.owner, ENotAuthorized);
        assert!(node_pricing.node_id == object::id(node_info), EInvalidNode);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Son güncelleme zamanını kontrol et
        assert!(
            now >= node_pricing.last_price_update + pricing_config.price_update_interval,
            ERateChangeViolation
        );
        
        let old_price = node_pricing.current_price;
        
        // Yeni fiyatı belirle
        let updated_price = if (option::is_some(&new_price)) {
            // Manuel fiyat güncellemesi
            let price = *option::borrow(&new_price);
            
            // Fiyat limitlerini kontrol et
            assert!(price >= node_pricing.min_price && price <= node_pricing.max_price, EPriceRangeViolation);
            
            // Fiyat değişim oranını kontrol et
            // Maksimum değişim: price_config.max_rate_change (binde)
            let max_change = (old_price * pricing_config.max_rate_change) / 1000;
            let max_price = old_price + max_change;
            let min_price = if (old_price > max_change) { old_price - max_change } else { 0 };
            
            assert!(price >= min_price && price <= max_price, ERateChangeViolation);
            
            price
        } else if (node_pricing.dynamic_pricing_enabled) {
            // Dinamik fiyatlandırma ile otomatik fiyat belirleme
            calculate_dynamic_price(
                pricing_config,
                market_analytics,
                node_info,
                node_pricing,
                now
            )
        } else {
            // Değişiklik yok
            old_price
        };
        
        // Fiyatı güncelle
        node_pricing.current_price = updated_price;
        node_pricing.last_price_update = now;
        
        // Fiyat geçmişini güncelle (maksimum 24 saat saklayalım)
        vector::push_back(&mut node_pricing.price_history, updated_price);
        if (vector::length(&node_pricing.price_history) > 24) {
            vector::remove(&mut node_pricing.price_history, 0);
        };
        
        // Fiyat güncelleme eventini yayınla
        event::emit(PriceUpdated {
            node_id: node_pricing.node_id,
            old_price,
            new_price: updated_price,
            update_time: now,
        });
    }
    
    /// Pazar analitiğini güncelle
    public entry fun update_market_analytics(
        market_analytics: &mut MarketAnalytics,
        user_count: u64,
        node_count: u64,
        bandwidth_usage: u64,
        region_distribution: VecMap<u8, u64>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Analitiği güncelle
        market_analytics.total_active_users = user_count;
        market_analytics.total_active_nodes = node_count;
        market_analytics.total_bandwidth_usage = bandwidth_usage;
        
        // Bölge dağılımlarını güncelle
        let regions = vec_map::keys(&region_distribution);
        let i = 0;
        let len = vector::length(&regions);
        
        while (i < len) {
            let region = *vector::borrow(&regions, i);
            let count = *vec_map::get(&region_distribution, &region);
            
            if (vec_map::contains(&market_analytics.user_distribution, &region)) {
                vec_map::insert(&mut market_analytics.user_distribution, region, count);
            };
            
            i = i + 1;
        };
        
        // Ortalama fiyatı hesapla (geçici bir değer kullanalım)
        let avg_price = 1_000_000; // 0.001 SVPN
        
        // Saatlik ortalama fiyatları güncelle
        vector::push_back(&mut market_analytics.hourly_avg_prices, avg_price);
        if (vector::length(&market_analytics.hourly_avg_prices) > 24) {
            vector::remove(&mut market_analytics.hourly_avg_prices, 0);
        };
        
        // Günlük ortalama fiyatları güncelle (eğer gerekirse)
        if ((now / 86400) > (market_analytics.last_updated / 86400)) {
            // Yeni gün
            let daily_avg = 0;
            let hourly_count = vector::length(&market_analytics.hourly_avg_prices);
            
            if (hourly_count > 0) {
                let sum = 0;
                let j = 0;
                
                while (j < hourly_count) {
                    sum = sum + *vector::borrow(&market_analytics.hourly_avg_prices, j);
                    j = j + 1;
                };
                
                daily_avg = sum / hourly_count;
            };
            
            vector::push_back(&mut market_analytics.daily_avg_prices, daily_avg);
            if (vector::length(&market_analytics.daily_avg_prices) > 30) {
                vector::remove(&mut market_analytics.daily_avg_prices, 0);
            };
        };
        
        market_analytics.last_updated = now;
        
        // Pazar analitiği güncelleme eventini yayınla
        event::emit(MarketAnalyticsUpdated {
            total_users: user_count,
            total_nodes: node_count,
            avg_price,
            update_time: now,
        });
    }
    
    /// Fiyat teklifi oluştur
    public entry fun create_price_offer(
        node_pricing: &NodePricing,
        price: u64,
        max_bandwidth: u64,
        start_time: u64,
        duration: u64,
        terms: Option<vector<u8>>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm sahibini kontrol et
        assert!(sender == node_pricing.owner, ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Fiyat ve zamanlamaları kontrol et
        assert!(price >= node_pricing.min_price && price <= node_pricing.max_price, EPriceRangeViolation);
        assert!(start_time >= now, EInvalidOffer);
        assert!(duration > 0, EInvalidOffer);
        
        let end_time = start_time + duration;
        
        let terms_str = if (option::is_some(&terms)) {
            option::some(string::utf8(*option::borrow(&terms)))
        } else {
            option::none()
        };
        
        let offer = PriceOffer {
            id: object::new(ctx),
            node_id: node_pricing.node_id,
            start_time,
            end_time,
            price,
            max_bandwidth,
            remaining_bandwidth: max_bandwidth,
            is_active: true,
            terms: terms_str,
            created_at: now,
        };
        
        let offer_id = object::id(&offer);
        
        // Teklif oluşturma eventini yayınla
        event::emit(OfferCreated {
            offer_id,
            node_id: node_pricing.node_id,
            price,
            max_bandwidth,
            start_time,
            end_time,
        });
        
        transfer::share_object(offer);
    }
    
    /// Fiyat teklifini güncelle
    public entry fun update_price_offer(
        offer: &mut PriceOffer,
        node_pricing: &NodePricing,
        new_price: Option<u64>,
        new_max_bandwidth: Option<u64>,
        is_active: Option<bool>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm sahibini kontrol et
        assert!(sender == node_pricing.owner, ENotAuthorized);
        assert!(node_pricing.node_id == offer.node_id, EInvalidNode);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Teklifin geçerli olup olmadığını kontrol et
        assert!(now < offer.end_time, EInvalidOffer);
        
        let old_price = offer.price;
        
        // Fiyatı güncelle (varsa)
        if (option::is_some(&new_price)) {
            let price = *option::borrow(&new_price);
            assert!(price >= node_pricing.min_price && price <= node_pricing.max_price, EPriceRangeViolation);
            offer.price = price;
        };
        
        // Maksimum bant genişliğini güncelle (varsa)
        if (option::is_some(&new_max_bandwidth)) {
            let max_bandwidth = *option::borrow(&new_max_bandwidth);
            assert!(max_bandwidth >= offer.remaining_bandwidth, EInvalidOffer);
            offer.max_bandwidth = max_bandwidth;
        };
        
        // Aktiflik durumunu güncelle (varsa)
        if (option::is_some(&is_active)) {
            offer.is_active = *option::borrow(&is_active);
        };
        
        // Teklif güncelleme eventini yayınla
        event::emit(OfferUpdated {
            offer_id: object::id(offer),
            old_price,
            new_price: offer.price,
            remaining_bandwidth: offer.remaining_bandwidth,
            update_time: now,
        });
    }
    
    /// Bant genişliği kullanımını kaydet
    public entry fun record_bandwidth_usage(
        offer: &mut PriceOffer,
        usage_amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Teklifin geçerli olup olmadığını kontrol et
        assert!(now >= offer.start_time && now <= offer.end_time, EInvalidOffer);
        assert!(offer.is_active, EInvalidOffer);
        
        // Kalan bant genişliğini kontrol et
        assert!(usage_amount <= offer.remaining_bandwidth, EInvalidOffer);
        
        // Kalan bant genişliğini güncelle
        offer.remaining_bandwidth = offer.remaining_bandwidth - usage_amount;
        
        // Eğer kalan bant genişliği sıfırsa, teklifi devre dışı bırak
        if (offer.remaining_bandwidth == 0) {
            offer.is_active = false;
        };
    }
    
    /// Dinamik fiyatlandırma konfigürasyonunu güncelle
    public entry fun update_pricing_config(
        pricing_config: &mut PricingConfig,
        base_price: Option<u64>,
        min_price: Option<u64>,
        max_price: Option<u64>,
        update_interval: Option<u64>,
        max_rate_change: Option<u64>,
        default_model: Option<u8>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Temel fiyatı güncelle (varsa)
        if (option::is_some(&base_price)) {
            pricing_config.base_price = *option::borrow(&base_price);
        };
        
        // Minimum fiyatı güncelle (varsa)
        if (option::is_some(&min_price)) {
            pricing_config.min_price = *option::borrow(&min_price);
            assert!(pricing_config.min_price <= pricing_config.max_price, EPriceRangeViolation);
        };
        
        // Maksimum fiyatı güncelle (varsa)
        if (option::is_some(&max_price)) {
            pricing_config.max_price = *option::borrow(&max_price);
            assert!(pricing_config.min_price <= pricing_config.max_price, EPriceRangeViolation);
        };
        
        // Güncelleme aralığını güncelle (varsa)
        if (option::is_some(&update_interval)) {
            pricing_config.price_update_interval = *option::borrow(&update_interval);
        };
        
        // Maksimum değişim oranını güncelle (varsa)
        if (option::is_some(&max_rate_change)) {
            pricing_config.max_rate_change = *option::borrow(&max_rate_change);
        };
        
        // Varsayılan fiyatlandırma modelini güncelle (varsa)
        if (option::is_some(&default_model)) {
            let model = *option::borrow(&default_model);
            assert!(
                model == PRICING_MODEL_LINEAR ||
                model == PRICING_MODEL_EXPONENTIAL ||
                model == PRICING_MODEL_SIGMOID ||
                model == PRICING_MODEL_CUSTOM,
                EInvalidModel
            );
            pricing_config.default_pricing_model = model;
        };
        
        pricing_config.last_updated = now;
    }
    
    /// Fiyatlandırma faktör ağırlıklarını güncelle
    public entry fun update_pricing_factors(
        pricing_config: &mut PricingConfig,
        demand_factor_users: u64,
        demand_factor_bandwidth: u64,
        demand_factor_time: u64,
        demand_factor_region: u64,
        supply_factor_nodes: u64,
        supply_factor_capacity: u64,
        supply_factor_quality: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Talep faktörleri toplamını kontrol et
        let demand_sum = demand_factor_users + demand_factor_bandwidth + demand_factor_time + demand_factor_region;
        assert!(demand_sum == 1000, EInvalidFactor); // Binde toplam 1000 olmalı
        
        // Arz faktörleri toplamını kontrol et
        let supply_sum = supply_factor_nodes + supply_factor_capacity + supply_factor_quality;
        assert!(supply_sum == 1000, EInvalidFactor); // Binde toplam 1000 olmalı
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Faktörleri güncelle
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_USERS, demand_factor_users);
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_BANDWIDTH, demand_factor_bandwidth);
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_TIME, demand_factor_time);
        vec_map::insert(&mut pricing_config.demand_factors, DEMAND_FACTOR_REGION, demand_factor_region);
        
        vec_map::insert(&mut pricing_config.supply_factors, SUPPLY_FACTOR_NODES, supply_factor_nodes);
        vec_map::insert(&mut pricing_config.supply_factors, SUPPLY_FACTOR_CAPACITY, supply_factor_capacity);
        vec_map::insert(&mut pricing_config.supply_factors, SUPPLY_FACTOR_QUALITY, supply_factor_quality);
        
        pricing_config.last_updated = now;
    }
    
    /// Bölge çarpanlarını güncelle
    public entry fun update_region_multipliers(
        pricing_config: &mut PricingConfig,
        region_multipliers: VecMap<u8, u64>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Bölge çarpanlarını kontrol et
        let regions = vec_map::keys(&region_multipliers);
        let i = 0;
        let len = vector::length(&regions);
        
        while (i < len) {
            let region = *vector::borrow(&regions, i);
            let multiplier = *vec_map::get(&region_multipliers, &region);
            
            // Çarpan değerini kontrol et (0.1x ile 5x arası olmalı)
            assert!(multiplier >= 100 && multiplier <= 5000, EInvalidFactor);
            
            // Çarpanı güncelle
            vec_map::insert(&mut pricing_config.region_multipliers, region, multiplier);
            
            i = i + 1;
        };
        
        pricing_config.last_updated = now;
    }
    
    // Yardımcı fonksiyonlar
    
    /// Düğüm için başlangıç fiyatını hesapla
    fun calculate_initial_price(
        pricing_config: &PricingConfig,
        node_info: &NodeInfo,
        min_price: u64,
        max_price: u64
    ): u64 {
        // Düğüm bölgesini al
        let region = registry::get_node_region(node_info);
        
        // Bölge çarpanını al (varsayılan: 1x)
        let region_multiplier = if (vec_map::contains(&pricing_config.region_multipliers, &region)) {
            *vec_map::get(&pricing_config.region_multipliers, &region)
        } else {
            1000
        };
        
        // Düğüm puanını al (registry'den alınmalı, şimdilik varsayalım)
        let node_score = 800; // 0-1000 arası puanlama
        
        // Kalite faktörünü hesapla (0.5 ile 1.5 arası)
        let quality_factor = 500 + ((node_score * 1000) / 1000);
        
        // Başlangıç fiyatını hesapla
        let base = pricing_config.base_price;
        let price = (base * region_multiplier * quality_factor) / (1000 * 1000);
        
        // Fiyatı sınırlar içerisinde tut
        if (price < min_price) {
            min_price
        } else if (price > max_price) {
            max_price
        } else {
            price
        }
    }
    
    /// Dinamik fiyatı hesapla
    fun calculate_dynamic_price(
        pricing_config: &PricingConfig,
        market_analytics: &MarketAnalytics,
        node_info: &NodeInfo,
        node_pricing: &NodePricing,
        now: u64
    ): u64 {
        // Mevcut fiyatı al
        let current_price = node_pricing.current_price;
        
        // Düğüm bölgesini al
        let region = registry::get_node_region(node_info);
        
        // Bölge çarpanını al
        let region_multiplier = if (vec_map::contains(&pricing_config.region_multipliers, &region)) {
            *vec_map::get(&pricing_config.region_multipliers, &region)
        } else {
            1000
        };
        
        // Talep metrikleri
        // Gerçek bir implementasyonda, bu metrikler daha detaylı olacaktır
        
        // Kullanıcı oranı (0-1000)
        let user_rate = if (market_analytics.total_active_users > 0) {
            min((market_analytics.total_active_users * 1000) / 1000, 1000)
        } else {
            0
        };
        
        // Bant genişliği kullanım oranı (0-1000)
        let bandwidth_rate = if (market_analytics.total_bandwidth_usage > 0) {
            min((market_analytics.total_bandwidth_usage * 1000) / 100000, 1000)
        } else {
            0
        };
        
        // Zaman faktörü (günün saati bazlı) (0-1000)
        let hour_of_day = (now % 86400) / 3600; // 0-23
        let time_factor = if (hour_of_day >= 8 && hour_of_day <= 20) {
            // Gündüz saatleri: Daha yüksek talep
            800 + (hour_of_day - 8) * 20
        } else {
            // Gece saatleri: Daha düşük talep
            400 - (hour_of_day * 20)
        };
        
        // Bölgesel talep faktörü (0-1000)
        let region_factor = if (vec_map::contains(&market_analytics.user_distribution, &region)) {
            let region_users = *vec_map::get(&market_analytics.user_distribution, &region);
            if (market_analytics.total_active_users > 0) {
                (region_users * 1000) / market_analytics.total_active_users
            } else {
                500 // Varsayılan değer
            }
        } else {
            500 // Varsayılan değer
        };
        
        // Arz metrikleri
        
        // Düğüm oranı (0-1000)
        let node_rate = if (market_analytics.total_active_nodes > 0) {
            min((market_analytics.total_active_nodes * 1000) / 1000, 1000)
        } else {
            0
        };
        
        // Kapasite faktörü (0-1000)
        let capacity_factor = 500; // Varsayılan değer
        
        // Kalite faktörü (0-1000)
        let quality_factor = 800; // Varsayılan değer
        
        // Talep skoru hesapla
        let demand_score = 
            (user_rate * *vec_map::get(&pricing_config.demand_factors, &DEMAND_FACTOR_USERS) +
             bandwidth_rate * *vec_map::get(&pricing_config.demand_factors, &DEMAND_FACTOR_BANDWIDTH) +
             time_factor * *vec_map::get(&pricing_config.demand_factors, &DEMAND_FACTOR_TIME) +
             region_factor * *vec_map::get(&pricing_config.demand_factors, &DEMAND_FACTOR_REGION)) / 1000;
        
        // Arz skoru hesapla
        let supply_score = 
            (node_rate * *vec_map::get(&pricing_config.supply_factors, &SUPPLY_FACTOR_NODES) +
             capacity_factor * *vec_map::get(&pricing_config.supply_factors, &SUPPLY_FACTOR_CAPACITY) +
             quality_factor * *vec_map::get(&pricing_config.supply_factors, &SUPPLY_FACTOR_QUALITY)) / 1000;
        
        // Arz-talep dengesi hesapla (0-2000)
        // 1000 = Denge, <1000 = Arz fazlası, >1000 = Talep fazlası
        let balance = if (supply_score > 0) {
            (demand_score * 1000) / supply_score
        } else {
            2000 // Maksimum talep, minimum arz
        };
        
        // Fiyat ayarlama faktörü hesapla
        // Talep > Arz ise, fiyat artar; Arz > Talep ise, fiyat düşer
        let price_adjustment_factor = if (balance > 1000) {
            // Talep fazlası
            1000 + min((balance - 1000) / 2, 500)
        } else if (balance < 1000) {
            // Arz fazlası
            1000 - min((1000 - balance) / 2, 300)
        } else {
            // Denge
            1000
        };
        
        // Fiyatlandırma modelini uygula
        let new_price = if (node_pricing.pricing_strategy == PRICING_MODEL_LINEAR) {
            // Doğrusal model: P = P0 * F
            (current_price * price_adjustment_factor) / 1000
        } else if (node_pricing.pricing_strategy == PRICING_MODEL_EXPONENTIAL) {
            // Üssel model: P = P0 * (b^((F-1000)/1000))
            // b = exponential_base (varsayılan 1.1)
            let exp_base = *vec_map::get(&pricing_config.model_parameters, &string::utf8(b"exponential_base"));
            let exponent = ((price_adjustment_factor as i64) - 1000) / 1000;
            
            // Basitleştirilmiş üssel hesaplama
            if (exponent > 0) {
                let factor = exp_base;
                let i = 1;
                while (i < exponent) {
                    factor = (factor * exp_base) / 1000;
                    i = i + 1;
                };
                (current_price * factor) / 1000
            } else if (exponent < 0) {
                let factor = 1000;
                let i = 0;
                while (i < (-exponent)) {
                    factor = (factor * 1000) / exp_base;
                    i = i + 1;
                };
                (current_price * factor) / 1000
            } else {
                current_price
            }
        } else if (node_pricing.pricing_strategy == PRICING_MODEL_SIGMOID) {
            // Sigmoid model: P = P0 * (1 + tanh(s*(F-1000)/1000))
            // s = sigmoid_steepness (varsayılan 0.5)
            // Basitleştirilmiş sigmoid yaklaşımı
            let sigmoid_steepness = *vec_map::get(&pricing_config.model_parameters, &string::utf8(b"sigmoid_steepness"));
            let x = ((price_adjustment_factor - 1000) * sigmoid_steepness) / 1000;
            
            // tanh yaklaşımı: tanh(x) ≈ x / (1 + |x|/3)
            let tanh_x = if (x >= 0) {
                (x * 1000) / (1000 + (x / 3))
            } else {
                (x * 1000) / (1000 + (-x / 3))
            };
            
            (current_price * (1000 + tanh_x)) / 1000
        } else {
            // Özel model veya varsayılan durumda doğrusal model kullan
            (current_price * price_adjustment_factor) / 1000
        };
        
        // Fiyatı sınırlar içerisinde tut
        let min_price = node_pricing.min_price;
        let max_price = node_pricing.max_price;
        
        if (new_price < min_price) {
            min_price
        } else if (new_price > max_price) {
            max_price
        } else {
            new_price
        }
    }
    
    /// İki değerden küçük olanını döndür
    fun min(a: u64, b: u64): u64 {
        if (a < b) { a } else { b }
    }
    
    // Getter fonksiyonları
    
    /// Fiyatlandırma konfigürasyonu bilgilerini al
    public fun get_pricing_config_info(
        pricing_config: &PricingConfig
    ): (u64, u64, u64, u64, u64, u8, u64) {
        (
            pricing_config.base_price,
            pricing_config.min_price,
            pricing_config.max_price,
            pricing_config.price_update_interval,
            pricing_config.max_rate_change,
            pricing_config.default_pricing_model,
            pricing_config.last_updated
        )
    }
    
    /// Düğüm fiyatlandırma bilgilerini al
    public fun get_node_pricing_info(
        node_pricing: &NodePricing
    ): (ID, address, u64, u64, u64, u8, bool, u64) {
        (
            node_pricing.node_id,
            node_pricing.owner,
            node_pricing.current_price,
            node_pricing.min_price,
            node_pricing.max_price,
            node_pricing.pricing_strategy,
            node_pricing.dynamic_pricing_enabled,
            node_pricing.last_price_update
        )
    }
    
    /// Teklif bilgilerini al
    public fun get_offer_info(
        offer: &PriceOffer
    ): (ID, u64, u64, u64, u64, u64, bool, u64) {
        (
            offer.node_id,
            offer.start_time,
            offer.end_time,
            offer.price,
            offer.max_bandwidth,
            offer.remaining_bandwidth,
            offer.is_active,
            offer.created_at
        )
    }
    
    /// Pazar analitiği bilgilerini al
    public fun get_market_analytics_info(
        market_analytics: &MarketAnalytics
    ): (u64, u64, u64, u64) {
        (
            market_analytics.total_active_users,
            market_analytics.total_active_nodes,
            market_analytics.total_bandwidth_usage,
            market_analytics.last_updated
        )
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_pricing_config_for_testing(ctx: &mut TxContext): PricingConfig {
        PricingConfig {
            id: object::new(ctx),
            base_price: DEFAULT_BASE_PRICE,
            min_price: DEFAULT_MIN_PRICE,
            max_price: DEFAULT_MAX_PRICE,
            price_update_interval: DEFAULT_PRICE_UPDATE_INTERVAL,
            max_rate_change: DEFAULT_MAX_RATE_CHANGE,
            default_pricing_model: PRICING_MODEL_LINEAR,
            demand_factors: vec_map::empty(),
            supply_factors: vec_map::empty(),
            region_multipliers: vec_map::empty(),
            model_parameters: vec_map::empty(),
            last_updated: 0,
        }
    }
}
