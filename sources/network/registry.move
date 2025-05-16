/// SuiVPN Registry Module
/// 
/// Bu modül, SuiVPN ağındaki düğümlerin yönetimini ve kayıt işlemlerini gerçekleştirir.
/// Düğüm bilgilerini, türlerini ve ağ topolojisini yönetir. Ayrıca düğüm keşif
/// mekanizmaları ve düğüm durumu güncellemeleri için gerekli fonksiyonları sağlar.
module suivpn::registry {
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
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const ENodeAlreadyRegistered: u64 = 1;
    const EInvalidNodeType: u64 = 2;
    const EInvalidRegion: u64 = 3;
    const EInvalidCountry: u64 = 4;
    const EInvalidPublicKey: u64 = 5;
    const ENodeNotFound: u64 = 6;
    const EInsufficientStake: u64 = 7;
    const EMaxNodesReached: u64 = 8;
    const ENodeNotActive: u64 = 9;
    const ERegionNotFound: u64 = 10;
    const ENodeLocked: u64 = 11;
    
    // Düğüm tipleri
    const NODE_TYPE_RELAY: u8 = 0;
    const NODE_TYPE_VALIDATOR: u8 = 1;
    const NODE_TYPE_COMPUTE: u8 = 2;
    const NODE_TYPE_STORAGE: u8 = 3;
    
    // Düğüm durumları
    const NODE_STATUS_PENDING: u8 = 0;
    const NODE_STATUS_ACTIVE: u8 = 1;
    const NODE_STATUS_OFFLINE: u8 = 2;
    const NODE_STATUS_SUSPENDED: u8 = 3;
    const NODE_STATUS_BANNED: u8 = 4;
    
    // Region (kıta) ID'leri
    const REGION_NORTH_AMERICA: u8 = 1;
    const REGION_SOUTH_AMERICA: u8 = 2;
    const REGION_EUROPE: u8 = 3;
    const REGION_AFRICA: u8 = 4;
    const REGION_ASIA: u8 = 5;
    const REGION_OCEANIA: u8 = 6;
    
    // Sabitler
    const MIN_NODE_STAKE: u64 = 10_000_000_000; // 10,000 SVPN
    const MAX_NODES_PER_REGION: u64 = 1000;
    const MAX_NODES_PER_COUNTRY: u64 = 500;
    
    /// Network Registry
    /// Ağdaki tüm düğümlerin ve topolojinin kaydını tutar
    struct NetworkRegistry has key {
        id: UID,
        // Tüm kayıtlı düğümler (node ID -> NodeInfo)
        nodes: Table<ID, NodeInfo>,
        // Bölge bazlı düğüm kümeleri (region -> node ID'leri)
        region_nodes: VecMap<u8, VecSet<ID>>,
        // Ülke bazlı düğüm kümeleri (ülke kodu -> node ID'leri)
        country_nodes: Table<String, VecSet<ID>>,
        // Tip bazlı düğüm kümeleri (tip -> node ID'leri)
        type_nodes: VecMap<u8, VecSet<ID>>,
        // Bölge başına maksimum düğüm sayısı
        max_nodes_per_region: VecMap<u8, u64>,
        // Minimum stake gereksinimleri (düğüm tipi bazında)
        min_stake_requirements: VecMap<u8, u64>,
        // Toplam düğüm sayısı
        total_nodes: u64,
        // Aktif düğüm sayısı
        active_nodes: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Node Info
    /// Bir ağ düğümü hakkında tüm bilgileri içerir
    struct NodeInfo has key, store {
        id: UID,
        // Düğüm sahibi
        owner: address,
        // Düğüm adı
        name: String,
        // Düğüm açıklaması
        description: String,
        // Düğüm tipi
        node_type: u8,
        // Düğüm durumu
        status: u8,
        // Bölge (kıta) ID'si
        region: u8,
        // Ülke kodu (ISO 3166-1 alpha-2)
        country: String,
        // Şehir
        city: Option<String>,
        // Lokasyon koordinatları
        latitude: Option<u64>,
        longitude: Option<u64>,
        // IP adresi (hash'lenmiş veya onion adresi)
        ip_address: Option<String>,
        // Port numarası
        port: Option<u64>,
        // Düğüm public key'i
        public_key: String,
        // Düğüm versiyonu
        version: String,
        // Stake miktarı
        stake_amount: u64,
        // Bant genişliği (Mbps)
        bandwidth: u64,
        // Son çevrimiçi zamanı
        last_online: u64,
        // Katılım zamanı
        joined_at: u64,
        // Düğüm metrik toplamları
        total_connections: u64,
        total_bandwidth_used: u64,
        total_uptime: u64,
        // Düğüm kilidi (örn. cezalandırma süresince)
        is_locked: bool,
        lock_reason: Option<String>,
        lock_until: Option<u64>,
    }
    
    /// NodeCapability
    /// Düğüm sahibine düğümü yönetme yetkisi verir
    struct NodeCapability has key, store {
        id: UID,
        // Düğüm ID'si
        node_id: ID,
        // İzin verilen işlemler (bit maskesi)
        permissions: u64,
    }
    
    /// Region Info
    /// Bir bölge (kıta) hakkında bilgileri içerir
    struct RegionInfo has store, drop, copy {
        // Bölge ID'si
        region_id: u8,
        // Bölge adı
        name: String,
        // Maksimum düğüm sayısı
        max_nodes: u64,
        // Mevcut düğüm sayısı
        node_count: u64,
        // Aktif düğüm sayısı
        active_nodes: u64,
    }
    
    // Eventler
    
    /// Düğüm kayıt eventi
    struct NodeRegistered has copy, drop {
        node_id: ID,
        owner: address,
        name: String,
        node_type: u8,
        region: u8,
        country: String,
        public_key: String,
        stake_amount: u64,
        time: u64,
    }
    
    /// Düğüm durumu değişikliği eventi
    struct NodeStatusChanged has copy, drop {
        node_id: ID,
        old_status: u8,
        new_status: u8,
        time: u64,
    }
    
    /// Düğüm güncelleme eventi
    struct NodeUpdated has copy, drop {
        node_id: ID,
        field: String,
        time: u64,
    }
    
    /// Düğüm kaldırma eventi
    struct NodeRemoved has copy, drop {
        node_id: ID,
        owner: address,
        reason: String,
        time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let network_registry = NetworkRegistry {
            id: object::new(ctx),
            nodes: table::new(ctx),
            region_nodes: vec_map::empty(),
            country_nodes: table::new(ctx),
            type_nodes: vec_map::empty(),
            max_nodes_per_region: vec_map::empty(),
            min_stake_requirements: vec_map::empty(),
            total_nodes: 0,
            active_nodes: 0,
            last_updated: 0,
        };
        
        // Bölge başına maksimum düğüm sayılarını ayarla
        vec_map::insert(&mut network_registry.max_nodes_per_region, REGION_NORTH_AMERICA, MAX_NODES_PER_REGION);
        vec_map::insert(&mut network_registry.max_nodes_per_region, REGION_SOUTH_AMERICA, MAX_NODES_PER_REGION);
        vec_map::insert(&mut network_registry.max_nodes_per_region, REGION_EUROPE, MAX_NODES_PER_REGION);
        vec_map::insert(&mut network_registry.max_nodes_per_region, REGION_AFRICA, MAX_NODES_PER_REGION);
        vec_map::insert(&mut network_registry.max_nodes_per_region, REGION_ASIA, MAX_NODES_PER_REGION);
        vec_map::insert(&mut network_registry.max_nodes_per_region, REGION_OCEANIA, MAX_NODES_PER_REGION);
        
        // Düğüm tipi başına stake gereksinimlerini ayarla
        vec_map::insert(&mut network_registry.min_stake_requirements, NODE_TYPE_RELAY, MIN_NODE_STAKE);
        vec_map::insert(&mut network_registry.min_stake_requirements, NODE_TYPE_VALIDATOR, MIN_NODE_STAKE * 10);
        vec_map::insert(&mut network_registry.min_stake_requirements, NODE_TYPE_COMPUTE, MIN_NODE_STAKE * 5);
        vec_map::insert(&mut network_registry.min_stake_requirements, NODE_TYPE_STORAGE, MIN_NODE_STAKE * 3);
        
        // Bölge (kıta) için VecSet'leri oluştur
        vec_map::insert(&mut network_registry.region_nodes, REGION_NORTH_AMERICA, vec_set::empty());
        vec_map::insert(&mut network_registry.region_nodes, REGION_SOUTH_AMERICA, vec_set::empty());
        vec_map::insert(&mut network_registry.region_nodes, REGION_EUROPE, vec_set::empty());
        vec_map::insert(&mut network_registry.region_nodes, REGION_AFRICA, vec_set::empty());
        vec_map::insert(&mut network_registry.region_nodes, REGION_ASIA, vec_set::empty());
        vec_map::insert(&mut network_registry.region_nodes, REGION_OCEANIA, vec_set::empty());
        
        // Düğüm tipi için VecSet'leri oluştur
        vec_map::insert(&mut network_registry.type_nodes, NODE_TYPE_RELAY, vec_set::empty());
        vec_map::insert(&mut network_registry.type_nodes, NODE_TYPE_VALIDATOR, vec_set::empty());
        vec_map::insert(&mut network_registry.type_nodes, NODE_TYPE_COMPUTE, vec_set::empty());
        vec_map::insert(&mut network_registry.type_nodes, NODE_TYPE_STORAGE, vec_set::empty());
        
        transfer::share_object(network_registry);
    }
    
    /// Yeni bir düğüm kaydı oluştur
    public entry fun register_node(
        network_registry: &mut NetworkRegistry,
        name: vector<u8>,
        description: vector<u8>,
        node_type: u8,
        region: u8,
        country: vector<u8>,
        city: vector<u8>,
        public_key: vector<u8>,
        version: vector<u8>,
        stake_amount: u64,
        bandwidth: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm tipini kontrol et
        assert!(
            node_type == NODE_TYPE_RELAY ||
            node_type == NODE_TYPE_VALIDATOR ||
            node_type == NODE_TYPE_COMPUTE ||
            node_type == NODE_TYPE_STORAGE,
            EInvalidNodeType
        );
        
        // Bölge ID'sini kontrol et
        assert!(
            region == REGION_NORTH_AMERICA ||
            region == REGION_SOUTH_AMERICA ||
            region == REGION_EUROPE ||
            region == REGION_AFRICA ||
            region == REGION_ASIA ||
            region == REGION_OCEANIA,
            EInvalidRegion
        );
        
        // Ülke kodunu kontrol et (basit kontrol, gerçek bir uygulamada daha kapsamlı olabilir)
        let country_str = string::utf8(country);
        assert!(string::length(&country_str) == 2, EInvalidCountry);
        
        // Public key'in boyutunu kontrol et
        assert!(vector::length(&public_key) > 0, EInvalidPublicKey);
        
        // Stake miktarını kontrol et
        let min_stake = *vec_map::get(&network_registry.min_stake_requirements, &node_type);
        assert!(stake_amount >= min_stake, EInsufficientStake);
        
        // Bölge kapasitesini kontrol et
        let region_nodes = vec_map::get_mut(&mut network_registry.region_nodes, &region);
        let max_nodes_in_region = *vec_map::get(&network_registry.max_nodes_per_region, &region);
        assert!(vec_set::size(region_nodes) < max_nodes_in_region, EMaxNodesReached);
        
        // Ülke kapasitesini kontrol et
        let country_nodes = if (table::contains(&network_registry.country_nodes, country_str)) {
            table::borrow_mut(&mut network_registry.country_nodes, country_str)
        } else {
            table::add(&mut network_registry.country_nodes, country_str, vec_set::empty());
            table::borrow_mut(&mut network_registry.country_nodes, country_str)
        };
        assert!(vec_set::size(country_nodes) < MAX_NODES_PER_COUNTRY, EMaxNodesReached);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni düğüm bilgisi oluştur
        let node_info = NodeInfo {
            id: object::new(ctx),
            owner: sender,
            name: string::utf8(name),
            description: string::utf8(description),
            node_type,
            status: NODE_STATUS_PENDING,
            region,
            country: country_str,
            city: if (vector::length(&city) > 0) { option::some(string::utf8(city)) } else { option::none() },
            latitude: option::none(),
            longitude: option::none(),
            ip_address: option::none(),
            port: option::none(),
            public_key: string::utf8(public_key),
            version: string::utf8(version),
            stake_amount,
            bandwidth,
            last_online: now,
            joined_at: now,
            total_connections: 0,
            total_bandwidth_used: 0,
            total_uptime: 0,
            is_locked: false,
            lock_reason: option::none(),
            lock_until: option::none(),
        };
        
        let node_id = object::id(&node_info);
        
        // Düğümü kaydet
        table::add(&mut network_registry.nodes, node_id, node_info);
        
        // Bölge, ülke ve tip indekslerine ekle
        vec_set::insert(region_nodes, node_id);
        vec_set::insert(country_nodes, node_id);
        vec_set::insert(vec_map::get_mut(&mut network_registry.type_nodes, &node_type), node_id);
        
        // Toplam düğüm sayısını artır
        network_registry.total_nodes = network_registry.total_nodes + 1;
        network_registry.last_updated = now;
        
        // Düğüm sahibine NodeCapability ver
        let node_cap = NodeCapability {
            id: object::new(ctx),
            node_id,
            permissions: 0xFFFFFFFFFFFFFFFF, // Tüm izinler
        };
        
        // Düğüm kayıt eventini yayınla
        event::emit(NodeRegistered {
            node_id,
            owner: sender,
            name: string::utf8(name),
            node_type,
            region,
            country: country_str,
            public_key: string::utf8(public_key),
            stake_amount,
            time: now,
        });
        
        transfer::transfer(node_cap, sender);
        transfer::share_object(node_info);
    }
    
    /// Düğüm durumunu güncelle
    public entry fun update_node_status(
        network_registry: &mut NetworkRegistry,
        node_info: &mut NodeInfo,
        node_cap: &NodeCapability,
        new_status: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Yetki kontrolü
        assert!(sender == node_info.owner, ENotAuthorized);
        assert!(node_cap.node_id == object::id(node_info), ENotAuthorized);
        
        // Düğümün kilitli olmadığını kontrol et
        assert!(!node_info.is_locked, ENodeLocked);
        
        // Durumun geçerli olup olmadığını kontrol et
        assert!(
            new_status == NODE_STATUS_PENDING ||
            new_status == NODE_STATUS_ACTIVE ||
            new_status == NODE_STATUS_OFFLINE ||
            new_status == NODE_STATUS_SUSPENDED,
            EInvalidNodeType
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Düğüm aktif durumundan çıkıyorsa veya aktif duruma geçiyorsa, aktif düğüm sayısını güncelle
        if (node_info.status == NODE_STATUS_ACTIVE && new_status != NODE_STATUS_ACTIVE) {
            network_registry.active_nodes = network_registry.active_nodes - 1;
        } else if (node_info.status != NODE_STATUS_ACTIVE && new_status == NODE_STATUS_ACTIVE) {
            network_registry.active_nodes = network_registry.active_nodes + 1;
        };
        
        let old_status = node_info.status;
        node_info.status = new_status;
        node_info.last_online = now;
        
        // Düğüm durumu değişikliği eventini yayınla
        event::emit(NodeStatusChanged {
            node_id: object::id(node_info),
            old_status,
            new_status,
            time: now,
        });
        
        network_registry.last_updated = now;
    }
    
    /// Düğüm metadatasını güncelle
    public entry fun update_node_metadata(
        node_info: &mut NodeInfo,
        node_cap: &NodeCapability,
        name: Option<vector<u8>>,
        description: Option<vector<u8>>,
        city: Option<vector<u8>>,
        version: Option<vector<u8>>,
        bandwidth: Option<u64>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Yetki kontrolü
        assert!(sender == node_info.owner, ENotAuthorized);
        assert!(node_cap.node_id == object::id(node_info), ENotAuthorized);
        
        // Düğümün kilitli olmadığını kontrol et
        assert!(!node_info.is_locked, ENodeLocked);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Alanları güncelle
        if (option::is_some(&name)) {
            node_info.name = string::utf8(*option::borrow(&name));
            event::emit(NodeUpdated {
                node_id: object::id(node_info),
                field: string::utf8(b"name"),
                time: now,
            });
        };
        
        if (option::is_some(&description)) {
            node_info.description = string::utf8(*option::borrow(&description));
            event::emit(NodeUpdated {
                node_id: object::id(node_info),
                field: string::utf8(b"description"),
                time: now,
            });
        };
        
        if (option::is_some(&city)) {
            node_info.city = option::some(string::utf8(*option::borrow(&city)));
            event::emit(NodeUpdated {
                node_id: object::id(node_info),
                field: string::utf8(b"city"),
                time: now,
            });
        };
        
        if (option::is_some(&version)) {
            node_info.version = string::utf8(*option::borrow(&version));
            event::emit(NodeUpdated {
                node_id: object::id(node_info),
                field: string::utf8(b"version"),
                time: now,
            });
        };
        
        if (option::is_some(&bandwidth)) {
            node_info.bandwidth = *option::borrow(&bandwidth);
            event::emit(NodeUpdated {
                node_id: object::id(node_info),
                field: string::utf8(b"bandwidth"),
                time: now,
            });
        };
        
        node_info.last_online = now;
    }
    
    /// Düğüm koordinatlarını güncelle
    public entry fun update_node_coordinates(
        node_info: &mut NodeInfo,
        node_cap: &NodeCapability,
        latitude: u64,
        longitude: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Yetki kontrolü
        assert!(sender == node_info.owner, ENotAuthorized);
        assert!(node_cap.node_id == object::id(node_info), ENotAuthorized);
        
        // Düğümün kilitli olmadığını kontrol et
        assert!(!node_info.is_locked, ENodeLocked);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Koordinatları güncelle
        node_info.latitude = option::some(latitude);
        node_info.longitude = option::some(longitude);
        node_info.last_online = now;
        
        event::emit(NodeUpdated {
            node_id: object::id(node_info),
            field: string::utf8(b"coordinates"),
            time: now,
        });
    }
    
    /// Düğüm bağlantı bilgilerini güncelle
    public entry fun update_node_connection_info(
        node_info: &mut NodeInfo,
        node_cap: &NodeCapability,
        ip_address: vector<u8>,
        port: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Yetki kontrolü
        assert!(sender == node_info.owner, ENotAuthorized);
        assert!(node_cap.node_id == object::id(node_info), ENotAuthorized);
        
        // Düğümün kilitli olmadığını kontrol et
        assert!(!node_info.is_locked, ENodeLocked);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Bağlantı bilgilerini güncelle
        node_info.ip_address = option::some(string::utf8(ip_address));
        node_info.port = option::some(port);
        node_info.last_online = now;
        
        event::emit(NodeUpdated {
            node_id: object::id(node_info),
            field: string::utf8(b"connection_info"),
            time: now,
        });
    }
    
    /// Düğüm istatistiklerini güncelle
    public entry fun update_node_stats(
        node_info: &mut NodeInfo,
        node_cap: &NodeCapability,
        connections: u64,
        bandwidth_used: u64,
        uptime: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Yetki kontrolü
        assert!(sender == node_info.owner, ENotAuthorized);
        assert!(node_cap.node_id == object::id(node_info), ENotAuthorized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // İstatistikleri güncelle
        node_info.total_connections = node_info.total_connections + connections;
        node_info.total_bandwidth_used = node_info.total_bandwidth_used + bandwidth_used;
        node_info.total_uptime = node_info.total_uptime + uptime;
        node_info.last_online = now;
        
        event::emit(NodeUpdated {
            node_id: object::id(node_info),
            field: string::utf8(b"stats"),
            time: now,
        });
    }
    
    /// Düğümü kilitle
    public entry fun lock_node(
        node_info: &mut NodeInfo,
        lock_reason: vector<u8>,
        lock_duration: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğümün zaten kilitli olup olmadığını kontrol et
        assert!(!node_info.is_locked, ENodeLocked);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Düğümü kilitle
        node_info.is_locked = true;
        node_info.lock_reason = option::some(string::utf8(lock_reason));
        node_info.lock_until = option::some(now + lock_duration);
        
        // Eğer düğüm aktifse, durum değişikliği yap
        if (node_info.status == NODE_STATUS_ACTIVE) {
            let old_status = node_info.status;
            node_info.status = NODE_STATUS_SUSPENDED;
            
            // Düğüm durumu değişikliği eventini yayınla
            event::emit(NodeStatusChanged {
                node_id: object::id(node_info),
                old_status,
                new_status: node_info.status,
                time: now,
            });
        };
        
        event::emit(NodeUpdated {
            node_id: object::id(node_info),
            field: string::utf8(b"lock"),
            time: now,
        });
    }
    
    /// Düğüm kilidini aç
    public entry fun unlock_node(
        node_info: &mut NodeInfo,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğümün kilitli olup olmadığını kontrol et
        assert!(node_info.is_locked, ENodeNotActive);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Düğüm kilidini aç
        node_info.is_locked = false;
        node_info.lock_reason = option::none();
        node_info.lock_until = option::none();
        
        event::emit(NodeUpdated {
            node_id: object::id(node_info),
            field: string::utf8(b"unlock"),
            time: now,
        });
    }
    
    /// Minimum stake gereksinimini güncelle
    public entry fun update_min_stake_requirement(
        network_registry: &mut NetworkRegistry,
        node_type: u8,
        min_stake: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Düğüm tipini kontrol et
        assert!(
            node_type == NODE_TYPE_RELAY ||
            node_type == NODE_TYPE_VALIDATOR ||
            node_type == NODE_TYPE_COMPUTE ||
            node_type == NODE_TYPE_STORAGE,
            EInvalidNodeType
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Stake gereksinimini güncelle
        vec_map::insert(&mut network_registry.min_stake_requirements, node_type, min_stake);
        network_registry.last_updated = now;
    }
    
    /// Bölge başına maksimum düğüm sayısını güncelle
    public entry fun update_max_nodes_per_region(
        network_registry: &mut NetworkRegistry,
        region: u8,
        max_nodes: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Bölge ID'sini kontrol et
        assert!(
            region == REGION_NORTH_AMERICA ||
            region == REGION_SOUTH_AMERICA ||
            region == REGION_EUROPE ||
            region == REGION_AFRICA ||
            region == REGION_ASIA ||
            region == REGION_OCEANIA,
            EInvalidRegion
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Maksimum düğüm sayısını güncelle
        vec_map::insert(&mut network_registry.max_nodes_per_region, region, max_nodes);
        network_registry.last_updated = now;
    }
    
    // Getter fonksiyonları
    
    /// Düğüm bilgisini al
    public fun get_node_info(
        node_info: &NodeInfo
    ): (address, String, u8, u8, u8, String, String, u64, u64, u64, u64, u64, u64, bool) {
        (
            node_info.owner,
            node_info.name,
            node_info.node_type,
            node_info.status,
            node_info.region,
            node_info.country,
            node_info.public_key,
            node_info.stake_amount,
            node_info.bandwidth,
            node_info.last_online,
            node_info.joined_at,
            node_info.total_connections,
            node_info.total_bandwidth_used,
            node_info.is_locked
        )
    }
    
    /// Düğüm koordinatlarını al
    public fun get_node_coordinates(
        node_info: &NodeInfo
    ): (Option<u64>, Option<u64>) {
        (node_info.latitude, node_info.longitude)
    }
    
    /// Düğüm bağlantı bilgilerini al
    public fun get_node_connection_info(
        node_info: &NodeInfo
    ): (Option<String>, Option<u64>) {
        (node_info.ip_address, node_info.port)
    }
    
    /// Düğüm tipine göre minimum stake gereksinimini al
    public fun get_min_stake_requirement(
        network_registry: &NetworkRegistry,
        node_type: u8
    ): u64 {
        *vec_map::get(&network_registry.min_stake_requirements, &node_type)
    }
    
    /// Bölge bazlı düğüm sayısını al
    public fun get_region_node_count(
        network_registry: &NetworkRegistry,
        region: u8
    ): u64 {
        assert!(vec_map::contains(&network_registry.region_nodes, &region), ERegionNotFound);
        vec_set::size(vec_map::get(&network_registry.region_nodes, &region))
    }
    
    /// Bölge için maksimum düğüm sayısını al
    public fun get_max_nodes_per_region(
        network_registry: &NetworkRegistry,
        region: u8
    ): u64 {
        *vec_map::get(&network_registry.max_nodes_per_region, &region)
    }
    
    /// Ağ istatistiklerini al
    public fun get_network_stats(
        network_registry: &NetworkRegistry
    ): (u64, u64, u64) {
        (
            network_registry.total_nodes,
            network_registry.active_nodes,
            network_registry.last_updated
        )
    }
    
    /// Bölge bazlı düğüm ID'lerinin bir vektörünü al
    public fun get_region_node_ids(
        network_registry: &NetworkRegistry,
        region: u8
    ): vector<ID> {
        assert!(vec_map::contains(&network_registry.region_nodes, &region), ERegionNotFound);
        vec_set::into_keys(*vec_map::get(&network_registry.region_nodes, &region))
    }
    
    /// Düğüm tipine göre düğüm ID'lerinin bir vektörünü al
    public fun get_node_type_ids(
        network_registry: &NetworkRegistry,
        node_type: u8
    ): vector<ID> {
        assert!(vec_map::contains(&network_registry.type_nodes, &node_type), EInvalidNodeType);
        vec_set::into_keys(*vec_map::get(&network_registry.type_nodes, &node_type))
    }
    
    /// Tüm bölge bilgilerini al
    public fun get_all_region_info(
        network_registry: &NetworkRegistry
    ): vector<RegionInfo> {
        let regions = vector::empty<RegionInfo>();
        
        // Her bölge için bilgi oluştur
        vector::push_back(&mut regions, get_region_info(network_registry, REGION_NORTH_AMERICA, b"North America"));
        vector::push_back(&mut regions, get_region_info(network_registry, REGION_SOUTH_AMERICA, b"South America"));
        vector::push_back(&mut regions, get_region_info(network_registry, REGION_EUROPE, b"Europe"));
        vector::push_back(&mut regions, get_region_info(network_registry, REGION_AFRICA, b"Africa"));
        vector::push_back(&mut regions, get_region_info(network_registry, REGION_ASIA, b"Asia"));
        vector::push_back(&mut regions, get_region_info(network_registry, REGION_OCEANIA, b"Oceania"));
        
        regions
    }
    
    /// Bölge bilgisini al
    fun get_region_info(
        network_registry: &NetworkRegistry,
        region_id: u8,
        name_bytes: vector<u8>
    ): RegionInfo {
        let node_count = get_region_node_count(network_registry, region_id);
        
        // Aktif düğüm sayısını hesapla (basitleştirilmiş versiyonda uygulanmadı)
        // Gerçek uygulamada, bölgedeki her düğümün durumu kontrol edilmelidir
        
        RegionInfo {
            region_id,
            name: string::utf8(name_bytes),
            max_nodes: *vec_map::get(&network_registry.max_nodes_per_region, &region_id),
            node_count,
            active_nodes: 0, // Bu örnekte hesaplanmadı
        }
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_network_registry_for_testing(ctx: &mut TxContext): NetworkRegistry {
        let network_registry = NetworkRegistry {
            id: object::new(ctx),
            nodes: table::new(ctx),
            region_nodes: vec_map::empty(),
            country_nodes: table::new(ctx),
            type_nodes: vec_map::empty(),
            max_nodes_per_region: vec_map::empty(),
            min_stake_requirements: vec_map::empty(),
            total_nodes: 0,
            active_nodes: 0,
            last_updated: 0,
        }
    }
}
