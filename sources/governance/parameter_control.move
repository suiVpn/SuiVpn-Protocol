/// SuiVPN Parameter Control Module
/// 
/// Bu modül, SuiVPN protokolünün parametrelerinin yönetimini sağlar.
/// DAO yönetişimi aracılığıyla protokol parametrelerinin güvenli bir şekilde
/// güncellenebilmesini ve geçmiş değişikliklerin izlenebilmesini mümkün kılar.
module suivpn::parameter_control {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::vec_map::{Self, VecMap};
    use std::vector;
    use std::string::{Self, String};
    use std::option::{Self, Option};
    use suivpn::governance::{Self, GovernanceCapability};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidParameter: u64 = 1;
    const EInvalidValue: u64 = 2;
    const EParameterNotFound: u64 = 3;
    const EModuleNotFound: u64 = 4;
    const EValueOutOfRange: u64 = 5;
    const EChangeRateTooHigh: u64 = 6;
    const EInvalidProposal: u64 = 7;
    const ECooldownPeriod: u64 = 8;
    const EAlreadyInitialized: u64 = 9;
    
    // Parametre kategorileri
    const CATEGORY_NETWORK: u8 = 0;
    const CATEGORY_ECONOMIC: u8 = 1;
    const CATEGORY_GOVERNANCE: u8 = 2;
    const CATEGORY_SECURITY: u8 = 3;
    
    // Parametre tipleri
    const PARAM_TYPE_U64: u8 = 0;
    const PARAM_TYPE_BOOL: u8 = 1;
    const PARAM_TYPE_VECTOR: u8 = 2;
    
    /// Parametre değer tipi
    /// Farklı tipte parametre değerlerini temsil eder
    struct ParameterValue has store, copy, drop {
        // Parametre tipi
        param_type: u8,
        // U64 değeri (varsa)
        u64_value: Option<u64>,
        // Boolean değeri (varsa)
        bool_value: Option<bool>,
        // Vector değeri (varsa) - String olarak temsil edilir
        vector_value: Option<String>,
    }
    
    /// Parametre Kaydı
    /// Protokolün tüm parametrelerini içerir
    struct ParameterRegistry has key {
        id: UID,
        // Modül bazlı parametre tablosu (modül adı -> parametre tablosu)
        modules: Table<String, ModuleParameters>,
        // Son güncelleme zamanı
        last_updated: u64,
        // Parametre değişikliği geçmişi
        change_history: vector<ParameterChange>,
        // Soğuma süresi (parametre başına minimum güncelleme aralığı, saniye)
        cooldown_period: u64,
    }
    
    /// Modül Parametreleri
    /// Bir modülün tüm parametrelerini içerir
    struct ModuleParameters has store {
        // Modül adı
        name: String,
        // Parametre tablosu (parametre adı -> parametre)
        parameters: Table<String, Parameter>,
    }
    
    /// Parametre
    /// Bir protokol parametresini temsil eder
    struct Parameter has store {
        // Parametre adı
        name: String,
        // Parametre açıklaması
        description: String,
        // Parametre kategorisi
        category: u8,
        // Mevcut değer
        current_value: ParameterValue,
        // Minimum değer (varsa)
        min_value: Option<u64>,
        // Maksimum değer (varsa)
        max_value: Option<u64>,
        // Son güncelleme zamanı
        last_updated: u64,
        // Değişiklik limiti (yüzde, binde)
        // Bir güncelleme ile değerin en fazla ne kadar değişebileceğini belirtir
        change_limit_pct: Option<u64>,
    }
    
    /// Parametre Değişikliği
    /// Bir parametre değişikliği geçmişini temsil eder
    struct ParameterChange has store, copy, drop {
        // Modül adı
        module_name: String,
        // Parametre adı
        parameter_name: String,
        // Eski değer
        old_value: ParameterValue,
        // Yeni değer
        new_value: ParameterValue,
        // Değişiklik zamanı
        change_time: u64,
        // Değişikliği yapan adres
        changed_by: address,
        // İlgili teklif ID'si (varsa)
        proposal_id: Option<ID>,
    }
    
    // Eventler
    
    /// Parametre oluşturma eventi
    struct ParameterCreated has copy, drop {
        module_name: String,
        parameter_name: String,
        category: u8,
        value: ParameterValue,
        time: u64,
    }
    
    /// Parametre değiştirme eventi
    struct ParameterUpdated has copy, drop {
        module_name: String,
        parameter_name: String,
        old_value: ParameterValue,
        new_value: ParameterValue,
        proposal_id: Option<ID>,
        time: u64,
    }
    
    /// Modül oluşturma eventi
    struct ModuleCreated has copy, drop {
        module_name: String,
        time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let parameter_registry = ParameterRegistry {
            id: object::new(ctx),
            modules: table::new(ctx),
            last_updated: 0,
            change_history: vector::empty(),
            cooldown_period: 86400, // 1 gün (saniye)
        };
        
        transfer::share_object(parameter_registry);
    }
    
    /// Yeni bir modül oluştur
    public entry fun create_module(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let name = string::utf8(module_name);
        
        // Modülün zaten var olup olmadığını kontrol et
        assert!(!table::contains(&registry.modules, name), EAlreadyInitialized);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni modül parametreleri oluştur
        let module_params = ModuleParameters {
            name: name,
            parameters: table::new(ctx),
        };
        
        // Modülü kaydet
        table::add(&mut registry.modules, name, module_params);
        
        // Modül oluşturma eventini yayınla
        event::emit(ModuleCreated {
            module_name: name,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// Yeni bir u64 parametre oluştur
    public entry fun create_u64_parameter(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        parameter_name: vector<u8>,
        description: vector<u8>,
        category: u8,
        initial_value: u64,
        min_value: Option<u64>,
        max_value: Option<u64>,
        change_limit_pct: Option<u64>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Limitleri kontrol et (varsa)
        if (option::is_some(&min_value)) {
            let min = *option::borrow(&min_value);
            assert!(initial_value >= min, EValueOutOfRange);
        };
        
        if (option::is_some(&max_value)) {
            let max = *option::borrow(&max_value);
            assert!(initial_value <= max, EValueOutOfRange);
        };
        
        // Değişiklik limitini kontrol et (varsa)
        if (option::is_some(&change_limit_pct)) {
            let limit = *option::borrow(&change_limit_pct);
            assert!(limit > 0 && limit <= 1000, EInvalidValue); // en fazla %100 (binde)
        };
        
        // Kategoriyi kontrol et
        assert!(
            category == CATEGORY_NETWORK || 
            category == CATEGORY_ECONOMIC || 
            category == CATEGORY_GOVERNANCE || 
            category == CATEGORY_SECURITY,
            EInvalidParameter
        );
        
        // Parameter değeri oluştur
        let value = ParameterValue {
            param_type: PARAM_TYPE_U64,
            u64_value: option::some(initial_value),
            bool_value: option::none(),
            vector_value: option::none(),
        };
        
        // Parametreyi oluştur
        let parameter = Parameter {
            name: param,
            description: string::utf8(description),
            category,
            current_value: value,
            min_value,
            max_value,
            last_updated: now,
            change_limit_pct,
        };
        
        // Modül parametrelerine erişim
        let module_params = table::borrow_mut(&mut registry.modules, module);
        
        // Parametrenin zaten var olup olmadığını kontrol et
        assert!(!table::contains(&module_params.parameters, param), EAlreadyInitialized);
        
        // Parametreyi kaydet
        table::add(&mut module_params.parameters, param, parameter);
        
        // Parametre oluşturma eventini yayınla
        event::emit(ParameterCreated {
            module_name: module,
            parameter_name: param,
            category,
            value,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// Yeni bir boolean parametre oluştur
    public entry fun create_bool_parameter(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        parameter_name: vector<u8>,
        description: vector<u8>,
        category: u8,
        initial_value: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Kategoriyi kontrol et
        assert!(
            category == CATEGORY_NETWORK || 
            category == CATEGORY_ECONOMIC || 
            category == CATEGORY_GOVERNANCE || 
            category == CATEGORY_SECURITY,
            EInvalidParameter
        );
        
        // Parameter değeri oluştur
        let value = ParameterValue {
            param_type: PARAM_TYPE_BOOL,
            u64_value: option::none(),
            bool_value: option::some(initial_value),
            vector_value: option::none(),
        };
        
        // Parametreyi oluştur
        let parameter = Parameter {
            name: param,
            description: string::utf8(description),
            category,
            current_value: value,
            min_value: option::none(),
            max_value: option::none(),
            last_updated: now,
            change_limit_pct: option::none(),
        };
        
        // Modül parametrelerine erişim
        let module_params = table::borrow_mut(&mut registry.modules, module);
        
        // Parametrenin zaten var olup olmadığını kontrol et
        assert!(!table::contains(&module_params.parameters, param), EAlreadyInitialized);
        
        // Parametreyi kaydet
        table::add(&mut module_params.parameters, param, parameter);
        
        // Parametre oluşturma eventini yayınla
        event::emit(ParameterCreated {
            module_name: module,
            parameter_name: param,
            category,
            value,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// Yeni bir vector parametre oluştur (string olarak temsil edilir)
    public entry fun create_vector_parameter(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        parameter_name: vector<u8>,
        description: vector<u8>,
        category: u8,
        initial_value: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Kategoriyi kontrol et
        assert!(
            category == CATEGORY_NETWORK || 
            category == CATEGORY_ECONOMIC || 
            category == CATEGORY_GOVERNANCE || 
            category == CATEGORY_SECURITY,
            EInvalidParameter
        );
        
        // Parameter değeri oluştur
        let value = ParameterValue {
            param_type: PARAM_TYPE_VECTOR,
            u64_value: option::none(),
            bool_value: option::none(),
            vector_value: option::some(string::utf8(initial_value)),
        };
        
        // Parametreyi oluştur
        let parameter = Parameter {
            name: param,
            description: string::utf8(description),
            category,
            current_value: value,
            min_value: option::none(),
            max_value: option::none(),
            last_updated: now,
            change_limit_pct: option::none(),
        };
        
        // Modül parametrelerine erişim
        let module_params = table::borrow_mut(&mut registry.modules, module);
        
        // Parametrenin zaten var olup olmadığını kontrol et
        assert!(!table::contains(&module_params.parameters, param), EAlreadyInitialized);
        
        // Parametreyi kaydet
        table::add(&mut module_params.parameters, param, parameter);
        
        // Parametre oluşturma eventini yayınla
        event::emit(ParameterCreated {
            module_name: module,
            parameter_name: param,
            category,
            value,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// U64 parametresini güncelle
    public entry fun update_u64_parameter(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        parameter_name: vector<u8>,
        new_value: u64,
        proposal_id: Option<ID>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow_mut(&mut registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow_mut(&mut module_params.parameters, param);
        
        // Parametre tipini kontrol et
        assert!(parameter.current_value.param_type == PARAM_TYPE_U64, EInvalidParameter);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Soğuma süresini kontrol et
        assert!(now >= parameter.last_updated + registry.cooldown_period, ECooldownPeriod);
        
        // Limitleri kontrol et (varsa)
        if (option::is_some(&parameter.min_value)) {
            let min = *option::borrow(&parameter.min_value);
            assert!(new_value >= min, EValueOutOfRange);
        };
        
        if (option::is_some(&parameter.max_value)) {
            let max = *option::borrow(&parameter.max_value);
            assert!(new_value <= max, EValueOutOfRange);
        };
        
        // Değişiklik limitini kontrol et (varsa)
        if (option::is_some(&parameter.change_limit_pct)) {
            let current_value = *option::borrow(&parameter.current_value.u64_value);
            let limit = *option::borrow(&parameter.change_limit_pct);
            
            // Değişiklik oranını hesapla
            let change_rate = if (new_value > current_value) {
                ((new_value - current_value) * 1000) / current_value
            } else {
                ((current_value - new_value) * 1000) / current_value
            };
            
            assert!(change_rate <= limit, EChangeRateTooHigh);
        };
        
        // Eski değeri kaydet
        let old_value = parameter.current_value;
        
        // Yeni değeri ayarla
        parameter.current_value.u64_value = option::some(new_value);
        parameter.last_updated = now;
        
        // Parametre değişiklik geçmişine ekle
        vector::push_back(&mut registry.change_history, ParameterChange {
            module_name: module,
            parameter_name: param,
            old_value,
            new_value: parameter.current_value,
            change_time: now,
            changed_by: tx_context::sender(ctx),
            proposal_id,
        });
        
        // Parametre değiştirme eventini yayınla
        event::emit(ParameterUpdated {
            module_name: module,
            parameter_name: param,
            old_value,
            new_value: parameter.current_value,
            proposal_id,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// Boolean parametresini güncelle
    public entry fun update_bool_parameter(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        parameter_name: vector<u8>,
        new_value: bool,
        proposal_id: Option<ID>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow_mut(&mut registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow_mut(&mut module_params.parameters, param);
        
        // Parametre tipini kontrol et
        assert!(parameter.current_value.param_type == PARAM_TYPE_BOOL, EInvalidParameter);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Soğuma süresini kontrol et
        assert!(now >= parameter.last_updated + registry.cooldown_period, ECooldownPeriod);
        
        // Eski değeri kaydet
        let old_value = parameter.current_value;
        
        // Eğer yeni değer eskisiyle aynıysa, değişiklik yapma
        if (*option::borrow(&parameter.current_value.bool_value) == new_value) {
            return
        };
        
        // Yeni değeri ayarla
        parameter.current_value.bool_value = option::some(new_value);
        parameter.last_updated = now;
        
        // Parametre değişiklik geçmişine ekle
        vector::push_back(&mut registry.change_history, ParameterChange {
            module_name: module,
            parameter_name: param,
            old_value,
            new_value: parameter.current_value,
            change_time: now,
            changed_by: tx_context::sender(ctx),
            proposal_id,
        });
        
        // Parametre değiştirme eventini yayınla
        event::emit(ParameterUpdated {
            module_name: module,
            parameter_name: param,
            old_value,
            new_value: parameter.current_value,
            proposal_id,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// Vector parametresini güncelle
    public entry fun update_vector_parameter(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        module_name: vector<u8>,
        parameter_name: vector<u8>,
        new_value: vector<u8>,
        proposal_id: Option<ID>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow_mut(&mut registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow_mut(&mut module_params.parameters, param);
        
        // Parametre tipini kontrol et
        assert!(parameter.current_value.param_type == PARAM_TYPE_VECTOR, EInvalidParameter);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Soğuma süresini kontrol et
        assert!(now >= parameter.last_updated + registry.cooldown_period, ECooldownPeriod);
        
        // Eski değeri kaydet
        let old_value = parameter.current_value;
        
        // Yeni değeri ayarla
        parameter.current_value.vector_value = option::some(string::utf8(new_value));
        parameter.last_updated = now;
        
        // Parametre değişiklik geçmişine ekle
        vector::push_back(&mut registry.change_history, ParameterChange {
            module_name: module,
            parameter_name: param,
            old_value,
            new_value: parameter.current_value,
            change_time: now,
            changed_by: tx_context::sender(ctx),
            proposal_id,
        });
        
        // Parametre değiştirme eventini yayınla
        event::emit(ParameterUpdated {
            module_name: module,
            parameter_name: param,
            old_value,
            new_value: parameter.current_value,
            proposal_id,
            time: now,
        });
        
        registry.last_updated = now;
    }
    
    /// Soğuma süresini güncelle
    public entry fun update_cooldown_period(
        registry: &mut ParameterRegistry,
        governance_cap: &GovernanceCapability,
        new_period: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni değeri ayarla
        registry.cooldown_period = new_period;
        registry.last_updated = now;
    }
    
    // Getter fonksiyonları
    
    /// U64 parametre değerini al
    public fun get_u64_parameter(
        registry: &ParameterRegistry,
        module_name: vector<u8>,
        parameter_name: vector<u8>
    ): u64 {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow(&registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow(&module_params.parameters, param);
        
        // Parametre tipini kontrol et
        assert!(parameter.current_value.param_type == PARAM_TYPE_U64, EInvalidParameter);
        
        // Değeri döndür
        *option::borrow(&parameter.current_value.u64_value)
    }
    
    /// Boolean parametre değerini al
    public fun get_bool_parameter(
        registry: &ParameterRegistry,
        module_name: vector<u8>,
        parameter_name: vector<u8>
    ): bool {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow(&registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow(&module_params.parameters, param);
        
        // Parametre tipini kontrol et
        assert!(parameter.current_value.param_type == PARAM_TYPE_BOOL, EInvalidParameter);
        
        // Değeri döndür
        *option::borrow(&parameter.current_value.bool_value)
    }
    
    /// Vector parametre değerini al
    public fun get_vector_parameter(
        registry: &ParameterRegistry,
        module_name: vector<u8>,
        parameter_name: vector<u8>
    ): String {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow(&registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow(&module_params.parameters, param);
        
        // Parametre tipini kontrol et
        assert!(parameter.current_value.param_type == PARAM_TYPE_VECTOR, EInvalidParameter);
        
        // Değeri döndür
        *option::borrow(&parameter.current_value.vector_value)
    }
    
    /// Parametre bilgilerini al
    public fun get_parameter_info(
        registry: &ParameterRegistry,
        module_name: vector<u8>,
        parameter_name: vector<u8>
    ): (String, String, u8, u8, u64, Option<u64>, Option<u64>, Option<u64>) {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow(&registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow(&module_params.parameters, param);
        
        (
            parameter.name,
            parameter.description,
            parameter.category,
            parameter.current_value.param_type,
            parameter.last_updated,
            parameter.min_value,
            parameter.max_value,
            parameter.change_limit_pct
        )
    }
    
    /// Parametre değerini ParameterValue olarak al
    public fun get_parameter_value(
        registry: &ParameterRegistry,
        module_name: vector<u8>,
        parameter_name: vector<u8>
    ): ParameterValue {
        let module = string::utf8(module_name);
        let param = string::utf8(parameter_name);
        
        // Modülün var olup olmadığını kontrol et
        assert!(table::contains(&registry.modules, module), EModuleNotFound);
        
        // Modül parametrelerine erişim
        let module_params = table::borrow(&registry.modules, module);
        
        // Parametrenin var olup olmadığını kontrol et
        assert!(table::contains(&module_params.parameters, param), EParameterNotFound);
        
        // Parametreye erişim
        let parameter = table::borrow(&module_params.parameters, param);
        
        parameter.current_value
    }
    
    /// Soğuma süresini al
    public fun get_cooldown_period(registry: &ParameterRegistry): u64 {
        registry.cooldown_period
    }
    
    /// Parametre değişiklik geçmişinin uzunluğunu al
    public fun get_change_history_length(registry: &ParameterRegistry): u64 {
        vector::length(&registry.change_history)
    }
    
    /// Belirli bir indexteki parametre değişikliğini al
    public fun get_change_history_at(
        registry: &ParameterRegistry,
        index: u64
    ): ParameterChange {
        assert!(index < vector::length(&registry.change_history), EInvalidValue);
        *vector::borrow(&registry.change_history, index)
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_parameter_registry_for_testing(ctx: &mut TxContext): ParameterRegistry {
        ParameterRegistry {
            id: object::new(ctx),
            modules: table::new(ctx),
            last_updated: 0,
            change_history: vector::empty(),
            cooldown_period: 86400, // 1 gün (saniye)
        }
    }
    
    #[test_only]
    public fun create_test_parameter_value_u64(value: u64): ParameterValue {
        ParameterValue {
            param_type: PARAM_TYPE_U64,
            u64_value: option::some(value),
            bool_value: option::none(),
            vector_value: option::none(),
        }
    }
    
    #[test_only]
    public fun create_test_parameter_value_bool(value: bool): ParameterValue {
        ParameterValue {
            param_type: PARAM_TYPE_BOOL,
            u64_value: option::none(),
            bool_value: option::some(value),
            vector_value: option::none(),
        }
    }
}
