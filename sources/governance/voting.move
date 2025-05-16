/// SuiVPN Voting Module
/// 
/// Bu modül, SuiVPN protokolünün oylama mekanizmasını uygular. Protokolün yönetişim
/// sürecinde karar verme mekanizması olarak hizmet eder. Farklı oylama stratejileri,
/// delege etme mekanizmaları ve oy gücü hesaplama yöntemlerini içerir.
module suivpn::voting {
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
    use suivpn::token::{Self, SVPN};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidProposal: u64 = 1;
    const EInvalidVote: u64 = 2;
    const EAlreadyVoted: u64 = 3;
    const EVotingNotActive: u64 = 4;
    const EInsufficientVotingPower: u64 = 5;
    const EDelegationNotAllowed: u64 = 6;
    const EInvalidDelegation: u64 = 7;
    const EInvalidVotingStrategy: u64 = 8;
    const EInvalidParameter: u64 = 9;
    const EInvalidVotingPeriod: u64 = 10;
    const EInvalidVotingPower: u64 = 11;
    const EInvalidAddress: u64 = 12;
    
    // Oylama stratejileri
    const VOTING_STRATEGY_TOKEN_WEIGHTED: u8 = 0;    // Token ağırlıklı (1 token = 1 oy)
    const VOTING_STRATEGY_QUADRATIC: u8 = 1;         // Kuadratik oylama (oy gücü = sqrt(token sayısı))
    const VOTING_STRATEGY_REPUTATION_WEIGHTED: u8 = 2; // İtibar ağırlıklı oylama
    const VOTING_STRATEGY_ONE_VOTE: u8 = 3;          // Bir adres = bir oy
    
    // Oy tipleri
    const VOTE_YES: u8 = 1;
    const VOTE_NO: u8 = 2;
    const VOTE_ABSTAIN: u8 = 3;
    
    // Oylama durumları
    const VOTING_STATUS_PENDING: u8 = 0;
    const VOTING_STATUS_ACTIVE: u8 = 1;
    const VOTING_STATUS_COMPLETED: u8 = 2;
    const VOTING_STATUS_CANCELLED: u8 = 3;
    
    /// Oylama konfigürasyonu
    /// Protokolün oylama parametrelerini ve ayarlarını içerir
    struct VotingConfig has key, store {
        id: UID,
        // Varsayılan oylama stratejisi
        default_voting_strategy: u8,
        // Minimum oylama süresi (saniye)
        min_voting_duration: u64,
        // Maksimum oylama süresi (saniye)
        max_voting_duration: u64,
        // Minimum oy yüzdesi (binde)
        min_participation_threshold: u64,
        // Minimum geçiş yüzdesi (binde)
        min_approval_threshold: u64,
        // Delegasyon izni
        delegation_allowed: bool,
        // Maksimum delegasyon derinliği
        max_delegation_depth: u8,
        // Geçerli oylama stratejileri
        valid_voting_strategies: VecSet<u8>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Oylama
    /// Belirli bir konu hakkında oylama bilgilerini içerir
    struct Voting has key, store {
        id: UID,
        // Oylama başlığı
        title: String,
        // Oylama açıklaması
        description: String,
        // İlgili teklif ID'si (varsa)
        proposal_id: Option<ID>,
        // Oylama oluşturucu
        creator: address,
        // Oylama stratejisi
        voting_strategy: u8,
        // Oylama başlangıç zamanı
        start_time: u64,
        // Oylama bitiş zamanı
        end_time: u64,
        // Oylama durumu
        status: u8,
        // Toplam oy sayısı
        total_votes: u64,
        // Toplam oy gücü
        total_voting_power: u64,
        // Evet oyları (oy gücü)
        yes_votes: u64,
        // Hayır oyları (oy gücü)
        no_votes: u64,
        // Çekimser oyları (oy gücü)
        abstain_votes: u64,
        // Oy verenler (adres -> oy tipi)
        voters: Table<address, Vote>,
        // Delege edilmiş oylar (delege eden -> delege edilen)
        delegations: Table<address, address>,
        // Delege zinciri yönlendirici (adres -> delegate_to)
        // Bu tablo, delegasyon zincirini takip etmek için kullanılır
        delegation_chains: Table<address, address>,
        // Ters delegasyon tablosu (delege edilen -> [delege edenler]) 
        // Bu tablo, bir adrese hangi adreslerin delege ettiğini takip etmek için kullanılır
        reverse_delegations: Table<address, vector<address>>,
    }
    
    /// Oy
    /// Bir kullanıcının verdiği oyu temsil eder
    struct Vote has store, drop, copy {
        // Oy veren
        voter: address,
        // Oy tipi
        vote_type: u8,
        // Oy gücü
        voting_power: u64,
        // Oylama zamanı
        time: u64,
        // Delege edilmiş oylar dahil mi?
        includes_delegated: bool,
    }
    
    /// Delegasyon
    /// Bir kullanıcının oy hakkını başka bir kullanıcıya devretmesini temsil eder
    struct Delegation has key, store {
        id: UID,
        // Delege eden
        delegator: address,
        // Delege edilen
        delegate: address,
        // Delegasyon başlangıç zamanı
        start_time: u64,
        // Delegasyon bitiş zamanı (varsa)
        end_time: Option<u64>,
        // Aktif mi?
        is_active: bool,
    }
    
    /// VotingPower nesnesi
    /// Bir kullanıcının oy gücünü temsil eder ve oy kullanırken bu nesne gerekir
    struct VotingPower has key, store {
        id: UID,
        // Sahibi
        owner: address,
        // Temel oy gücü
        base_power: u64,
        // Delege edilmiş oy gücü
        delegated_power: u64,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    // Eventler
    
    /// Oylama oluşturma eventi
    struct VotingCreated has copy, drop {
        voting_id: ID,
        title: String,
        creator: address,
        strategy: u8,
        start_time: u64,
        end_time: u64,
    }
    
    /// Oy kullanma eventi
    struct VoteCast has copy, drop {
        voting_id: ID,
        voter: address,
        vote_type: u8,
        voting_power: u64,
        time: u64,
    }
    
    /// Oylama durumu değişikliği eventi
    struct VotingStatusChanged has copy, drop {
        voting_id: ID,
        old_status: u8,
        new_status: u8,
        time: u64,
    }
    
    /// Delegasyon eventi
    struct DelegationCreated has copy, drop {
        delegation_id: ID,
        delegator: address,
        delegate: address,
        time: u64,
    }
    
    /// Delegasyon iptal eventi
    struct DelegationRevoked has copy, drop {
        delegation_id: ID,
        delegator: address,
        delegate: address,
        time: u64,
    }
    
    /// Oylama sonucu eventi
    struct VotingResult has copy, drop {
        voting_id: ID,
        title: String,
        total_votes: u64,
        total_power: u64,
        yes_votes: u64,
        no_votes: u64,
        abstain_votes: u64,
        passed: bool,
        time: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let voting_config = VotingConfig {
            id: object::new(ctx),
            default_voting_strategy: VOTING_STRATEGY_TOKEN_WEIGHTED,
            min_voting_duration: 86400, // 1 gün (saniye)
            max_voting_duration: 1209600, // 14 gün (saniye)
            min_participation_threshold: 100, // %10 (binde)
            min_approval_threshold: 667, // %66.7 (binde)
            delegation_allowed: true,
            max_delegation_depth: 2,
            valid_voting_strategies: vec_set::empty(),
            last_updated: 0,
        };
        
        // Geçerli oylama stratejilerini ekle
        vec_set::insert(&mut voting_config.valid_voting_strategies, VOTING_STRATEGY_TOKEN_WEIGHTED);
        vec_set::insert(&mut voting_config.valid_voting_strategies, VOTING_STRATEGY_QUADRATIC);
        vec_set::insert(&mut voting_config.valid_voting_strategies, VOTING_STRATEGY_REPUTATION_WEIGHTED);
        vec_set::insert(&mut voting_config.valid_voting_strategies, VOTING_STRATEGY_ONE_VOTE);
        
        transfer::share_object(voting_config);
    }
    
    /// Yeni bir oylama oluştur
    public entry fun create_voting(
        voting_config: &VotingConfig,
        title: vector<u8>,
        description: vector<u8>,
        voting_strategy: u8,
        voting_duration: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Oylama stratejisinin geçerli olup olmadığını kontrol et
        assert!(vec_set::contains(&voting_config.valid_voting_strategies, &voting_strategy), EInvalidVotingStrategy);
        
        // Oylama süresinin geçerli aralıkta olup olmadığını kontrol et
        assert!(
            voting_duration >= voting_config.min_voting_duration && 
            voting_duration <= voting_config.max_voting_duration,
            EInvalidVotingPeriod
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni oylama nesnesi oluştur
        let voting = Voting {
            id: object::new(ctx),
            title: string::utf8(title),
            description: string::utf8(description),
            proposal_id: option::none(),
            creator: sender,
            voting_strategy,
            start_time: now,
            end_time: now + voting_duration,
            status: VOTING_STATUS_ACTIVE,
            total_votes: 0,
            total_voting_power: 0,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            voters: table::new(ctx),
            delegations: table::new(ctx),
            delegation_chains: table::new(ctx),
            reverse_delegations: table::new(ctx),
        };
        
        // Oylama oluşturma eventini yayınla
        event::emit(VotingCreated {
            voting_id: object::id(&voting),
            title: string::utf8(title),
            creator: sender,
            strategy: voting_strategy,
            start_time: now,
            end_time: now + voting_duration,
        });
        
        transfer::share_object(voting);
    }
    
    /// Teklif için oylama oluştur
    public entry fun create_proposal_voting(
        voting_config: &VotingConfig,
        title: vector<u8>,
        description: vector<u8>,
        proposal_id: ID,
        voting_strategy: u8,
        voting_duration: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Oylama stratejisinin geçerli olup olmadığını kontrol et
        assert!(vec_set::contains(&voting_config.valid_voting_strategies, &voting_strategy), EInvalidVotingStrategy);
        
        // Oylama süresinin geçerli aralıkta olup olmadığını kontrol et
        assert!(
            voting_duration >= voting_config.min_voting_duration && 
            voting_duration <= voting_config.max_voting_duration,
            EInvalidVotingPeriod
        );
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Yeni oylama nesnesi oluştur
        let voting = Voting {
            id: object::new(ctx),
            title: string::utf8(title),
            description: string::utf8(description),
            proposal_id: option::some(proposal_id),
            creator: sender,
            voting_strategy,
            start_time: now,
            end_time: now + voting_duration,
            status: VOTING_STATUS_ACTIVE,
            total_votes: 0,
            total_voting_power: 0,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            voters: table::new(ctx),
            delegations: table::new(ctx),
            delegation_chains: table::new(ctx),
            reverse_delegations: table::new(ctx),
        };
        
        // Oylama oluşturma eventini yayınla
        event::emit(VotingCreated {
            voting_id: object::id(&voting),
            title: string::utf8(title),
            creator: sender,
            strategy: voting_strategy,
            start_time: now,
            end_time: now + voting_duration,
        });
        
        transfer::share_object(voting);
    }
    
    /// Oy kullan
    public entry fun cast_vote(
        voting: &mut Voting,
        vote_type: u8,
        voting_power_amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Oylamanın aktif olup olmadığını kontrol et
        assert!(voting.status == VOTING_STATUS_ACTIVE, EVotingNotActive);
        
        // Oylamanın süresini kontrol et
        assert!(now >= voting.start_time && now <= voting.end_time, EVotingNotActive);
        
        // Kullanıcının daha önce oy kullanıp kullanmadığını kontrol et
        assert!(!table::contains(&voting.voters, sender), EAlreadyVoted);
        
        // Oyun geçerli olup olmadığını kontrol et
        assert!(vote_type == VOTE_YES || vote_type == VOTE_NO || vote_type == VOTE_ABSTAIN, EInvalidVote);
        
        // Oy gücünün yeterli olup olmadığını kontrol et
        assert!(voting_power_amount > 0, EInsufficientVotingPower);
        
        // Delegasyon zincirini kontrol et ve delegasyonları dahil et
        let actual_voting_power = voting_power_amount;
        let includes_delegated = false;
        
        if (voting.voting_strategy == VOTING_STRATEGY_TOKEN_WEIGHTED) {
            // Token ağırlıklı oylama için delegasyon kontrolü
            if (voting_config.delegation_allowed && table::contains(&voting.reverse_delegations, sender)) {
                let delegators = table::borrow(&voting.reverse_delegations, sender);
                let delegated_power = calculate_delegated_power(delegators, voting_power_amount);
                actual_voting_power = actual_voting_power + delegated_power;
                includes_delegated = true;
            };
        } else if (voting.voting_strategy == VOTING_STRATEGY_QUADRATIC) {
            // Kuadratik oylama için oy gücü hesaplaması
            // Burada basit bir yaklaşım kullanıyoruz: sqrt(token_amount)
            actual_voting_power = (voting_power_amount as u64); // TODO: Gerçek kuadratik formül
        } else if (voting.voting_strategy == VOTING_STRATEGY_ONE_VOTE) {
            // Bir adres = bir oy stratejisi için sabit oy gücü
            actual_voting_power = 1;
        };
        // VOTING_STRATEGY_REPUTATION_WEIGHTED için özel hesaplama gerekecek
        
        // Oy nesnesini oluştur
        let vote = Vote {
            voter: sender,
            vote_type,
            voting_power: actual_voting_power,
            time: now,
            includes_delegated,
        };
        
        // Oyu kaydet
        table::add(&mut voting.voters, sender, vote);
        
        // Oy sayılarını güncelle
        if (vote_type == VOTE_YES) {
            voting.yes_votes = voting.yes_votes + actual_voting_power;
        } else if (vote_type == VOTE_NO) {
            voting.no_votes = voting.no_votes + actual_voting_power;
        } else if (vote_type == VOTE_ABSTAIN) {
            voting.abstain_votes = voting.abstain_votes + actual_voting_power;
        };
        
        voting.total_votes = voting.total_votes + 1;
        voting.total_voting_power = voting.total_voting_power + actual_voting_power;
        
        // Oy kullanma eventini yayınla
        event::emit(VoteCast {
            voting_id: object::id(voting),
            voter: sender,
            vote_type,
            voting_power: actual_voting_power,
            time: now,
        });
    }
    
    /// Delegasyon oluştur
    public entry fun create_delegation(
        voting_config: &VotingConfig,
        delegate_to: address,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Delegasyonun izin verilip verilmediğini kontrol et
        assert!(voting_config.delegation_allowed, EDelegationNotAllowed);
        
        // Kendine delegasyon kontrolü
        assert!(sender != delegate_to, EInvalidDelegation);
        
        // Delegasyon döngüsü kontrolü (A -> B -> A gibi)
        // Bu daha karmaşık bir kontrol gerektirir ve gerçek uygulamada
        // delegasyon zinciri boyunca kontrol yapılmalıdır.
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Delegasyon nesnesi oluştur
        let delegation = Delegation {
            id: object::new(ctx),
            delegator: sender,
            delegate: delegate_to,
            start_time: now,
            end_time: option::none(),
            is_active: true,
        };
        
        // Delegasyon oluşturma eventini yayınla
        event::emit(DelegationCreated {
            delegation_id: object::id(&delegation),
            delegator: sender,
            delegate: delegate_to,
            time: now,
        });
        
        transfer::transfer(delegation, sender);
    }
    
    /// Delegasyonu iptal et
    public entry fun revoke_delegation(
        delegation: &mut Delegation,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        
        // Delegasyon sahibini kontrol et
        assert!(sender == delegation.delegator, ENotAuthorized);
        
        // Delegasyonun aktif olup olmadığını kontrol et
        assert!(delegation.is_active, EInvalidDelegation);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Delegasyonu deaktive et
        delegation.is_active = false;
        delegation.end_time = option::some(now);
        
        // Delegasyon iptal eventini yayınla
        event::emit(DelegationRevoked {
            delegation_id: object::id(delegation),
            delegator: delegation.delegator,
            delegate: delegation.delegate,
            time: now,
        });
    }
    
    /// Oylama sonucunu hesapla ve sonlandır
    public entry fun finalize_voting(
        voting: &mut Voting,
        voting_config: &VotingConfig,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Oylamanın aktif olup olmadığını kontrol et
        assert!(voting.status == VOTING_STATUS_ACTIVE, EVotingNotActive);
        
        // Oylamanın süresinin bitip bitmediğini kontrol et
        assert!(now > voting.end_time, EVotingNotActive);
        
        let old_status = voting.status;
        
        // Katılım oranını kontrol et (toplam oy gücü / potansiyel oy gücü)
        // Gerçek uygulamada, potansiyel oy gücü hesaplanmalıdır
        // Burada basitçe min_participation_threshold'u kullanıyoruz
        
        // Sonucu hesapla
        let total_valid_votes = voting.yes_votes + voting.no_votes;
        let approval_threshold = (total_valid_votes * voting_config.min_approval_threshold) / 1000;
        
        let passed = voting.yes_votes >= approval_threshold;
        
        // Oylama durumunu güncelle
        voting.status = VOTING_STATUS_COMPLETED;
        
        // Oylama durumu değişikliği eventini yayınla
        event::emit(VotingStatusChanged {
            voting_id: object::id(voting),
            old_status,
            new_status: voting.status,
            time: now,
        });
        
        // Oylama sonucu eventini yayınla
        event::emit(VotingResult {
            voting_id: object::id(voting),
            title: voting.title,
            total_votes: voting.total_votes,
            total_power: voting.total_voting_power,
            yes_votes: voting.yes_votes,
            no_votes: voting.no_votes,
            abstain_votes: voting.abstain_votes,
            passed,
            time: now,
        });
    }
    
    /// Oylama konfigürasyonunu güncelle
    public entry fun update_voting_config(
        voting_config: &mut VotingConfig,
        governance_cap: &GovernanceCapability,
        default_strategy: u8,
        min_duration: u64,
        max_duration: u64,
        min_participation: u64,
        min_approval: u64,
        allow_delegation: bool,
        max_delegation_depth: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Parametrelerin geçerliliğini kontrol et
        assert!(vec_set::contains(&voting_config.valid_voting_strategies, &default_strategy), EInvalidVotingStrategy);
        assert!(min_duration > 0 && max_duration > min_duration, EInvalidVotingPeriod);
        assert!(min_participation > 0 && min_participation <= 1000, EInvalidParameter);
        assert!(min_approval > 0 && min_approval <= 1000, EInvalidParameter);
        assert!(max_delegation_depth <= 5, EInvalidParameter); // Aşırı delegasyon derinliğini sınırla
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Konfigürasyonu güncelle
        voting_config.default_voting_strategy = default_strategy;
        voting_config.min_voting_duration = min_duration;
        voting_config.max_voting_duration = max_duration;
        voting_config.min_participation_threshold = min_participation;
        voting_config.min_approval_threshold = min_approval;
        voting_config.delegation_allowed = allow_delegation;
        voting_config.max_delegation_depth = max_delegation_depth;
        voting_config.last_updated = now;
    }
    
    /// Oylama konfigürasyonuna yeni bir oylama stratejisi ekle
    public entry fun add_voting_strategy(
        voting_config: &mut VotingConfig,
        governance_cap: &GovernanceCapability,
        strategy: u8,
        ctx: &mut TxContext
    ) {
        // Stratejinin zaten ekli olup olmadığını kontrol et
        assert!(!vec_set::contains(&voting_config.valid_voting_strategies, &strategy), EInvalidVotingStrategy);
        
        // Sadece geçerli strateji değerlerini kabul et (0-3)
        assert!(strategy <= VOTING_STRATEGY_ONE_VOTE, EInvalidVotingStrategy);
        
        // Stratejiyi ekle
        vec_set::insert(&mut voting_config.valid_voting_strategies, strategy);
    }
    
    /// Oylama konfigürasyonundan bir oylama stratejisini kaldır
    public entry fun remove_voting_strategy(
        voting_config: &mut VotingConfig,
        governance_cap: &GovernanceCapability,
        strategy: u8,
        ctx: &mut TxContext
    ) {
        // Stratejinin var olup olmadığını kontrol et
        assert!(vec_set::contains(&voting_config.valid_voting_strategies, &strategy), EInvalidVotingStrategy);
        
        // En az bir strateji kalmalı
        assert!(vec_set::size(&voting_config.valid_voting_strategies) > 1, EInvalidVotingStrategy);
        
        // Varsayılan strateji kaldırılamaz
        assert!(strategy != voting_config.default_voting_strategy, EInvalidVotingStrategy);
        
        // Stratejiyi kaldır
        vec_set::remove(&mut voting_config.valid_voting_strategies, &strategy);
    }
    
    // Yardımcı fonksiyonlar
    
    /// Delege edilmiş oy gücünü hesapla
    fun calculate_delegated_power(delegators: &vector<address>, base_power: u64): u64 {
        let delegated_power = 0;
        
        // Bu basitleştirilmiş bir hesaplamadır
        // Gerçekte, her delege edenin token miktarı veya oy gücü hesaplanmalıdır
        
        let len = vector::length(delegators);
        let i = 0;
        
        while (i < len) {
            // Her delegatör için baz güce bir miktar ekle
            // Bu basit bir tahmin, gerçek uygulamada delegatörün gerçek token miktarı baz alınmalıdır
            delegated_power = delegated_power + base_power / 10;
            i = i + 1;
        };
        
        delegated_power
    }
    
    /// Oy gücü hesapla (strateji bazlı)
    public fun calculate_voting_power(
        voter: address,
        token_amount: u64,
        voting_strategy: u8
    ): u64 {
        if (voting_strategy == VOTING_STRATEGY_TOKEN_WEIGHTED) {
            // 1 token = 1 oy
            token_amount
        } else if (voting_strategy == VOTING_STRATEGY_QUADRATIC) {
            // sqrt(token_amount) - basitleştirilmiş
            // Gerçek kuadratik formül daha karmaşıktır
            (token_amount as u64) // TODO: implement sqrt
        } else if (voting_strategy == VOTING_STRATEGY_ONE_VOTE) {
            // Her adres için 1 oy
            1
        } else if (voting_strategy == VOTING_STRATEGY_REPUTATION_WEIGHTED) {
            // İtibar bazlı oy gücü
            // Bu implementasyon, itibar sistemine erişim gerektirir
            token_amount // Basitleştirilmiş, gerçekte itibar değeri kullanılmalıdır
        } else {
            // Bilinmeyen strateji
            0
        }
    }
    
    /// Bir oylamanın sonucunu kontrol et
    public fun check_voting_result(
        voting: &Voting,
        voting_config: &VotingConfig
    ): bool {
        // Oylamanın tamamlanıp tamamlanmadığını kontrol et
        if (voting.status != VOTING_STATUS_COMPLETED) {
            return false
        };
        
        // Toplam geçerli oyları hesapla
        let total_valid_votes = voting.yes_votes + voting.no_votes;
        
        // Gerekli onay eşiğini hesapla
        let approval_threshold = (total_valid_votes * voting_config.min_approval_threshold) / 1000;
        
        // Sonucu kontrol et
        voting.yes_votes >= approval_threshold
    }
    
    /// Bir kullanıcının oy kullanıp kullanmadığını kontrol et
    public fun has_voted(voting: &Voting, voter: address): bool {
        table::contains(&voting.voters, voter)
    }
    
    /// Bir kullanıcının nasıl oy kullandığını kontrol et
    public fun get_vote(voting: &Voting, voter: address): Vote {
        assert!(table::contains(&voting.voters, voter), EInvalidAddress);
        *table::borrow(&voting.voters, voter)
    }
    
    /// Oylama bilgilerini al
    public fun get_voting_info(voting: &Voting): (
        String, String, Option<ID>, address, u8, u64, u64, u8, u64, u64, u64, u64, u64
    ) {
        (
            voting.title,
            voting.description,
            voting.proposal_id,
            voting.creator,
            voting.voting_strategy,
            voting.start_time,
            voting.end_time,
            voting.status,
            voting.total_votes,
            voting.total_voting_power,
            voting.yes_votes,
            voting.no_votes,
            voting.abstain_votes
        )
    }
    
    /// Oylama konfigürasyon bilgilerini al
    public fun get_voting_config_info(voting_config: &VotingConfig): (
        u8, u64, u64, u64, u64, bool, u8, u64
    ) {
        (
            voting_config.default_voting_strategy,
            voting_config.min_voting_duration,
            voting_config.max_voting_duration,
            voting_config.min_participation_threshold,
            voting_config.min_approval_threshold,
            voting_config.delegation_allowed,
            voting_config.max_delegation_depth,
            voting_config.last_updated
        )
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_voting_config_for_testing(ctx: &mut TxContext): VotingConfig {
        let voting_config = VotingConfig {
            id: object::new(ctx),
            default_voting_strategy: VOTING_STRATEGY_TOKEN_WEIGHTED,
            min_voting_duration: 86400, // 1 gün (saniye)
            max_voting_duration: 1209600, // 14 gün (saniye)
            min_participation_threshold: 100, // %10 (binde)
            min_approval_threshold: 667, // %66.7 (binde)
            delegation_allowed: true,
            max_delegation_depth: 2,
            valid_voting_strategies: vec_set::empty(),
            last_updated: 0,
        }
    }
}
