/// SuiVPN Governance Module
/// 
/// Bu modül, SuiVPN protokolünün yönetişim süreçlerini yönetir. DAO yapısını,
/// teklifleri, oy verme mekanizmasını ve protokol güncellemelerini içerir.
/// Protokolün merkeziyetsiz ve demokratik yönetişimini sağlar.
module suivpn::governance {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::vec_map::{Self, VecMap};
    use sui::vec_set::{Self, VecSet};
    use sui::dynamic_field as df;
    use suivpn::token::{Self, SVPN};
    use std::string::{Self, String};
    use std::vector;
    use std::option::{Self, Option};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidProposal: u64 = 1;
    const EProposalNotActive: u64 = 2;
    const EProposalAlreadyVoted: u64 = 3;
    const EInvalidVote: u64 = 4;
    const EInsufficientVotingPower: u64 = 5;
    const EProposalNotFinalized: u64 = 6;
    const EProposalAlreadyFinalized: u64 = 7;
    const EProposalRejected: u64 = 8;
    const EInvalidThreshold: u64 = 9;
    const EInvalidDuration: u64 = 10;
    const EInvalidParameter: u64 = 11;
    const EVotingNotStarted: u64 = 12;
    const EVotingNotEnded: u64 = 13;
    
    // Proposal durumları
    const PROPOSAL_STATUS_PENDING: u8 = 0;
    const PROPOSAL_STATUS_ACTIVE: u8 = 1;
    const PROPOSAL_STATUS_PASSED: u8 = 2;
    const PROPOSAL_STATUS_REJECTED: u8 = 3;
    const PROPOSAL_STATUS_EXECUTED: u8 = 4;
    const PROPOSAL_STATUS_CANCELLED: u8 = 5;
    
    // Proposal tipleri
    const PROPOSAL_TYPE_PARAMETER_CHANGE: u8 = 0;
    const PROPOSAL_TYPE_UPGRADE: u8 = 1;
    const PROPOSAL_TYPE_FUNDING: u8 = 2;
    const PROPOSAL_TYPE_TEXT: u8 = 3;
    
    // Oy tipleri
    const VOTE_YES: u8 = 1;
    const VOTE_NO: u8 = 2;
    const VOTE_ABSTAIN: u8 = 3;
    
    /// Yönetişim yetkisi
    /// Bu yetenek, sadece protokolün ilk kurulumunda oluşturulur ve
    /// yönetişim fonksiyonlarını çağırmak için kullanılır.
    struct GovernanceCapability has key, store {
        id: UID,
    }
    
    /// Yönetişim konfigürasyonu
    /// Protokolün yönetişim parametrelerini içerir.
    struct GovernanceConfig has key, store {
        id: UID,
        // Minimum teklif oluşturma gücü (1000 SVPN token = 1000_000_000)
        min_proposal_power: u64,
        // Teklifin geçmesi için gereken minimum oy oranı (binde)
        min_approval_threshold: u64,
        // Teklifin geçerli sayılması için gereken minimum katılım oranı (binde)
        min_quorum_threshold: u64,
        // Teklif süresi (saniye)
        proposal_duration: u64,
        // Teklif yürütme gecikmesi (saniye)
        execution_delay: u64,
        // Son güncelleme zamanı
        last_updated: u64,
        // Toplam teklif sayısı
        total_proposals: u64,
        // Protokol hazine adresi
        treasury: address,
        // Yönetişim forum adresi
        forum_url: String,
        // Aktif teklifler
        active_proposals: VecSet<ID>,
    }
    
    /// Teklif yapısı
    /// Bir yönetişim teklifi hakkında tüm bilgileri içerir.
    struct Proposal has key, store {
        id: UID,
        // Teklif sahibi
        proposer: address,
        // Teklif başlığı
        title: String,
        // Teklif açıklaması
        description: String,
        // Teklif türü
        proposal_type: u8,
        // Teklif verileri (tipe bağlı olarak farklı yapılar)
        // df olarak saklanır
        // Teklif oluşturma zamanı
        created_at: u64,
        // Oylama başlangıç zamanı
        voting_start: u64,
        // Oylama bitiş zamanı 
        voting_end: u64,
        // Teklif durumu
        status: u8,
        // Evet oyları
        yes_votes: u64,
        // Hayır oyları 
        no_votes: u64,
        // Çekimser oyları
        abstain_votes: u64,
        // Toplam oy gücü
        total_voting_power: u64,
        // Oy kullananlar
        voters: VecSet<address>,
        // Yürütme zamanı (geçerse)
        execution_time: u64,
        // Teklif numarası
        proposal_id: u64,
    }
    
    /// Parametre değişikliği verisi
    struct ParameterChangeData has store, drop {
        // Parametre adı
        name: String,
        // Mevcut değer
        current_value: u64,
        // Yeni değer
        new_value: u64,
        // Parametre açıklaması
        description: String,
    }
    
    /// Fon aktarımı verisi
    struct FundingData has store, drop {
        // Alıcı adresi
        recipient: address,
        // Miktar
        amount: u64,
        // Kullanım amacı
        purpose: String,
    }
    
    /// Oy kaydı yapısı
    struct VoteRecord has store, drop {
        // Oy veren
        voter: address,
        // Oy tipi
        vote: u8,
        // Oy gücü
        power: u64,
        // Oy zamanı
        time: u64,
    }
    
    /// Veto yetkisi
    /// Bu yetenek, kritik durumlarda teklifleri veto etme yetkisi verir.
    /// Çoklu imza ile korunur ve sadece acil durumlarda kullanılır.
    struct VetoCapability has key {
        id: UID,
        // Veto kullananlar
        veto_history: vector<ID>,
    }
    
    // Eventler
    
    /// Teklif oluşturma eventi
    struct ProposalCreated has copy, drop {
        proposal_id: ID,
        proposer: address,
        title: String,
        proposal_type: u8,
        voting_start: u64,
        voting_end: u64,
    }
    
    /// Oy kullanma eventi
    struct VoteCast has copy, drop {
        proposal_id: ID,
        voter: address,
        vote: u8,
        power: u64,
    }
    
    /// Teklif durumu değişikliği eventi
    struct ProposalStatusChanged has copy, drop {
        proposal_id: ID,
        old_status: u8,
        new_status: u8,
        time: u64,
    }
    
    /// Yönetişim parametresi değişikliği eventi
    struct GovernanceConfigUpdated has copy, drop {
        parameter: String,
        old_value: u64,
        new_value: u64,
        time: u64,
    }
    
    /// Teklif yürütme eventi
    struct ProposalExecuted has copy, drop {
        proposal_id: ID,
        execution_time: u64,
    }
    
    /// Veto eventi
    struct ProposalVetoed has copy, drop {
        proposal_id: ID,
        veto_time: u64,
        reason: String,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let governance_cap = GovernanceCapability {
            id: object::new(ctx),
        };
        
        let governance_config = GovernanceConfig {
            id: object::new(ctx),
            min_proposal_power: 50_000_000_000, // 50,000 SVPN
            min_approval_threshold: 667, // %66.7
            min_quorum_threshold: 334, // %33.4
            proposal_duration: 604800, // 7 gün
            execution_delay: 172800, // 2 gün
            last_updated: 0,
            total_proposals: 0,
            treasury: tx_context::sender(ctx),
            forum_url: string::utf8(b"https://forum.suivpn.com"),
            active_proposals: vec_set::empty(),
        };
        
        let veto_cap = VetoCapability {
            id: object::new(ctx),
            veto_history: vector::empty(),
        };
        
        // İlk kurulumda, yetki modül dağıtıcısına gider
        transfer::transfer(governance_cap, tx_context::sender(ctx));
        transfer::share_object(governance_config);
        transfer::transfer(veto_cap, tx_context::sender(ctx));
    }
    
    /// Yeni bir metin teklifi oluştur
    public entry fun create_text_proposal(
        governance_config: &mut GovernanceConfig,
        title: vector<u8>,
        description: vector<u8>,
        staked_token_amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let voting_power = staked_token_amount;
        
        // Teklif verme gücünün yeterli olup olmadığını kontrol et
        assert!(voting_power >= governance_config.min_proposal_power, EInsufficientVotingPower);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        let proposal_id = governance_config.total_proposals + 1;
        governance_config.total_proposals = proposal_id;
        
        let proposal = Proposal {
            id: object::new(ctx),
            proposer: tx_context::sender(ctx),
            title: string::utf8(title),
            description: string::utf8(description),
            proposal_type: PROPOSAL_TYPE_TEXT,
            created_at: now,
            voting_start: now,
            voting_end: now + governance_config.proposal_duration,
            status: PROPOSAL_STATUS_ACTIVE,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_voting_power: 0,
            voters: vec_set::empty(),
            execution_time: 0,
            proposal_id,
        };
        
        let proposal_id_obj = object::id(&proposal);
        vec_set::insert(&mut governance_config.active_proposals, proposal_id_obj);
        
        // Teklif oluşturma eventini yayınla
        event::emit(ProposalCreated {
            proposal_id: proposal_id_obj,
            proposer: tx_context::sender(ctx),
            title: string::utf8(title),
            proposal_type: PROPOSAL_TYPE_TEXT,
            voting_start: now,
            voting_end: now + governance_config.proposal_duration,
        });
        
        transfer::share_object(proposal);
    }
    
    /// Parametre değişikliği teklifi oluştur
    public entry fun create_parameter_change_proposal(
        governance_config: &mut GovernanceConfig,
        title: vector<u8>,
        description: vector<u8>,
        param_name: vector<u8>,
        current_value: u64,
        new_value: u64,
        param_description: vector<u8>,
        staked_token_amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let voting_power = staked_token_amount;
        
        // Teklif verme gücünün yeterli olup olmadığını kontrol et
        assert!(voting_power >= governance_config.min_proposal_power, EInsufficientVotingPower);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        let proposal_id = governance_config.total_proposals + 1;
        governance_config.total_proposals = proposal_id;
        
        let proposal = Proposal {
            id: object::new(ctx),
            proposer: tx_context::sender(ctx),
            title: string::utf8(title),
            description: string::utf8(description),
            proposal_type: PROPOSAL_TYPE_PARAMETER_CHANGE,
            created_at: now,
            voting_start: now,
            voting_end: now + governance_config.proposal_duration,
            status: PROPOSAL_STATUS_ACTIVE,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_voting_power: 0,
            voters: vec_set::empty(),
            execution_time: 0,
            proposal_id,
        };
        
        // Parametre değişikliği verisini ekle
        df::add(&mut proposal.id, b"parameter_data", ParameterChangeData {
            name: string::utf8(param_name),
            current_value,
            new_value,
            description: string::utf8(param_description),
        });
        
        let proposal_id_obj = object::id(&proposal);
        vec_set::insert(&mut governance_config.active_proposals, proposal_id_obj);
        
        // Teklif oluşturma eventini yayınla
        event::emit(ProposalCreated {
            proposal_id: proposal_id_obj,
            proposer: tx_context::sender(ctx),
            title: string::utf8(title),
            proposal_type: PROPOSAL_TYPE_PARAMETER_CHANGE,
            voting_start: now,
            voting_end: now + governance_config.proposal_duration,
        });
        
        transfer::share_object(proposal);
    }
    
    /// Fonlama teklifi oluştur
    public entry fun create_funding_proposal(
        governance_config: &mut GovernanceConfig,
        title: vector<u8>,
        description: vector<u8>,
        recipient: address,
        amount: u64,
        purpose: vector<u8>,
        staked_token_amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let voting_power = staked_token_amount;
        
        // Teklif verme gücünün yeterli olup olmadığını kontrol et
        assert!(voting_power >= governance_config.min_proposal_power, EInsufficientVotingPower);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        let proposal_id = governance_config.total_proposals + 1;
        governance_config.total_proposals = proposal_id;
        
        let proposal = Proposal {
            id: object::new(ctx),
            proposer: tx_context::sender(ctx),
            title: string::utf8(title),
            description: string::utf8(description),
            proposal_type: PROPOSAL_TYPE_FUNDING,
            created_at: now,
            voting_start: now,
            voting_end: now + governance_config.proposal_duration,
            status: PROPOSAL_STATUS_ACTIVE,
            yes_votes: 0,
            no_votes: 0,
            abstain_votes: 0,
            total_voting_power: 0,
            voters: vec_set::empty(),
            execution_time: 0,
            proposal_id,
        };
        
        // Fonlama verisini ekle
        df::add(&mut proposal.id, b"funding_data", FundingData {
            recipient,
            amount,
            purpose: string::utf8(purpose),
        });
        
        let proposal_id_obj = object::id(&proposal);
        vec_set::insert(&mut governance_config.active_proposals, proposal_id_obj);
        
        // Teklif oluşturma eventini yayınla
        event::emit(ProposalCreated {
            proposal_id: proposal_id_obj,
            proposer: tx_context::sender(ctx),
            title: string::utf8(title),
            proposal_type: PROPOSAL_TYPE_FUNDING,
            voting_start: now,
            voting_end: now + governance_config.proposal_duration,
        });
        
        transfer::share_object(proposal);
    }
    
    /// Teklif üzerinde oy kullan
    public entry fun cast_vote(
        proposal: &mut Proposal,
        governance_config: &mut GovernanceConfig,
        vote: u8,
        voting_power: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Teklifin aktif olup olmadığını kontrol et
        assert!(proposal.status == PROPOSAL_STATUS_ACTIVE, EProposalNotActive);
        
        // Oylama sürecinin başlayıp başlamadığını kontrol et
        assert!(now >= proposal.voting_start, EVotingNotStarted);
        
        // Oylama sürecinin bitip bitmediğini kontrol et
        assert!(now <= proposal.voting_end, EVotingNotEnded);
        
        // Kullanıcının daha önce oy kullanıp kullanmadığını kontrol et
        assert!(!vec_set::contains(&proposal.voters, &sender), EProposalAlreadyVoted);
        
        // Oyun geçerli olup olmadığını kontrol et
        assert!(vote == VOTE_YES || vote == VOTE_NO || vote == VOTE_ABSTAIN, EInvalidVote);
        
        // Oy gücünün yeterli olup olmadığını kontrol et
        assert!(voting_power > 0, EInsufficientVotingPower);
        
        // Oyu kaydet
        if (vote == VOTE_YES) {
            proposal.yes_votes = proposal.yes_votes + voting_power;
        } else if (vote == VOTE_NO) {
            proposal.no_votes = proposal.no_votes + voting_power;
        } else if (vote == VOTE_ABSTAIN) {
            proposal.abstain_votes = proposal.abstain_votes + voting_power;
        };
        
        proposal.total_voting_power = proposal.total_voting_power + voting_power;
        vec_set::insert(&mut proposal.voters, sender);
        
        // Oy kaydını ekle
        let vote_record = VoteRecord {
            voter: sender,
            vote,
            power: voting_power,
            time: now,
        };
        
        // Dinamik alan olarak oy kaydını sakla
        let voter_key = std::string::utf8(b"vote_");
        let voter_key_str = std::string::append(&mut voter_key, std::string::from_ascii(std::ascii::into_bytes(std::ascii::string(sender))));
        df::add(&mut proposal.id, std::string::bytes(&voter_key_str), vote_record);
        
        // Oy kullanma eventini yayınla
        event::emit(VoteCast {
            proposal_id: object::id(proposal),
            voter: sender,
            vote,
            power: voting_power,
        });
    }
    
    /// Teklif durumunu güncelle
    public entry fun finalize_proposal(
        proposal: &mut Proposal,
        governance_config: &mut GovernanceConfig,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Teklifin aktif olup olmadığını kontrol et
        assert!(proposal.status == PROPOSAL_STATUS_ACTIVE, EProposalNotActive);
        
        // Oylama sürecinin bitip bitmediğini kontrol et
        assert!(now > proposal.voting_end, EVotingNotEnded);
        
        // Teklifin durumunu belirle
        let total_votes = proposal.yes_votes + proposal.no_votes;
        let quorum_threshold = (proposal.total_voting_power * governance_config.min_quorum_threshold) / 1000;
        
        let old_status = proposal.status;
        
        if (total_votes >= quorum_threshold) {
            let approval_threshold = (total_votes * governance_config.min_approval_threshold) / 1000;
            
            if (proposal.yes_votes >= approval_threshold) {
                // Teklif kabul edildi
                proposal.status = PROPOSAL_STATUS_PASSED;
                proposal.execution_time = now + governance_config.execution_delay;
            } else {
                // Teklif reddedildi
                proposal.status = PROPOSAL_STATUS_REJECTED;
            };
        } else {
            // Yeterli katılım sağlanamadı
            proposal.status = PROPOSAL_STATUS_REJECTED;
        };
        
        // Aktif teklifler listesinden çıkar
        vec_set::remove(&mut governance_config.active_proposals, &object::id(proposal));
        
        // Teklif durumu değişikliği eventini yayınla
        event::emit(ProposalStatusChanged {
            proposal_id: object::id(proposal),
            old_status,
            new_status: proposal.status,
            time: now,
        });
    }
    
    /// Kabul edilen bir teklifi yürüt
    public entry fun execute_proposal(
        proposal: &mut Proposal,
        governance_cap: &GovernanceCapability,
        governance_config: &mut GovernanceConfig,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Teklifin kabul edilip edilmediğini kontrol et
        assert!(proposal.status == PROPOSAL_STATUS_PASSED, EProposalRejected);
        
        // Teklifin yürütme zamanının gelip gelmediğini kontrol et
        assert!(now >= proposal.execution_time, EProposalNotFinalized);
        
        // Teklif tipine göre işlemi gerçekleştir
        if (proposal.proposal_type == PROPOSAL_TYPE_PARAMETER_CHANGE && df::exists_(&proposal.id, b"parameter_data")) {
            // Parametre değişikliği verilerini al
            let parameter_data: &ParameterChangeData = df::borrow(&proposal.id, b"parameter_data");
            let param_name = parameter_data.name;
            let new_value = parameter_data.new_value;
            
            // Parametre adına göre konfigürasyonu güncelle
            if (std::string::bytes(&param_name) == b"min_proposal_power") {
                let old_value = governance_config.min_proposal_power;
                governance_config.min_proposal_power = new_value;
                
                event::emit(GovernanceConfigUpdated {
                    parameter: param_name,
                    old_value,
                    new_value,
                    time: now,
                });
            } else if (std::string::bytes(&param_name) == b"min_approval_threshold") {
                let old_value = governance_config.min_approval_threshold;
                assert!(new_value > 500 && new_value <= 1000, EInvalidThreshold); // en az %50, en çok %100
                governance_config.min_approval_threshold = new_value;
                
                event::emit(GovernanceConfigUpdated {
                    parameter: param_name,
                    old_value,
                    new_value,
                    time: now,
                });
            } else if (std::string::bytes(&param_name) == b"min_quorum_threshold") {
                let old_value = governance_config.min_quorum_threshold;
                assert!(new_value > 0 && new_value <= 1000, EInvalidThreshold); // en az %0, en çok %100
                governance_config.min_quorum_threshold = new_value;
                
                event::emit(GovernanceConfigUpdated {
                    parameter: param_name,
                    old_value,
                    new_value,
                    time: now,
                });
            } else if (std::string::bytes(&param_name) == b"proposal_duration") {
                let old_value = governance_config.proposal_duration;
                assert!(new_value >= 86400 && new_value <= 2592000, EInvalidDuration); // en az 1 gün, en çok 30 gün
                governance_config.proposal_duration = new_value;
                
                event::emit(GovernanceConfigUpdated {
                    parameter: param_name,
                    old_value,
                    new_value,
                    time: now,
                });
            } else if (std::string::bytes(&param_name) == b"execution_delay") {
                let old_value = governance_config.execution_delay;
                assert!(new_value >= 0 && new_value <= 604800, EInvalidDuration); // en az 0, en çok 7 gün
                governance_config.execution_delay = new_value;
                
                event::emit(GovernanceConfigUpdated {
                    parameter: param_name,
                    old_value,
                    new_value,
                    time: now,
                });
            } else {
                // Bilinmeyen parametre
                abort EInvalidParameter
            };
            
            governance_config.last_updated = now;
        };
        // Burada diğer teklif tipleri için işlemler (örn. PROPOSAL_TYPE_FUNDING) eklenebilir
        // Fonlama teklifleri çok daha karmaşık olacağı için, coin transferi, hazine yönetimi gibi 
        // fonksiyonlar daha detaylı implementasyon gerektirir.
        
        // Teklifi yürütülmüş olarak işaretle
        proposal.status = PROPOSAL_STATUS_EXECUTED;
        
        // Teklif yürütme eventini yayınla
        event::emit(ProposalExecuted {
            proposal_id: object::id(proposal),
            execution_time: now,
        });
    }
    
    /// Teklifi veto et (sadece VetoCapability sahibi çağırabilir)
    public entry fun veto_proposal(
        proposal: &mut Proposal,
        governance_config: &mut GovernanceConfig,
        veto_cap: &mut VetoCapability,
        reason: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Teklifin aktif veya kabul edilmiş olup olmadığını kontrol et
        assert!(
            proposal.status == PROPOSAL_STATUS_ACTIVE || proposal.status == PROPOSAL_STATUS_PASSED,
            EProposalNotActive
        );
        
        let old_status = proposal.status;
        proposal.status = PROPOSAL_STATUS_CANCELLED;
        
        // Aktif teklifler listesinden çıkar
        if (vec_set::contains(&governance_config.active_proposals, &object::id(proposal))) {
            vec_set::remove(&mut governance_config.active_proposals, &object::id(proposal));
        };
        
        // Veto geçmişine ekle
        vector::push_back(&mut veto_cap.veto_history, object::id(proposal));
        
        // Veto eventini yayınla
        event::emit(ProposalVetoed {
            proposal_id: object::id(proposal),
            veto_time: now,
            reason: string::utf8(reason),
        });
        
        // Teklif durumu değişikliği eventini yayınla
        event::emit(ProposalStatusChanged {
            proposal_id: object::id(proposal),
            old_status,
            new_status: proposal.status,
            time: now,
        });
    }
    
    /// Forum URL'sini güncelle
    public entry fun update_forum_url(
        governance_config: &mut GovernanceConfig,
        governance_cap: &GovernanceCapability,
        new_url: vector<u8>,
        ctx: &mut TxContext
    ) {
        governance_config.forum_url = string::utf8(new_url);
    }
    
    /// Hazine adresini güncelle
    public entry fun update_treasury(
        governance_config: &mut GovernanceConfig,
        governance_cap: &GovernanceCapability,
        new_treasury: address,
        ctx: &mut TxContext
    ) {
        governance_config.treasury = new_treasury;
    }
    
    // Getter fonksiyonları
    
    /// Teklif bilgilerini al
    public fun get_proposal_info(proposal: &Proposal): (
        address, String, String, u8, u64, u64, u64, u8, u64, u64, u64, u64, u64, u64
    ) {
        (
            proposal.proposer,
            proposal.title,
            proposal.description,
            proposal.proposal_type,
            proposal.created_at,
            proposal.voting_start,
            proposal.voting_end,
            proposal.status,
            proposal.yes_votes,
            proposal.no_votes,
            proposal.abstain_votes,
            proposal.total_voting_power,
            proposal.execution_time,
            proposal.proposal_id
        )
    }
    
    /// Yönetişim konfigürasyonunu al
    public fun get_governance_config(config: &GovernanceConfig): (
        u64, u64, u64, u64, u64, u64, u64, address, String
    ) {
        (
            config.min_proposal_power,
            config.min_approval_threshold,
            config.min_quorum_threshold,
            config.proposal_duration,
            config.execution_delay,
            config.last_updated,
            config.total_proposals,
            config.treasury,
            config.forum_url
        )
    }
    
    /// Aktif tekliflerin sayısını al
    public fun get_active_proposals_count(config: &GovernanceConfig): u64 {
        vec_set::size(&config.active_proposals)
    }
    
    /// Teklifin oylamasının durumunu kontrol et
    public fun check_proposal_outcome(
        proposal: &Proposal,
        governance_config: &GovernanceConfig
    ): (bool, bool) {
        let total_votes = proposal.yes_votes + proposal.no_votes;
        let quorum_threshold = (proposal.total_voting_power * governance_config.min_quorum_threshold) / 1000;
        
        let quorum_reached = total_votes >= quorum_threshold;
        
        let approval_threshold = (total_votes * governance_config.min_approval_threshold) / 1000;
        let approved = proposal.yes_votes >= approval_threshold;
        
        (quorum_reached, approved)
    }
    
    /// Kullanıcının bir teklif üzerinde oy kullanıp kullanmadığını kontrol et
    public fun has_voted(proposal: &Proposal, voter: address): bool {
        vec_set::contains(&proposal.voters, &voter)
    }
    
    // İç yardımcı fonksiyonlar
    
    /// Yeterli yetkilendirmeye sahip olunup olunmadığını kontrol et
    fun assert_governance_cap(cap: &GovernanceCapability, ctx: &TxContext) {
        // Burada gelecekte daha karmaşık yetkilendirme kontrolleri eklenebilir
        // Şu anda sadece kapasite sahibi olunup olunmadığı kontrol ediliyor
    }
    
    /// Yönetişim konfigürasyonu yayınlama fonksiyonu, modül dağıtımında çağrılır
    #[test_only]
    public fun publish_governance_config_for_testing(
        ctx: &mut TxContext
    ): GovernanceConfig {
        GovernanceConfig {
            id: object::new(ctx),
            min_proposal_power: 50_000_000_000, // 50,000 SVPN
            min_approval_threshold: 667, // %66.7
            min_quorum_threshold: 334, // %33.4
            proposal_duration: 604800, // 7 gün
            execution_delay: 172800, // 2 gün
            last_updated: 0,
            total_proposals: 0,
            treasury: tx_context::sender(ctx),
            forum_url: string::utf8(b"https://forum.suivpn.com"),
            active_proposals: vec_set::empty(),
        }
    }
    
    #[test_only]
    public fun create_governance_cap_for_testing(ctx: &mut TxContext): GovernanceCapability {
        GovernanceCapability {
            id: object::new(ctx),
        }
    }
}
