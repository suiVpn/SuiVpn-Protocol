/// SuiVPN Quality Metrics Module
/// 
/// Bu modül, SuiVPN ağındaki düğümlerin hizmet kalitesini ölçmek,
/// değerlendirmek ve raporlamak için gerekli mekanizmaları sağlar.
/// Ağın performansını ve güvenilirliğini artırmak için kalite metriklerini takip eder.
module suivpn::quality_metrics {
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
    use suivpn::registry::{Self, NodeInfo};
    use suivpn::validator::{Self, Validator};
    use suivpn::node_validation::{Self};
    
    // Hata kodları
    const ENotAuthorized: u64 = 0;
    const EInvalidNode: u64 = 1;
    const EInvalidMetric: u64 = 2;
    const EInvalidValue: u64 = 3;
    const EInvalidPeriod: u64 = 4;
    const ENoData: u64 = 5;
    const EInvalidWeight: u64 = 6;
    const EInvalidNodeType: u64 = 7;
    const EInvalidThreshold: u64 = 8;
    const ENodeNotActive: u64 = 9;
    const EReportNotFound: u64 = 10;
    
    // Metrik türleri
    const METRIC_UPTIME: u8 = 0;
    const METRIC_LATENCY: u8 = 1;
    const METRIC_BANDWIDTH: u8 = 2;
    const METRIC_PACKET_LOSS: u8 = 3;
    const METRIC_SECURITY_SCORE: u8 = 4;
    const METRIC_SUCCESS_RATE: u8 = 5;
    const METRIC_RESPONSE_TIME: u8 = 6;
    const METRIC_RELIABILITY: u8 = 7;
    
    // Düğüm tipleri
    const NODE_TYPE_RELAY: u8 = 0;
    const NODE_TYPE_VALIDATOR: u8 = 1;
    const NODE_TYPE_COMPUTE: u8 = 2;
    const NODE_TYPE_STORAGE: u8 = 3;
    
    // Sabitler
    const DEFAULT_MEASUREMENT_PERIOD: u64 = 3600; // 1 saat (saniye)
    const DEFAULT_REPORT_AGGREGATION_PERIOD: u64 = 86400; // 1 gün (saniye)
    const DEFAULT_MIN_REPORT_COUNT: u64 = 10; // Bir metrik için minimum rapor sayısı
    const MAX_LATENCY_THRESHOLD: u64 = 500; // msec cinsinden maksimum gecikme
    const MIN_UPTIME_THRESHOLD: u64 = 990; // Minimum çalışma süresi (binde)
    const MIN_SUCCESS_RATE: u64 = 950; // Minimum başarı oranı (binde)
    
    /// Kalite Metrikleri Konfigürasyonu
    /// Kalite metriklerinin değerlendirme parametrelerini içerir
    struct QualityConfig has key, store {
        id: UID,
        // Ölçüm periyodu (saniye)
        measurement_period: u64,
        // Rapor toplama periyodu (saniye)
        report_aggregation_period: u64,
        // Minimum rapor sayısı
        min_report_count: u64,
        // Metrik ağırlıkları (binde)
        metric_weights: VecMap<u8, u64>,
        // Performans eşikleri - geçme/kalma
        performance_thresholds: VecMap<u8, u64>,
        // Düğüm tipi bazlı metrik ağırlıkları
        node_type_weights: VecMap<u8, VecMap<u8, u64>>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Kalite Metrikleri Kaydı
    /// Tüm düğümlerin kalite metriklerini tutar
    struct QualityRegistry has key {
        id: UID,
        // Düğüm bazlı kalite skoru geçmişi
        node_quality_history: Table<ID, vector<QualitySnapshot>>,
        // Aktif metrik ölçümlerini toplar
        current_measurements: Table<ID, Table<u8, vector<MetricReport>>>,
        // Düğüm bazlı toplam kalite puanları
        node_scores: Table<ID, u64>,
        // Metrik türü bazlı ağ ortalamaları
        network_averages: VecMap<u8, u64>,
        // Düğüm tipi bazlı metrik ortalamaları
        node_type_averages: VecMap<u8, VecMap<u8, u64>>,
        // Ağ genelinde en iyi performans gösteren düğümler
        top_performers: VecSet<ID>,
        // Ağ genelinde düşük performans gösteren düğümler
        low_performers: VecSet<ID>,
        // Son güncelleme zamanı
        last_updated: u64,
    }
    
    /// Kalite Anlık Görüntüsü
    /// Bir düğümün belirli bir zamandaki kalite metriklerini içerir
    struct QualitySnapshot has store, drop {
        // Hesaplama zamanı
        timestamp: u64,
        // Toplam kalite puanı (0-1000)
        total_score: u64,
        // Metrik bazlı puanlar
        metric_scores: VecMap<u8, u64>,
        // Rapor sayısı
        report_count: u64,
        // Düğüm durumu
        node_status: u8,
    }
    
    /// Metrik Raporu
    /// Belirli bir metrik için bir ölçüm raporunu içerir
    struct MetricReport has store, drop {
        // Rapor ID'si
        report_id: ID,
        // Rapor gönderen
        reporter: address,
        // Rapor edilen düğüm
        node_id: ID,
        // Metrik türü
        metric_type: u8,
        // Metrik değeri
        value: u64,
        // Rapor zamanı
        timestamp: u64,
        // İlgili ölçüm ID'si (varsa)
        measurement_id: Option<ID>,
        // Ek veri
        additional_data: Option<vector<u8>>,
    }
    
    /// Kalite Ölçümü İsteği
    /// Belirli bir düğüm veya düğüm kümesi için ölçüm isteği
    struct MeasurementRequest has key {
        id: UID,
        // İstek oluşturucu
        requester: address,
        // Ölçülecek düğümler
        target_nodes: vector<ID>,
        // Ölçülecek metrikler
        target_metrics: vector<u8>,
        // Ölçüm başlangıç zamanı
        start_time: u64,
        // Ölçüm bitiş zamanı (0 ise sürekli)
        end_time: u64,
        // Ölçüm sıklığı (saniye)
        frequency: u64,
        // İstek durumu
        is_active: bool,
        // Oluşturma zamanı
        created_at: u64,
    }
    
    // Eventler
    
    /// Metrik raporu eventi
    struct MetricReported has copy, drop {
        report_id: ID,
        node_id: ID,
        metric_type: u8,
        value: u64,
        reporter: address,
        timestamp: u64,
    }
    
    /// Kalite puanı güncelleme eventi
    struct QualityScoreUpdated has copy, drop {
        node_id: ID,
        old_score: u64,
        new_score: u64,
        update_time: u64,
    }
    
    /// Ölçüm isteği eventi
    struct MeasurementRequested has copy, drop {
        request_id: ID,
        requester: address,
        target_count: u64,
        metrics_count: u64,
        start_time: u64,
    }
    
    /// Periyodik değerlendirme eventi
    struct QualityEvaluationCompleted has copy, drop {
        evaluated_nodes: u64,
        top_performers: u64,
        low_performers: u64,
        timestamp: u64,
    }
    
    /// Modül başlatma fonksiyonu, sadece bir kez çağrılabilir.
    fun init(ctx: &mut TxContext) {
        let quality_config = QualityConfig {
            id: object::new(ctx),
            measurement_period: DEFAULT_MEASUREMENT_PERIOD,
            report_aggregation_period: DEFAULT_REPORT_AGGREGATION_PERIOD,
            min_report_count: DEFAULT_MIN_REPORT_COUNT,
            metric_weights: vec_map::empty(),
            performance_thresholds: vec_map::empty(),
            node_type_weights: vec_map::empty(),
            last_updated: 0,
        };
        
        // Metrik ağırlıklarını ayarla (toplam 1000)
        vec_map::insert(&mut quality_config.metric_weights, METRIC_UPTIME, 200); // %20
        vec_map::insert(&mut quality_config.metric_weights, METRIC_LATENCY, 200); // %20
        vec_map::insert(&mut quality_config.metric_weights, METRIC_BANDWIDTH, 150); // %15
        vec_map::insert(&mut quality_config.metric_weights, METRIC_PACKET_LOSS, 100); // %10
        vec_map::insert(&mut quality_config.metric_weights, METRIC_SECURITY_SCORE, 150); // %15
        vec_map::insert(&mut quality_config.metric_weights, METRIC_SUCCESS_RATE, 100); // %10
        vec_map::insert(&mut quality_config.metric_weights, METRIC_RESPONSE_TIME, 50); // %5
        vec_map::insert(&mut quality_config.metric_weights, METRIC_RELIABILITY, 50); // %5
        
        // Performans eşiklerini ayarla
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_UPTIME, MIN_UPTIME_THRESHOLD); // En az %99 uptime
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_LATENCY, MAX_LATENCY_THRESHOLD); // En fazla 500ms gecikme
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_PACKET_LOSS, 50); // En fazla %5 paket kaybı
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_SUCCESS_RATE, MIN_SUCCESS_RATE); // En az %95 başarı oranı
        
        // Düğüm tipi ağırlıklarını ayarla
        let relay_weights = vec_map::empty<u8, u64>();
        vec_map::insert(&mut relay_weights, METRIC_LATENCY, 250); // %25
        vec_map::insert(&mut relay_weights, METRIC_BANDWIDTH, 250); // %25
        vec_map::insert(&mut relay_weights, METRIC_PACKET_LOSS, 150); // %15
        vec_map::insert(&mut relay_weights, METRIC_UPTIME, 150); // %15
        vec_map::insert(&mut relay_weights, METRIC_SECURITY_SCORE, 100); // %10
        vec_map::insert(&mut relay_weights, METRIC_SUCCESS_RATE, 100); // %10
        
        let validator_weights = vec_map::empty<u8, u64>();
        vec_map::insert(&mut validator_weights, METRIC_SECURITY_SCORE, 300); // %30
        vec_map::insert(&mut validator_weights, METRIC_UPTIME, 250); // %25
        vec_map::insert(&mut validator_weights, METRIC_SUCCESS_RATE, 200); // %20
        vec_map::insert(&mut validator_weights, METRIC_RELIABILITY, 150); // %15
        vec_map::insert(&mut validator_weights, METRIC_RESPONSE_TIME, 100); // %10
        
        let compute_weights = vec_map::empty<u8, u64>();
        vec_map::insert(&mut compute_weights, METRIC_BANDWIDTH, 300); // %30
        vec_map::insert(&mut compute_weights, METRIC_LATENCY, 200); // %20
        vec_map::insert(&mut compute_weights, METRIC_UPTIME, 200); // %20
        vec_map::insert(&mut compute_weights, METRIC_SUCCESS_RATE, 150); // %15
        vec_map::insert(&mut compute_weights, METRIC_SECURITY_SCORE, 150); // %15
        
        let storage_weights = vec_map::empty<u8, u64>();
        vec_map::insert(&mut storage_weights, METRIC_RELIABILITY, 300); // %30
        vec_map::insert(&mut storage_weights, METRIC_UPTIME, 250); // %25
        vec_map::insert(&mut storage_weights, METRIC_SECURITY_SCORE, 200); // %20
        vec_map::insert(&mut storage_weights, METRIC_BANDWIDTH, 150); // %15
        vec_map::insert(&mut storage_weights, METRIC_SUCCESS_RATE, 100); // %10
        
        vec_map::insert(&mut quality_config.node_type_weights, NODE_TYPE_RELAY, relay_weights);
        vec_map::insert(&mut quality_config.node_type_weights, NODE_TYPE_VALIDATOR, validator_weights);
        vec_map::insert(&mut quality_config.node_type_weights, NODE_TYPE_COMPUTE, compute_weights);
        vec_map::insert(&mut quality_config.node_type_weights, NODE_TYPE_STORAGE, storage_weights);
        
        let quality_registry = QualityRegistry {
            id: object::new(ctx),
            node_quality_history: table::new(ctx),
            current_measurements: table::new(ctx),
            node_scores: table::new(ctx),
            network_averages: vec_map::empty(),
            node_type_averages: vec_map::empty(),
            top_performers: vec_set::empty(),
            low_performers: vec_set::empty(),
            last_updated: 0,
        };
        
        // Ağ ortalamalarını başlat
        vec_map::insert(&mut quality_registry.network_averages, METRIC_UPTIME, 980); // %98 ortalama uptime
        vec_map::insert(&mut quality_registry.network_averages, METRIC_LATENCY, 200); // 200ms ortalama gecikme
        vec_map::insert(&mut quality_registry.network_averages, METRIC_BANDWIDTH, 500); // 500Mbps ortalama bant genişliği
        vec_map::insert(&mut quality_registry.network_averages, METRIC_PACKET_LOSS, 20); // %2 ortalama paket kaybı
        vec_map::insert(&mut quality_registry.network_averages, METRIC_SECURITY_SCORE, 850); // %85 ortalama güvenlik puanı
        vec_map::insert(&mut quality_registry.network_averages, METRIC_SUCCESS_RATE, 950); // %95 ortalama başarı oranı
        vec_map::insert(&mut quality_registry.network_averages, METRIC_RESPONSE_TIME, 150); // 150ms ortalama cevap süresi
        vec_map::insert(&mut quality_registry.network_averages, METRIC_RELIABILITY, 900); // %90 ortalama güvenilirlik
        
        transfer::share_object(quality_config);
        transfer::share_object(quality_registry);
    }
    
    /// Yeni bir metrik raporu gönder
    public entry fun report_metric(
        quality_registry: &mut QualityRegistry,
        node_id: ID,
        metric_type: u8,
        value: u64,
        measurement_id: Option<ID>,
        additional_data: Option<vector<u8>>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Metrik türünü kontrol et
        assert!(
            metric_type == METRIC_UPTIME ||
            metric_type == METRIC_LATENCY ||
            metric_type == METRIC_BANDWIDTH ||
            metric_type == METRIC_PACKET_LOSS ||
            metric_type == METRIC_SECURITY_SCORE ||
            metric_type == METRIC_SUCCESS_RATE ||
            metric_type == METRIC_RESPONSE_TIME ||
            metric_type == METRIC_RELIABILITY,
            EInvalidMetric
        );
        
        // Değer aralığını kontrol et
        if (metric_type == METRIC_UPTIME || 
            metric_type == METRIC_SUCCESS_RATE || 
            metric_type == METRIC_SECURITY_SCORE || 
            metric_type == METRIC_RELIABILITY) {
            // Bu metrikler 0-1000 arasında olmalı (binde olarak)
            assert!(value <= 1000, EInvalidValue);
        };
        
        let reporter = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Rapor ID'si oluştur
        let report_uid = object::new(ctx);
        let report_id = object::uid_to_inner(&report_uid);
        object::delete(report_uid);
        
        // Metrik raporu oluştur
        let report = MetricReport {
            report_id,
            reporter,
            node_id,
            metric_type,
            value,
            timestamp: now,
            measurement_id,
            additional_data,
        };
        
        // Düğüm için ölçüm tablosu var mı?
        if (!table::contains(&quality_registry.current_measurements, node_id)) {
            table::add(
                &mut quality_registry.current_measurements, 
                node_id, 
                table::new(ctx)
            );
        };
        
        let node_measurements = table::borrow_mut(
            &mut quality_registry.current_measurements, 
            node_id
        );
        
        // Metrik tipi için rapor vektörü var mı?
        if (!table::contains(node_measurements, metric_type)) {
            table::add(
                node_measurements, 
                metric_type, 
                vector::empty<MetricReport>()
            );
        };
        
        let metric_reports = table::borrow_mut(node_measurements, metric_type);
        
        // Raporu ekle
        vector::push_back(metric_reports, report);
        
        // Rapor eventi yayınla
        event::emit(MetricReported {
            report_id,
            node_id,
            metric_type,
            value,
            reporter,
            timestamp: now,
        });
        
        quality_registry.last_updated = now;
    }
    
    /// Bir düğüm için toplu metrik raporu gönder
    public entry fun batch_report_metrics(
        quality_registry: &mut QualityRegistry,
        node_id: ID,
        metric_types: vector<u8>,
        values: vector<u64>,
        measurement_id: Option<ID>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Metrik ve değer sayılarının eşit olup olmadığını kontrol et
        assert!(vector::length(&metric_types) == vector::length(&values), EInvalidMetric);
        
        let i = 0;
        let len = vector::length(&metric_types);
        
        // Her metrik için rapor gönder
        while (i < len) {
            let metric_type = *vector::borrow(&metric_types, i);
            let value = *vector::borrow(&values, i);
            
            report_metric(
                quality_registry,
                node_id,
                metric_type,
                value,
                measurement_id,
                option::none(),
                clock,
                ctx
            );
            
            i = i + 1;
        };
    }
    
    /// Bir metrik ölçüm isteği oluştur
    public entry fun create_measurement_request(
        target_nodes: vector<ID>,
        target_metrics: vector<u8>,
        start_delay: u64,
        duration: u64,
        frequency: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let requester = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Metrikleri kontrol et
        let i = 0;
        let metrics_len = vector::length(&target_metrics);
        
        while (i < metrics_len) {
            let metric_type = *vector::borrow(&target_metrics, i);
            assert!(
                metric_type == METRIC_UPTIME ||
                metric_type == METRIC_LATENCY ||
                metric_type == METRIC_BANDWIDTH ||
                metric_type == METRIC_PACKET_LOSS ||
                metric_type == METRIC_SECURITY_SCORE ||
                metric_type == METRIC_SUCCESS_RATE ||
                metric_type == METRIC_RESPONSE_TIME ||
                metric_type == METRIC_RELIABILITY,
                EInvalidMetric
            );
            i = i + 1;
        };
        
        // Frekans ve süreyi kontrol et
        assert!(frequency > 0, EInvalidPeriod);
        
        // Başlangıç zamanını hesapla
        let start_time = now + start_delay;
        
        // Bitiş zamanını hesapla
        let end_time = if (duration > 0) { start_time + duration } else { 0 };
        
        // Ölçüm isteği oluştur
        let request = MeasurementRequest {
            id: object::new(ctx),
            requester,
            target_nodes,
            target_metrics,
            start_time,
            end_time,
            frequency,
            is_active: true,
            created_at: now,
        };
        
        let request_id = object::id(&request);
        
        // Ölçüm isteği eventi yayınla
        event::emit(MeasurementRequested {
            request_id,
            requester,
            target_count: vector::length(&target_nodes),
            metrics_count: vector::length(&target_metrics),
            start_time,
        });
        
        transfer::share_object(request);
    }
    
    /// Periyodik kalite değerlendirmesi yap
    public entry fun evaluate_node_quality(
        quality_registry: &mut QualityRegistry,
        quality_config: &QualityConfig,
        node_id: ID,
        node_info: &NodeInfo,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Düğüm için ölçüm var mı?
        assert!(table::contains(&quality_registry.current_measurements, node_id), ENoData);
        
        // Düğüm tipini al
        let node_type = registry::get_node_type(node_info);
        
        // Düğüm tipi ağırlıklarını al
        let type_weights = if (vec_map::contains(&quality_config.node_type_weights, &node_type)) {
            vec_map::get(&quality_config.node_type_weights, &node_type)
        } else {
            // Varsayılan ağırlıkları kullan
            &quality_config.metric_weights
        };
        
        // Düğümün mevcut puanını al
        let old_score = if (table::contains(&quality_registry.node_scores, node_id)) {
            *table::borrow(&quality_registry.node_scores, node_id)
        } else {
            500 // Varsayılan başlangıç puanı
        };
        
        // Metrik bazlı puanları hesapla
        let metric_scores = vec_map::empty<u8, u64>();
        let total_weighted_score = 0;
        let total_weight = 0;
        let report_count = 0;
        
        let node_measurements = table::borrow(&quality_registry.current_measurements, node_id);
        
        // Her metrik için puan hesapla
        let metrics = vec_map::keys(type_weights);
        let i = 0;
        let metrics_len = vector::length(&metrics);
        
        while (i < metrics_len) {
            let metric_type = *vector::borrow(&metrics, i);
            
            if (table::contains(node_measurements, metric_type)) {
                let reports = table::borrow(node_measurements, metric_type);
                let reports_len = vector::length(reports);
                
                if (reports_len >= quality_config.min_report_count) {
                    // Metrik değerini hesapla
                    let metric_value = calculate_metric_value(reports, metric_type);
                    
                    // Metrik puanını hesapla
                    let metric_score = calculate_metric_score(metric_value, metric_type, quality_config);
                    
                    // Metrik ağırlığını al
                    let weight = *vec_map::get(type_weights, &metric_type);
                    
                    // Toplam ağırlıklı puana ekle
                    total_weighted_score = total_weighted_score + (metric_score * weight);
                    total_weight = total_weight + weight;
                    
                    // Metrik puanını kaydet
                    vec_map::insert(&mut metric_scores, metric_type, metric_score);
                    
                    // Rapor sayısını güncelle
                    if (reports_len > report_count) {
                        report_count = reports_len;
                    };
                };
            };
            
            i = i + 1;
        };
        
        // Toplam puanı hesapla
        let total_score = if (total_weight > 0) {
            total_weighted_score / total_weight
        } else {
            old_score // Değişiklik yok
        };
        
        // Düğüm durumunu al
        let node_status = registry::get_node_status(node_info);
        
        // Kalite anlık görüntüsü oluştur
        let snapshot = QualitySnapshot {
            timestamp: now,
            total_score,
            metric_scores,
            report_count,
            node_status,
        };
        
        // Düğüm kalite geçmişini güncelle
        if (!table::contains(&quality_registry.node_quality_history, node_id)) {
            table::add(
                &mut quality_registry.node_quality_history, 
                node_id, 
                vector::empty<QualitySnapshot>()
            );
        };
        
        let history = table::borrow_mut(&mut quality_registry.node_quality_history, node_id);
        
        // Geçmişi güncelle (en fazla 24 anlık görüntü sakla)
        vector::push_back(history, snapshot);
        if (vector::length(history) > 24) {
            vector::remove(history, 0);
        };
        
        // Düğüm puanını güncelle
        if (table::contains(&quality_registry.node_scores, node_id)) {
            *table::borrow_mut(&quality_registry.node_scores, node_id) = total_score;
        } else {
            table::add(&mut quality_registry.node_scores, node_id, total_score);
        };
        
        // Puan değişikliği eventi yayınla
        event::emit(QualityScoreUpdated {
            node_id,
            old_score,
            new_score: total_score,
            update_time: now,
        });
        
        // Top ve low performer listelerini güncelle (basitleştirilmiş)
        if (total_score >= 900) { // %90 ve üzeri
            vec_set::insert(&mut quality_registry.top_performers, node_id);
        } else if (total_score < 700) { // %70'in altı
            vec_set::insert(&mut quality_registry.low_performers, node_id);
        };
        
        quality_registry.last_updated = now;
    }
    
    /// Ağ genelinde periyodik kalite değerlendirmesi
    public entry fun network_quality_evaluation(
        quality_registry: &mut QualityRegistry,
        quality_config: &QualityConfig,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Ağ ortalamalarını güncelle
        update_network_averages(quality_registry);
        
        // Top performers ve low performers listelerini temizle
        quality_registry.top_performers = vec_set::empty();
        quality_registry.low_performers = vec_set::empty();
        
        // Değerlendirme tamamlandı eventi yayınla
        event::emit(QualityEvaluationCompleted {
            evaluated_nodes: table::length(&quality_registry.node_scores),
            top_performers: vec_set::size(&quality_registry.top_performers),
            low_performers: vec_set::size(&quality_registry.low_performers),
            timestamp: now,
        });
        
        quality_registry.last_updated = now;
    }
    
    /// Kalite konfigürasyonunu güncelle
    public entry fun update_quality_config(
        quality_config: &mut QualityConfig,
        measurement_period: Option<u64>,
        aggregation_period: Option<u64>,
        min_report_count: Option<u64>,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Ölçüm periyodunu güncelle (varsa)
        if (option::is_some(&measurement_period)) {
            quality_config.measurement_period = *option::borrow(&measurement_period);
        };
        
        // Toplama periyodunu güncelle (varsa)
        if (option::is_some(&aggregation_period)) {
            quality_config.report_aggregation_period = *option::borrow(&aggregation_period);
        };
        
        // Minimum rapor sayısını güncelle (varsa)
        if (option::is_some(&min_report_count)) {
            quality_config.min_report_count = *option::borrow(&min_report_count);
        };
        
        quality_config.last_updated = now;
    }
    
    /// Metrik ağırlıklarını güncelle
    public entry fun update_metric_weights(
        quality_config: &mut QualityConfig,
        uptime_weight: u64,
        latency_weight: u64,
        bandwidth_weight: u64,
        packet_loss_weight: u64,
        security_score_weight: u64,
        success_rate_weight: u64,
        response_time_weight: u64,
        reliability_weight: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Toplam ağırlığın 1000 olup olmadığını kontrol et
        let total_weight = uptime_weight + 
                          latency_weight + 
                          bandwidth_weight + 
                          packet_loss_weight + 
                          security_score_weight + 
                          success_rate_weight + 
                          response_time_weight + 
                          reliability_weight;
                          
        assert!(total_weight == 1000, EInvalidWeight);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Ağırlıkları güncelle
        vec_map::insert(&mut quality_config.metric_weights, METRIC_UPTIME, uptime_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_LATENCY, latency_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_BANDWIDTH, bandwidth_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_PACKET_LOSS, packet_loss_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_SECURITY_SCORE, security_score_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_SUCCESS_RATE, success_rate_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_RESPONSE_TIME, response_time_weight);
        vec_map::insert(&mut quality_config.metric_weights, METRIC_RELIABILITY, reliability_weight);
        
        quality_config.last_updated = now;
    }
    
    /// Performans eşiklerini güncelle
    public entry fun update_performance_thresholds(
        quality_config: &mut QualityConfig,
        uptime_threshold: u64,
        latency_threshold: u64,
        packet_loss_threshold: u64,
        success_rate_threshold: u64,
        governance_cap: &GovernanceCapability,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Eşik değerlerinin geçerli olup olmadığını kontrol et
        assert!(uptime_threshold <= 1000, EInvalidThreshold);
        assert!(packet_loss_threshold <= 1000, EInvalidThreshold);
        assert!(success_rate_threshold <= 1000, EInvalidThreshold);
        
        let now = clock::timestamp_ms(clock) / 1000; // saniyeye çevir
        
        // Eşikleri güncelle
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_UPTIME, uptime_threshold);
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_LATENCY, latency_threshold);
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_PACKET_LOSS, packet_loss_threshold);
        vec_map::insert(&mut quality_config.performance_thresholds, METRIC_SUCCESS_RATE, success_rate_threshold);
        
        quality_config.last_updated = now;
    }
    
    // Yardımcı fonksiyonlar
    
    /// Rapor vektöründen metrik değerini hesapla
    fun calculate_metric_value(reports: &vector<MetricReport>, metric_type: u8): u64 {
        let sum = 0;
        let count = vector::length(reports);
        let i = 0;
        
        while (i < count) {
            let report = vector::borrow(reports, i);
            sum = sum + report.value;
            i = i + 1;
        };
        
        // Ortalama değeri hesapla
        if (count > 0) {
            sum / count
        } else {
            0
        }
    }
    
    /// Metrik değerine göre puan hesapla
    fun calculate_metric_score(
        value: u64, 
        metric_type: u8, 
        quality_config: &QualityConfig
    ): u64 {
        // Metrik tipine göre puan hesapla
        if (metric_type == METRIC_UPTIME || 
            metric_type == METRIC_SUCCESS_RATE || 
            metric_type == METRIC_SECURITY_SCORE || 
            metric_type == METRIC_RELIABILITY) {
            // Bu metrikler için yüksek değer daha iyi
            value
        } else if (metric_type == METRIC_LATENCY || 
                  metric_type == METRIC_PACKET_LOSS || 
                  metric_type == METRIC_RESPONSE_TIME) {
            // Bu metrikler için düşük değer daha iyi
            let threshold = if (vec_map::contains(&quality_config.performance_thresholds, &metric_type)) {
                *vec_map::get(&quality_config.performance_thresholds, &metric_type)
            } else if (metric_type == METRIC_LATENCY) {
                MAX_LATENCY_THRESHOLD
            } else {
                1000 // Varsayılan
            };
            
            if (value >= threshold) {
                0
            } else {
                1000 - ((value * 1000) / threshold)
            }
        } else if (metric_type == METRIC_BANDWIDTH) {
            // Bant genişliği için yüksek değer daha iyi, ama bir üst sınır var
            let max_bandwidth = 1000; // 1 Gbps
            if (value >= max_bandwidth) {
                1000
            } else {
                (value * 1000) / max_bandwidth
            }
        } else {
            500 // Bilinmeyen metrik tipi için varsayılan puan
        }
    }
    
    /// Ağ ortalamalarını güncelle
    fun update_network_averages(quality_registry: &mut QualityRegistry) {
        // Her metrik için ağ ortalamasını hesapla
        let metrics = vec_map::keys(&quality_registry.network_averages);
        let i = 0;
        let metrics_len = vector::length(&metrics);
        
        while (i < metrics_len) {
            let metric_type = *vector::borrow(&metrics, i);
            let total_value = 0;
            let node_count = 0;
            
            // Tüm düğümlerin ölçümlerini topla
            let nodes = table::keys(&quality_registry.current_measurements);
            let j = 0;
            let nodes_len = vector::length(&nodes);
            
            while (j < nodes_len) {
                let node_id = *vector::borrow(&nodes, j);
                let node_measurements = table::borrow(&quality_registry.current_measurements, node_id);
                
                if (table::contains(node_measurements, metric_type)) {
                    let reports = table::borrow(node_measurements, metric_type);
                    if (vector::length(reports) > 0) {
                        total_value = total_value + calculate_metric_value(reports, metric_type);
                        node_count = node_count + 1;
                    };
                };
                
                j = j + 1;
            };
            
            // Ortalamayı güncelle
            if (node_count > 0) {
                let avg_value = total_value / node_count;
                vec_map::insert(&mut quality_registry.network_averages, metric_type, avg_value);
            };
            
            i = i + 1;
        };
    }
    
    // Getter fonksiyonları
    
    /// Düğümün kalite puanını al
    public fun get_node_quality_score(quality_registry: &QualityRegistry, node_id: ID): u64 {
        if (table::contains(&quality_registry.node_scores, node_id)) {
            *table::borrow(&quality_registry.node_scores, node_id)
        } else {
            0
        }
    }
    
    /// Düğümün metrik değerini al
    public fun get_node_metric_value(
        quality_registry: &QualityRegistry,
        node_id: ID,
        metric_type: u8
    ): u64 {
        if (!table::contains(&quality_registry.current_measurements, node_id)) {
            return 0
        };
        
        let node_measurements = table::borrow(&quality_registry.current_measurements, node_id);
        
        if (!table::contains(node_measurements, metric_type)) {
            return 0
        };
        
        let reports = table::borrow(node_measurements, metric_type);
        calculate_metric_value(reports, metric_type)
    }
    
    /// Ağ ortalamasını al
    public fun get_network_average(
        quality_registry: &QualityRegistry,
        metric_type: u8
    ): u64 {
        if (vec_map::contains(&quality_registry.network_averages, &metric_type)) {
            *vec_map::get(&quality_registry.network_averages, &metric_type)
        } else {
            0
        }
    }
    
    /// Metrik ağırlığını al
    public fun get_metric_weight(
        quality_config: &QualityConfig,
        metric_type: u8
    ): u64 {
        if (vec_map::contains(&quality_config.metric_weights, &metric_type)) {
            *vec_map::get(&quality_config.metric_weights, &metric_type)
        } else {
            0
        }
    }
    
    /// Performans eşiğini al
    public fun get_performance_threshold(
        quality_config: &QualityConfig,
        metric_type: u8
    ): u64 {
        if (vec_map::contains(&quality_config.performance_thresholds, &metric_type)) {
            *vec_map::get(&quality_config.performance_thresholds, &metric_type)
        } else {
            0
        }
    }
    
    /// Düğüm kalite geçmişini al
    public fun get_node_quality_history(
        quality_registry: &QualityRegistry,
        node_id: ID
    ): vector<u64> {
        let result = vector::empty<u64>();
        
        if (!table::contains(&quality_registry.node_quality_history, node_id)) {
            return result
        };
        
        let history = table::borrow(&quality_registry.node_quality_history, node_id);
        let i = 0;
        let len = vector::length(history);
        
        while (i < len) {
            let snapshot = vector::borrow(history, i);
            vector::push_back(&mut result, snapshot.total_score);
            i = i + 1;
        };
        
        result
    }
    
    // Test fonksiyonları
    
    #[test_only]
    public fun create_quality_config_for_testing(ctx: &mut TxContext): QualityConfig {
        QualityConfig {
            id: object::new(ctx),
            measurement_period: DEFAULT_MEASUREMENT_PERIOD,
            report_aggregation_period: DEFAULT_REPORT_AGGREGATION_PERIOD,
            min_report_count: DEFAULT_MIN_REPORT_COUNT,
            metric_weights: vec_map::empty(),
            performance_thresholds: vec_map::empty(),
            node_type_weights: vec_map::empty(),
            last_updated: 0,
        }
    }
}
