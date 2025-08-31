//! DNSSEC module tests

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, TransientTtl};
    use crate::dns::authority::Authority;
    use std::net::Ipv4Addr;

    #[test]
    fn test_key_generation() {
        // Test ECDSA P-256 key generation
        let zsk = DnssecKey::generate(KeyType::ZSK, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(zsk.is_ok());
        let zsk = zsk.unwrap();
        assert_eq!(zsk.key_type, KeyType::ZSK);
        assert_eq!(zsk.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(!zsk.public_key.is_empty());
        assert!(zsk.is_active);

        // Test KSK generation
        let ksk = DnssecKey::generate(KeyType::KSK, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(ksk.is_ok());
        let ksk = ksk.unwrap();
        assert_eq!(ksk.key_type, KeyType::KSK);

        // Test RSA key generation
        let rsa_key = DnssecKey::generate(KeyType::ZSK, DnssecAlgorithm::RsaSha256);
        assert!(rsa_key.is_ok());
        let rsa_key = rsa_key.unwrap();
        assert_eq!(rsa_key.algorithm, DnssecAlgorithm::RsaSha256);
    }

    #[test]
    fn test_signing_and_verification() {
        // Generate a key
        let key = DnssecKey::generate(KeyType::ZSK, DnssecAlgorithm::EcdsaP256Sha256).unwrap();
        
        // Test data to sign
        let data = b"test.example.com A 192.168.1.1";
        
        // Sign the data
        let signature = key.sign(data);
        assert!(signature.is_ok());
        let signature = signature.unwrap();
        assert!(!signature.is_empty());
        
        // Verify the signature
        let valid = key.verify(data, &signature);
        assert!(valid.is_ok());
        assert!(valid.unwrap());
        
        // Verify with wrong data should fail
        let wrong_data = b"wrong.example.com A 192.168.1.2";
        let invalid = key.verify(wrong_data, &signature);
        assert!(invalid.is_ok());
        assert!(!invalid.unwrap());
    }

    #[test]
    fn test_signing_config_default() {
        let config = SigningConfig::default();
        assert_eq!(config.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(config.use_nsec3);
        assert_eq!(config.nsec3_iterations, 10);
        assert_eq!(config.nsec3_salt_length, 8);
        assert!(!config.enabled);
    }

    #[test]
    fn test_dnssec_signer_creation() {
        let config = SigningConfig::default();
        let signer = DnssecSigner::new(config);
        let stats = signer.get_statistics();
        assert_eq!(stats.zones_signed, 0);
        assert_eq!(stats.keys_generated, 0);
        assert_eq!(stats.signatures_created, 0);
    }

    #[test]
    fn test_zone_signing() {
        let config = SigningConfig {
            enabled: true,
            ..SigningConfig::default()
        };
        let mut signer = DnssecSigner::new(config);
        
        // Create test authority with a zone
        let authority = Authority::new();
        authority.create_zone("example.com", "ns1.example.com", "admin.example.com").unwrap();
        
        // Add some records to the zone
        let a_record = DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: "192.168.1.1".parse().unwrap(),
            ttl: TransientTtl(3600),
        };
        authority.add_record("example.com", &a_record).unwrap();
        
        // Sign the zone
        let result = signer.enable_zone("example.com", &authority);
        assert!(result.is_ok());
        
        let signed_zone = result.unwrap();
        assert_eq!(signed_zone.zone, "example.com");
        assert!(!signed_zone.dnskeys.is_empty());
        assert!(!signed_zone.rrsigs.is_empty());
        assert!(!signed_zone.ds_records.is_empty());
        
        // Check statistics
        let stats = signer.get_statistics();
        assert_eq!(stats.zones_signed, 1);
        assert!(stats.keys_generated >= 2); // At least KSK and ZSK
        assert!(stats.signatures_created > 0);
    }

    #[test]
    fn test_ds_record_generation() {
        let config = SigningConfig::default();
        let signer = DnssecSigner::new(config);
        
        // Generate a KSK
        let ksk = DnssecKey::generate(KeyType::KSK, DnssecAlgorithm::EcdsaP256Sha256).unwrap();
        
        // Generate DS record
        let ds_result = signer.generate_ds_record("example.com", &ksk);
        assert!(ds_result.is_ok());
        
        let ds = ds_result.unwrap();
        assert_eq!(ds.key_tag, ksk.key_tag);
        assert_eq!(ds.algorithm, ksk.algorithm);
        assert_eq!(ds.digest_type, DigestType::Sha256);
        assert!(!ds.digest.is_empty());
    }

    #[test]
    fn test_nsec3_hash() {
        let config = SigningConfig::default();
        let signer = DnssecSigner::new(config);
        
        let name = "example.com";
        let salt = vec![0x01, 0x02, 0x03, 0x04];
        let iterations = 10;
        
        let hash = signer.nsec3_hash(name, &salt, iterations);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
        
        // Same input should produce same hash
        let hash2 = signer.nsec3_hash(name, &salt, iterations);
        assert_eq!(hash, hash2);
        
        // Different input should produce different hash
        let hash3 = signer.nsec3_hash("other.com", &salt, iterations);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_key_rollover() {
        let config = SigningConfig::default();
        let mut signer = DnssecSigner::new(config);
        
        // Create and sign a zone
        let authority = Authority::new();
        authority.create_zone("example.com", "ns1.example.com", "admin.example.com").unwrap();
        signer.enable_zone("example.com", &authority).unwrap();
        
        // Get initial statistics
        let stats_before = signer.get_statistics();
        let keys_before = stats_before.keys_generated;
        
        // Perform key rollover
        let rollover_result = signer.rollover_keys("example.com");
        assert!(rollover_result.is_ok());
        
        // Check that new keys were generated
        let stats_after = signer.get_statistics();
        assert!(stats_after.keys_generated > keys_before);
        assert_eq!(stats_after.key_rollovers, 1);
    }

    #[test]
    fn test_rrsig_record_creation() {
        let key = DnssecKey::generate(KeyType::ZSK, DnssecAlgorithm::EcdsaP256Sha256).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        
        let rrsig = RrsigRecord {
            type_covered: QueryType::A,
            algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            labels: 2,
            original_ttl: 3600,
            expiration: now + 86400,
            inception: now,
            key_tag: key.key_tag,
            signer_name: "example.com".to_string(),
            signature: vec![0x01, 0x02, 0x03],
        };
        
        assert_eq!(rrsig.type_covered, QueryType::A);
        assert_eq!(rrsig.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(rrsig.signer_name, "example.com");
    }

    #[test]
    fn test_dnskey_record_creation() {
        let key = DnssecKey::generate(KeyType::KSK, DnssecAlgorithm::EcdsaP256Sha256).unwrap();
        
        let dnskey = DnskeyRecord {
            flags: 257, // KSK flag
            protocol: 3,
            algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            public_key: key.public_key.clone(),
        };
        
        assert_eq!(dnskey.flags, 257);
        assert_eq!(dnskey.protocol, 3);
        assert_eq!(dnskey.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(dnskey.public_key, key.public_key);
    }

    #[test]
    fn test_nsec3_record_creation() {
        let nsec3 = Nsec3Record {
            hash_algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: vec![0x01, 0x02],
            next_hashed: vec![0x03, 0x04],
            type_bitmaps: vec![0xFF],
        };
        
        assert_eq!(nsec3.hash_algorithm, 1);
        assert_eq!(nsec3.iterations, 10);
        assert_eq!(nsec3.salt.len(), 2);
    }

    #[test]
    fn test_signed_zone_structure() {
        let now = std::time::SystemTime::now();
        let signed_zone = SignedZone {
            zone: "example.com".to_string(),
            records: vec![],
            rrsigs: vec![],
            dnskeys: vec![],
            ds_records: vec![],
            nsec3_records: vec![],
            signed_at: now,
            resign_at: now + std::time::Duration::from_secs(86400),
        };
        
        assert_eq!(signed_zone.zone, "example.com");
        assert!(signed_zone.records.is_empty());
        assert!(signed_zone.resign_at > signed_zone.signed_at);
    }

    #[test]
    fn test_algorithm_values() {
        assert_eq!(DnssecAlgorithm::RsaSha256 as u8, 8);
        assert_eq!(DnssecAlgorithm::RsaSha512 as u8, 10);
        assert_eq!(DnssecAlgorithm::EcdsaP256Sha256 as u8, 13);
        assert_eq!(DnssecAlgorithm::EcdsaP384Sha384 as u8, 14);
        assert_eq!(DnssecAlgorithm::Ed25519 as u8, 15);
    }

    #[test]
    fn test_digest_type_values() {
        assert_eq!(DigestType::Sha1 as u8, 1);
        assert_eq!(DigestType::Sha256 as u8, 2);
        assert_eq!(DigestType::Sha384 as u8, 4);
    }
}