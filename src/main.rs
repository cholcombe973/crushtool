//Decompile a ceph crushmap for fun and profit
//
extern crate byteorder;
#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate log;
#[macro_use] extern crate nom;
extern crate num;
extern crate simple_logger;

use std::io::{self, ErrorKind, Read};
use std::string::FromUtf8Error;

use byteorder::{LittleEndian, WriteBytesExt};
use num::FromPrimitive;
use nom::{le_u8, le_u16, le_i32, le_u32};

static CRUSH_MAGIC: u32 = 0x00010000;  /* for detecting algorithm revisions */

#[cfg(test)]
mod tests {
    extern crate nom;
    use super::{CrushMap, BucketTypes, CrushBucketStraw, OpCode, BucketAlg, CrushRuleStep,
                Bucket, CrushRuleMask, Rule, parse_crushmap, encode_crushmap};

    #[test]
    fn test_decode_crushmap() {
        let crushmap_compiled: &[u8] = &[
            0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xfc, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x01, 0x0a, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x6f, 0x73, 0x64, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x68,
            0x6f, 0x73, 0x74, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x63, 0x68, 0x61, 0x73, 0x73,
            0x69, 0x73, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x72, 0x61, 0x63, 0x6b, 0x04, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x77, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x70, 0x64, 0x75, 0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x70, 0x6f, 0x64, 0x07,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x6d, 0x08, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x00, 0x00, 0x64, 0x61, 0x74, 0x61, 0x63, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x09, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x00, 0x00, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x0a, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x07, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x0e,
            0x00, 0x00, 0x00, 0x69, 0x70, 0x2d, 0x31, 0x37, 0x32, 0x2d, 0x33, 0x31, 0x2d, 0x34, 0x2d, 0x35,
            0x36, 0xfd, 0xff, 0xff, 0xff, 0x0e, 0x00, 0x00, 0x00, 0x69, 0x70, 0x2d, 0x31, 0x37, 0x32, 0x2d,
            0x33, 0x31, 0x2d, 0x32, 0x32, 0x2d, 0x32, 0xfe, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00, 0x00, 0x69,
            0x70, 0x2d, 0x31, 0x37, 0x32, 0x2d, 0x33, 0x31, 0x2d, 0x34, 0x33, 0x2d, 0x31, 0x34, 0x37, 0xff,
            0xff, 0xff, 0xff, 0x07, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x6f, 0x73, 0x64, 0x2e, 0x30, 0x01, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x6f, 0x73, 0x64, 0x2e, 0x31, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x6f, 0x73, 0x64, 0x2e, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
            0x00, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x72, 0x75, 0x6c, 0x65,
            0x73, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        println!("crushmap compiled len {}", crushmap_compiled.len());
        let expected_result = CrushMap{
            magic: 65536,
            max_buckets: 8,
            max_rules: 1,
            max_devices: 3,
            buckets: vec![
                BucketTypes::Straw(
                    CrushBucketStraw {
                        bucket: Bucket {
                            struct_size: 4,
                            id: -1,
                            bucket_type: OpCode::SetChooseLocalTries,
                            alg: BucketAlg::Straw,
                            hash: 0,
                            weight: 0,
                            size: 3,
                            items: vec![-2, -3, -4],
                            perm_n: 0,
                            perm: 3
                        },
                        item_weights: vec![(0, 0), (0, 0), (0, 0)] }),
                BucketTypes::Straw(CrushBucketStraw {
                    bucket: Bucket { id: -2, struct_size: 4, bucket_type: OpCode::Take, alg: BucketAlg::Straw, hash: 0, weight: 0, size: 1, items: vec![0], perm_n: 0, perm: 1 }, item_weights: vec![(0, 0)] }),
                BucketTypes::Straw(CrushBucketStraw {
                    bucket: Bucket { id: -3, struct_size: 4, bucket_type: OpCode::Take, alg: BucketAlg::Straw, hash: 0, weight: 0, size: 1, items: vec![1], perm_n: 0, perm: 1 }, item_weights: vec![(0, 0)] }),
                BucketTypes::Straw(CrushBucketStraw {
                    bucket: Bucket { id: -4, struct_size: 4, bucket_type: OpCode::Take, alg: BucketAlg::Straw, hash: 0, weight: 0, size: 1, items: vec![2], perm_n: 0, perm: 1 }, item_weights: vec![(0, 0)] }),
                BucketTypes::Unknown, BucketTypes::Unknown, BucketTypes::Unknown, BucketTypes::Unknown],
            rules: vec![
                Some(
                    Rule {
                        len: 3,
                        mask: CrushRuleMask {
                            ruleset: 0,
                            rule_type: 1,
                            min_size: 1,
                            max_size: 10 },
                        steps: vec![
                            CrushRuleStep {
                                op: 1,
                                arg1: -1,
                                arg2: 0 },
                            CrushRuleStep { op: 6, arg1: 0, arg2: 1 },
                            CrushRuleStep { op: 4, arg1: 0, arg2: 0 }] })],
            type_map: vec![ (0, "osd".to_string()),
                            (1, "host".to_string()),
                            (2, "chassis".to_string()),
                            (3, "rack".to_string()),
                            (4, "row".to_string()),
                            (5, "pdu".to_string()),
                            (6, "pod".to_string()),
                            (7, "room".to_string()),
                            (8, "datacenter".to_string()),
                            (9, "region".to_string()),
                            (10, "root".to_string())],
            name_map: vec![
                (-4, "ip-172-31-4-56".to_string()),
                (-3, "ip-172-31-22-2".to_string()),
                (-2, "ip-172-31-43-147".to_string()),
                (-1, "default".to_string()),
                (0, "osd.0".to_string()),
                (1, "osd.1".to_string()),
                (2, "osd.2".to_string())],
            rule_name_map: vec![(0, "replicated_ruleset".to_string())],
            choose_local_tries: Some(0),
            choose_local_fallback_tries: Some(0),
            choose_total_tries: Some(50),
            chooseleaf_descend_once: Some(1),
            chooseleaf_vary_r: Some(0),
            straw_calc_version: Some(1),
            choose_tries: None
        };
        let result = parse_crushmap(&crushmap_compiled);
        println!("crushmap {:?}", result);
        let x: &[u8] = &[];
        assert_eq!(nom::IResult::Done(x, expected_result), result);
    }

    #[test]
    fn test_encode_crushmap() {
        let expected_result: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff, 0xff, 0xfc, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff,
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x01, 0x0a, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x6f, 0x73, 0x64, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x68,
            0x6f, 0x73, 0x74, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x63, 0x68, 0x61, 0x73, 0x73,
            0x69, 0x73, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x72, 0x61, 0x63, 0x6b, 0x04, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x77, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x70, 0x64, 0x75, 0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x70, 0x6f, 0x64, 0x07,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x6d, 0x08, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x00, 0x00, 0x64, 0x61, 0x74, 0x61, 0x63, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x09, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x00, 0x00, 0x72, 0x65, 0x67, 0x69, 0x6f, 0x6e, 0x0a, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x07, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x0e,
            0x00, 0x00, 0x00, 0x69, 0x70, 0x2d, 0x31, 0x37, 0x32, 0x2d, 0x33, 0x31, 0x2d, 0x34, 0x2d, 0x35,
            0x36, 0xfd, 0xff, 0xff, 0xff, 0x0e, 0x00, 0x00, 0x00, 0x69, 0x70, 0x2d, 0x31, 0x37, 0x32, 0x2d,
            0x33, 0x31, 0x2d, 0x32, 0x32, 0x2d, 0x32, 0xfe, 0xff, 0xff, 0xff, 0x10, 0x00, 0x00, 0x00, 0x69,
            0x70, 0x2d, 0x31, 0x37, 0x32, 0x2d, 0x33, 0x31, 0x2d, 0x34, 0x33, 0x2d, 0x31, 0x34, 0x37, 0xff,
            0xff, 0xff, 0xff, 0x07, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x6f, 0x73, 0x64, 0x2e, 0x30, 0x01, 0x00, 0x00, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x6f, 0x73, 0x64, 0x2e, 0x31, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            0x6f, 0x73, 0x64, 0x2e, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
            0x00, 0x72, 0x65, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x72, 0x75, 0x6c, 0x65,
            0x73, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let crushmap = CrushMap{
            magic: 65536,
            max_buckets: 8,
            max_rules: 1,
            max_devices: 3,
            buckets: vec![
                BucketTypes::Straw(
                    CrushBucketStraw {
                        bucket: Bucket {
                            struct_size: 4,
                            id: -1,
                            bucket_type: OpCode::SetChooseLocalTries,
                            alg: BucketAlg::Straw,
                            hash: 0,
                            weight: 0,
                            size: 3,
                            items: vec![-2, -3, -4],
                            perm_n: 0,
                            perm: 3
                        },
                        item_weights: vec![(0, 0), (0, 0), (0, 0)] }),
                BucketTypes::Straw(CrushBucketStraw {
                    bucket: Bucket { id: -2, struct_size: 4, bucket_type: OpCode::Take, alg: BucketAlg::Straw, hash: 0, weight: 0, size: 1, items: vec![0], perm_n: 0, perm: 1 }, item_weights: vec![(0, 0)] }),
                BucketTypes::Straw(CrushBucketStraw {
                    bucket: Bucket { id: -3, struct_size: 4, bucket_type: OpCode::Take, alg: BucketAlg::Straw, hash: 0, weight: 0, size: 1, items: vec![1], perm_n: 0, perm: 1 }, item_weights: vec![(0, 0)] }),
                BucketTypes::Straw(CrushBucketStraw {
                    bucket: Bucket { id: -4, struct_size: 4, bucket_type: OpCode::Take, alg: BucketAlg::Straw, hash: 0, weight: 0, size: 1, items: vec![2], perm_n: 0, perm: 1 }, item_weights: vec![(0, 0)] }),
                BucketTypes::Unknown, BucketTypes::Unknown, BucketTypes::Unknown, BucketTypes::Unknown],
            rules: vec![
                Some(
                    Rule {
                        len: 3,
                        mask: CrushRuleMask {
                            ruleset: 0,
                            rule_type: 1,
                            min_size: 1,
                            max_size: 10 },
                        steps: vec![
                            CrushRuleStep {
                                op: 1,
                                arg1: -1,
                                arg2: 0 },
                            CrushRuleStep { op: 6, arg1: 0, arg2: 1 },
                            CrushRuleStep { op: 4, arg1: 0, arg2: 0 }] })],
            type_map: vec![ (0, "osd".to_string()),
                            (1, "host".to_string()),
                            (2, "chassis".to_string()),
                            (3, "rack".to_string()),
                            (4, "row".to_string()),
                            (5, "pdu".to_string()),
                            (6, "pod".to_string()),
                            (7, "room".to_string()),
                            (8, "datacenter".to_string()),
                            (9, "region".to_string()),
                            (10, "root".to_string())],
            name_map: vec![
                (-4, "ip-172-31-4-56".to_string()),
                (-3, "ip-172-31-22-2".to_string()),
                (-2, "ip-172-31-43-147".to_string()),
                (-1, "default".to_string()),
                (0, "osd.0".to_string()),
                (1, "osd.1".to_string()),
                (2, "osd.2".to_string())],
            rule_name_map: vec![(0, "replicated_ruleset".to_string())],
            choose_local_tries: Some(0),
            choose_local_fallback_tries: Some(0),
            choose_total_tries: Some(50),
            chooseleaf_descend_once: Some(1),
            chooseleaf_vary_r: Some(0),
            straw_calc_version: Some(1),
            choose_tries: None
        };
        let result = encode_crushmap(crushmap);
        assert_eq!(expected_result, result.unwrap());
    }
}
/*
//TODO: Set default tunables to optimal
fn set_tunables_firefly<'a>(input: &'a mut CrushMap) ->&'a mut CrushMap{
  input.choose_local_tries = Some(0);
  input.choose_local_fallback_tries = Some(0);
  input.choose_total_tries = Some(50);
  input.chooseleaf_descend_once = Some(1);
  input.chooseleaf_vary_r = Some(1);
  input
}

fn set_tunables_optimal<'a>(input: &'a mut CrushMap) ->&'a mut CrushMap{
  let input = set_tunables_firefly(input);
  input.straw_calc_version = Some(1);
  input
}
*/

#[derive(Debug)]
pub enum EncodingError {
	IoError(io::Error),
	InvalidValue,
	InvalidType,
    FromUtf8Error(FromUtf8Error),
}

impl EncodingError{
    pub fn new(err: String) -> EncodingError {
        EncodingError::IoError(
            io::Error::new(ErrorKind::Other, err)
        )
    }
}

impl From<FromUtf8Error> for EncodingError {
    fn from(err: FromUtf8Error) -> EncodingError {
        EncodingError::FromUtf8Error(err)
    }
}

impl From<io::Error> for EncodingError {
    fn from(err: io::Error) -> EncodingError {
        EncodingError::IoError(err)
    }
}

/*
 * A bucket is a named container of other items (either devices or
 * other buckets).  Items within a bucket are chosen using one of a
 * few different algorithms.  The table summarizes how the speed of
 * each option measures up against mapping stability when items are
 * added or removed.
 *
 *  Bucket Alg     Speed       Additions    Removals
 *  ------------------------------------------------
 *  uniform         O(1)       poor         poor
 *  list            O(n)       optimal      poor
 *  tree            O(log n)   good         good
 *  straw           O(n)       optimal      optimal
 */
enum_from_primitive!{
    #[repr(u8)]
    #[derive(Debug, Clone, Eq, PartialEq)]
    enum BucketAlg{
        Uniform = 1,
        List = 2,
        Tree = 3,
        Straw = 4,
    }
}

/* step op codes */
enum_from_primitive!{
    #[repr(u16)]
    #[derive(Debug, Clone, Eq, PartialEq)]
    enum OpCode{
        Noop = 0,
        Take = 1,          /* arg1 = value to start with */
        ChooseFirstN = 2, /* arg1 = num items to pick */
                          /* arg2 = type */
        ChooseIndep = 3,  /* same */
        Emit = 4,          /* no args */
        ChooseLeafFirstN = 6,
        ChooseLeafIndep = 7,

        SetChooseTries = 8, /* override choose_total_tries */
        SetChooseLeafTries = 9, /* override chooseleaf_descend_once */
        SetChooseLocalTries = 10,
        SetChooseLocalFallbackTries = 11,
        SetChooseLeafVaryR = 12
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CrushBucketUniform {
    bucket: Bucket,
    item_weight: u32,  /* 16-bit fixed point; all items equally weighted */
}

impl CrushBucketUniform{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            bucket: call!(Bucket::parse)~
            weight: le_u32,
            ||{
                CrushBucketUniform{
                    bucket: bucket,
                    item_weight: weight,
                }
            }
        )
    }

    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.encode()));
        try!(buffer.write_u32::<LittleEndian>(self.item_weight));

        Ok(buffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CrushBucketList {
    bucket: Bucket,
    item_weights: Vec<(u32, u32)>,  /* 16-bit fixed point */
    //sum_weights: u32,   /* 16-bit fixed point.  element i is sum
    //             of weights 0..i, inclusive */
}
impl CrushBucketList{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            bucket: call!(Bucket::parse)~
            item_weights: count!(
                pair!(le_u32, le_u32),
                bucket.size as usize),
            ||{
                CrushBucketList{
                    bucket: bucket,
                    item_weights: item_weights,
                }
            }
        )
    }

    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.encode()));

        for weights in self.item_weights.iter(){
            try!(buffer.write_u32::<LittleEndian>(weights.0));
            try!(buffer.write_u32::<LittleEndian>(weights.1));
        }

        Ok(buffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CrushBucketTree {
    /* note: h.size is _tree_ size, not number of
           actual items */
    bucket: Bucket,
    num_nodes: u8,
    node_weights: Vec<u32>,
}

impl CrushBucketTree{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            bucket: call!(Bucket::parse)~
            num_nodes: le_u8~
            node_weights: count!(le_u32, num_nodes as usize),
            ||{
                CrushBucketTree{
                    bucket: bucket,
                    num_nodes: num_nodes,
                    node_weights: node_weights
                }
            }
        )
    }
    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.encode()));

        try!(buffer.write_u8(self.num_nodes));

        for weight in self.node_weights.iter(){
            try!(buffer.write_u32::<LittleEndian>(*weight));
        }

        Ok(buffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CrushBucketStraw {
    bucket: Bucket,
    item_weights: Vec<(u32, u32)>,   /* 16-bit fixed point */
    //straws: u32,         /* 16-bit fixed point */
}

impl CrushBucketStraw{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            bucket: call!(Bucket::parse)~
            item_weights: count!(pair!(le_u32, le_u32), bucket.size as usize),
            //straws: le_u32,
            ||{
                CrushBucketStraw{
                    bucket: bucket,
                    item_weights: item_weights,
                    //straws: straws,
                }
            }
        )
    }
    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.encode()));

        for weights in self.item_weights.iter(){
            try!(buffer.write_u32::<LittleEndian>(weights.0));
            try!(buffer.write_u32::<LittleEndian>(weights.1));
        }

        Ok(buffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
enum BucketTypes{
    Uniform(CrushBucketUniform),
    List(CrushBucketList),
    Tree(CrushBucketTree),
    Straw(CrushBucketStraw),
    Unknown
}

named!(decode_32_or_64<&[u8], u32>,
    chain!(
        a: le_u32~
        //if a ==0 take another u32
        b: cond!(a==0, le_u32),
        ||{
            b.unwrap_or(a)
        }
    )
);

fn try_le_u8(input: &[u8]) ->nom::IResult<&[u8], Option<u8>>{
    if input.len() == 0{
        nom::IResult::Done(input, None)
    }else{
        chain!(input,
            a: le_u8,
            ||{
                Some(a)
            }
        )
    }
}

fn try_le_u32(input: &[u8]) ->nom::IResult<&[u8], Option<u32>>{
    if input.len() < 5{
        nom::IResult::Done(input, None)
    }else{
        chain!(input,
            a: le_u32,
            ||{
                Some(a)
            }
        )
    }
}

fn parse_string(i: & [u8]) -> nom::IResult<&[u8], String> {
    trace!("parse_string input: {:?}", i);
    chain!(i,
        length: decode_32_or_64 ~
        s: dbg!(take_str!(length)),
        ||{
            s.to_string()
        }
    )
}

fn parse_string_map(input: & [u8])->nom::IResult<&[u8], Vec<(i32,String)>>{
    trace!("parse_string_map input: {:?}", input);
    chain!(input,
        count: le_u32~
        string_map: dbg!(
            count!(
                pair!(le_i32,
                    dbg!(call!(parse_string))), count as usize)),
        ||{
            string_map
        }
    )
}

fn encode_string_map(input: Vec<(i32, String)>)->Result<Vec<u8>, EncodingError>{
    let mut buffer = Vec::new();
    //Count
    try!(buffer.write_u32::<LittleEndian>(input.len() as u32));

    for pair in input.into_iter(){
        try!(buffer.write_i32::<LittleEndian>(pair.0));

        //String length
        try!(buffer.write_u32::<LittleEndian>(pair.1.len() as u32));
        //String data
        buffer.extend(pair.1.into_bytes());
    }

    Ok(buffer)
}

fn parse_bucket<'a>(input: &'a [u8]) -> nom::IResult<&[u8], BucketTypes>{
    trace!("parse_bucket input: {:?}", input);
    let alg_type_bits = le_u32(input);
    match alg_type_bits{
        nom::IResult::Done(unparsed_data, alg_bits) =>{
            let some_alg = BucketAlg::from_u32(alg_bits);
            let alg = match some_alg{
                Some(t) => t,
                None => {
                    trace!("Unknown bucket: {:?}", alg_bits);
                    return nom::IResult::Done(unparsed_data, BucketTypes::Unknown);
                }
            };
            match alg{
                BucketAlg::Uniform =>{
                trace!("Trying to decode uniform bucket");
                    chain!(
                        input,
                        uniform_bucket: dbg!(call!(CrushBucketUniform::parse)),
                        ||{
                            BucketTypes::Uniform(uniform_bucket)
                        }
                    )
                },
                BucketAlg::List => {
                trace!("Trying to decode list bucket");
                    chain!(
                        input,
                        list_bucket: dbg!(call!(CrushBucketList::parse)),
                        ||{
                            BucketTypes::List(list_bucket)
                        }
                    )
                },
                BucketAlg::Tree => {
                trace!("Trying to decode tree bucket");
                    chain!(
                        input,
                        tree_bucket: dbg!(call!(CrushBucketTree::parse)),
                        ||{
                            BucketTypes::Tree(tree_bucket)
                        }
                    )
                },
                BucketAlg::Straw => {
                trace!("Trying to decode straw bucket");
                    chain!(
                        input,
                        straw_bucket: dbg!(call!(CrushBucketStraw::parse)),
                        ||{
                            BucketTypes::Straw(straw_bucket)
                        }
                    )
                },
            }
        }
        nom::IResult::Incomplete(needed) => {
            return nom::IResult::Incomplete(needed);
        }
        nom::IResult::Error(e) => {
            return nom::IResult::Error(e);
        },
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Bucket{
    struct_size: u32,
    id: i32,          /* this'll be negative */
    bucket_type: OpCode, /* non-zero; type=0 is reserved for devices */
    alg: BucketAlg,          /* one of CRUSH_BUCKET_* */
    hash: u8,         /* which hash function to use, CRUSH_HASH_* */
    weight: u32,      /* 16-bit fixed point */
    size: u32,        /* num items */
    items: Vec<i32>,
    /*
     * cached random permutation: used for uniform bucket and for
     * the linear search fallback for the other bucket types.
     */
    //perm_x: u32, /* @x for which *perm is defined */
    perm_n: u32, /* num elements of *perm that are permuted/defined */
    perm: u32,
}

impl Bucket{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        trace!("bucket input: {:?}", input);
        chain!(
            input,
            struct_size: le_u32~
            //switch on algorithm
            id: le_i32~
            bucket_type_bits: le_u16 ~
            bucket_type: expr_opt!(OpCode::from_u16(bucket_type_bits)) ~
            alg_bits: le_u8~
            alg: expr_opt!(BucketAlg::from_u8(alg_bits))~
            hash: le_u8~
            weight: le_u32~
            size: le_u32~
            items: dbg!(count!(le_i32, size as usize)),
            ||{
                Bucket{
                    struct_size: struct_size,
                    id: id,
                    bucket_type: bucket_type,
                    alg: alg,
                    hash: hash,
                    weight: weight,
                    size: size,
                    perm_n: 0,
                    perm: size,
                    items: items,
                }
            }
        )
    }
    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u32::<LittleEndian>(self.struct_size));
        try!(buffer.write_i32::<LittleEndian>(self.id));
        try!(buffer.write_u16::<LittleEndian>(self.bucket_type.clone() as u16));
        try!(buffer.write_u8(self.alg.clone() as u8));
        try!(buffer.write_u8(self.hash));
        try!(buffer.write_u32::<LittleEndian>(self.weight));
        try!(buffer.write_u32::<LittleEndian>(self.size));

        for item in self.items.iter(){
            try!(buffer.write_i32::<LittleEndian>(*item));
        }

        Ok(buffer)
    }
}

/*
 * CRUSH uses user-defined "rules" to describe how inputs should be
 * mapped to devices.  A rule consists of sequence of steps to perform
 * to generate the set of output devices.
 */
#[derive(Debug, Eq, PartialEq)]
struct CrushRuleStep {
    op: u32,
    arg1: i32,
    arg2: i32,
}

impl CrushRuleStep{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        trace!("rule step input: {:?}", input);
        chain!(
            input,
            op: le_u32~
            arg1: le_i32~
            arg2: le_i32,
            ||{
                CrushRuleStep{
                    op: op,
                    arg1: arg1,
                    arg2: arg2,
                }
            }
        )
    }
    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u32::<LittleEndian>(self.op));
        try!(buffer.write_i32::<LittleEndian>(self.arg1));
        try!(buffer.write_i32::<LittleEndian>(self.arg2));

        Ok(buffer)
    }
}

/*
 * The rule mask is used to describe what the rule is intended for.
 * Given a ruleset and size of output set, we search through the
 * rule list for a matching rule_mask.
 */
#[derive(Debug, Eq, PartialEq)]
struct CrushRuleMask {
    ruleset: u8,
    rule_type: u8,
    min_size: u8,
    max_size: u8,
}

impl CrushRuleMask{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        trace!("rule mask input: {:?}", input);
        chain!(
            input,
            ruleset: le_u8~
            rule_type: le_u8~
            min_size: le_u8~
            max_size: le_u8,
            ||{
                CrushRuleMask{
                    ruleset: ruleset,
                    rule_type: rule_type,
                    min_size: min_size,
                    max_size: max_size,
                }
            }
        )
    }
    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.ruleset));
        try!(buffer.write_u8(self.rule_type));
        try!(buffer.write_u8(self.min_size));
        try!(buffer.write_u8(self.max_size));

        Ok(buffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Rule{
    len: u32,
    mask: CrushRuleMask,
    steps: Vec<CrushRuleStep>,
}

impl Rule{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Option<Self>>{
        trace!("rule input: {:?}", input);
        let yes_bits = le_u32(input);
        match yes_bits{
            nom::IResult::Done(unparsed_data, yes) =>{
                if yes == 0{
                    return nom::IResult::Done(unparsed_data, None)
                }else{
                    chain!(
                        unparsed_data,
                        length: le_u32~
                        mask: dbg!(call!(CrushRuleMask::parse))~
                        steps: dbg!(count!(call!(CrushRuleStep::parse), length as usize)),
                        ||{
                            Some(Rule{
                                len: length,
                                mask: mask,
                                steps: steps,
                            })
                        }
                    )
                }
            },
            nom::IResult::Incomplete(needed) => {
                return nom::IResult::Incomplete(needed);
            }
            nom::IResult::Error(e) => {
                return nom::IResult::Error(e);
            },
        }
    }
    fn encode(&self) -> Result<Vec<u8>, EncodingError>{
        let mut buffer: Vec<u8> = Vec::new();
        //YES
        try!(buffer.write_u32::<LittleEndian>(1));

        try!(buffer.write_u32::<LittleEndian>(self.len));
        buffer.extend(try!(self.mask.encode()));
        //Steps length
        for step in self.steps.iter(){
            buffer.extend(try!(step.encode()));
        }

        Ok(buffer)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CrushMap {
    magic: u32,
    max_buckets: i32,
    max_rules: u32,
    max_devices: i32,

    buckets: Vec<BucketTypes>,
    rules: Vec<Option<Rule>>,

    type_map: Vec<(i32, String)>,
    name_map: Vec<(i32, String)>,
    rule_name_map: Vec<(i32, String)>,

    /* choose local retries before re-descent */
    choose_local_tries: Option<u32>,
    /* choose local attempts using a fallback permutation before
     * re-descent */
    choose_local_fallback_tries: Option<u32>,
    /* choose attempts before giving up */
    choose_total_tries: Option<u32>,
    /* attempt chooseleaf inner descent once for firstn mode; on
     * reject retry outer descent.  Note that this does *not*
     * apply to a collision: in that case we will retry as we used
     * to. */
    chooseleaf_descend_once: Option<u32>,

    /* if non-zero, feed r into chooseleaf, bit-shifted right by (r-1)
     * bits.  a value of 1 is best for new clusters.  for legacy clusters
     * that want to limit reshuffling, a value of 3 or 4 will make the
     * mappings line up a bit better with previous mappings. */
    chooseleaf_vary_r: Option<u8>,
    straw_calc_version: Option<u8>,
    choose_tries: Option<u32>,
}

fn parse_crushmap<'a>(input: &'a [u8]) -> nom::IResult<&[u8], CrushMap>{
    trace!("crushmap input: {:?}", input);
    chain!(
        input,
        //preamble
        crush_magic: le_u32 ~

        max_buckets: le_i32 ~
        max_rules: le_u32 ~
        max_devices: le_i32 ~

        buckets: dbg!(count!(
            call!(parse_bucket),
            max_buckets as usize
        ))~
        rules: dbg!(count!(
            call!(Rule::parse),
            max_rules as usize
        ))~
        type_map: call!(parse_string_map)~
        name_map: call!(parse_string_map)~
        rule_name_map: call!(parse_string_map)~

        //Tunables
        choose_local_tries: call!(try_le_u32)~
        choose_local_fallback_tries: call!(try_le_u32)~
        choose_total_tries: call!(try_le_u32)~
        chooseleaf_descend_once: call!(try_le_u32) ~
        chooseleaf_vary_r: call!(try_le_u8) ~
        straw_calc_version: call!(try_le_u8) ~
        choose_tries: call!(try_le_u32) ,
        || {
            CrushMap{
                magic: crush_magic,
                max_buckets: max_buckets,
                max_rules: max_rules,
                max_devices: max_devices,

                buckets: buckets,
                rules: rules,
                type_map: type_map,
                name_map: name_map,
                rule_name_map: rule_name_map,

                choose_local_tries: choose_local_tries,
                choose_local_fallback_tries: choose_local_fallback_tries,
                choose_total_tries: choose_total_tries,
                chooseleaf_descend_once: chooseleaf_descend_once,
                chooseleaf_vary_r: chooseleaf_vary_r,
                straw_calc_version: straw_calc_version,
                choose_tries: choose_tries,
            }
        }
    )
}
fn encode_crushmap(crushmap: CrushMap) -> Result<Vec<u8>, EncodingError>{
    let mut buffer: Vec<u8> = Vec::new();
    try!(buffer.write_u32::<LittleEndian>(CRUSH_MAGIC));

    try!(buffer.write_i32::<LittleEndian>(crushmap.max_buckets));
    try!(buffer.write_u32::<LittleEndian>(crushmap.max_rules));
    try!(buffer.write_i32::<LittleEndian>(crushmap.max_devices));

    for bucket in crushmap.buckets.iter(){
        match bucket{
            &BucketTypes::Uniform(ref uniform) =>{
                trace!("Trying to encode uniform bucket");
                buffer.extend(try!(uniform.encode()));
            },
            &BucketTypes::List(ref list) => {
                trace!("Trying to encode list bucket");
                buffer.extend(try!(list.encode()));
            },
            &BucketTypes::Tree(ref tree) => {
                trace!("Trying to encode tree bucket");
                buffer.extend(try!(tree.encode()));
            },
            &BucketTypes::Straw(ref straw) => {
                trace!("Trying to encode straw bucket");
                buffer.extend(try!(straw.encode()));
            },
            &BucketTypes::Unknown => {
                try!(buffer.write_u32::<LittleEndian>(0));
            }
        }
    }

    for rule in crushmap.rules.into_iter(){
        if rule.is_some(){
            let unwrapped_rule = rule.unwrap();
            buffer.extend(try!(unwrapped_rule.encode()));
        }else{
            //yes bits == 0
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    }
    buffer.extend(try!(encode_string_map(crushmap.type_map)));
    buffer.extend(try!(encode_string_map(crushmap.name_map)));
    buffer.extend(try!(encode_string_map(crushmap.rule_name_map)));

    if crushmap.choose_local_tries.is_some(){
        try!(buffer.write_u32::<LittleEndian>(crushmap.choose_local_tries.unwrap()));
    }
    if crushmap.choose_local_fallback_tries.is_some(){
        try!(buffer.write_u32::<LittleEndian>(crushmap.choose_local_fallback_tries.unwrap()));
    }
    if crushmap.choose_total_tries.is_some(){
        try!(buffer.write_u32::<LittleEndian>(crushmap.choose_total_tries.unwrap()));
    }
    if crushmap.chooseleaf_descend_once.is_some(){
        try!(buffer.write_u32::<LittleEndian>(crushmap.chooseleaf_descend_once.unwrap()));
    }
    if crushmap.chooseleaf_vary_r.is_some(){
        try!(buffer.write_u8(crushmap.chooseleaf_vary_r.unwrap()));
    }
    if crushmap.straw_calc_version.is_some(){
        try!(buffer.write_u8(crushmap.straw_calc_version.unwrap()));
    }
    if crushmap.choose_tries.is_some(){
        try!(buffer.write_u32::<LittleEndian>(crushmap.choose_tries.unwrap()));
    }

    Ok(buffer)
}

fn main() {
    // simple_logger::init_with_level(log::LogLevel::Trace).unwrap();
    simple_logger::init_with_level(log::LogLevel::Warn).unwrap();
    let mut buffer: Vec<u8> = vec![];
    match io::stdin().read_to_end(&mut buffer) {
        Ok(_) => trace!("Read input from STDIN"),
        Err(e) => trace!("Failed to read STDIN: {:?}", e)
    };

    let input: &[u8] = &buffer.as_slice();
    let result: CrushMap = match parse_crushmap(&input){
        nom::IResult::Done(_, r) => r,
        _ => panic!("There was a problem parsing the crushmap"),
    };
    if result.magic != CRUSH_MAGIC {
        panic!("Could not decompile crushmap");
    }
    println!("{:?}", result);
}
