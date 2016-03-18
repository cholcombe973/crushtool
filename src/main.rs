//Decompile a ceph crushmap for fun and profit
//

#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate log;
#[macro_use] extern crate nom;
extern crate num;
extern crate simple_logger;

use std::io::{self, Read};

use num::FromPrimitive;
use nom::{le_u8, le_u16, le_i32, le_u32};

static CRUSH_MAGIC: u32 = 0x00010000;  /* for detecting algorithm revisions */

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
    let result = parse_crushmap(&crushmap_compiled);
    println!("crushmap {:?}", result);
    // assert_eq!(result, expected_bytes);
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
    #[derive(Debug, Clone)]
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
    #[derive(Debug)]
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

#[derive(Debug)]
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
}

#[derive(Debug)]
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
}

#[derive(Debug)]
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
}

#[derive(Debug)]
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
}

#[derive(Debug)]
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

#[derive(Debug)]
struct Bucket{
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
}

/*
 * CRUSH uses user-defined "rules" to describe how inputs should be
 * mapped to devices.  A rule consists of sequence of steps to perform
 * to generate the set of output devices.
 */
#[derive(Debug)]
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
}

/*
 * The rule mask is used to describe what the rule is intended for.
 * Given a ruleset and size of output set, we search through the
 * rule list for a matching rule_mask.
 */
#[derive(Debug)]
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
}

#[derive(Debug)]
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
}

#[derive(Debug)]
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
    /*
    choose_local_tries: u32,
    /* choose local attempts using a fallback permutation before
     * re-descent */
    choose_local_fallback_tries: u32,
    /* choose attempts before giving up */
    choose_total_tries: u32,
    /* attempt chooseleaf inner descent once for firstn mode; on
     * reject retry outer descent.  Note that this does *not*
     * apply to a collision: in that case we will retry as we used
     * to. */
    chooseleaf_descend_once: u32,

    /* if non-zero, feed r into chooseleaf, bit-shifted right by (r-1)
     * bits.  a value of 1 is best for new clusters.  for legacy clusters
     * that want to limit reshuffling, a value of 3 or 4 will make the
     * mappings line up a bit better with previous mappings. */
    chooseleaf_vary_r: u8,
    straw_calc_version: u8,
    choose_tries: u32,
    */
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
        rule_name_map: call!(parse_string_map),

        //Tunables
        /*
        choose_local_tries: le_u32 ~
        choose_local_fallback_tries: le_u32 ~
        choose_total_tries: le_u32 ~
        chooseleaf_descend_once: le_u32 ~
        chooseleaf_vary_r: le_u8 ~
        straw_calc_version: le_u8 ~
        choose_tries: le_u32 ,
        */
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

                /*
                choose_local_tries: choose_local_tries,
                choose_local_fallback_tries: choose_local_fallback_tries,
                choose_total_tries: choose_total_tries,
                chooseleaf_descend_once: chooseleaf_descend_once,
                chooseleaf_vary_r: chooseleaf_vary_r,
                straw_calc_version: straw_calc_version,
                choose_tries: choose_tries,
                */
            }
        }
    )
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
