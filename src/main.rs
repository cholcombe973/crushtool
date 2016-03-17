//Decompile a ceph crushmap for fun and profit
//

#[macro_use] extern crate enum_primitive;
#[macro_use] extern crate nom;
extern crate num;
use num::FromPrimitive;
//extern crate byteorder;

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

enum_from_primitive!{
    #[repr(u8)]
    #[derive(Debug, Clone)]
    enum BucketAlg{
        Uniform = 1,
        List = 2,
        Tree = 3,
        Straw = 4
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
    item_weight: u32,  /* 16-bit fixed point; all items equally weighted */
}

impl CrushBucketUniform{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            weight: le_u32,
            ||{
                CrushBucketUniform{
                    item_weight: weight,
                }
            }
        )
    }
}

#[derive(Debug)]
struct CrushBucketList {
    item_weights: Vec<(u32, u32)>,  /* 16-bit fixed point */
    //sum_weights: u32,   /* 16-bit fixed point.  element i is sum
    //             of weights 0..i, inclusive */
}
impl CrushBucketList{
    fn parse<'a>(input: &'a [u8], size: u32) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            item_weights: count!(
                pair!(le_u32, le_u32),
                size as usize),
            ||{
                CrushBucketList{
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
    num_nodes: u8,
    node_weights: Vec<u32>,
}

impl CrushBucketTree{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            num_nodes: le_u8~
            node_weights: count!(le_u32, num_nodes as usize),
            ||{
                CrushBucketTree{
                    num_nodes: num_nodes,
                    node_weights: node_weights
                }
            }
        )
    }
}

#[derive(Debug)]
struct CrushBucketStraw {
    item_weights: Vec<(u32, u32)>,   /* 16-bit fixed point */
    //straws: u32,         /* 16-bit fixed point */
}

impl CrushBucketStraw{
    fn parse<'a>(input: &'a [u8], size: u32) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            item_weights: count!(pair!(le_u32, le_u32), size as usize),
            //straws: le_u32,
            ||{
                CrushBucketStraw{
                    item_weights: item_weights,
                    //straws: straws,
                }
            }
        )
    }
}

#[derive(Debug)]
enum BucketTypes{
    uniform(CrushBucketUniform),
    list(CrushBucketList),
    tree(CrushBucketTree),
    straw(CrushBucketStraw),
}

fn parse_bucket<'a>(input: &'a [u8], algorithm: BucketAlg, size: u32) -> nom::IResult<&[u8], BucketTypes>{
    match algorithm{
        BucketAlg::Uniform =>{
            chain!(
                input,
                uniform_bucket: dbg!(call!(CrushBucketUniform::parse)),
                ||{
                    BucketTypes::uniform(uniform_bucket)
                }
            )
        },
        BucketAlg::List => {
            chain!(
                input,
                list_bucket: dbg!(call!(CrushBucketList::parse, size)),
                ||{
                    BucketTypes::list(list_bucket)
                }
            )
        },
        BucketAlg::Tree => {
            chain!(
                input,
                tree_bucket: dbg!(call!(CrushBucketTree::parse)),
                ||{
                    BucketTypes::tree(tree_bucket)
                }
            )
        },
        BucketAlg::Straw => {
            chain!(
                input,
                straw_bucket: dbg!(call!(CrushBucketStraw::parse, size)),
                ||{
                    BucketTypes::straw(straw_bucket)
                }
            )
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
    buckets: BucketTypes,
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
        //println!("bucket input: {:?}", input);
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
            items: dbg!(count!(le_i32, size as usize))~
            buckets: dbg!(call!(parse_bucket, alg.clone(), size)),
            ||{
                Bucket{
                    id: id,
                    bucket_type: bucket_type,
                    alg: alg,
                    hash: hash,
                    weight: weight,
                    size: size,
                    buckets: buckets,
                    perm_n: 0,
                    perm: size,
                    items: items,
                }
            }
        )
    }
}

#[derive(Debug)]
struct CrushRuleStep {
    op: u32,
    arg1: i32,
    arg2: i32,
}

impl CrushRuleStep{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        println!("rule step input: {:?}", input);
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

#[derive(Debug)]
struct CrushRuleMask {
    ruleset: u8,
    rule_type: u8,
    min_size: u8,
    max_size: u8,
}

impl CrushRuleMask{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        println!("rule mask input: {:?}", input);
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
    steps: CrushRuleStep,
}

impl Rule{
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        println!("rule input: {:?}", input);
        chain!(
            input,
            length: le_u32~
            mask: dbg!(call!(CrushRuleMask::parse))~
            steps: dbg!(call!(CrushRuleStep::parse)),
            ||{
                Rule{
                    len: length,
                    mask: mask,
                    steps: steps,
                }
            }
        )
    }
}

#[derive(Debug)]
struct CrushMap {
    magic: u32,
    max_buckets: i32,
    max_rules: u32,
    max_devices: i32,

    buckets: Vec<Bucket>,
    /*
    rules: Vec<Rule>,

    /* choose local retries before re-descent */
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
    chooseleaf_vary_r: u8,bucket input: [0, 0, 0, 255, 255, 255, 10, 0, 4, 0, 0, 0, 0, 0, 3, 0, 0, 0, 254, 255, 255, 253, 255, 255, 255, 252, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 254, 255, 255, 255, 1, 0, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 253, 255, 255, 255, 1, 0, 4, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 252, 255, 255, 255, 1, 0, 4, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 1, 1, 10, 1, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 111, 115, 100, 0, 0, 0, 4, 0, 0, 0, 104, 111, 115, 116, 2, 0, 0, 0, 0, 0, 0, 99, 104, 97, 115, 115, 105, 115, 3, 0, 0, 0, 4, 0, 0, 114, 97, 99, 107, 4, 0, 0, 0, 3, 0, 0, 0, 114, 119, 5, 0, 0, 0, 3, 0, 0, 0, 112, 100, 117, 6, 0, 0, 3, 0, 0, 0, 112, 111, 100, 7, 0, 0, 0, 4, 0, 0, 0, 111, 111, 109, 8, 0, 0, 0, 10, 0, 0, 0, 100, 97, 116, 97, 101, 110, 116, 101, 114, 9, 0, 0, 0, 6, 0, 0, 0, 114, 101, 105, 111, 110, 10, 0, 0, 0, 4, 0, 0, 0, 114, 111, 111, 116, 0, 0, 0, 252, 255, 255, 255, 14, 0, 0, 0, 105, 112, 45, 49, 50, 45, 51, 49, 45, 52, 45, 53, 54, 253, 255, 255, 255, 14, 0, 0, 105, 112, 45, 49, 55, 50, 45, 51, 49, 45, 50, 50, 45, 50, 255, 255, 255, 16, 0, 0, 0, 105, 112, 45, 49, 55, 50, 45, 51, 45, 52, 51, 45, 49, 52, 55, 255, 255, 255, 255, 7, 0, 0, 0, 101, 102, 97, 117, 108, 116, 0, 0, 0, 0, 5, 0, 0, 0, 111, 100, 46, 48, 1, 0, 0, 0, 5, 0, 0, 0, 111, 115, 100, 46, 2, 0, 0, 0, 5, 0, 0, 0, 111, 115, 100, 46, 50, 1, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 114, 101, 112, 108, 105, 99, 116, 101, 100, 95, 114, 117, 108, 101, 115, 101, 116, 0, 0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 1, 0, 0, 0, 0, 1]
 has various flaws.  version 1
     * fixes a few of them.
     */
     /*
    straw_calc_version: u8,
    choose_tries: u32,
    */
}

fn parse_crushmap<'a>(input: &'a [u8]) -> nom::IResult<&[u8], CrushMap>{
    println!("crushmap input: {:?}", input);
    chain!(
        input,
        //preamble
        crush_magic: le_u32 ~

        max_buckets: le_i32 ~
        max_rules: le_u32 ~
        max_devices: le_i32 ~

        buckets: dbg!(count!(
            call!(Bucket::parse),
            4
            //max_buckets as usize
        )),
        /*
        rules: dbg!(count!(
            call!(Rule::parse),
            max_rules as usize
        ))~
        //Tunables
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
                /*
                rules: rules,

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
    let input: &[u8] = &[];
    parse_crushmap(&input);
}
