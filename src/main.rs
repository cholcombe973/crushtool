//Decompile a ceph crushmap for fun and profit
//
extern crate nom;
extern crate byteorder;

use nom::{le_i8, le_u8, le_i16, le_u16, le_i32, le_u32, le_i64, le_u64, be_u16};

static CRUSH_MAGIC: u32 = 0x00010000;  /* for detecting algorithm revisions */

enum BUCKET_ALG{
    UNIFORM = 1,
    LIST = 2,
    TREE = 3,
    STRAW = 4
}

/* step op codes */
enum OP_CODE{
    NOOP = 0,
    TAKE = 1,          /* arg1 = value to start with */
    CHOOSE_FIRSTN = 2, /* arg1 = num items to pick */
                      /* arg2 = type */
    CHOOSE_INDEP = 3,  /* same */
    EMIT = 4,          /* no args */
    CHOOSELEAF_FIRSTN = 6,
    CHOOSELEAF_INDEP = 7,

    SET_CHOOSE_TRIES = 8, /* override choose_total_tries */
    SET_CHOOSELEAF_TRIES = 9, /* override chooseleaf_descend_once */
    SET_CHOOSE_LOCAL_TRIES = 10,
    SET_CHOOSE_LOCAL_FALLBACK_TRIES = 11,
    SET_CHOOSELEAF_VARY_R = 12
}

struct Bucket{
    id: i32,          /* this'll be negative */
    bucket_type: u16, /* non-zero; type=0 is reserved for devices */
    alg: u8,          /* one of CRUSH_BUCKET_* */
    hash: u8,         /* which hash function to use, CRUSH_HASH_* */
    weight: u32,      /* 16-bit fixed point */
    size: u32,        /* num items */
    items: Vec<i32>,

    /*
     * cached random permutation: used for uniform bucket and for
     * the linear search fallback for the other bucket types.
     */
    perm_x: u32, /* @x for which *perm is defined */
    perm_n: u32, /* num elements of *perm that are permuted/defined */
    perm: u32,
}

impl Bucket{
    fn parse(input: &'a [u8]) -> nom::IResult<&[u8], Self>{
        chain!(
            input,
            algorithm: le_u32,
            //switch on algorithm
            id: le_i32,
            bucket_type: le_u16,
            alg: le_u8,
            hash: le_u8,
            weight: le_u32,
            size: le_u32,
        )
    }
}

struct CrushRuleStep {
    op: u32,
    arg1: i32,
    arg2: i32,
}

struct CrushRuleMask {
    ruleset: u8,
    rule_type: u8,
    min_size: u8,
    max_size: u8,
}

struct Rule{
    len: u32,
    mask: CrushRuleMask,
    steps: CrushRuleStep,
}

struct CrushMap {
    buckets: Vec<Bucket>,
    rules: Vec<Rule>,
    max_buckets: i32,
    max_rules: u32,
    max_devices: i32,

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
    chooseleaf_vary_r: u8,

    /*
     * version 0 (original) of straw_calc has various flaws.  version 1
     * fixes a few of them.
     */
    straw_calc_version: u8,
    choose_tries: u32,
}

fn parse_crushmap<'a>(input: &'a [u8]) -> nom::IResult<&[u8], CrushMap>{
    chain!(
        input,
        //preamble
        crush_magic: le_u32 ~

        max_buckets: le_i32 ~
        max_rules: le_u32 ~
        max_devices: le_i32 ~

        buckets: count!(
            call!(Bucket::parse),
            max_buckets as usize
        )
        rules: count!(
            call!(Rule::parse),
            max_rules as usize
        )
        //Tunables
        choose_local_tries: le_u32 ~
        choose_local_fallback_tries: le_u32 ~
        choose_total_tries: le_u32 ~
        chooseleaf_descend_once: le_u32 ~
        chooseleaf_vary_r: le_u32 ~
        straw_calc_version: le_u8 ~

        || {
            CrushMap{
                max_buckets: max_buckets,
                max_rules: max_rules,
                max_devices: max_devices,

                choose_local_tries: choose_local_tries,
                choose_local_fallback_tries: choose_local_fallback_tries,
                choose_total_tries: choose_total_tries,
                chooseleaf_descend_once: chooseleaf_descend_once,
                chooseleaf_vary_r: chooseleaf_vary_r,
                straw_calc_version: straw_calc_version,
            }
        }
    )
}

fn main() {
    let input: &[u8] = &[];
    parse_crushmap(input);
}
