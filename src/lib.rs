//! Decompile a ceph crushmap for fun and profit
//!
//!
//! CRUSH is a pseudo-random data distribution algorithm that
//! efficiently distributes input values (typically, data objects)
//! across a heterogeneous, structured storage cluster.
//!
//! The algorithm was originally described in detail in this paper
//! (although the algorithm has evolved somewhat since then):
//! http://www.ssrc.ucsc.edu/Papers/weil-sc06.pdf
//!

extern crate byteorder;
#[macro_use]
extern crate enum_primitive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate num;
extern crate rustc_serialize;

use std::io as std_io;
use std::string::FromUtf8Error;

// use rustc_serialize::json;

mod io;

pub use io::{encode_crushmap, decode_crushmap};

/// Set the crush tunables to Argonaut
///
pub fn set_tunables_argonaut(crushmap: &mut CrushMap) -> &mut CrushMap {
    let algorithm: u32 = (1 << BucketAlg::Uniform as u32) | (1 << BucketAlg::List as u32) |
                         (1 << BucketAlg::Straw as u32);
    crushmap.choose_local_tries = Some(2);
    crushmap.choose_local_fallback_tries = Some(5);
    crushmap.choose_total_tries = Some(19);
    crushmap.chooseleaf_descend_once = Some(0);
    crushmap.chooseleaf_vary_r = Some(0);
    crushmap.chooseleaf_stable = Some(0);
    crushmap.allowed_bucket_algorithms = Some(algorithm);
    crushmap
}
/// Set the crush tunables to Bobtail
///
pub fn set_tunables_bobtail(crushmap: &mut CrushMap) -> &mut CrushMap {
    set_tunables_argonaut(crushmap);
    crushmap.choose_local_tries = Some(0);
    crushmap.choose_local_fallback_tries = Some(0);
    crushmap.choose_total_tries = Some(50);
    crushmap.chooseleaf_descend_once = Some(1);
    crushmap
}
/// Set the crush tunables to Firefly
///
pub fn set_tunables_firefly(crushmap: &mut CrushMap) -> &mut CrushMap {
    set_tunables_bobtail(crushmap);
    crushmap.chooseleaf_vary_r = Some(1);
    crushmap
}
/// Set the crush tunables to Hammer
///
pub fn set_tunables_hammer(crushmap: &mut CrushMap) -> &mut CrushMap {
    let algorithm: u32 = (1 << BucketAlg::Uniform as u32) | (1 << BucketAlg::List as u32) |
                         (1 << BucketAlg::Straw as u32) |
                         (1 << BucketAlg::Straw2 as u32);
    set_tunables_firefly(crushmap);
    crushmap.allowed_bucket_algorithms = Some(algorithm);
    crushmap
}

/// Set the crush tunables to Jewel
///
pub fn set_tunables_jewel(crushmap: &mut CrushMap) -> &mut CrushMap {
    set_tunables_hammer(crushmap);
    crushmap.chooseleaf_stable = Some(1);
    crushmap
}

#[derive(Debug)]
pub enum EncodingError {
    IoError(std_io::Error),
    InvalidValue,
    InvalidType,
    FromUtf8Error(FromUtf8Error),
}

/// A bucket is a named container of other items (either devices or
/// other buckets).  Items within a bucket are chosen using one of a
/// few different algorithms.  The table summarizes how the speed of
/// each option measures up against mapping stability when items are
/// added or removed.
///
///  Bucket Alg     Speed       Additions    Removals
///  ------------------------------------------------
///  uniform         O(1)       poor         poor
///  list            O(n)       optimal      poor
///  tree            O(log n)   good         good
///  straw           O(n)       optimal      optimal
///
enum_from_primitive!{
    #[repr(u8)]
    #[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
    pub enum BucketAlg{
        Uniform = 1,
        List = 2,
        Tree = 3,
        Straw = 4,
        Straw2 = 5,
    }
}

enum_from_primitive!{
    #[repr(u8)]
    #[derive(Debug, Clone, Eq, PartialEq, RustcDecodable, RustcEncodable)]
    pub enum RuleType{
        Replicated = 1,
        Raid4 = 2, //NOTE: never implemented
        Erasure = 3,
    }
}

enum_from_primitive!{
    #[repr(u8)]
    #[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
    pub enum CrushHash{
        RJenkins1 = 0,
    }
}

// step op codes
enum_from_primitive!{
    #[repr(u16)]
    #[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
    pub enum OpCode{
        Noop = 0,
        /* arg1 = value to start with*/
        Take = 1,
        /* arg1 = num items to pick
        / arg2 = type*/
        ChooseFirstN = 2,

        /* same */
        ChooseIndep = 3,
        /*/ no args */
        Emit = 4,
        ChooseLeafFirstN = 6,
        ChooseLeafIndep = 7,

        SetChooseTries = 8, /*/ override choose_total_tries */
        SetChooseLeafTries = 9, /*/ override chooseleaf_descend_once */
        SetChooseLocalTries = 10,
        SetChooseLocalFallbackTries = 11,
        SetChooseLeafVaryR = 12
    }
}

/// All items are equally weighted.
#[derive(Debug, Clone, Eq, Hash, PartialEq, RustcEncodable, RustcDecodable)]
pub struct CrushBucketUniform {
    pub bucket: Bucket,
    /// 16-bit fixed point; all items equally weighted
    pub item_weight: u32,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketList {
    pub bucket: Bucket,
    ///  All weights are in 16-bit fixed point
    pub item_weights: Vec<(u32, u32)>,
}

/// CrushBucketTree is generally not used in Ceph because the
/// algorithm is buggy.
#[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketTree {
    /// note: h.size is _tree_ size, not number of
    /// actual items
    pub bucket: Bucket,
    pub num_nodes: u8,
    pub node_weights: Vec<u32>,
}

#[derive(Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketStraw2 {
    pub bucket: Bucket,
    ///  All weights are in 16-bit fixed point
    pub item_weights: Vec<u32>,
}

#[derive(Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketStraw {
    pub bucket: Bucket,
    ///  All weights are in 16-bit fixed point
    pub item_weights: Vec<(u32, u32)>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub enum BucketTypes {
    Uniform(CrushBucketUniform),
    List(CrushBucketList),
    Tree(CrushBucketTree),
    Straw(CrushBucketStraw),
    Straw2(CrushBucketStraw2),
    Unknown,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Bucket {
    /// this'll be negative
    pub id: i32,
    /// non-zero; type=0 is reserved for devices
    pub bucket_type: OpCode,
    /// Which algorithm to use
    pub alg: BucketAlg,
    /// which hash function to use
    pub hash: CrushHash,
    /// 16-bit fixed point
    pub weight: u32,
    pub size: u32,
    /// num items
    pub items: Vec<(i32, Option<String>)>,
    // cached random permutation: used for uniform bucket and for
    // the linear search fallback for the other bucket types.
    // /
    // perm_x: u32, /* @x for which *perm is defined */
    pub perm_n: u32,
    /// num elements of *perm that are permuted/defined
    pub perm: u32,
}

/// CRUSH uses user-defined "rules" to describe how inputs should be
/// mapped to devices.  A rule consists of sequence of steps to perform
/// to generate the set of output devices.
///
#[derive(Clone, Eq, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushRuleStep {
    pub op: OpCode,
    pub arg1: (i32, Option<String>),
    pub arg2: (i32, Option<String>),
}

/// The rule mask is used to describe what the rule is intended for.
/// Given a ruleset and size of output set, we search through the
/// rule list for a matching rule_mask.
///
#[derive(Clone, Eq, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushRuleMask {
    pub ruleset: u8,
    pub rule_type: RuleType,
    pub min_size: u8,
    pub max_size: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Rule {
    pub mask: CrushRuleMask,
    pub steps: Vec<CrushRuleStep>,
}

/// CrushMap includes all buckets, rules, etc.
#[derive(Clone, Eq, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushMap {
    pub magic: u32,
    pub max_buckets: i32,
    pub max_rules: u32,
    pub max_devices: i32,

    pub buckets: Vec<BucketTypes>,
    pub rules: Vec<Option<Rule>>,

    pub type_map: Vec<(i32, String)>,
    pub name_map: Vec<(i32, String)>,
    pub rule_name_map: Vec<(i32, String)>,

    /// choose local retries before re-descent
    pub choose_local_tries: Option<u32>,
    /// choose local attempts using a fallback permutation before
    /// re-descent
    pub choose_local_fallback_tries: Option<u32>,
    /// choose attempts before giving up
    pub choose_total_tries: Option<u32>,
    /// attempt chooseleaf inner descent once for firstn mode; on
    /// reject retry outer descent.  Note that this does *not*
    /// apply to a collision: in that case we will retry as we used
    /// to.
    pub chooseleaf_descend_once: Option<u32>,

    /// if non-zero, feed r into chooseleaf, bit-shifted right by (r-1)
    /// bits.  a value of 1 is best for new clusters.  for legacy clusters
    /// that want to limit reshuffling, a value of 3 or 4 will make the
    /// mappings line up a bit better with previous mappings.
    pub chooseleaf_vary_r: Option<u8>,
    pub straw_calc_version: Option<u8>,
    ///
    /// allowed_bucket_algorithms is a bitmask, here the bit positions
    /// are BucketAlg::*.  note that these are *bits* and
    /// BucketAlg* values are not, so we need to or together (1
    /// << BucketAlg::Some_Value).  The 0th bit is not used to
    /// minimize confusion (bucket type values start at 1).
    ///
    pub allowed_bucket_algorithms: Option<u32>,
    /// if set to 1, it makes chooseleaf firstn to return stable results (if
    /// no local retry) so that data migrations would be optimal when some
    /// device fails.
    pub chooseleaf_stable: Option<u8>,
}
