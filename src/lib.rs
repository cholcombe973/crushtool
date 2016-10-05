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

use std::error::Error;
use std::fmt;
use std::io::{self, ErrorKind};
use std::string::FromUtf8Error;

use byteorder::{LittleEndian, WriteBytesExt};
use num::FromPrimitive;
use nom::{le_u8, le_u16, le_i32, le_u32};
// use rustc_serialize::json;

static CRUSH_MAGIC: u32 = 0x00010000;  /* for detecting algorithm revisions */

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
    let algorithm: u32 = (1 << BucketAlg::Uniform as u32) | (1 << BucketAlg::List as u32) |
                         (1 << BucketAlg::Straw as u32);
    crushmap.choose_local_tries = Some(0);
    crushmap.choose_local_fallback_tries = Some(0);
    crushmap.choose_total_tries = Some(50);
    crushmap.chooseleaf_descend_once = Some(1);
    crushmap.chooseleaf_vary_r = Some(0);
    crushmap.chooseleaf_stable = Some(0);
    crushmap.allowed_bucket_algorithms = Some(algorithm);
    crushmap
}
/// Set the crush tunables to Firefly
///
pub fn set_tunables_firefly(crushmap: &mut CrushMap) -> &mut CrushMap {
    let algorithm: u32 = (1 << BucketAlg::Uniform as u32) | (1 << BucketAlg::List as u32) |
                         (1 << BucketAlg::Straw as u32);
    crushmap.choose_local_tries = Some(0);
    crushmap.choose_local_fallback_tries = Some(0);
    crushmap.choose_total_tries = Some(50);
    crushmap.chooseleaf_descend_once = Some(1);
    crushmap.chooseleaf_vary_r = Some(1);
    crushmap.chooseleaf_stable = Some(0);
    crushmap.allowed_bucket_algorithms = Some(algorithm);
    crushmap
}
/// Set the crush tunables to Hammer
///
pub fn set_tunables_hammer(crushmap: &mut CrushMap) -> &mut CrushMap {
    let algorithm: u32 = (1 << BucketAlg::Uniform as u32) | (1 << BucketAlg::List as u32) |
                         (1 << BucketAlg::Straw as u32) |
                         (1 << BucketAlg::Straw2 as u32);
    crushmap.choose_local_tries = Some(0);
    crushmap.choose_local_fallback_tries = Some(0);
    crushmap.choose_total_tries = Some(50);
    crushmap.chooseleaf_descend_once = Some(1);
    crushmap.chooseleaf_vary_r = Some(1);
    crushmap.chooseleaf_stable = Some(0);
    crushmap.allowed_bucket_algorithms = Some(algorithm);
    crushmap
}

/// Set the crush tunables to Jewel
///
pub fn set_tunables_jewel(crushmap: &mut CrushMap) -> &mut CrushMap {
    let algorithm: u32 = (1 << BucketAlg::Uniform as u32) | (1 << BucketAlg::List as u32) |
                         (1 << BucketAlg::Straw as u32) |
                         (1 << BucketAlg::Straw2 as u32);
    crushmap.choose_local_tries = Some(0);
    crushmap.choose_local_fallback_tries = Some(0);
    crushmap.choose_total_tries = Some(50);
    crushmap.chooseleaf_descend_once = Some(1);
    crushmap.chooseleaf_vary_r = Some(1);
    crushmap.chooseleaf_stable = Some(1);
    crushmap.allowed_bucket_algorithms = Some(algorithm);
    crushmap
}

#[derive(Debug)]
pub enum EncodingError {
    IoError(io::Error),
    InvalidValue,
    InvalidType,
    FromUtf8Error(FromUtf8Error),
}

impl EncodingError {
    pub fn new(err: String) -> EncodingError {
        EncodingError::IoError(io::Error::new(ErrorKind::Other, err))
    }
    pub fn to_string(&self) -> String {
        match *self {
            EncodingError::IoError(ref err) => err.description().to_string(),
            EncodingError::InvalidValue => "Invalid Value".to_string(),
            EncodingError::InvalidType => "Invalid Type".to_string(),
            EncodingError::FromUtf8Error(ref err) => err.utf8_error().to_string(),
        }
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

impl CrushBucketUniform {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
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

    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.compile()));
        try!(buffer.write_u32::<LittleEndian>(self.item_weight));

        Ok(buffer)
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketList {
    pub bucket: Bucket,
    ///  All weights are in 16-bit fixed point
    pub item_weights: Vec<(u32, u32)>,
}
impl CrushBucketList {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
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

    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.compile()));

        for weights in self.item_weights.iter() {
            try!(buffer.write_u32::<LittleEndian>(weights.0));
            try!(buffer.write_u32::<LittleEndian>(weights.1));
        }

        Ok(buffer)
    }
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

impl CrushBucketTree {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
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
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.compile()));

        try!(buffer.write_u8(self.num_nodes));

        for weight in self.node_weights.iter() {
            try!(buffer.write_u32::<LittleEndian>(*weight));
        }

        Ok(buffer)
    }
}
#[derive(Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketStraw2 {
    pub bucket: Bucket,
    ///  All weights are in 16-bit fixed point
    pub item_weights: Vec<u32>,
}

impl CrushBucketStraw2 {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
        chain!(
            input,
            bucket: call!(Bucket::parse)~
            item_weights: count!(le_u32, bucket.size as usize),
            ||{
                CrushBucketStraw2{
                    bucket: bucket,
                    item_weights: item_weights,
                }
            }
        )
    }
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.compile()));

        for weight in self.item_weights.iter() {
            try!(buffer.write_u32::<LittleEndian>(*weight));
        }

        Ok(buffer)
    }
}
impl fmt::Debug for CrushBucketStraw2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            r#"Straw(CrushBucketStraw {{
                bucket: Bucket {{
                    id: {},
                    bucket_type: {:?},
                    alg: {:?},
                    hash: {:?},
                    weight: {},
                    size: {},
                    items: {:?},
                    perm_n: {},
                    perm: {}
                }},
                item_weights: {:?}
            }})"#,
            self.bucket.id,
            self.bucket.bucket_type,
            self.bucket.alg,
            self.bucket.hash,
            self.bucket.weight,
            self.bucket.size,
            self.bucket.items,
            self.bucket.perm_n,
            self.bucket.perm,
            self.item_weights,
        )
    }
}

#[derive(Clone, Eq, Hash, PartialEq, RustcDecodable, RustcEncodable)]
pub struct CrushBucketStraw {
    pub bucket: Bucket,
    ///  All weights are in 16-bit fixed point
    pub item_weights: Vec<(u32, u32)>,
}

impl CrushBucketStraw {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
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
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend(try!(self.bucket.compile()));

        for weights in self.item_weights.iter() {
            try!(buffer.write_u32::<LittleEndian>(weights.0));
            try!(buffer.write_u32::<LittleEndian>(weights.1));
        }

        Ok(buffer)
    }
}

impl fmt::Debug for CrushBucketStraw {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            r#"Straw(CrushBucketStraw {{
                bucket: Bucket {{
                    id: {},
                    bucket_type: {:?},
                    alg: {:?},
                    hash: {:?},
                    weight: {},
                    size: {},
                    items: {:?},
                    perm_n: {},
                    perm: {}
                }},
                item_weights: {:?}
            }})"#,
            self.bucket.id,
            self.bucket.bucket_type,
            self.bucket.alg,
            self.bucket.hash,
            self.bucket.weight,
            self.bucket.size,
            self.bucket.items,
            self.bucket.perm_n,
            self.bucket.perm,
            self.item_weights,
        )
    }
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

named!(decode_32_or_64<&[u8], u32>,
    chain!(
        a: le_u32~
// if a ==0 take another u32
        b: cond!(a==0, le_u32),
        ||{
            b.unwrap_or(a)
        }
    )
);

// This silly function is needed because we don't know the name_map while
// parsing the crush buckets. Only after we're finished parsing the crushmap
// do we know the names
fn none(input: &[u8]) -> nom::IResult<&[u8], Option<String>> {
    nom::IResult::Done(input, None)
}

fn try_le_u8(input: &[u8]) -> nom::IResult<&[u8], Option<u8>> {
    if input.len() < 1 {
        nom::IResult::Done(input, None)
    } else {
        chain!(input,
            a: le_u8,
            ||{
                Some(a)
            }
        )
    }
}

fn try_le_u32(input: &[u8]) -> nom::IResult<&[u8], Option<u32>> {
    if input.len() < 4 {
        nom::IResult::Done(input, None)
    } else {
        chain!(input,
            a: le_u32,
            ||{
                Some(a)
            }
        )
    }
}

fn parse_string(i: &[u8]) -> nom::IResult<&[u8], String> {
    trace!("parse_string input: {:?}", i);
    chain!(i,
        length: decode_32_or_64 ~
        s: dbg!(take_str!(length)),
        ||{
            s.to_string()
        }
    )
}

fn parse_string_map(input: &[u8]) -> nom::IResult<&[u8], Vec<(i32, String)>> {
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

fn encode_string_map(input: Vec<(i32, String)>) -> Result<Vec<u8>, EncodingError> {
    let mut buffer = Vec::new();
    // Count
    try!(buffer.write_u32::<LittleEndian>(input.len() as u32));

    for pair in input.into_iter() {
        try!(buffer.write_i32::<LittleEndian>(pair.0));

        // String length
        try!(buffer.write_u32::<LittleEndian>(pair.1.len() as u32));
        // String data
        buffer.extend(pair.1.into_bytes());
    }

    Ok(buffer)
}

fn parse_bucket<'a>(input: &'a [u8]) -> nom::IResult<&[u8], BucketTypes> {
    trace!("parse_bucket input: {:?}", input);
    let alg_type_bits = le_u32(input);
    match alg_type_bits {
        nom::IResult::Done(unparsed_data, alg_bits) => {
            let some_alg = BucketAlg::from_u32(alg_bits);
            let alg = match some_alg {
                Some(t) => t,
                None => {
                    trace!("Unknown bucket: {:?}", alg_bits);
                    return nom::IResult::Done(unparsed_data, BucketTypes::Unknown);
                }
            };
            match alg {
                BucketAlg::Uniform => {
                    trace!("Trying to decode uniform bucket");
                    chain!(
                        input,
                        uniform_bucket: dbg!(call!(CrushBucketUniform::parse)),
                        ||{
                            BucketTypes::Uniform(uniform_bucket)
                        }
                    )
                }
                BucketAlg::List => {
                    trace!("Trying to decode list bucket");
                    chain!(
                        input,
                        list_bucket: dbg!(call!(CrushBucketList::parse)),
                        ||{
                            BucketTypes::List(list_bucket)
                        }
                    )
                }
                BucketAlg::Tree => {
                    trace!("Trying to decode tree bucket");
                    chain!(
                        input,
                        tree_bucket: dbg!(call!(CrushBucketTree::parse)),
                        ||{
                            BucketTypes::Tree(tree_bucket)
                        }
                    )
                }
                BucketAlg::Straw => {
                    trace!("Trying to decode straw bucket");
                    chain!(
                        input,
                        straw_bucket: dbg!(call!(CrushBucketStraw::parse)),
                        ||{
                            BucketTypes::Straw(straw_bucket)
                        }
                    )
                }
                BucketAlg::Straw2 => {
                    trace!("Trying to decode straw2 bucket");
                    chain!(
                        input,
                        straw_bucket: dbg!(call!(CrushBucketStraw2::parse)),
                        ||{
                            BucketTypes::Straw2(straw_bucket)
                        }
                    )
                }
            }
        }
        nom::IResult::Incomplete(needed) => {
            return nom::IResult::Incomplete(needed);
        }
        nom::IResult::Error(e) => {
            return nom::IResult::Error(e);
        }
    }
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

impl Bucket {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
        trace!("bucket input: {:?}", input);
        chain!(
            input,
            le_u32~
            //switch on algorithm
            id: le_i32~
            bucket_type_bits: le_u16 ~
            bucket_type: expr_opt!(OpCode::from_u16(bucket_type_bits)) ~
            alg_bits: le_u8~
            alg: expr_opt!(BucketAlg::from_u8(alg_bits))~
            hash_bits: le_u8~
            hash: expr_opt!(CrushHash::from_u8(hash_bits))~
            weight: le_u32~
            size: le_u32~
            items: dbg!(
                count!(
                    pair!(le_i32, call!(none)), size as usize
                )
            ),
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
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u32::<LittleEndian>(self.alg.clone() as u32));
        try!(buffer.write_i32::<LittleEndian>(self.id));
        try!(buffer.write_u16::<LittleEndian>(self.bucket_type.clone() as u16));
        try!(buffer.write_u8(self.alg.clone() as u8));
        try!(buffer.write_u8(self.hash.clone() as u8));
        try!(buffer.write_u32::<LittleEndian>(self.weight));
        try!(buffer.write_u32::<LittleEndian>(self.size));

        for item in self.items.iter() {
            try!(buffer.write_i32::<LittleEndian>(item.0));
        }

        Ok(buffer)
    }

    fn update_name_mapping(&mut self, name_map: &Vec<(i32, String)>) {
        trace!("Updating name mapping with {:?}", name_map);
        let mut new_items: Vec<(i32, Option<String>)> = Vec::with_capacity(self.items.len());

        // I want to preserve the vec ordering
        for item_tuple in self.items.iter_mut() {
            let mut resolved_item: (i32, Option<String>) = (item_tuple.0, None);

            for name in name_map {
                if name.0 == item_tuple.0 {
                    resolved_item.1 = Some(name.1.clone());
                }
            }
            new_items.push(resolved_item);
        }
        self.items = new_items;
    }
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

impl CrushRuleStep {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
        trace!("rule step input: {:?}", input);
        chain!(
            input,
            op_bits: le_u32~
            op_code: expr_opt!(OpCode::from_u32(op_bits)) ~
            arg1: le_i32~
            arg2: le_i32,
            ||{
                CrushRuleStep{
                    op: op_code,
                    //These get resolved later once we know the type_map
                    arg1: (arg1, None),
                    arg2: (arg2, None),
                }
            }
        )
    }
    // Change the arg's.1 from None to a proper name
    fn update_arg_mapping(&mut self, type_map: &Vec<(i32, String)>) {
        trace!("Updating arg mapping with {:?}", type_map);
        for tuple in type_map {
            if tuple.0 == self.arg1.0 {
                self.arg1.1 = Some(tuple.1.clone());
            }
            if tuple.0 == self.arg2.0 {
                self.arg2.1 = Some(tuple.1.clone());
            }
        }
    }
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u32::<LittleEndian>(self.op.clone() as u32));
        try!(buffer.write_i32::<LittleEndian>(self.arg1.0));
        try!(buffer.write_i32::<LittleEndian>(self.arg2.0));

        Ok(buffer)
    }
}

impl fmt::Debug for CrushRuleStep {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            r#"CrushRuleStep {{
                op: {:?},
                arg1: {:?},
                arg2: {:?},
            }}"#,
            self.op,
            self.arg1,
            self.arg2,
        )
    }
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

impl CrushRuleMask {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Self> {
        trace!("rule mask input: {:?}", input);
        chain!(
            input,
            ruleset: le_u8~
            rule_type_bits: le_u8 ~
            rule_type: expr_opt!(RuleType::from_u8(rule_type_bits)) ~
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
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        try!(buffer.write_u8(self.ruleset));
        try!(buffer.write_u8(self.rule_type.clone() as u8));
        try!(buffer.write_u8(self.min_size));
        try!(buffer.write_u8(self.max_size));

        Ok(buffer)
    }
}
impl fmt::Debug for CrushRuleMask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            r#"CrushRuleMask {{
                ruleset: {},
                rule_type: {:?},
                min_size: {},
                max_size: {},
            }}"#,
            self.ruleset,
            self.rule_type,
            self.min_size,
            self.max_size,
        )
    }
}


#[derive(Debug, Clone, Eq, PartialEq, RustcDecodable, RustcEncodable)]
pub struct Rule {
    pub mask: CrushRuleMask,
    pub steps: Vec<CrushRuleStep>,
}

impl Rule {
    fn parse<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Option<Self>> {
        trace!("rule input: {:?}", input);
        let yes_bits = le_u32(input);
        match yes_bits {
            nom::IResult::Done(unparsed_data, yes) => {
                if yes == 0 {
                    return nom::IResult::Done(unparsed_data, None);
                } else {
                    chain!(
                        unparsed_data,
                        //Length.  We don't need this because we know how long the Vec is
                        length: le_u32~
                        mask: dbg!(call!(CrushRuleMask::parse))~
                        steps: dbg!(count!(call!(CrushRuleStep::parse), length as usize)),
                        ||{
                            Some(Rule{
                                mask: mask,
                                steps: steps,
                            })
                        }
                    )
                }
            }
            nom::IResult::Incomplete(needed) => {
                return nom::IResult::Incomplete(needed);
            }
            nom::IResult::Error(e) => {
                return nom::IResult::Error(e);
            }
        }
    }
    fn compile(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buffer: Vec<u8> = Vec::new();
        // YES
        try!(buffer.write_u32::<LittleEndian>(1));

        try!(buffer.write_u32::<LittleEndian>(self.steps.len() as u32));
        buffer.extend(try!(self.mask.compile()));
        // Steps length
        for step in self.steps.iter() {
            buffer.extend(try!(step.compile()));
        }

        Ok(buffer)
    }
}

// Try to update the CrushRuleStep's now that we know the type_map.  I wish Ceph
// had included the type_map first in the compiled crush so I could skip this workaround.
fn update_rule_steps<'a>(rules: &'a mut Vec<Option<Rule>>,
                         type_map: &Vec<(i32, String)>)
                         -> &'a mut Vec<Option<Rule>> {
    for rule in rules.iter_mut() {
        match *rule {
            Some(ref mut r) => {
                for step in r.steps.iter_mut() {
                    step.update_arg_mapping(type_map)
                }
            }
            None => {
                // Skip None's
            }
        }
    }
    rules
}

fn update_buckets<'a>(crush_buckets: &'a mut Vec<BucketTypes>,
                      name_map: &Vec<(i32, String)>)
                      -> &'a mut Vec<BucketTypes> {
    for crush_bucket in crush_buckets.iter_mut() {
        match *crush_bucket {
            BucketTypes::Uniform(ref mut uniform) => {
                uniform.bucket.update_name_mapping(name_map);
            }
            BucketTypes::List(ref mut list) => {
                list.bucket.update_name_mapping(name_map);
            }
            BucketTypes::Tree(ref mut tree) => {
                tree.bucket.update_name_mapping(name_map);
            }
            BucketTypes::Straw(ref mut straw) => {
                straw.bucket.update_name_mapping(name_map);
            }
            BucketTypes::Straw2(ref mut straw) => {
                straw.bucket.update_name_mapping(name_map);
            }
            BucketTypes::Unknown => {}
        }
    }
    crush_buckets
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

impl fmt::Debug for CrushMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            r#"CrushMap {{
                magic: {},
                max_buckets: {},
                max_rules: {},
                max_devices: {},
                buckets: {:?},
                rules: {:?},
                name_map: {:?},
                rule_name_map: {:?},
                choose_local_tries: {:?},
                choose_local_fallback_tries: {:?},
                choose_total_tries: {:?},
                chooseleaf_descend_once: {:?},
                chooseleaf_vary_r: {:?},
                straw_calc_version: {:?},
                allowed_bucket_algorithms: {:?},
                chooseleaf_stable: {:?},
            }}"#,
            self.magic,
            self.max_buckets,
            self.max_rules,
            self.max_devices,
            self.buckets,
            self.rules,
            self.name_map,
            self.rule_name_map,
            self.choose_local_tries,
            self.choose_local_fallback_tries,
            self.choose_total_tries,
            self.chooseleaf_descend_once,
            self.chooseleaf_vary_r,
            self.straw_calc_version,
            self.allowed_bucket_algorithms,
            self.chooseleaf_stable,
        )
    }
}

pub fn decode_crushmap<'a>(input: &'a [u8]) -> Result<CrushMap, String> {
    let mut result = parse_crushmap(input);
    match result {
        nom::IResult::Done(_, ref mut map) => {
            // Resolve the argument types
            update_rule_steps(&mut map.rules, &map.type_map);

            // Resolve the item names
            update_buckets(&mut map.buckets, &map.name_map);

            // TODO: Can we get rid of this clone?
            return Ok(map.clone());
        }
        nom::IResult::Error(_) => Err("parsing error".to_string()),
        nom::IResult::Incomplete(_) => Err("Incomplete".to_string()),
    }
}

fn parse_crushmap<'a>(input: &'a [u8]) -> nom::IResult<&[u8], CrushMap> {
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
        allowed_bucket_algorithms: call!(try_le_u32) ~
        chooseleaf_stable: call!(try_le_u8),
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
                allowed_bucket_algorithms: allowed_bucket_algorithms,
                chooseleaf_stable: chooseleaf_stable,
            }
        }
    )
}
pub fn encode_crushmap(crushmap: CrushMap) -> Result<Vec<u8>, EncodingError> {
    let mut buffer: Vec<u8> = Vec::new();
    try!(buffer.write_u32::<LittleEndian>(CRUSH_MAGIC));

    try!(buffer.write_i32::<LittleEndian>(crushmap.max_buckets));
    try!(buffer.write_u32::<LittleEndian>(crushmap.max_rules));
    try!(buffer.write_i32::<LittleEndian>(crushmap.max_devices));

    for bucket in crushmap.buckets.iter() {
        match bucket {
            &BucketTypes::Uniform(ref uniform) => {
                trace!("Trying to encode uniform bucket");
                buffer.extend(try!(uniform.compile()));
            }
            &BucketTypes::List(ref list) => {
                trace!("Trying to encode list bucket");
                buffer.extend(try!(list.compile()));
            }
            &BucketTypes::Tree(ref tree) => {
                trace!("Trying to encode tree bucket");
                buffer.extend(try!(tree.compile()));
            }
            &BucketTypes::Straw(ref straw) => {
                trace!("Trying to encode straw bucket");
                buffer.extend(try!(straw.compile()));
            }
            &BucketTypes::Straw2(ref straw) => {
                trace!("Trying to encode straw2 bucket");
                buffer.extend(try!(straw.compile()));
            }
            &BucketTypes::Unknown => {
                try!(buffer.write_u32::<LittleEndian>(0));
            }
        }
    }

    for rule in crushmap.rules.into_iter() {
        if rule.is_some() {
            let unwrapped_rule = rule.unwrap();
            buffer.extend(try!(unwrapped_rule.compile()));
        } else {
            // yes bits == 0
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    }
    buffer.extend(try!(encode_string_map(crushmap.type_map)));
    buffer.extend(try!(encode_string_map(crushmap.name_map)));
    buffer.extend(try!(encode_string_map(crushmap.rule_name_map)));

    match crushmap.choose_local_tries {
        Some(val) => {
            try!(buffer.write_u32::<LittleEndian>(val));
        }
        None => {
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    };

    match crushmap.choose_local_fallback_tries {
        Some(val) => {
            try!(buffer.write_u32::<LittleEndian>(val));
        }
        None => {
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    };
    match crushmap.choose_total_tries {
        Some(val) => {
            try!(buffer.write_u32::<LittleEndian>(val));
        }
        None => {
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    };
    match crushmap.chooseleaf_descend_once {
        Some(val) => {
            try!(buffer.write_u32::<LittleEndian>(val));
        }
        None => {
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    };
    match crushmap.chooseleaf_vary_r {
        Some(val) => {
            try!(buffer.write_u8(val));
        }
        None => {
            try!(buffer.write_u8(0));
        }
    };
    match crushmap.straw_calc_version {
        Some(val) => {
            try!(buffer.write_u8(val));
        }
        None => {
            try!(buffer.write_u8(0));
        }
    };
    match crushmap.allowed_bucket_algorithms {
        Some(val) => {
            try!(buffer.write_u32::<LittleEndian>(val));
        }
        None => {
            try!(buffer.write_u32::<LittleEndian>(0));
        }
    };
    match crushmap.chooseleaf_stable {
        Some(val) => {
            try!(buffer.write_u8(val));
        }
        None => {
            try!(buffer.write_u8(0));
        }
    }

    Ok(buffer)
}
