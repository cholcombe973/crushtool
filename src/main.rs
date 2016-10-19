#![allow(non_camel_case_types)]

#[macro_use]
extern crate clap;
extern crate crushtool;
extern crate rustc_serialize;

use std::fs::File;
use std::io::{self, Error};
use std::io::prelude::*;

use rustc_serialize::json;

use clap::{Arg, App};

use crushtool::{decode_crushmap, encode_crushmap, CrushMap};
// use crushtool::{CrushMap, BucketTypes, CrushBucketStraw, OpCode, BucketAlg, CrushRuleStep,
//                 Bucket, CrushRuleMask, CrushHash, Rule, RuleType, CephVersion};
// use crushtool::{CephCrushMap, CephDisk as Disk, CephHost as Host, CephPool as Pool, CephBucket,
//                 CephBucketType};

arg_enum!{
  enum Mode {
    compile,
    decompile
  }
}

fn main() {

    let matches = App::new("crushtool")
        .version(crate_version!())
        .arg(Arg::with_name("mode")
            .short("m")
            .required(true)
            .takes_value(true)
            .help("Compile or decompile the crushmap")
            .possible_values(&Mode::variants()))
        .arg(Arg::with_name("custom")
            .short("c")
            .help("EXPERIMENTAL:: This will read in the custom crushmap syntax"))
        .arg(Arg::with_name("output")
            .short("o")
            .help("Output file to put compiled crushmap into")
            .required(true)
            .takes_value(true))
        .get_matches();


    let mode = value_t!(matches.value_of("mode"), Mode).unwrap();

    match mode {
        Mode::compile => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).unwrap();
            input = input.trim_right().into();

            let input_map: CrushMap = if matches.is_present("custom") {
                panic!("Coming soon!")
            } else {
                json::decode(&input).expect("The provided crushmap JSON could not be understood")
            };
            write_to_file(matches.value_of("output").unwrap(), input_map)
                .expect("Failed to write the crushmap to the file")
        }
        Mode::decompile => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer).unwrap();

            let crushmap = decode_crushmap(&buffer)
                .expect("Could not decode the provided crushmap");
            println!("{}", json::encode(&crushmap).unwrap());
        }
    }

}

fn write_to_file(filename: &str, crushmap: CrushMap) -> Result<(), Error> {

    let compiled_crushmap = encode_crushmap(crushmap)
        .expect("Could not compile this input into a valid crushmap");

    let mut f = try!(File::create(filename));
    try!(f.write_all(&compiled_crushmap));
    Ok(())
}
