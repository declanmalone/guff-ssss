// An implementation of key reconstruction from

// Shamir A.,
// How to Share a Secret,
// Communications of the ACM, 22, 1979, pp. 612--613.

// Original implementation written by Charles Karney
// <charles@karney.com> in 2001 and licensed under the GPL.  For more
// information, see http://charles.karney.info/misc/secret.html

// This implementation is a modification of the original, and was
// written by Declan Malone in 2021. It is also licensed under the
// GPL. This version re-implements the original algorithm to use
// Galois fields instead of the original integer field mod 257.

// This is a Rust port of my Perl version that appears in the
// Math::FastGF2 module on CPAN.
//

// l = number of bits in subkey (4, 8, 16 or 32)
// n = number of shares

extern crate clap;
use clap::{Arg, App, SubCommand};
use gf_2px::field;
use gf_2px::field::*;



// shares have the format:
//
// K=W=S=Values=
//
// K  quorum value
// W  width of field in bits
// S  this share number
//
// Values is a list of word-sized values, each of which is a share of
// the corresponding word in the secret key.
//
// Each value in a share represents the result of calculating a
// random polynomial. 
//
// f(x) = a_0 * 1  +  a_1 * x  +  a_2 * x**2  +  ...  +  a_o * x**o
//
// at x = S.
//
// The polynomial is of order o = K - 1.

// Decoding a single word of the original key proceeds by:
//
// * extracting all the S and f(S) values
// * using them to solve for the shared coefficients a_1 .. a_o
// * plugging the shared coefficients into any f(S) to recover a_0
//
// To check the correctness of our algorithm, we can repeat the third
// step for all shares and verify that the produced a_0's all agree.

extern crate hex;
use std::io::{self, BufRead};

// Will store all field values as Vec<u8> rather than trying
// to make a generic storage object.
struct Decoder {
    // use largest word size for these variables
    quorum : u16,		// aka 'k'
    width : u16,		// width in bits; GF(2**8) = width 8
    hex_length : usize,		// length of hex string (nibbles)
    // problem ... we want vectors of appropriate size
    // solution ... store as Vec<u8> for now and convert/iterate later
    x_values    : Vec<u8>,	// taken from shares
    shares : Vec<u8>,		// taken from shares
    coefficients : Vec<u8>,     // calculated in pass 1
    solution : Vec<u8>,		// calculated in pass 2
    // don't store the field, pass it
    // field : &'a impl GenericField<_, _>,
}

// // organise solver as a trait
// trait Solver<T: NumericOps, P: NumericOps> { // : GenericField<T,P> {
//     fn f(&self) -> &dyn GenericField<T,P>;
//     fn pass_1(decoder : &mut Decoder, ) {
//         // code for pass 1
//     }
//     fn pass_2() {
//         // code for pass 2
//     }
//     // add default iterator?
// }

// struct GenericSolver<'a, T: NumericOps, P: NumericOps> {
//     field : &'a dyn GenericField<T,P>
// }

// // impl<T: NumericOps, P: NumericOps> Solver<T,P> for GenericSolver<'_, u8,u8> {
// impl Solver<T, P> for GenericSolver<'_, u8,u8>
//     // where T: NumericOps, P: NumericOps {
// 	{
//     fn f(&self) -> &dyn GenericField<T,P> { self.field }
// }
	
// I'm confused. 

fn parse_shares() -> Decoder {

    let stdin = io::stdin();

    let mut count = 0;
    let mut decoder = Decoder {
	quorum : 0, width : 0, hex_length : 0,
	x_values     : Vec::<u8>::new(),
	shares       : Vec::<u8>::new(),
	coefficients : Vec::<u8>::new(),
	solution     : Vec::<u8>::new(),
    };

    for line in stdin.lock().lines() {
	let line = line.unwrap();

	// split/collect gives us str refs
	let v: Vec<&str> = line.trim().split("=").collect();
	if v.len() != 5 {
	    panic!("Line {}: wrong number of fields", count + 1)
	}
	// K=W=S=Values=
	//
	// K  quorum value
	// W  width of field in bits
	// S  this share number

	// convert k, w, s
	let k : u16 = v[0].parse().unwrap();
	let w : u16 = v[1].parse().unwrap();
	let s : u64 = v[2].parse().unwrap();
	let hlen = v[3].len();
	assert_eq!(v[4].len(), 0); // nothing after final =
	
	// we can't stash references to line because it goes out of
	// scope, so rather than copying the data, might as well do
	// hex conversion here.

	let hlen_bits = hlen * 4; // hex digit == 4 bits
	if hlen_bits % w as usize != 0 {
	    panic!("Line {}: hex data {} is not a multiple of field width", count + 1, v[3])
	}
	if w == 4 && (hlen % 2) != 0 {
	    panic!("Line {}: hex data {} missing final (padding) nibble", count + 1, v[3])
	}

	// decode to Vec<u8>
	let mut vector = hex::decode(v[3])
	    .unwrap();
		//format!("Problem with hex conversion for {}", vec[3]));
	decoder.shares.append(&mut vector);

	// if this is the first line
	if count == 0 {
	    // stash k, w, in decoder
	    if w!=4 && w!=8 && w!=16 && w!=32 { panic!("bad field width") }
	    if k < 1 || k > 1 << (w-1) { panic!("bad quorum value {}", k) }
	    decoder.quorum = k;
	    decoder.width  = w;
	    decoder.hex_length = hlen;
	} else {
	    // compare k, w with values in decoder
	    if w != decoder.width { panic!("mismatched field width value {}", w) }
	    if k != decoder.quorum { panic!("mismatched quorum value {}", k) }
	    if hlen != decoder.hex_length { panic!("wrong share length {}", v[3]) }
	}
	count += 1;
	if s < 1 || s > 1 << (w - 1) { panic!("bad share index {}", s) }
	if count > k {
	    println!("Ignoring share {}", s);
	    continue
	}
	// store as little-endian byte stream
	match w {
	    8 => { decoder.x_values.push((s & 255) as u8); },
	    _ => { unimplemented!(); }
	}
    }
    decoder
}



fn take_something_implementing_field<T,P>(field : &impl GenericField<T,P>)
where T: NumericOps, P: NumericOps {
    panic!("Got field size {}", field.order());
}

// non-storable structs used as type parameters to Iter
// struct U4();
// struct U8();
// struct U16();
// struct U32();

// //trait Iter<T> {
// //    type Output;		// type of return
// //    fn next(&mut self) -> Option<Self::Output>;
// //    fn rewind(&mut self);
// //}

// // impl<T> Iter<P = Type> {}

// struct IterState<'a> {
//     offset : usize,
//     slice : &'a [u8]
// }

// impl<'a, T> Iter<T> for IterState<'a> {
// //    type Output;
//     fn next(&mut self) -> Option<Self::Output> { None }
//     fn rewind(&mut self) {}
// }

// fn new_iter<T> (slice : &[u8]) -> impl Iter<T> + '_ { // IterState<'_> 
//     IterState { offset : 0, slice : slice }
// }

// Eventually want to make solver/iterator stuff generic over unit
// structs
struct U4 {}
struct U8 {}
struct U16 {}
struct U32 {}

// So I think we'll have:
//
// fn solve<U, T, P >(field : impl GenericField<T,P>)
// where U: CustomIter<U>, T : NumericOps, P: NumericOps {
//
// This looks worse than the version without U, but it should help me
// separate out issue of creating iterators over a new, clean type
// rather than having a mess of <T,P> types each with a foreign
// dependency. Also, by using unit structs in the same way, I think
// that I should be able to refactor the library code so that it
// becomes generic for <U> rather than <T,P> (by using associated
// types), which should hopefully be much cleaner/less confusing.


// I know that the signature from take_something_implementing_field()
// works, so use it for solver routines. I'll implement the rest of
// the algorithm for u8 first, then work on adding the U type for
// field-specific iterators.
fn pass_1<T,P>(field : &impl GenericField<T,P>, decoder : &mut Decoder)
where T: NumericOps, P: NumericOps {
    // panic!("Got field size {} in pass 1", field.order());
    // Pass 1: calculate common coefficients a1 .. a_k-1
    // j and l are normal array indices
    let k = decoder.quorum;
    eprintln!("pass 1: k is {}", k);
    for j in 0..k {
	let mut temp : T = T::one();
	for l in 0..k {
	    if l != j {
		temp = field.mul(temp, T::from(decoder.x_values[l as usize]).unwrap());
		temp = field.div(temp, T::from(decoder.x_values[j as usize]).unwrap()
	 			     ^ T::from(decoder.x_values[l as usize]).unwrap())
	    }
	}
	if temp == T::zero() { panic!("Linear independence not satisfied") }
	decoder.coefficients.push(temp.to_u8().unwrap());
    }
}

fn pass_2<T,P>(field : &impl GenericField<T,P>, decoder : &mut Decoder)
    -> Vec<u8>
where T: NumericOps, P: NumericOps {
    //    panic!("Got field size {} in pass 2", field.order());
    let w = decoder.width;	// width in bits
    let k = decoder.quorum;
    let stride = w / 8;

    let words = decoder.hex_length / 2;

    eprintln!("pass 2: hex length {}, words {}", decoder.hex_length, words);
    eprintln!("x_values has length {}", decoder.x_values.len());
    eprintln!("coefficients has length {}", decoder.coefficients.len());
    eprintln!("hex length {}, stride {}", decoder.hex_length, stride);
    
    let mut ans = Vec::<u8>::new();
    for i in 0..words {
	let mut temp : T = T::zero();
	eprintln!("i = {}", i);
	// if k == 1 {continue};
	for j in 0..k {
	    eprintln!("j = {}", j);
	    	    let lindex = i as usize + (j as usize * words);
	    //	    let lindex = i as usize;
	    eprintln!("lindex = {}", lindex);
	    let l = decoder.shares[lindex];
	    let r = decoder.coefficients[j as usize];
	    temp = temp
		^ field.mul( l, r); //T::from(l).unwrap(), T::from(r).unwrap())
	}
	ans.push(temp.to_u8().unwrap());
    }
    ans
}

fn pass_3<T,P>(field : &impl GenericField<T,P>, decoder : &mut Decoder)
where T: NumericOps, P: NumericOps {
    panic!("Got field size {} in pass 3", field.order());
}

fn main() {

    let matches = App::new("shamir-combine")
	.version("1.0")
	.author("Declan Malone <idablack@users.sourceforge.net>")
	.about("Shamir's Secret Sharing Scheme")
	.usage("cat share1 share2 ... | shamir-combine")
	.get_matches();

    let mut decoder = parse_shares();

    // create a field of the appropriate size
    match decoder.width {
	4  => {
	    let field = gf_2px::field::new_gf4(19,3);
	    take_something_implementing_field(&field)
	},
	8  => { //field = gf_2px::field::new_gf8(0x11b,0x1b);
	    let field = gf_2px::fast_gf_2p8::new();
	    pass_1(&field, &mut decoder);
	    let ans = pass_2(&field, &mut decoder);
	    println!("Answer: {:?}", String::from_utf8(ans));
	},
	16 => {
	    let field = gf_2px::field::new_gf16(0x1002b,0x002b);
	    take_something_implementing_field(&field);
	},
	32 => {
	    let field = gf_2px::field::new_gf32(0x10000008d,0x0000008d);
	    take_something_implementing_field(&field);
	},
	_ => { panic!() },	    
    }

}
