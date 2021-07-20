// An implementation of key sharing from

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

fn main() {

    


}
