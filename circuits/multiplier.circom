pragma circom 2.0.0;

/*
This circuit template checks that c is the multiplication of a and b.
*/

template Multiplier() {

    // declaration of signals
    signal input a;
    signal input b;
    signal output c;

    // constraint
    c <== a * b;
}

// circuit instance
component main = Multiplier();