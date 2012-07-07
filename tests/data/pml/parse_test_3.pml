# Constant and inline optimization test
#
const A = 10;
const B = 5;
const C = A + B;
const D = A - B;
const E = A * B;
const F = A / B;
const G = A % B;


inline square(x) { x * x }

const H = square(B);
const I = square(square(B));

inline wierd(i, j) { i + -j }

const J = wierd(E, A);
const K = wierd(square(A), wierd(E, A));

const L = pop(0x1818181818181818);
const M = min(300, -5);
const N = max(300, -5);
const O = log2(0x4321);
