# TFHE

This is Fast Fully Homomorphic Encryption (TFHE) library written in Rust by Zama concreate. The library is based on the paper [TFHE: Fast Fully Homomorphic Encryption over the Torus](https://eprint.iacr.org/2018/183.pdf) by Gentry, Halevi, Smart, and Vaikuntanathan.

The goal of the project is to re-implement the TFHE library in C++ to fully optimize the performance of the library using OpenMP & SIMD instructions, CUDA, and implement a hardware accelerator in HLS for the library.
