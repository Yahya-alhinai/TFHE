use concrete_boolean::client_key::ClientKey;
use concrete_boolean::parameters::{BooleanParameters, DEFAULT_PARAMETERS, TFHE_LIB_PARAMETERS};
use concrete_boolean::prelude::BinaryBooleanGates;
use concrete_boolean::server_key::ServerKey;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

criterion_group!(
    gates_benches,
    bench_default_parameters,
    bench_tfhe_lib_parameters
);

criterion_main!(gates_benches);

// Put all `bench_function` in one place
// so the keygen is only run once per parameters saving time.
fn bench_gates(c: &mut Criterion, params: BooleanParameters, parameter_name: &str) {
    let cks = ClientKey::new(&params);
    let sks = ServerKey::new(&cks);

    let ct1 = cks.encrypt(true);
    let ct2 = cks.encrypt(false);
    let ct3 = cks.encrypt(true);

    let id = format!("AND gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.and(&ct1, &ct2))));

    let id = format!("NAND gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.nand(&ct1, &ct2))));

    let id = format!("OR gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.or(&ct1, &ct2))));

    let id = format!("XOR gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.xor(&ct1, &ct2))));

    let id = format!("XNOR gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.xnor(&ct1, &ct2))));

    let id = format!("NOT gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.not(&ct1))));

    let id = format!("MUX gate {}", parameter_name);
    c.bench_function(&id, |b| b.iter(|| black_box(sks.mux(&ct1, &ct2, &ct3))));
}

#[cfg(not(feature = "cuda"))]
fn bench_default_parameters(c: &mut Criterion) {
    bench_gates(c, DEFAULT_PARAMETERS, "DEFAULT_PARAMETERS");
}

#[cfg(feature = "cuda")]
fn bench_default_parameters(_: &mut Criterion) {
    let _ = DEFAULT_PARAMETERS; // to avoid unused import warnings
    println!("DEFAULT_PARAMETERS not benched as they are not compatible with the cuda feature.");
}

fn bench_tfhe_lib_parameters(c: &mut Criterion) {
    bench_gates(c, TFHE_LIB_PARAMETERS, "TFHE_LIB_PARAMETERS");
}
