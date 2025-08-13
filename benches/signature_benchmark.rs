use criterion::{Criterion, criterion_group, criterion_main};
use crypdefi_bot_sdk::http::Signature;
use std::hint::black_box;

fn bench_to_der(c: &mut Criterion) {
    let signature = Signature {
        r: "bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9".to_string(),
        s: "4a28dc564d87e36871d032a208ccef1229a8c95875928f867d77daa21991ca2e".to_string(),
        recovery_id: Some(0),
    };

    c.bench_function("signature_to_der", |b| {
        b.iter(|| {
            black_box(black_box(&signature).to_der()).unwrap();
        })
    });
}

fn bench_secp_der(c: &mut Criterion) {
    let signature = Signature {
        r: "bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9".to_string(),
        s: "4a28dc564d87e36871d032a208ccef1229a8c95875928f867d77daa21991ca2e".to_string(),
        recovery_id: Some(0),
    };

    c.bench_function("signature_secp_der", |b| {
        b.iter(|| {
            black_box(black_box(&signature).secp_der()).unwrap();
        })
    });
}

criterion_group!(benches, bench_to_der, bench_secp_der);
criterion_main!(benches);
