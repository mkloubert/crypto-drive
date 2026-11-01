// crypto-drive
// Copyright (C) 2026  Marcel Joachim Kloubert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Throughput benchmarks for chunks, names and the file system logic.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use crypto_drive_core::content::{CHUNK_SIZE, ChunkCipher, FileHeader};
use crypto_drive_core::fs::{CryptoFs, VPath};
use crypto_drive_core::names::NameCipher;
use crypto_drive_core::testutil::test_vault;
use std::hint::black_box;

const MIB: usize = 1024 * 1024;

fn chunk_seal_open(c: &mut Criterion) {
    let header = FileHeader::random(1, [3u8; 16]).expect("header");
    let cipher = ChunkCipher::new(&[7u8; 32], &header);
    let plain = vec![0x5au8; CHUNK_SIZE as usize];
    let sealed = cipher.seal(3, false, &plain).expect("seal");

    let mut group = c.benchmark_group("chunk_seal_open");
    group.throughput(Throughput::Bytes(CHUNK_SIZE));
    group.bench_function("seal_64KiB", |b| {
        b.iter(|| black_box(cipher.seal(3, false, black_box(&plain)).expect("seal")));
    });
    group.bench_function("open_64KiB", |b| {
        b.iter(|| black_box(cipher.open(3, false, black_box(&sealed)).expect("open")));
    });
    group.finish();
}

fn name_encrypt_decrypt(c: &mut Criterion) {
    let cipher = NameCipher::new(&[9u8; 64]);
    let dir_id = [1u8; 16];
    let entry_id = [2u8; 16];
    let name = "a-name-with-30-characters-abc!";
    assert_eq!(name.chars().count(), 30);
    let encoded = cipher.encrypt(&dir_id, &entry_id, name).expect("encrypt");

    let mut group = c.benchmark_group("name_encrypt_decrypt");
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            black_box(
                cipher
                    .encrypt(&dir_id, &entry_id, black_box(name))
                    .expect("encrypt"),
            )
        });
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            black_box(
                cipher
                    .decrypt(&dir_id, black_box(&encoded))
                    .expect("decrypt"),
            )
        });
    });
    group.finish();
}

fn new_fs() -> (tempfile::TempDir, CryptoFs) {
    let (tmp, vault, _mk) = test_vault();
    let fs = CryptoFs::new(vault).expect("fs");
    (tmp, fs)
}

fn fs_sequential_write_read_16mib(c: &mut Criterion) {
    let (_tmp, fs) = new_fs();
    let data = vec![0xa5u8; MIB];
    let path = VPath::parse("/seq.bin").expect("path");
    let mut group = c.benchmark_group("fs_sequential_write_read_16MiB");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(16 * MIB as u64));
    group.bench_function("write", |b| {
        b.iter(|| {
            // Start with a new file each time. The first call has nothing to remove.
            let _ = fs.unlink(&path);
            let (_attr, fh) = fs.create(&path, 0o644).expect("create");
            for i in 0..16 {
                fs.write(fh, (i * MIB) as u64, &data).expect("write");
            }
            fs.release(fh).expect("release");
        });
    });
    group.bench_function("read", |b| {
        b.iter(|| {
            let fh = fs.open(&path, false, false).expect("open");
            let mut total = 0;
            for i in 0..16 {
                total += fs
                    .read(fh, (i * MIB) as u64, MIB as u32)
                    .expect("read")
                    .len();
            }
            fs.release(fh).expect("release");
            assert_eq!(total, 16 * MIB);
        });
    });
    group.finish();
}

fn fs_random_4k_writes(c: &mut Criterion) {
    let (_tmp, fs) = new_fs();
    let path = VPath::parse("/random.bin").expect("path");
    let (_attr, fh) = fs.create(&path, 0o644).expect("create");
    let size = 16 * MIB;
    fs.truncate_handle(fh, size as u64).expect("truncate");
    fs.flush(fh).expect("flush");
    let block = vec![0x3cu8; 4096];
    let slots = (size / 4096) as u64;
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;

    let mut group = c.benchmark_group("fs_random_4k_writes");
    group.throughput(Throughput::Bytes(4096));
    group.bench_function("write_4KiB", |b| {
        b.iter_batched(
            || {
                // xorshift: a cheap, repeatable offset generator
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state % slots) * 4096
            },
            |offset| {
                fs.write(fh, offset, &block).expect("write");
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
    fs.release(fh).expect("release");
}

criterion_group!(
    benches,
    chunk_seal_open,
    name_encrypt_decrypt,
    fs_sequential_write_read_16mib,
    fs_random_4k_writes
);
criterion_main!(benches);
